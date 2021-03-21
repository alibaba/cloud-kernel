// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>

#include <asm/cpu_device_id.h>
#include "uncore.h"

static struct zhaoxin_uncore_type *empty_uncore[] = { NULL, };
static struct zhaoxin_uncore_type **uncore_msr_uncores = empty_uncore;

/* mask of cpus that collect uncore events */
static cpumask_t uncore_cpu_mask;

/* constraint for the fixed counter */
static struct event_constraint uncore_constraint_fixed =
	EVENT_CONSTRAINT(~0ULL, 1 << UNCORE_PMC_IDX_FIXED, ~0ULL);

static int max_packages;

/* CHX event control */
#define CHX_UNC_CTL_EV_SEL_MASK			0x000000ff
#define CHX_UNC_CTL_UMASK_MASK			0x0000ff00
#define CHX_UNC_CTL_EDGE_DET			(1 << 18)
#define CHX_UNC_CTL_EN				(1 << 22)
#define CHX_UNC_CTL_INVERT			(1 << 23)
#define CHX_UNC_CTL_CMASK_MASK			0xff000000
#define CHX_UNC_FIXED_CTR_CTL_EN		(1 << 0)

#define CHX_UNC_RAW_EVENT_MASK			(CHX_UNC_CTL_EV_SEL_MASK | \
						 CHX_UNC_CTL_UMASK_MASK | \
						 CHX_UNC_CTL_EDGE_DET | \
						 CHX_UNC_CTL_INVERT | \
						 CHX_UNC_CTL_CMASK_MASK)

/* CHX global control register */
#define CHX_UNC_PERF_GLOBAL_CTL                 0x391
#define CHX_UNC_FIXED_CTR                       0x394
#define CHX_UNC_FIXED_CTR_CTRL                  0x395

/* CHX uncore global control */
#define CHX_UNC_GLOBAL_CTL_EN_PC_ALL            ((1ULL << 4) - 1)
#define CHX_UNC_GLOBAL_CTL_EN_FC                (1ULL << 32)

/* CHX uncore register */
#define CHX_UNC_PERFEVTSEL0                     0x3c0
#define CHX_UNC_UNCORE_PMC0                     0x3b0

DEFINE_UNCORE_FORMAT_ATTR(event, event, "config:0-7");
DEFINE_UNCORE_FORMAT_ATTR(umask, umask, "config:8-15");
DEFINE_UNCORE_FORMAT_ATTR(edge, edge, "config:18");
DEFINE_UNCORE_FORMAT_ATTR(inv, inv, "config:23");
DEFINE_UNCORE_FORMAT_ATTR(cmask8, cmask, "config:24-31");

ssize_t zx_uncore_event_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct uncore_event_desc *event =
		container_of(attr, struct uncore_event_desc, attr);
	return sprintf(buf, "%s", event->config);
}

/*chx uncore support */
static void chx_uncore_msr_disable_event(struct zhaoxin_uncore_box *box, struct perf_event *event)
{
	wrmsrl(event->hw.config_base, 0);
}

static u64 uncore_msr_read_counter(struct zhaoxin_uncore_box *box, struct perf_event *event)
{
	u64 count;

	rdmsrl(event->hw.event_base, count);

	return count;
}

static void chx_uncore_msr_disable_box(struct zhaoxin_uncore_box *box)
{
	wrmsrl(CHX_UNC_PERF_GLOBAL_CTL, 0);
}

static void chx_uncore_msr_enable_box(struct zhaoxin_uncore_box *box)
{
	wrmsrl(CHX_UNC_PERF_GLOBAL_CTL, CHX_UNC_GLOBAL_CTL_EN_PC_ALL | CHX_UNC_GLOBAL_CTL_EN_FC);
}

static void chx_uncore_msr_enable_event(struct zhaoxin_uncore_box *box, struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;

	if (hwc->idx < UNCORE_PMC_IDX_FIXED)
		wrmsrl(hwc->config_base, hwc->config | CHX_UNC_CTL_EN);
	else
		wrmsrl(hwc->config_base, CHX_UNC_FIXED_CTR_CTL_EN);
}

static struct attribute *chx_uncore_formats_attr[] = {
	&format_attr_event.attr,
	&format_attr_umask.attr,
	&format_attr_edge.attr,
	&format_attr_inv.attr,
	&format_attr_cmask8.attr,
	NULL,
};

static struct attribute_group chx_uncore_format_group = {
	.name = "format",
	.attrs = chx_uncore_formats_attr,
};

static struct uncore_event_desc chx_uncore_events[] = {
	{ /* end: all zeroes */ },
};

static struct zhaoxin_uncore_ops chx_uncore_msr_ops = {
	.disable_box	= chx_uncore_msr_disable_box,
	.enable_box	= chx_uncore_msr_enable_box,
	.disable_event	= chx_uncore_msr_disable_event,
	.enable_event	= chx_uncore_msr_enable_event,
	.read_counter	= uncore_msr_read_counter,
};

static struct zhaoxin_uncore_type chx_uncore_box = {
	.name		= "",
	.num_counters   = 4,
	.num_boxes	= 1,
	.perf_ctr_bits	= 48,
	.fixed_ctr_bits	= 48,
	.event_ctl	= CHX_UNC_PERFEVTSEL0,
	.perf_ctr	= CHX_UNC_UNCORE_PMC0,
	.fixed_ctr	= CHX_UNC_FIXED_CTR,
	.fixed_ctl	= CHX_UNC_FIXED_CTR_CTRL,
	.event_mask	= CHX_UNC_RAW_EVENT_MASK,
	.event_descs	= chx_uncore_events,
	.ops		= &chx_uncore_msr_ops,
	.format_group	= &chx_uncore_format_group,
};

static struct zhaoxin_uncore_type *chx_msr_uncores[] = {
	&chx_uncore_box,
	NULL,
};

static struct zhaoxin_uncore_box *uncore_pmu_to_box(struct zhaoxin_uncore_pmu *pmu, int cpu)
{
	unsigned int package_id = topology_logical_package_id(cpu);

	/*
	 * The unsigned check also catches the '-1' return value for non
	 * existent mappings in the topology map.
	 */
	return package_id < max_packages ? pmu->boxes[package_id] : NULL;
}

static void uncore_assign_hw_event(struct zhaoxin_uncore_box *box,
				   struct perf_event *event, int idx)
{
	struct hw_perf_event *hwc = &event->hw;

	hwc->idx = idx;
	hwc->last_tag = ++box->tags[idx];

	if (uncore_pmc_fixed(hwc->idx)) {
		hwc->event_base = uncore_fixed_ctr(box);
		hwc->config_base = uncore_fixed_ctl(box);
		return;
	}

	hwc->config_base = uncore_event_ctl(box, hwc->idx);
	hwc->event_base  = uncore_perf_ctr(box, hwc->idx);
}

void uncore_perf_event_update(struct zhaoxin_uncore_box *box, struct perf_event *event)
{
	u64 prev_count, new_count, delta;
	int shift;

	if (uncore_pmc_fixed(event->hw.idx))
		shift = 64 - uncore_fixed_ctr_bits(box);
	else
		shift = 64 - uncore_perf_ctr_bits(box);

	/* the hrtimer might modify the previous event value */
again:
	prev_count = local64_read(&event->hw.prev_count);
	new_count = uncore_read_counter(box, event);
	if (local64_xchg(&event->hw.prev_count, new_count) != prev_count)
		goto again;

	delta = (new_count << shift) - (prev_count << shift);
	delta >>= shift;

	local64_add(delta, &event->count);
}

static enum hrtimer_restart uncore_pmu_hrtimer(struct hrtimer *hrtimer)
{
	struct zhaoxin_uncore_box *box;
	struct perf_event *event;
	unsigned long flags;
	int bit;

	box = container_of(hrtimer, struct zhaoxin_uncore_box, hrtimer);
	if (!box->n_active || box->cpu != smp_processor_id())
		return HRTIMER_NORESTART;
	/*
	 * disable local interrupt to prevent uncore_pmu_event_start/stop
	 * to interrupt the update process
	 */
	local_irq_save(flags);

	/*
	 * handle boxes with an active event list as opposed to active
	 * counters
	 */
	list_for_each_entry(event, &box->active_list, active_entry) {
		uncore_perf_event_update(box, event);
	}

	for_each_set_bit(bit, box->active_mask, UNCORE_PMC_IDX_MAX)
		uncore_perf_event_update(box, box->events[bit]);

	local_irq_restore(flags);

	hrtimer_forward_now(hrtimer, ns_to_ktime(box->hrtimer_duration));
	return HRTIMER_RESTART;
}

static void uncore_pmu_start_hrtimer(struct zhaoxin_uncore_box *box)
{
	hrtimer_start(&box->hrtimer, ns_to_ktime(box->hrtimer_duration),
		      HRTIMER_MODE_REL_PINNED);
}

static void uncore_pmu_cancel_hrtimer(struct zhaoxin_uncore_box *box)
{
	hrtimer_cancel(&box->hrtimer);
}

static void uncore_pmu_init_hrtimer(struct zhaoxin_uncore_box *box)
{
	hrtimer_init(&box->hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	box->hrtimer.function = uncore_pmu_hrtimer;
}

static struct zhaoxin_uncore_box *uncore_alloc_box(struct zhaoxin_uncore_type *type,
						 int node)
{
	int i, size, numshared = type->num_shared_regs;
	struct zhaoxin_uncore_box *box;

	size = sizeof(*box) + numshared * sizeof(struct zhaoxin_uncore_extra_reg);

	box = kzalloc_node(size, GFP_KERNEL, node);
	if (!box)
		return NULL;

	for (i = 0; i < numshared; i++)
		raw_spin_lock_init(&box->shared_regs[i].lock);

	uncore_pmu_init_hrtimer(box);
	box->cpu = -1;
	box->package_id = -1;

	/* set default hrtimer timeout */
	box->hrtimer_duration = UNCORE_PMU_HRTIMER_INTERVAL;

	INIT_LIST_HEAD(&box->active_list);

	return box;
}

static bool is_box_event(struct zhaoxin_uncore_box *box, struct perf_event *event)
{
	return &box->pmu->pmu == event->pmu;
}

static struct event_constraint *
uncore_get_event_constraint(struct zhaoxin_uncore_box *box, struct perf_event *event)
{
	struct zhaoxin_uncore_type *type = box->pmu->type;
	struct event_constraint *c;

	if (type->ops->get_constraint) {
		c = type->ops->get_constraint(box, event);
		if (c)
			return c;
	}

	if (event->attr.config == UNCORE_FIXED_EVENT)
		return &uncore_constraint_fixed;

	if (type->constraints) {
		for_each_event_constraint(c, type->constraints) {
			if ((event->hw.config & c->cmask) == c->code)
				return c;
		}
	}

	return &type->unconstrainted;
}

static void uncore_put_event_constraint(struct zhaoxin_uncore_box *box,
					struct perf_event *event)
{
	if (box->pmu->type->ops->put_constraint)
		box->pmu->type->ops->put_constraint(box, event);
}

static int uncore_assign_events(struct zhaoxin_uncore_box *box, int assign[], int n)
{
	unsigned long used_mask[BITS_TO_LONGS(UNCORE_PMC_IDX_MAX)];
	struct event_constraint *c;
	int i, wmin, wmax, ret = 0;
	struct hw_perf_event *hwc;

	bitmap_zero(used_mask, UNCORE_PMC_IDX_MAX);

	for (i = 0, wmin = UNCORE_PMC_IDX_MAX, wmax = 0; i < n; i++) {
		c = uncore_get_event_constraint(box, box->event_list[i]);
		box->event_constraint[i] = c;
		wmin = min(wmin, c->weight);
		wmax = max(wmax, c->weight);
	}

	/* fastpath, try to reuse previous register */
	for (i = 0; i < n; i++) {
		hwc = &box->event_list[i]->hw;
		c = box->event_constraint[i];

		/* never assigned */
		if (hwc->idx == -1)
			break;

		/* constraint still honored */
		if (!test_bit(hwc->idx, c->idxmsk))
			break;

		/* not already used */
		if (test_bit(hwc->idx, used_mask))
			break;

		__set_bit(hwc->idx, used_mask);
		if (assign)
			assign[i] = hwc->idx;
	}
	/* slow path */
	if (i != n)
		ret = perf_assign_events(box->event_constraint, n,
					 wmin, wmax, n, assign);

	if (!assign || ret) {
		for (i = 0; i < n; i++)
			uncore_put_event_constraint(box, box->event_list[i]);
	}
	return ret ? -EINVAL : 0;
}

static void uncore_pmu_event_start(struct perf_event *event, int flags)
{
	struct zhaoxin_uncore_box *box = uncore_event_to_box(event);
	int idx = event->hw.idx;


	if (WARN_ON_ONCE(idx == -1 || idx >= UNCORE_PMC_IDX_MAX))
		return;

	if (WARN_ON_ONCE(!(event->hw.state & PERF_HES_STOPPED)))
		return;

	event->hw.state = 0;
	box->events[idx] = event;
	box->n_active++;
	__set_bit(idx, box->active_mask);

	local64_set(&event->hw.prev_count, uncore_read_counter(box, event));
	uncore_enable_event(box, event);

	if (box->n_active == 1) {
		uncore_enable_box(box);
		uncore_pmu_start_hrtimer(box);
	}
}

static void uncore_pmu_event_stop(struct perf_event *event, int flags)
{
	struct zhaoxin_uncore_box *box = uncore_event_to_box(event);
	struct hw_perf_event *hwc = &event->hw;

	if (__test_and_clear_bit(hwc->idx, box->active_mask)) {
		uncore_disable_event(box, event);
		box->n_active--;
		box->events[hwc->idx] = NULL;
		WARN_ON_ONCE(hwc->state & PERF_HES_STOPPED);
		hwc->state |= PERF_HES_STOPPED;

		if (box->n_active == 0) {
			uncore_disable_box(box);
			uncore_pmu_cancel_hrtimer(box);
		}
	}

	if ((flags & PERF_EF_UPDATE) && !(hwc->state & PERF_HES_UPTODATE)) {
		/*
		 * Drain the remaining delta count out of a event
		 * that we are disabling:
		 */
		uncore_perf_event_update(box, event);
		hwc->state |= PERF_HES_UPTODATE;
	}
}

static int
uncore_collect_events(struct zhaoxin_uncore_box *box, struct perf_event *leader,
		      bool dogrp)
{
	struct perf_event *event;
	int n, max_count;

	max_count = box->pmu->type->num_counters;
	if (box->pmu->type->fixed_ctl)
		max_count++;

	if (box->n_events >= max_count)
		return -EINVAL;

	n = box->n_events;

	if (is_box_event(box, leader)) {
		box->event_list[n] = leader;
		n++;
	}

	if (!dogrp)
		return n;

	for_each_sibling_event(event, leader) {
		if (!is_box_event(box, event) ||
		    event->state <= PERF_EVENT_STATE_OFF)
			continue;

		if (n >= max_count)
			return -EINVAL;

		box->event_list[n] = event;
		n++;
	}
	return n;
}

static int uncore_pmu_event_add(struct perf_event *event, int flags)
{
	struct zhaoxin_uncore_box *box = uncore_event_to_box(event);
	struct hw_perf_event *hwc = &event->hw;
	int assign[UNCORE_PMC_IDX_MAX];
	int i, n, ret;

	if (!box)
		return -ENODEV;

	ret = n = uncore_collect_events(box, event, false);
	if (ret < 0)
		return ret;

	hwc->state = PERF_HES_UPTODATE | PERF_HES_STOPPED;
	if (!(flags & PERF_EF_START))
		hwc->state |= PERF_HES_ARCH;

	ret = uncore_assign_events(box, assign, n);
	if (ret)
		return ret;

	/* save events moving to new counters */
	for (i = 0; i < box->n_events; i++) {
		event = box->event_list[i];
		hwc = &event->hw;

		if (hwc->idx == assign[i] &&
			hwc->last_tag == box->tags[assign[i]])
			continue;
		/*
		 * Ensure we don't accidentally enable a stopped
		 * counter simply because we rescheduled.
		 */
		if (hwc->state & PERF_HES_STOPPED)
			hwc->state |= PERF_HES_ARCH;

		uncore_pmu_event_stop(event, PERF_EF_UPDATE);
	}

	/* reprogram moved events into new counters */
	for (i = 0; i < n; i++) {
		event = box->event_list[i];
		hwc = &event->hw;

		if (hwc->idx != assign[i] ||
			hwc->last_tag != box->tags[assign[i]])
			uncore_assign_hw_event(box, event, assign[i]);
		else if (i < box->n_events)
			continue;

		if (hwc->state & PERF_HES_ARCH)
			continue;

		uncore_pmu_event_start(event, 0);
	}
	box->n_events = n;

	return 0;
}

static int uncore_validate_group(struct zhaoxin_uncore_pmu *pmu,
				struct perf_event *event)
{
	struct perf_event *leader = event->group_leader;
	struct zhaoxin_uncore_box *fake_box;
	int ret = -EINVAL, n;

	fake_box = uncore_alloc_box(pmu->type, NUMA_NO_NODE);
	if (!fake_box)
		return -ENOMEM;

	fake_box->pmu = pmu;
	/*
	 * the event is not yet connected with its
	 * siblings therefore we must first collect
	 * existing siblings, then add the new event
	 * before we can simulate the scheduling
	 */
	n = uncore_collect_events(fake_box, leader, true);
	if (n < 0)
		goto out;

	fake_box->n_events = n;
	n = uncore_collect_events(fake_box, event, false);
	if (n < 0)
		goto out;

	fake_box->n_events = n;

	ret = uncore_assign_events(fake_box, NULL, n);
out:
	kfree(fake_box);
	return ret;
}

static void uncore_pmu_event_del(struct perf_event *event, int flags)
{
	struct zhaoxin_uncore_box *box = uncore_event_to_box(event);
	int i;

	uncore_pmu_event_stop(event, PERF_EF_UPDATE);

	for (i = 0; i < box->n_events; i++) {
		if (event == box->event_list[i]) {
			uncore_put_event_constraint(box, event);

			for (++i; i < box->n_events; i++)
				box->event_list[i - 1] = box->event_list[i];

			--box->n_events;
			break;
		}
	}

	event->hw.idx = -1;
	event->hw.last_tag = ~0ULL;
}

static void uncore_pmu_event_read(struct perf_event *event)
{
	struct zhaoxin_uncore_box *box = uncore_event_to_box(event);

	uncore_perf_event_update(box, event);
}

static int uncore_pmu_event_init(struct perf_event *event)
{
	struct zhaoxin_uncore_pmu *pmu;
	struct zhaoxin_uncore_box *box;
	struct hw_perf_event *hwc = &event->hw;
	int ret;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	pmu = uncore_event_to_pmu(event);
	/* no device found for this pmu */
	if (pmu->func_id < 0)
		return -ENOENT;

	/* Sampling not supported yet */
	if (hwc->sample_period)
		return -EINVAL;

	/*
	 * Place all uncore events for a particular physical package
	 * onto a single cpu
	 */
	if (event->cpu < 0)
		return -EINVAL;
	box = uncore_pmu_to_box(pmu, event->cpu);
	if (!box || box->cpu < 0)
		return -EINVAL;
	event->cpu = box->cpu;
	event->pmu_private = box;

	event->event_caps |= PERF_EV_CAP_READ_ACTIVE_PKG;

	event->hw.idx = -1;
	event->hw.last_tag = ~0ULL;
	event->hw.extra_reg.idx = EXTRA_REG_NONE;
	event->hw.branch_reg.idx = EXTRA_REG_NONE;

	if (event->attr.config == UNCORE_FIXED_EVENT) {
		/* no fixed counter */
		if (!pmu->type->fixed_ctl)
			return -EINVAL;
		/*
		 * if there is only one fixed counter, only the first pmu
		 * can access the fixed counter
		 */
		if (pmu->type->single_fixed && pmu->pmu_idx > 0)
			return -EINVAL;

		/* fixed counters have event field hardcoded to zero */
		hwc->config = 0ULL;
	} else {
		hwc->config = event->attr.config &
			      (pmu->type->event_mask | ((u64)pmu->type->event_mask_ext << 32));
		if (pmu->type->ops->hw_config) {
			ret = pmu->type->ops->hw_config(box, event);
			if (ret)
				return ret;
		}
	}

	if (event->group_leader != event)
		ret = uncore_validate_group(pmu, event);
	else
		ret = 0;

	return ret;
}

static ssize_t uncore_get_attr_cpumask(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpumap_print_to_pagebuf(true, buf, &uncore_cpu_mask);
}

static DEVICE_ATTR(cpumask, S_IRUGO, uncore_get_attr_cpumask, NULL);

static struct attribute *uncore_pmu_attrs[] = {
	&dev_attr_cpumask.attr,
	NULL,
};

static const struct attribute_group uncore_pmu_attr_group = {
	.attrs = uncore_pmu_attrs,
};

static void uncore_pmu_unregister(struct zhaoxin_uncore_pmu *pmu)
{
	if (!pmu->registered)
		return;
	perf_pmu_unregister(&pmu->pmu);
	pmu->registered = false;
}

static void uncore_free_boxes(struct zhaoxin_uncore_pmu *pmu)
{
	int package;

	for (package = 0; package < max_packages; package++)
		kfree(pmu->boxes[package]);
	kfree(pmu->boxes);
}

static void uncore_type_exit(struct zhaoxin_uncore_type *type)
{
	struct zhaoxin_uncore_pmu *pmu = type->pmus;
	int i;

	if (pmu) {
		for (i = 0; i < type->num_boxes; i++, pmu++) {
			uncore_pmu_unregister(pmu);
			uncore_free_boxes(pmu);
		}
		kfree(type->pmus);
		type->pmus = NULL;
	}
	kfree(type->events_group);
	type->events_group = NULL;
}

static void uncore_types_exit(struct zhaoxin_uncore_type **types)
{
	for (; *types; types++)
		uncore_type_exit(*types);
}

static int __init uncore_type_init(struct zhaoxin_uncore_type *type, bool setid)
{
	struct zhaoxin_uncore_pmu *pmus;
	size_t size;
	int i, j;

	pmus = kcalloc(type->num_boxes, sizeof(*pmus), GFP_KERNEL);
	if (!pmus)
		return -ENOMEM;

	size = max_packages*sizeof(struct zhaoxin_uncore_box *);

	for (i = 0; i < type->num_boxes; i++) {
		pmus[i].func_id	= setid ? i : -1;
		pmus[i].pmu_idx	= i;
		pmus[i].type	= type;
		pmus[i].boxes	= kzalloc(size, GFP_KERNEL);
		if (!pmus[i].boxes)
			goto err;
	}

	type->pmus = pmus;
	type->unconstrainted = (struct event_constraint)
		__EVENT_CONSTRAINT(0, (1ULL << type->num_counters) - 1,
				0, type->num_counters, 0, 0);

	if (type->event_descs) {
		struct {
			struct attribute_group group;
			struct attribute *attrs[];
		} *attr_group;
		for (i = 0; type->event_descs[i].attr.attr.name; i++)
			;

		attr_group = kzalloc(struct_size(attr_group, attrs, i + 1), GFP_KERNEL);
		if (!attr_group)
			goto err;

		attr_group->group.name = "events";
		attr_group->group.attrs = attr_group->attrs;

		for (j = 0; j < i; j++)
			attr_group->attrs[j] = &type->event_descs[j].attr.attr;

		type->events_group = &attr_group->group;
	}

	type->pmu_group = &uncore_pmu_attr_group;

	return 0;

err:
	for (i = 0; i < type->num_boxes; i++)
		kfree(pmus[i].boxes);
	kfree(pmus);

	return -ENOMEM;
}

static int __init
uncore_types_init(struct zhaoxin_uncore_type **types, bool setid)
{
	int ret;

	for (; *types; types++) {
		ret = uncore_type_init(*types, setid);
		if (ret)
			return ret;
	}
	return 0;
}

static void uncore_change_type_ctx(struct zhaoxin_uncore_type *type, int old_cpu,
				   int new_cpu)
{
	struct zhaoxin_uncore_pmu *pmu = type->pmus;
	struct zhaoxin_uncore_box *box;
	int i, package;

	package = topology_logical_package_id(old_cpu < 0 ? new_cpu : old_cpu);
	for (i = 0; i < type->num_boxes; i++, pmu++) {
		box = pmu->boxes[package];
		if (!box)
			continue;

		if (old_cpu < 0) {
			WARN_ON_ONCE(box->cpu != -1);
			box->cpu = new_cpu;
			continue;
		}

		WARN_ON_ONCE(box->cpu != old_cpu);
		box->cpu = -1;
		if (new_cpu < 0)
			continue;

		uncore_pmu_cancel_hrtimer(box);
		perf_pmu_migrate_context(&pmu->pmu, old_cpu, new_cpu);
		box->cpu = new_cpu;
	}
}

static void uncore_change_context(struct zhaoxin_uncore_type **uncores,
				  int old_cpu, int new_cpu)
{
	for (; *uncores; uncores++)
		uncore_change_type_ctx(*uncores, old_cpu, new_cpu);
}

static void uncore_box_unref(struct zhaoxin_uncore_type **types, int id)
{
	struct zhaoxin_uncore_type *type;
	struct zhaoxin_uncore_pmu *pmu;
	struct zhaoxin_uncore_box *box;
	int i;

	for (; *types; types++) {
		type = *types;
		pmu = type->pmus;
		for (i = 0; i < type->num_boxes; i++, pmu++) {
			box = pmu->boxes[id];
			if (box && atomic_dec_return(&box->refcnt) == 0)
				uncore_box_exit(box);
		}
	}
}

static int uncore_event_cpu_offline(unsigned int cpu)
{
	int package, target;

	/* Check if exiting cpu is used for collecting uncore events */
	if (!cpumask_test_and_clear_cpu(cpu, &uncore_cpu_mask))
		goto unref;
	/* Find a new cpu to collect uncore events */
	target = cpumask_any_but(topology_core_cpumask(cpu), cpu);

	/* Migrate uncore events to the new target */
	if (target < nr_cpu_ids)
		cpumask_set_cpu(target, &uncore_cpu_mask);
	else
		target = -1;

	uncore_change_context(uncore_msr_uncores, cpu, target);

unref:
	/* Clear the references */
	package = topology_logical_package_id(cpu);
	uncore_box_unref(uncore_msr_uncores, package);
	return 0;
}

static int allocate_boxes(struct zhaoxin_uncore_type **types,
			 unsigned int package, unsigned int cpu)
{
	struct zhaoxin_uncore_box *box, *tmp;
	struct zhaoxin_uncore_type *type;
	struct zhaoxin_uncore_pmu *pmu;
	LIST_HEAD(allocated);
	int i;

	/* Try to allocate all required boxes */
	for (; *types; types++) {
		type = *types;
		pmu = type->pmus;
		for (i = 0; i < type->num_boxes; i++, pmu++) {
			if (pmu->boxes[package])
				continue;
			box = uncore_alloc_box(type, cpu_to_node(cpu));
			if (!box)
				goto cleanup;
			box->pmu = pmu;
			box->package_id = package;
			list_add(&box->active_list, &allocated);
		}
	}
	/* Install them in the pmus */
	list_for_each_entry_safe(box, tmp, &allocated, active_list) {
		list_del_init(&box->active_list);
		box->pmu->boxes[package] = box;
	}
	return 0;

cleanup:
	list_for_each_entry_safe(box, tmp, &allocated, active_list) {
		list_del_init(&box->active_list);
		kfree(box);
	}
	return -ENOMEM;
}

static int uncore_box_ref(struct zhaoxin_uncore_type **types,
			  int id, unsigned int cpu)
{
	struct zhaoxin_uncore_type *type;
	struct zhaoxin_uncore_pmu *pmu;
	struct zhaoxin_uncore_box *box;
	int i, ret;

	ret = allocate_boxes(types, id, cpu);
	if (ret)
		return ret;

	for (; *types; types++) {
		type = *types;
		pmu = type->pmus;
		for (i = 0; i < type->num_boxes; i++, pmu++) {
			box = pmu->boxes[id];
			if (box && atomic_inc_return(&box->refcnt) == 1)
				uncore_box_init(box);
		}
	}
	return 0;
}

static int uncore_event_cpu_online(unsigned int cpu)
{
	int package, target, msr_ret;

	package = topology_logical_package_id(cpu);
	msr_ret = uncore_box_ref(uncore_msr_uncores, package, cpu);

	if (msr_ret)
		return -ENOMEM;

	/*
	 * Check if there is an online cpu in the package
	 * which collects uncore events already.
	 */
	target = cpumask_any_and(&uncore_cpu_mask, topology_core_cpumask(cpu));
	if (target < nr_cpu_ids)
		return 0;

	cpumask_set_cpu(cpu, &uncore_cpu_mask);

	if (!msr_ret)
		uncore_change_context(uncore_msr_uncores, -1, cpu);

	return 0;
}

static int uncore_pmu_register(struct zhaoxin_uncore_pmu *pmu)
{
	int ret;

	if (!pmu->type->pmu) {
		pmu->pmu = (struct pmu) {
			.attr_groups	= pmu->type->attr_groups,
			.task_ctx_nr	= perf_invalid_context,
			.event_init	= uncore_pmu_event_init,
			.add		= uncore_pmu_event_add,
			.del		= uncore_pmu_event_del,
			.start		= uncore_pmu_event_start,
			.stop		= uncore_pmu_event_stop,
			.read		= uncore_pmu_event_read,
			.module		= THIS_MODULE,
		};
	} else {
		pmu->pmu = *pmu->type->pmu;
		pmu->pmu.attr_groups = pmu->type->attr_groups;
	}

	if (pmu->type->num_boxes == 1) {
		if (strlen(pmu->type->name) > 0)
			sprintf(pmu->name, "uncore_%s", pmu->type->name);
		else
			sprintf(pmu->name, "uncore");
	} else {
		sprintf(pmu->name, "uncore_%s_%d", pmu->type->name,
			pmu->pmu_idx);
	}

	ret = perf_pmu_register(&pmu->pmu, pmu->name, -1);
	if (!ret)
		pmu->registered = true;
	return ret;
}

static int __init type_pmu_register(struct zhaoxin_uncore_type *type)
{
	int i, ret;

	for (i = 0; i < type->num_boxes; i++) {
		ret = uncore_pmu_register(&type->pmus[i]);
		if (ret)
			return ret;
	}
	return 0;
}

static int __init uncore_msr_pmus_register(void)
{
	struct zhaoxin_uncore_type **types = uncore_msr_uncores;
	int ret;

	for (; *types; types++) {
		ret = type_pmu_register(*types);
		if (ret)
			return ret;
	}
	return 0;
}

static int __init uncore_cpu_init(void)
{
	int ret;

	ret = uncore_types_init(uncore_msr_uncores, true);
	if (ret)
		goto err;

	ret = uncore_msr_pmus_register();
	if (ret)
		goto err;
	return 0;
err:
	uncore_types_exit(uncore_msr_uncores);
	uncore_msr_uncores = empty_uncore;
	return ret;
}


#define CENTAUR_UNCORE_MODEL_MATCH(model, init)	\
	{ X86_VENDOR_CENTAUR, 7, model, X86_FEATURE_ANY, (unsigned long)&init }

#define ZHAOXIN_UNCORE_MODEL_MATCH(model, init)	\
	{ X86_VENDOR_ZHAOXIN, 7, model, X86_FEATURE_ANY, (unsigned long)&init }

struct zhaoxin_uncore_init_fun {
	void	(*cpu_init)(void);
};

void chx_uncore_cpu_init(void)
{
	uncore_msr_uncores = chx_msr_uncores;
}

static const struct zhaoxin_uncore_init_fun chx_uncore_init __initconst = {
	.cpu_init = chx_uncore_cpu_init,
};

static const struct x86_cpu_id zhaoxin_uncore_match[] __initconst = {
	CENTAUR_UNCORE_MODEL_MATCH(ZHAOXIN_FAM7_CHX001,	  chx_uncore_init),
	CENTAUR_UNCORE_MODEL_MATCH(ZHAOXIN_FAM7_CHX002,	  chx_uncore_init),
	ZHAOXIN_UNCORE_MODEL_MATCH(ZHAOXIN_FAM7_CHX001,	  chx_uncore_init),
	ZHAOXIN_UNCORE_MODEL_MATCH(ZHAOXIN_FAM7_CHX002,	  chx_uncore_init),
	{},
};

MODULE_DEVICE_TABLE(x86cpu, zhaoxin_uncore_match);

static int __init zhaoxin_uncore_init(void)
{
	const struct x86_cpu_id *id;
	struct zhaoxin_uncore_init_fun *uncore_init;
	int cret = 0, ret;

	id = x86_match_cpu(zhaoxin_uncore_match);

	if (!id)
		return -ENODEV;

	if (boot_cpu_has(X86_FEATURE_HYPERVISOR))
		return -ENODEV;

	max_packages = topology_max_packages();

	pr_info("welcome to uncore!\n");

	uncore_init = (struct zhaoxin_uncore_init_fun *)id->driver_data;

	if (uncore_init->cpu_init) {
		uncore_init->cpu_init();
		cret = uncore_cpu_init();
	}

	if (cret)
		return -ENODEV;

	ret = cpuhp_setup_state(CPUHP_AP_PERF_X86_UNCORE_ONLINE,
				"perf/x86/zhaoxin/uncore:online",
				uncore_event_cpu_online,
				uncore_event_cpu_offline);
	if (ret)
		goto err;

	pr_info("uncore init success!\n");
	return 0;
err:
	uncore_types_exit(uncore_msr_uncores);
	return ret;
}
module_init(zhaoxin_uncore_init);

static void __exit zhaoxin_uncore_exit(void)
{
	cpuhp_remove_state(CPUHP_AP_PERF_X86_UNCORE_ONLINE);
	uncore_types_exit(uncore_msr_uncores);
}
module_exit(zhaoxin_uncore_exit);

MODULE_LICENSE("GPL");
