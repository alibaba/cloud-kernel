// SPDX-License-Identifier: GPL-2.0
/* M1 DDR Sub-System PMU driver
 * Copyright (C) 2016-2020 Arm Limited
 * Copyright (C) 2021 Alibaba Inc
 */

#define M1_DDRSS_PMUNAME		"m1_ddrss"
#define M1_DDRSS_DRVNAME		M1_DDRSS_PMUNAME "_pmu"
#define pr_fmt(fmt)		        M1_DDRSS_DRVNAME ": " fmt

#include <linux/acpi.h>
#include <linux/perf_event.h>
#include <linux/platform_device.h>

#define M1_DRW_PMU_COMMON_MAX_COUNTERS			16
#define M1_DRW_PMU_TEST_SEL_COMMON_COUNTER_BASE		19

#define M1_DRW_PMU_PA_SHIFT		12
#define M1_DRW_PMU_CNT_INIT		0x00000000
#define M1_DRW_CNT_MAX_PERIOD		0xffffffff

#define M1_DRW_PMU_CYCLE_EVT_ID	0x80

#define M1_DRW_PMU_CNT_CTRL		0xC00
#define M1_DRW_PMU_CNT_STATE		0xC04
#define M1_DRW_PMU_TEST_CTRL		0xC08
#define M1_DRW_PMU_CNT_PRELOAD		0xC0C

#define M1_DRW_PMU_CYCLE_CNT_HIGH_MASK	GENMASK(23, 0)
#define M1_DRW_PMU_CYCLE_CNT_LOW_MASK	GENMASK(31, 0)
#define M1_DRW_PMU_CYCLE_CNT_HIGH	0xC10
#define M1_DRW_PMU_CYCLE_CNT_LOW	0xC14

/* PMU EVENT SEL 0-3, each SEL register's address is 4 offset */
#define M1_DRW_PMU_EVENT_SEL0		0xC68
/* PMU COMMON COUNTER 0-15, each common counter's address is 4 offset */
#define M1_DRW_PMU_COMMON_COUNTER0	0xC78
#define M1_DRW_PMU_OV_INT_ENABLE_CTL	0xCB8
#define M1_DRW_PMU_OV_INT_DISABLE_CTL   0xCBC
#define M1_DRW_PMU_OV_INT_ENABLE_STATUS 0xCC0
#define M1_DRW_PMU_OV_INT_CLR		0xCC4
#define M1_DRW_PMU_OV_INT_STATUS	0xCC8
#define M1_DRW_PMU_OV_INT_MASK		GENMASK_ULL(63, 0)

/* offset of the registers for a given counter.*/
#define M1_DRW_PMU_COMMON_COUNTERn_OFFSET(n) \
	(M1_DRW_PMU_COMMON_COUNTER0 + 0x4 * (n))

static int m1_ddrss_cpuhp_state_num;

static LIST_HEAD(m1_ddrss_pmu_irqs);
static DEFINE_MUTEX(m1_ddrss_pmu_irqs_lock);

struct m1_ddrss_pmu_irq {
	struct hlist_node node;
	struct list_head irqs_node;
	struct list_head pmus_node;
	int irq_num;
	int cpu;
	refcount_t refcount;
};

struct m1_ddrss_pmu {
	void __iomem *drw_cfg_base;
	struct device *dev;

	struct list_head pmus_node;
	struct m1_ddrss_pmu_irq *irq;
	int irq_num;
	int cpu;
	DECLARE_BITMAP(used_mask, M1_DRW_PMU_COMMON_MAX_COUNTERS);
	struct perf_event *events[M1_DRW_PMU_COMMON_MAX_COUNTERS];
	int evtids[M1_DRW_PMU_COMMON_MAX_COUNTERS];

	struct pmu pmu;
};

#define to_m1_ddrss_pmu(p) (container_of(p, struct m1_ddrss_pmu, pmu))

#define DDRSS_CONFIG_EVENTID		GENMASK(7, 0)
#define GET_DDRSS_EVENTID(event)	FIELD_GET(DDRSS_CONFIG_EVENTID, (event)->attr.config)

ssize_t m1_ddrss_pmu_format_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct dev_ext_attribute *eattr;

	eattr = container_of(attr, struct dev_ext_attribute, attr);

	return sprintf(buf, "%s\n", (char *)eattr->var);
}

/*
 * PMU event attributes
 */
ssize_t m1_ddrss_pmu_event_show(struct device *dev,
				struct device_attribute *attr, char *page)
{
	struct dev_ext_attribute *eattr;

	eattr = container_of(attr, struct dev_ext_attribute, attr);

	return sprintf(page, "config=0x%lx\n", (unsigned long)eattr->var);
}

#define M1_DDRSS_PMU_ATTR(_name, _func, _config)                            \
		(&((struct dev_ext_attribute[]) {                               \
				{ __ATTR(_name, 0444, _func, NULL), (void *)_config }   \
		})[0].attr.attr)

#define M1_DDRSS_PMU_FORMAT_ATTR(_name, _config)            \
	M1_DDRSS_PMU_ATTR(_name, m1_ddrss_pmu_format_show, (void *)_config)
#define M1_DDRSS_PMU_EVENT_ATTR(_name, _config)             \
	M1_DDRSS_PMU_ATTR(_name, m1_ddrss_pmu_event_show, (unsigned long)_config)

static struct attribute *m1_ddrss_pmu_events_attrs[] = {
	M1_DDRSS_PMU_EVENT_ATTR(perf_hif_rd_or_wr,		0x0),
	M1_DDRSS_PMU_EVENT_ATTR(perf_hif_wr,			0x1),
	M1_DDRSS_PMU_EVENT_ATTR(perf_hif_rd,			0x2),
	M1_DDRSS_PMU_EVENT_ATTR(perf_hif_rmw,			0x3),
	M1_DDRSS_PMU_EVENT_ATTR(perf_hif_hi_pri_rd,		0x4),
	M1_DDRSS_PMU_EVENT_ATTR(perf_dfi_wr_data_cycles,	0x7),
	M1_DDRSS_PMU_EVENT_ATTR(perf_dfi_rd_data_cycles,	0x8),
	M1_DDRSS_PMU_EVENT_ATTR(perf_hpr_xact_when_critical,	0x9),
	M1_DDRSS_PMU_EVENT_ATTR(perf_lpr_xact_when_critical,	0xA),
	M1_DDRSS_PMU_EVENT_ATTR(perf_wpr_xact_when_critical,	0xB),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_activate,		0xC),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_rd_or_wr,		0xD),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_rd_activate,		0xE),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_rd,			0xF),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_wr,			0x10),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_mwr,			0x11),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_precharge,		0x12),
	M1_DDRSS_PMU_EVENT_ATTR(perf_precharge_for_rdwr,	0x13),
	M1_DDRSS_PMU_EVENT_ATTR(perf_precharge_for_other,	0x14),
	M1_DDRSS_PMU_EVENT_ATTR(perf_rdwr_transitions,		0x15),
	M1_DDRSS_PMU_EVENT_ATTR(perf_write_combine,		0x16),
	M1_DDRSS_PMU_EVENT_ATTR(perf_war_hazard,		0x17),
	M1_DDRSS_PMU_EVENT_ATTR(perf_raw_hazard,		0x18),
	M1_DDRSS_PMU_EVENT_ATTR(perf_waw_hazard,		0x19),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_enter_selfref_rk0,	0x1A),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_enter_selfref_rk1,	0x1B),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_enter_selfref_rk2,	0x1C),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_enter_selfref_rk3,	0x1D),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_enter_powerdown_rk0,	0x1E),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_enter_powerdown_rk1,	0x1F),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_enter_powerdown_rk2,	0x20),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_enter_powerdown_rk3,	0x21),
	M1_DDRSS_PMU_EVENT_ATTR(perf_selfref_mode_rk0,		0x26),
	M1_DDRSS_PMU_EVENT_ATTR(perf_selfref_mode_rk1,		0x27),
	M1_DDRSS_PMU_EVENT_ATTR(perf_selfref_mode_rk2,		0x28),
	M1_DDRSS_PMU_EVENT_ATTR(perf_selfref_mode_rk3,		0x29),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_refresh,		0x2A),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_crit_ref,		0x2B),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_load_mode,		0x2D),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_zqcl,		0x2E),
	M1_DDRSS_PMU_EVENT_ATTR(perf_visible_window_limit_reached_rd, 0x30),
	M1_DDRSS_PMU_EVENT_ATTR(perf_visible_window_limit_reached_wr, 0x31),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_dqsosc_mpc,		0x34),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_dqsosc_mrr,		0x35),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_tcr_mrr,		0x36),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_zqstart,		0x37),
	M1_DDRSS_PMU_EVENT_ATTR(perf_op_is_zqlatch,		0x38),
	M1_DDRSS_PMU_EVENT_ATTR(perf_chi_txreq,			0x39),
	M1_DDRSS_PMU_EVENT_ATTR(perf_chi_txdat,			0x3A),
	M1_DDRSS_PMU_EVENT_ATTR(perf_chi_rxdat,			0x3B),
	M1_DDRSS_PMU_EVENT_ATTR(perf_chi_rxrsp,			0x3C),
	M1_DDRSS_PMU_EVENT_ATTR(perf_tsz_vio,			0x3D),
	M1_DDRSS_PMU_EVENT_ATTR(perf_cycle,			0x80),
	NULL,
};


static struct attribute_group m1_ddrss_pmu_events_attr_group = {
	.name = "events",
	.attrs = m1_ddrss_pmu_events_attrs,
};

static struct attribute *m1_ddrss_pmu_format_attr[] = {
	M1_DDRSS_PMU_FORMAT_ATTR(event, "config:0-7"),
	NULL,
};

static const struct attribute_group m1_ddrss_pmu_format_group = {
	.name = "format",
	.attrs = m1_ddrss_pmu_format_attr,
};

static ssize_t m1_ddrss_pmu_cpumask_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct m1_ddrss_pmu *ddrss_pmu = to_m1_ddrss_pmu(dev_get_drvdata(dev));

	return cpumap_print_to_pagebuf(true, buf, cpumask_of(ddrss_pmu->cpu));
}

static struct device_attribute m1_ddrss_pmu_cpumask_attr =
		__ATTR(cpumask, 0444, m1_ddrss_pmu_cpumask_show, NULL);

static struct attribute *m1_ddrss_pmu_cpumask_attrs[] = {
	&m1_ddrss_pmu_cpumask_attr.attr,
	NULL,
};

static const struct attribute_group m1_ddrss_pmu_cpumask_attr_group = {
	.attrs = m1_ddrss_pmu_cpumask_attrs,
};

static const struct attribute_group *m1_ddrss_pmu_attr_groups[] = {
	&m1_ddrss_pmu_events_attr_group,
	&m1_ddrss_pmu_cpumask_attr_group,
	&m1_ddrss_pmu_format_group,
	NULL,
};

/* find a counter for event, then in add func, hw.idx will equal to counter */
static int m1_ddrss_get_counter_idx(struct perf_event *event)
{
	struct m1_ddrss_pmu *ddrss_pmu = to_m1_ddrss_pmu(event->pmu);
	int idx;

	for (idx = 0; idx < M1_DRW_PMU_COMMON_MAX_COUNTERS; ++idx) {
		if (!test_and_set_bit(idx, ddrss_pmu->used_mask))
			return idx;
	}

	/* The counters are all in use. */
	return -EBUSY;
}

static u64 m1_ddrss_pmu_read_counter(struct perf_event *event)
{
	struct m1_ddrss_pmu *ddrss_pmu = to_m1_ddrss_pmu(event->pmu);
	u64 cycle_high, cycle_low;

	if (GET_DDRSS_EVENTID(event) == M1_DRW_PMU_CYCLE_EVT_ID) {
		cycle_high = readl(ddrss_pmu->drw_cfg_base + M1_DRW_PMU_CYCLE_CNT_HIGH)
							& M1_DRW_PMU_CYCLE_CNT_HIGH_MASK;
		cycle_low = readl(ddrss_pmu->drw_cfg_base + M1_DRW_PMU_CYCLE_CNT_LOW)
							& M1_DRW_PMU_CYCLE_CNT_LOW_MASK;
		return (cycle_high << 32 | cycle_low);
	}

	return readl(ddrss_pmu->drw_cfg_base + M1_DRW_PMU_COMMON_COUNTERn_OFFSET(event->hw.idx));
}

static void m1_ddrss_pmu_event_update(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	u64 delta, prev, now;

	do {
		prev = local64_read(&hwc->prev_count);
		now = m1_ddrss_pmu_read_counter(event);
	} while (local64_cmpxchg(&hwc->prev_count, prev, now) != prev);

	/* handle overflow.*/
	delta = now - prev;
	if (GET_DDRSS_EVENTID(event) == M1_DRW_PMU_CYCLE_EVT_ID)
		delta &= M1_DRW_PMU_OV_INT_MASK;
	else
		delta &= M1_DRW_CNT_MAX_PERIOD;
	local64_add(delta, &event->count);
}

static void m1_ddrss_pmu_event_set_period(struct perf_event *event)
{
	u64 pre_val;
	struct m1_ddrss_pmu *ddrss_pmu = to_m1_ddrss_pmu(event->pmu);

	/* set a preload counter for test purpose */
	writel(M1_DRW_PMU_TEST_SEL_COMMON_COUNTER_BASE + event->hw.idx,
		ddrss_pmu->drw_cfg_base + M1_DRW_PMU_TEST_CTRL);

	/* set conunter initial value */
	pre_val = M1_DRW_PMU_CNT_INIT;
	writel(pre_val, ddrss_pmu->drw_cfg_base + M1_DRW_PMU_CNT_PRELOAD);
	local64_set(&event->hw.prev_count, pre_val);

	/* set sel mode to zero to start test */
	writel(0x0, ddrss_pmu->drw_cfg_base + M1_DRW_PMU_TEST_CTRL);
}

static inline int get_enable_counter_en_offset(int idx)
{
	/*counter 0: bit 7, counter 1: bit 15, counter 2: bit 23*/
	return 7 + 8 * (idx % 4);
}

static inline int get_enable_counter_event_offset(int idx)
{
	return 8 * (idx % 4);
}

/*
 * pmu_event_sel0..3. Setting dr_pmcom_cnt[x]_en = 1’b1
 * shall enable the Xth common counter
 */
static void m1_ddrss_pmu_enable_counter(struct perf_event *event)
{
	u32 val;
	u32 reg;
	int counter = event->hw.idx;
	struct m1_ddrss_pmu *ddrss_pmu = to_m1_ddrss_pmu(event->pmu);

	if (counter > 15 || counter < 0) {
		pr_err("get counter failed, counter = %d\n", counter);
		return;
	}

	/* counter 0-3 use sel0, counter 4-7 use sel1...*/
	reg = M1_DRW_PMU_EVENT_SEL0 + (counter / 4) * 0x4;

	val = readl(ddrss_pmu->drw_cfg_base + reg);
	/* enable the common counter n */
	val |= (1 << get_enable_counter_en_offset(counter));
	/* decides the event which will be counted by the common counter n */
	val |= ((ddrss_pmu->evtids[counter] & 0x3F) << get_enable_counter_event_offset(counter));
	writel(val, ddrss_pmu->drw_cfg_base + reg);
}

static void m1_ddrss_pmu_disable_counter(struct perf_event *event)
{
	/*
	 * pmu_event_sel0..3. Setting dr_pmcom_cnt[x]_en = 1’b1
	 * shall enable the Xth common counter, hw.idx is the selected counter.
	 */
	u32 val;
	u32 reg;
	struct m1_ddrss_pmu *ddrss_pmu = to_m1_ddrss_pmu(event->pmu);
	int counter = event->hw.idx;

	if (counter > 15 || counter < 0) {
		pr_err("get counter failed, counter = %d\n", counter);
		return;
	}

	/* counter 0-3 use sel0, counter 4-7 use sel1... */
	reg = M1_DRW_PMU_EVENT_SEL0 + (counter / 4) * 0x4;
	val = readl(ddrss_pmu->drw_cfg_base + reg);
	val &= ~(1 << get_enable_counter_en_offset(counter));
	val &= ~(0x3F << get_enable_counter_event_offset(counter));
	writel(val, ddrss_pmu->drw_cfg_base + reg);
}

static irqreturn_t m1_ddrss_pmu_isr(int irq_num, void *data)
{
	struct m1_ddrss_pmu_irq *irq = data;
	struct m1_ddrss_pmu *ddrss_pmu;
	irqreturn_t ret = IRQ_NONE;

	rcu_read_lock();
	list_for_each_entry_rcu(ddrss_pmu, &irq->pmus_node, pmus_node) {
		unsigned long status;
		struct perf_event *event;
		unsigned int idx;

		for (idx = 0; idx < M1_DRW_PMU_COMMON_MAX_COUNTERS; idx++) {
			event = ddrss_pmu->events[idx];
			if (!event)
				continue;
			m1_ddrss_pmu_disable_counter(event);
		}

		/* common counter intr status */
		status = (readl(ddrss_pmu->drw_cfg_base + M1_DRW_PMU_OV_INT_STATUS) >> 8) & 0xFFFF;
		if (status) {
			for_each_set_bit(idx, &status, M1_DRW_PMU_COMMON_MAX_COUNTERS) {
				event = ddrss_pmu->events[idx];
				if (WARN_ON_ONCE(!event))
					continue;
				m1_ddrss_pmu_event_update(event);
				m1_ddrss_pmu_event_set_period(event);
			}

			/* clear common counter intr status */
			writel((status & 0xFFFF) << 8,
				ddrss_pmu->drw_cfg_base + M1_DRW_PMU_OV_INT_CLR);

		}

		for (idx = 0; idx < M1_DRW_PMU_COMMON_MAX_COUNTERS; idx++) {
			event = ddrss_pmu->events[idx];
			if (!event)
				continue;
			if (!(event->hw.state & PERF_HES_STOPPED))
				m1_ddrss_pmu_enable_counter(event);
		}

		ret = IRQ_HANDLED;
	}
	rcu_read_unlock();
	return ret;
}

static struct m1_ddrss_pmu_irq *__m1_ddrss_pmu_init_irq(struct platform_device *pdev, int irq_num)
{
	int ret;
	struct m1_ddrss_pmu_irq *irq;

	list_for_each_entry(irq, &m1_ddrss_pmu_irqs, irqs_node) {
		if (irq->irq_num == irq_num && refcount_inc_not_zero(&irq->refcount))
			return irq;
	}

	irq = kzalloc(sizeof(*irq), GFP_KERNEL);
	if (!irq)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&irq->pmus_node);

	/* Pick one CPU to be the preferred one to use */
	irq->cpu = smp_processor_id();
	refcount_set(&irq->refcount, 1);

	ret = devm_request_irq(&pdev->dev, irq_num, m1_ddrss_pmu_isr,
				IRQF_NOBALANCING | IRQF_NO_THREAD,
				dev_name(&pdev->dev), irq);
	if (ret < 0) {
		dev_err(&pdev->dev,
			"Fail to request IRQ:%d ret:%d\n", irq_num, ret);
		goto out_free;
	}

	ret = irq_set_affinity_hint(irq_num, cpumask_of(irq->cpu));
	if (ret)
		goto out_free;

	ret = cpuhp_state_add_instance_nocalls(m1_ddrss_cpuhp_state_num, &irq->node);
	if (ret)
		goto out_free;

	irq->irq_num = irq_num;
	list_add(&irq->irqs_node, &m1_ddrss_pmu_irqs);

	return irq;

out_free:
	kfree(irq);
	return ERR_PTR(ret);
}

static int m1_ddrss_pmu_init_irq(struct m1_ddrss_pmu *ddrss_pmu,
				  struct platform_device *pdev)
{
	int irq_num;
	struct m1_ddrss_pmu_irq *irq;

	/* Read and init IRQ */
	irq_num = platform_get_irq(pdev, 0);
	if (irq_num < 0)
		return irq_num;

	mutex_lock(&m1_ddrss_pmu_irqs_lock);
	irq = __m1_ddrss_pmu_init_irq(pdev, irq_num);
	mutex_unlock(&m1_ddrss_pmu_irqs_lock);

	if (IS_ERR(irq))
		return PTR_ERR(irq);

	ddrss_pmu->irq = irq;

	mutex_lock(&m1_ddrss_pmu_irqs_lock);
	list_add_rcu(&ddrss_pmu->pmus_node, &irq->pmus_node);
	mutex_unlock(&m1_ddrss_pmu_irqs_lock);

	return 0;
}

static void m1_ddrss_pmu_uninit_irq(struct m1_ddrss_pmu *ddrss_pmu)
{
	struct m1_ddrss_pmu_irq *irq = ddrss_pmu->irq;

	mutex_lock(&m1_ddrss_pmu_irqs_lock);
	list_del_rcu(&ddrss_pmu->pmus_node);

	if (!refcount_dec_and_test(&irq->refcount)) {
		mutex_unlock(&m1_ddrss_pmu_irqs_lock);
		return;
	}

	list_del(&irq->irqs_node);
	mutex_unlock(&m1_ddrss_pmu_irqs_lock);

	WARN_ON(irq_set_affinity_hint(irq->irq_num, NULL));
	cpuhp_state_remove_instance_nocalls(m1_ddrss_cpuhp_state_num, &irq->node);
	kfree(irq);
}

static int m1_ddrss_pmu_event_init(struct perf_event *event)
{
	struct m1_ddrss_pmu *ddrss_pmu = to_m1_ddrss_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	struct perf_event *sibling;
	struct device *dev = ddrss_pmu->pmu.dev;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	if (is_sampling_event(event)) {
		dev_err(dev, "Sampling not supported!\n");
		return -EOPNOTSUPP;
	}

	if (event->attach_state & PERF_ATTACH_TASK) {
		dev_err(dev, "Per-task counter cannot allocate!\n");
		return -EOPNOTSUPP;
	}

	event->cpu = ddrss_pmu->cpu;
	if (event->cpu < 0) {
		dev_err(dev, "Per-task mode not supported!\n");
		return -EOPNOTSUPP;
	}

	if (event->group_leader != event &&
		!is_software_event(event->group_leader)) {
		dev_err(dev, "driveway only allow one event!\n");
		return -EINVAL;
	}

	for_each_sibling_event(sibling, event->group_leader) {
		if (sibling != event &&
			!is_software_event(sibling)) {
			dev_err(dev, "driveway event not allowed!\n");
			return -EINVAL;
		}
	}

	/* reset all the pmu counters*/
	writel(1 << 2, ddrss_pmu->drw_cfg_base + M1_DRW_PMU_CNT_CTRL);

	hwc->idx = -1;

	return 0;
}

static void m1_ddrss_pmu_start(struct perf_event *event, int flags)
{
	struct m1_ddrss_pmu *ddrss_pmu = to_m1_ddrss_pmu(event->pmu);

	event->hw.state = 0;

	if (GET_DDRSS_EVENTID(event) == M1_DRW_PMU_CYCLE_EVT_ID) {
		writel(0x1, ddrss_pmu->drw_cfg_base + M1_DRW_PMU_CNT_CTRL);
		return;
	}

	m1_ddrss_pmu_event_set_period(event);
	if (flags & PERF_EF_RELOAD) {
		unsigned long prev_raw_count =
			local64_read(&event->hw.prev_count);
		writel(prev_raw_count, ddrss_pmu->drw_cfg_base + M1_DRW_PMU_CNT_PRELOAD);
	}

	m1_ddrss_pmu_enable_counter(event);

	/* bit 0 indicates start */
	writel(0x1, ddrss_pmu->drw_cfg_base + M1_DRW_PMU_CNT_CTRL);
}

static void m1_ddrss_pmu_stop(struct perf_event *event, int flags)
{
	struct m1_ddrss_pmu *ddrss_pmu = to_m1_ddrss_pmu(event->pmu);

	if (event->hw.state & PERF_HES_STOPPED)
		return;

	if (GET_DDRSS_EVENTID(event) != M1_DRW_PMU_CYCLE_EVT_ID)
		m1_ddrss_pmu_disable_counter(event);

	/* bit 1 indicates stop */
	writel(0x2, ddrss_pmu->drw_cfg_base + M1_DRW_PMU_CNT_CTRL);

	m1_ddrss_pmu_event_update(event);
	event->hw.state |= PERF_HES_STOPPED | PERF_HES_UPTODATE;
}

static int m1_ddrss_pmu_add(struct perf_event *event, int flags)
{
	struct m1_ddrss_pmu *ddrss_pmu = to_m1_ddrss_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	int idx = -1;
	int evtid;

	evtid = GET_DDRSS_EVENTID(event);

	if (evtid != M1_DRW_PMU_CYCLE_EVT_ID) {
		idx = m1_ddrss_get_counter_idx(event);
		if (idx < 0)
			return idx;
		ddrss_pmu->events[idx] = event;
		ddrss_pmu->evtids[idx] = evtid;
	}
	hwc->idx = idx;

	hwc->state = PERF_HES_STOPPED | PERF_HES_UPTODATE;

	if (flags & PERF_EF_START)
		m1_ddrss_pmu_start(event, PERF_EF_RELOAD);

	/* Propagate our changes to the userspace mapping. */
	perf_event_update_userpage(event);

	return 0;
}

static void m1_ddrss_pmu_del(struct perf_event *event, int flags)
{
	struct m1_ddrss_pmu *ddrss_pmu = to_m1_ddrss_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	int idx = hwc->idx;

	m1_ddrss_pmu_stop(event, PERF_EF_UPDATE);

	if (0 <= idx && 15 >= idx) {
		ddrss_pmu->events[idx] = NULL;
		ddrss_pmu->evtids[idx] = 0;
		clear_bit(idx, ddrss_pmu->used_mask);
	}

	perf_event_update_userpage(event);
}

static void m1_ddrss_pmu_read(struct perf_event *event)
{
	m1_ddrss_pmu_event_update(event);
}

static int m1_ddrss_pmu_probe(struct platform_device *pdev)
{
	struct m1_ddrss_pmu *ddrss_pmu;
	struct resource *res;
	char *name;
	int i, ret;

	ddrss_pmu = devm_kzalloc(&pdev->dev, sizeof(*ddrss_pmu), GFP_KERNEL);
	if (!ddrss_pmu)
		return -ENOMEM;

	ddrss_pmu->dev = &pdev->dev;
	platform_set_drvdata(pdev, ddrss_pmu);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	ddrss_pmu->drw_cfg_base = devm_ioremap_resource(&pdev->dev, res);
	if (!ddrss_pmu->drw_cfg_base)
		return -ENOMEM;

	name = devm_kasprintf(ddrss_pmu->dev, GFP_KERNEL, "m1_ddr_%llx",
			(u64)(res->start >> M1_DRW_PMU_PA_SHIFT));
	if (!name)
		return -ENOMEM;

	/* reset all the pmu counters*/
	writel(1 << 2, ddrss_pmu->drw_cfg_base + M1_DRW_PMU_CNT_CTRL);

	/* enable the generation of interrupt by all common counters */
	for (i = 0; i < M1_DRW_PMU_COMMON_MAX_COUNTERS; i++)
		writel(1 << (8 + i), ddrss_pmu->drw_cfg_base + M1_DRW_PMU_OV_INT_ENABLE_CTL);

	/* clearing interrupt status */
	writel(0xffffff, ddrss_pmu->drw_cfg_base + M1_DRW_PMU_OV_INT_CLR);

	ddrss_pmu->cpu = smp_processor_id();

	ret = m1_ddrss_pmu_init_irq(ddrss_pmu, pdev);
	if (ret)
		return ret;

	ddrss_pmu->pmu = (struct pmu) {
		.module		= THIS_MODULE,
		.task_ctx_nr	= perf_invalid_context,
		.event_init	= m1_ddrss_pmu_event_init,
		.add		= m1_ddrss_pmu_add,
		.del		= m1_ddrss_pmu_del,
		.start		= m1_ddrss_pmu_start,
		.stop		= m1_ddrss_pmu_stop,
		.read		= m1_ddrss_pmu_read,
		.attr_groups	= m1_ddrss_pmu_attr_groups,
		.capabilities	= PERF_PMU_CAP_NO_EXCLUDE,
	};

	ret = perf_pmu_register(&ddrss_pmu->pmu, name, -1);
	if (ret) {
		dev_err(ddrss_pmu->dev, "DDR Sub-System PMU register failed!\n");
		m1_ddrss_pmu_uninit_irq(ddrss_pmu);
	}

	return ret;
}

static int m1_ddrss_pmu_remove(struct platform_device *pdev)
{
	struct m1_ddrss_pmu *ddrss_pmu = platform_get_drvdata(pdev);
	int i;

	/* disable the generation of interrupt by all common counters */
	for (i = 0; i < M1_DRW_PMU_COMMON_MAX_COUNTERS; i++)
		writel(1 << (8 + i), ddrss_pmu->drw_cfg_base + M1_DRW_PMU_OV_INT_DISABLE_CTL);

	m1_ddrss_pmu_uninit_irq(ddrss_pmu);
	perf_pmu_unregister(&ddrss_pmu->pmu);

	return 0;
}

static int m1_ddrss_pmu_offline_cpu(unsigned int cpu, struct hlist_node *node)
{
	struct m1_ddrss_pmu_irq *irq;
	struct m1_ddrss_pmu *ddrss_pmu;
	unsigned int target;

	irq = hlist_entry_safe(node, struct m1_ddrss_pmu_irq, node);
	if (cpu != irq->cpu)
		return 0;

	target = cpumask_any_but(cpu_online_mask, cpu);
	if (target >= nr_cpu_ids)
		return 0;

	/* We're only reading, but this isn't the place to be involving RCU */
	mutex_lock(&m1_ddrss_pmu_irqs_lock);
	list_for_each_entry(ddrss_pmu, &irq->pmus_node, pmus_node)
		perf_pmu_migrate_context(&ddrss_pmu->pmu, irq->cpu, target);
	mutex_unlock(&m1_ddrss_pmu_irqs_lock);

	WARN_ON(irq_set_affinity_hint(irq->irq_num, cpumask_of(target)));
	irq->cpu = target;

	return 0;
}

static const struct acpi_device_id m1_ddrss_acpi_match[] = {
	{"ARMHD700", 0},
	{}
};

MODULE_DEVICE_TABLE(acpi, m1_ddrss_acpi_match);

static struct platform_driver m1_ddrss_pmu_driver = {
	.driver = {
		.name = "m1_ddrss_pmu",
		.acpi_match_table = ACPI_PTR(m1_ddrss_acpi_match),
	},
	.probe = m1_ddrss_pmu_probe,
	.remove = m1_ddrss_pmu_remove,
};

static int __init m1_ddrss_pmu_init(void)
{
	int ret;

	m1_ddrss_cpuhp_state_num = cpuhp_setup_state_multi(CPUHP_AP_ONLINE_DYN,
						  "m1_ddrss_pmu:online",
						  NULL,
						  m1_ddrss_pmu_offline_cpu);

	if (m1_ddrss_cpuhp_state_num < 0) {
		pr_err("M1 DDRSS PMU: setup hotplug failed, ret = %d\n", m1_ddrss_cpuhp_state_num);
		return m1_ddrss_cpuhp_state_num;
	}

	ret = platform_driver_register(&m1_ddrss_pmu_driver);
	if (ret)
		cpuhp_remove_multi_state(m1_ddrss_cpuhp_state_num);

	return ret;
}

static void __exit m1_ddrss_pmu_exit(void)
{
	platform_driver_unregister(&m1_ddrss_pmu_driver);
	cpuhp_remove_multi_state(m1_ddrss_cpuhp_state_num);
}

module_init(m1_ddrss_pmu_init);
module_exit(m1_ddrss_pmu_exit);

MODULE_AUTHOR("Hongbo Yao <yaohongbo@linux.alibaba.com>");
MODULE_AUTHOR("Neng Chen <nengchen@linux.alibaba.com>");
MODULE_AUTHOR("Shuai Xue <xueshuai@linux.alibaba.com>");
MODULE_DESCRIPTION("DDR Sub-System PMU driver");
MODULE_LICENSE("GPL v2");
