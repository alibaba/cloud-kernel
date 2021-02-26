// SPDX-License-Identifier: GPL-2.0+
/*
 * Common code for ARM v8 MPAM
 *
 * Copyright (C) 2020-2021 Huawei Technologies Co., Ltd
 *
 * Author: Wang Shaobo <bobo.shaobowang@huawei.com>
 *
 * Code was partially borrowed from http://www.linux-arm.org/
 * git?p=linux-jm.git;a=shortlog;h=refs/heads/mpam/snapshot/may.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * More information about MPAM be found in the Arm Architecture Reference
 * Manual.
 *
 * https://static.docs.arm.com/ddi0598/a/DDI0598_MPAM_supp_armv8a.pdf
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/slab.h>
#include <linux/err.h>

#include "mpam_device.h"
#include "mpam_internal.h"

/*
 * The classes we've picked to map to resctrl resources.
 * Class pointer may be NULL.
 */
struct mpam_resctrl_res mpam_resctrl_exports[RDT_NUM_RESOURCES];
struct mpam_resctrl_res mpam_resctrl_events[RESCTRL_NUM_EVENT_IDS];

/* Like resctrl_get_domain_from_cpu(), but for offline CPUs */
static struct mpam_resctrl_dom *
mpam_get_domain_from_cpu(int cpu, struct mpam_resctrl_res *res)
{
	struct rdt_domain *d;
	struct mpam_resctrl_dom *dom;

	list_for_each_entry(d, &res->resctrl_res.domains, list) {
		dom = container_of(d, struct mpam_resctrl_dom, resctrl_dom);

		if (cpumask_test_cpu(cpu, &dom->comp->fw_affinity))
			return dom;
	}

	return NULL;
}

static int mpam_resctrl_setup_domain(unsigned int cpu,
				struct mpam_resctrl_res *res)
{
	struct mpam_resctrl_dom *dom;
	struct mpam_class *class = res->class;
	struct mpam_component *comp_iter, *comp;
	u32 num_partid;
	u32 **ctrlval_ptr;
	enum resctrl_ctrl_type type;

	num_partid = mpam_sysprops_num_partid();

	comp = NULL;
	list_for_each_entry(comp_iter, &class->components, class_list) {
		if (cpumask_test_cpu(cpu, &comp_iter->fw_affinity)) {
			comp = comp_iter;
			break;
		}
	}

	/* cpu with unknown exported component? */
	if (WARN_ON_ONCE(!comp))
		return 0;

	dom = kzalloc_node(sizeof(*dom), GFP_KERNEL, cpu_to_node(cpu));
	if (!dom)
		return -ENOMEM;

	dom->comp = comp;
	INIT_LIST_HEAD(&dom->resctrl_dom.list);
	dom->resctrl_dom.id = comp->comp_id;
	cpumask_set_cpu(cpu, &dom->resctrl_dom.cpu_mask);

	for_each_ctrl_type(type) {
		ctrlval_ptr = &dom->resctrl_dom.ctrl_val[type];
		*ctrlval_ptr = kmalloc_array(num_partid,
			sizeof(**ctrlval_ptr), GFP_KERNEL);
		if (!*ctrlval_ptr) {
			kfree(dom);
			return -ENOMEM;
		}
	}

	/* TODO: this list should be sorted */
	list_add_tail(&dom->resctrl_dom.list, &res->resctrl_res.domains);
	res->resctrl_res.dom_num++;

	return 0;
}

int mpam_resctrl_cpu_online(unsigned int cpu)
{
	int ret;
	struct mpam_resctrl_dom *dom;
	struct mpam_resctrl_res *res;

	for_each_supported_resctrl_exports(res) {
		dom = mpam_get_domain_from_cpu(cpu, res);
		if (dom) {
			cpumask_set_cpu(cpu, &dom->resctrl_dom.cpu_mask);
		} else {
			ret = mpam_resctrl_setup_domain(cpu, res);
			if (ret)
				return ret;
		}
	}

	return mpam_resctrl_set_default_cpu(cpu);
}

static inline struct rdt_domain *
resctrl_get_domain_from_cpu(int cpu, struct resctrl_resource *r)
{
	struct rdt_domain *d;

	list_for_each_entry(d, &r->domains, list) {
		/* Find the domain that contains this CPU */
		if (cpumask_test_cpu(cpu, &d->cpu_mask))
			return d;
	}

	return NULL;
}

int mpam_resctrl_cpu_offline(unsigned int cpu)
{
	struct rdt_domain *d;
	struct mpam_resctrl_res *res;
	struct mpam_resctrl_dom *dom;

	for_each_supported_resctrl_exports(res) {
		 d = resctrl_get_domain_from_cpu(cpu, &res->resctrl_res);

		/* cpu with unknown exported component? */
		if (WARN_ON_ONCE(!d))
			continue;

		cpumask_clear_cpu(cpu, &d->cpu_mask);

		if (!cpumask_empty(&d->cpu_mask))
			continue;

		list_del(&d->list);
		dom = container_of(d, struct mpam_resctrl_dom, resctrl_dom);
		kfree(dom);
	}

	mpam_resctrl_clear_default_cpu(cpu);

	return 0;
}


/* Test whether we can export MPAM_CLASS_CACHE:{2,3}? */
static void mpam_resctrl_pick_caches(void)
{
	struct mpam_class *class;
	struct mpam_resctrl_res *res;

	mpam_class_list_lock_held();

	list_for_each_entry(class, &mpam_classes, classes_list) {
		if (class->type != MPAM_CLASS_CACHE)
			continue;

		if (class->level != 2 && class->level != 3)
			continue;

		if (!mpam_has_feature(mpam_feat_cpor_part, class->features) &&
			!mpam_has_feature(mpam_feat_msmon_csu, class->features))
			continue;

		if (!mpam_has_feature(mpam_feat_msmon_csu, class->features) &&
			mpam_sysprops_num_partid() <= 1)
			continue;

		if (class->cpbm_wd > RESCTRL_MAX_CBM)
			continue;

		if (class->level == 2) {
			res = &mpam_resctrl_exports[RDT_RESOURCE_L2];
			res->resctrl_res.name = "L2";
		} else {
			res = &mpam_resctrl_exports[RDT_RESOURCE_L3];
			res->resctrl_res.name = "L3";
		}
		res->class = class;
	}
}

/* Find what we can export as MBA */
static void mpam_resctrl_pick_mba(void)
{
	u8 resctrl_llc;
	struct mpam_class *class;
	struct mpam_class *candidate = NULL;

	mpam_class_list_lock_held();

    /* At least two partitions ... */
	if (mpam_sysprops_num_partid() <= 1)
		return;

	if (mpam_resctrl_exports[RDT_RESOURCE_L3].class)
		resctrl_llc = 3;
	else if (mpam_resctrl_exports[RDT_RESOURCE_L2].class)
		resctrl_llc = 2;
	else
		resctrl_llc = 0;

	list_for_each_entry(class, &mpam_classes, classes_list) {
		if (class->type == MPAM_CLASS_UNKNOWN)
			continue;

		if (class->level < resctrl_llc)
			continue;

		/*
		 * Once we support MBM counters, we should require the MBA
		 * class to be at the same point in the hierarchy. Practically,
		 * this means the MBA class must support MBWU. Until then
		 * having something is better than nothing, but this may cause
		 * the MBA resource to disappear over a kernel update on a
		 * system that could support both, but not at the same time.
		 */

		/*
		 * There are two ways we can generate delays for MBA, either
		 * with the mbw portion bitmap, or the mbw max control.
		 */
		if (!mpam_has_feature(mpam_feat_mbw_part, class->features) &&
			!mpam_has_feature(mpam_feat_mbw_max, class->features)) {
			continue;
		}

		/* pick the class 'closest' to resctrl_llc */
		if (!candidate || (class->level < candidate->level))
			candidate = class;
	}

	if (candidate)
		mpam_resctrl_exports[RDT_RESOURCE_MC].class = candidate;
}

static void mpam_resctrl_pick_event_l3_occup(void)
{
	/*
	 * as the name suggests, resctrl can only use this if your cache is
	 * called 'l3'.
	 */
	struct mpam_resctrl_res *res = &mpam_resctrl_exports[RDT_RESOURCE_L3];

	if (!res->class)
		return;

	if (!mpam_has_feature(mpam_feat_msmon_csu, res->class->features))
		return;

	mpam_resctrl_events[QOS_L3_OCCUP_EVENT_ID] = *res;

	rdt_mon_capable = true;
	res->resctrl_res.mon_capable = true;
	res->resctrl_res.mon_capable = true;
}

static void mpam_resctrl_pick_event_mbm_total(void)
{
	u64 num_counters;
	struct mpam_resctrl_res *res;

    /* We prefer to measure mbm_total on whatever we used as MBA... */
	res = &mpam_resctrl_exports[RDT_RESOURCE_MC];
	if (!res->class) {
		/* ... but if there isn't one, the L3 cache works */
		res = &mpam_resctrl_exports[RDT_RESOURCE_L3];
		if (!res->class)
			return;
	}

	/*
	 * to measure bandwidth in a resctrl like way, we need to leave a
	 * counter running all the time. As these are PMU-like, it is really
	 * unlikely we have enough... To be useful, we'd need at least one per
	 * closid.
	 */
	num_counters = mpam_sysprops_num_partid();

	if (mpam_has_feature(mpam_feat_msmon_mbwu, res->class->features)) {
		if (res->class->num_mbwu_mon >= num_counters) {
			/*
			 * We don't support this use of monitors, let the
			 * world know this platform could make use of them
			 * if we did!
			 */
		}
	}
}

static void mpam_resctrl_pick_event_mbm_local(void)
{
	struct mpam_resctrl_res *res;

	res = &mpam_resctrl_exports[RDT_RESOURCE_MC];
	if (!res->class)
		return;

	if (mpam_has_feature(mpam_feat_msmon_mbwu, res->class->features)) {
		res->resctrl_res.mon_capable = true;
		mpam_resctrl_events[QOS_L3_MBM_LOCAL_EVENT_ID] = *res;
	}
}

static int mpam_resctrl_resource_init(struct mpam_resctrl_res *res)
{
	struct mpam_class *class = res->class;
	struct resctrl_resource *r = &res->resctrl_res;
	struct raw_resctrl_resource *rr = NULL;

	if (class && !r->default_ctrl) {
		r->default_ctrl = kmalloc_array(SCHEMA_NUM_CTRL_TYPE,
			sizeof(*r->default_ctrl), GFP_KERNEL);
		if (!r->default_ctrl)
			return -ENOMEM;
	}

	if (class == mpam_resctrl_exports[RDT_RESOURCE_SMMU].class) {
		return 0;
	} else if (class == mpam_resctrl_exports[RDT_RESOURCE_MC].class) {
		r->rid = RDT_RESOURCE_MC;
		r->name = "MB";
		r->fflags = RFTYPE_RES_MC;
		r->mbw.delay_linear = true;
		rr = mpam_get_raw_resctrl_resource(RDT_RESOURCE_MC);
		rr->num_mon = class->num_mbwu_mon;
		r->res = rr;

		if (mpam_has_feature(mpam_feat_mbw_part, class->features)) {
			res->resctrl_mba_uses_mbw_part = true;

			/*
			 * The maximum throttling is the number of bits we can
			 * unset in the bitmap. We never clear all of them,
			 * so the minimum is one bit, as a percentage.
			 */
			r->mbw.min_bw = MAX_MBA_BW / class->mbw_pbm_bits;
		} else {
			/* we're using mpam_feat_mbw_max's */
			res->resctrl_mba_uses_mbw_part = false;

			/*
			 * The maximum throttling is the number of fractions we
			 * can represent with the implemented bits. We never
			 * set 0. The minimum is the LSB, as a percentage.
			 */
			r->mbw.min_bw = MAX_MBA_BW /
				((1ULL << class->bwa_wd) - 1);
			/* the largest mbw_max is 100 */
			r->default_ctrl[SCHEMA_COMM] = 100;
		}
		/* Just in case we have an excessive number of bits */
		if (!r->mbw.min_bw)
			r->mbw.min_bw = 1;

		/*
		 * because its linear with no offset, the granule is the same
		 * as the smallest value
		 */
		r->mbw.bw_gran = r->mbw.min_bw;

		/* We will only pick a class that can monitor and control */
		r->alloc_capable = true;
		r->alloc_enabled = true;
		rdt_alloc_capable = true;
		r->mon_capable = true;
		r->mon_enabled = true;
		/* Export memory bandwidth hardlimit, default active hardlimit */
		rr->hdl_wd = 2;
		r->default_ctrl[SCHEMA_HDL] = rr->hdl_wd - 1;
	} else if (class == mpam_resctrl_exports[RDT_RESOURCE_L3].class) {
		r->rid = RDT_RESOURCE_L3;
		rr = mpam_get_raw_resctrl_resource(RDT_RESOURCE_L3);
		rr->num_mon = class->num_csu_mon;
		r->res = rr;
		r->fflags = RFTYPE_RES_CACHE;
		r->name = "L3";

		r->cache.cbm_len = class->cpbm_wd;
		r->default_ctrl[SCHEMA_COMM] = GENMASK(class->cpbm_wd - 1, 0);
		/*
		 * Which bits are shared with other ...things...
		 * Unknown devices use partid-0 which uses all the bitmap
		 * fields. Until we configured the SMMU and GIC not to do this
		 * 'all the bits' is the correct answer here.
		 */
		r->cache.shareable_bits = r->default_ctrl[SCHEMA_COMM];
		r->cache.min_cbm_bits = 1;

		if (mpam_has_feature(mpam_feat_cpor_part, class->features)) {
			r->alloc_capable = true;
			r->alloc_enabled = true;
			rdt_alloc_capable = true;
		}
		/*
		 * While this is a CPU-interface feature of MPAM, we only tell
		 * resctrl about it for caches, as that seems to be how x86
		 * works, and thus what resctrl expects.
		 */
		r->cdp_capable = true;
		r->mon_capable = true;
		r->mon_enabled = true;

	} else if (class == mpam_resctrl_exports[RDT_RESOURCE_L2].class) {
		r->rid = RDT_RESOURCE_L2;
		rr = mpam_get_raw_resctrl_resource(RDT_RESOURCE_L2);
		rr->num_mon = class->num_csu_mon;
		r->res = rr;
		r->fflags = RFTYPE_RES_CACHE;
		r->name = "L2";

		r->cache.cbm_len = class->cpbm_wd;
		r->default_ctrl[SCHEMA_COMM] = GENMASK(class->cpbm_wd - 1, 0);
		/*
		 * Which bits are shared with other ...things...
		 * Unknown devices use partid-0 which uses all the bitmap
		 * fields. Until we configured the SMMU and GIC not to do this
		 * 'all the bits' is the correct answer here.
		 */
		r->cache.shareable_bits = r->default_ctrl[SCHEMA_COMM];

		if (mpam_has_feature(mpam_feat_cpor_part, class->features)) {
			r->alloc_capable = true;
			r->alloc_enabled = true;
			rdt_alloc_capable = true;
		}

		/*
		 * While this is a CPU-interface feature of MPAM, we only tell
		 * resctrl about it for caches, as that seems to be how x86
		 * works, and thus what resctrl expects.
		 */
		r->cdp_capable = true;
		r->mon_capable = false;
	}

	if (rr && class) {
		rr->num_partid = class->num_partid;
		rr->num_intpartid = class->num_intpartid;
		rr->num_pmg = class->num_pmg;

		/* Export priority setting, default highest priority */
		rr->pri_wd = max(class->intpri_wd, class->dspri_wd);
		r->default_ctrl[SCHEMA_PRI] = (rr->pri_wd > 0) ?
			rr->pri_wd - 1 : 0;
	}

	return 0;
}

/* Called with the mpam classes lock held */
int mpam_resctrl_setup(void)
{
	int rc;
	struct mpam_resctrl_res *res;
	enum resctrl_resource_level level = 0;

	for_each_resctrl_exports(res) {
		INIT_LIST_HEAD(&res->resctrl_res.domains);
		res->resctrl_res.rid = level;
		level++;
	}

	mpam_resctrl_pick_caches();
	mpam_resctrl_pick_mba();

	mpam_resctrl_pick_event_l3_occup();
	mpam_resctrl_pick_event_mbm_total();
	mpam_resctrl_pick_event_mbm_local();

	for_each_supported_resctrl_exports(res) {
		rc = mpam_resctrl_resource_init(res);
		if (rc)
			return rc;
	}

	if (!rdt_alloc_capable && !rdt_mon_capable)
		return -EOPNOTSUPP;

	return 0;
}

struct resctrl_resource *
mpam_resctrl_get_resource(enum resctrl_resource_level level)
{
	if (level >= RDT_NUM_RESOURCES ||
		!mpam_resctrl_exports[level].class)
		return NULL;

	return &mpam_resctrl_exports[level].resctrl_res;
}
