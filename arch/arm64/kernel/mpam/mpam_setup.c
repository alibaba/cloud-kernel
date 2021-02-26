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
#include <linux/resctrlfs.h>
#include <asm/resctrl.h>

#include "mpam_device.h"
#include "mpam_internal.h"

/*
 * The classes we've picked to map to resctrl resources.
 * Class pointer may be NULL.
 */
struct mpam_resctrl_res mpam_resctrl_exports[RDT_NUM_RESOURCES];
struct mpam_resctrl_res mpam_resctrl_events[RESCTRL_NUM_EVENT_IDS];

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

/* Called with the mpam classes lock held */
int mpam_resctrl_setup(void)
{
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

	return 0;
}
