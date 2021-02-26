// SPDX-License-Identifier: GPL-2.0+
/*
 * Common code for ARM v8 MPAM
 *
 * Copyright (C) 2018-2019 Huawei Technologies Co., Ltd
 *
 * Author: Xie XiuQi <xiexiuqi@huawei.com>
 *
 * Code was partially borrowed from arch/x86/kernel/cpu/intel_rdt*.
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

#include <linux/module.h>
#include <linux/slab.h>

#include "mpam_internal.h"

/*
 * Global boolean for rdt_monitor which is true if any
 * resource monitoring is enabled.
 */
bool rdt_mon_capable;

struct rmid_entry {
	u32             rmid;
	u32             mon[RDT_NUM_RESOURCES];
	struct list_head        mon_exclusive_q;
	struct list_head        mon_wait_q;
};

/**
 * @rmid_mon_exclusive_all  List of allocated RMIDs with
 * exclusive available mon.
 */
static LIST_HEAD(rmid_mon_exclusive_all);

/**
 * @rmid_mon_wait_all  List of allocated RMIDs with default
 * 0 mon and wait for exclusive available mon.
 */
static LIST_HEAD(rmid_mon_wait_all);

static u32 rmid_ptrs_len;

/**
 * @rmid_entry - The entry in the mon list.
 */
static struct rmid_entry    *rmid_ptrs;

static int mon_free_map[RDT_NUM_RESOURCES];

static void mon_init(void)
{
	u16 mon_num;
	u32 times, flag;
	struct mpam_resctrl_res *res;
	struct resctrl_resource *r;
	struct raw_resctrl_resource *rr;

	for_each_supported_resctrl_exports(res) {
		r = &res->resctrl_res;
		rr = r->res;

		hw_alloc_times_validate(times, flag);
		/* for cdp*/
		mon_num = rounddown(rr->num_mon, times);
		mon_free_map[r->rid] = BIT_MASK(mon_num) - 1;

		/* mon = 0 is reserved */
		mon_free_map[r->rid] &= ~(BIT_MASK(times) - 1);
	}
}

static u32 mon_alloc(enum resctrl_resource_level rid)
{
	u32 mon = 0;
	u32 times, flag;

	hw_alloc_times_validate(times, flag);

	mon = ffs(mon_free_map[rid]);
	if (mon == 0)
		return -ENOSPC;

	mon--;
	mon_free_map[rid] &= ~(GENMASK(mon + times - 1, mon));

	return mon;
}

static void mon_free(u32 mon, enum resctrl_resource_level rid)
{
	u32 times, flag;

	hw_alloc_times_validate(times, flag);
	mon_free_map[rid] |= GENMASK(mon + times - 1, mon);
}

static inline struct rmid_entry *__rmid_entry(u32 rmid)
{
	struct rmid_entry *entry;

	if (rmid >= rmid_ptrs_len)
		return NULL;

	entry = &rmid_ptrs[rmid];
	WARN_ON(entry->rmid != rmid);

	return entry;
}

static void mon_wait_q_init(void)
{
	INIT_LIST_HEAD(&rmid_mon_wait_all);
}

static void mon_exclusive_q_init(void)
{
	INIT_LIST_HEAD(&rmid_mon_exclusive_all);
}

static void put_mon_wait_q(struct rmid_entry *entry)
{
	list_add_tail(&entry->mon_wait_q, &rmid_mon_wait_all);
}

static void put_mon_exclusive_q(struct rmid_entry *entry)
{
	list_add_tail(&entry->mon_exclusive_q, &rmid_mon_exclusive_all);
}

static void mon_wait_q_del(struct rmid_entry *entry)
{
	list_del(&entry->mon_wait_q);
}

static void mon_exclusive_q_del(struct rmid_entry *entry)
{
	list_del(&entry->mon_exclusive_q);
}

static int is_mon_wait_q_exist(u32 rmid)
{
	struct rmid_entry *entry;

	list_for_each_entry(entry, &rmid_mon_wait_all, mon_wait_q) {
		if (entry->rmid == rmid)
			return 1;
	}

	return 0;
}

static int is_mon_exclusive_q_exist(u32 rmid)
{
	struct rmid_entry *entry;

	list_for_each_entry(entry, &rmid_mon_exclusive_all, mon_exclusive_q) {
		if (entry->rmid == rmid)
			return 1;
	}

	return 0;
}

static int is_rmid_mon_wait_q_exist(u32 rmid)
{
	struct rmid_entry *entry;

	list_for_each_entry(entry, &rmid_mon_wait_all, mon_wait_q) {
		if (entry->rmid == rmid)
			return 1;
	}

	return 0;
}

int rmid_mon_ptrs_init(u32 nr_rmids)
{
	struct rmid_entry *entry = NULL;
	int i;

	if (rmid_ptrs)
		kfree(rmid_ptrs);

	rmid_ptrs = kcalloc(nr_rmids, sizeof(struct rmid_entry), GFP_KERNEL);
	if (!rmid_ptrs)
		return -ENOMEM;

	rmid_ptrs_len = nr_rmids;

	for (i = 0; i < nr_rmids; i++) {
		entry = &rmid_ptrs[i];
		entry->rmid = i;
	}

	mon_exclusive_q_init();
	mon_wait_q_init();

    /*
     * RMID 0 is special and is always allocated. It's used for all
     * tasks monitoring.
     */
	entry = __rmid_entry(0);
	if (!entry) {
		kfree(rmid_ptrs);
		rmid_ptrs = NULL;
		return -EINVAL;
	}

	put_mon_exclusive_q(entry);

	mon_init();

	return 0;
}

int assoc_rmid_with_mon(u32 rmid)
{
	int mon;
	bool has_mon_wait = false;
	struct rmid_entry *entry;
	struct mpam_resctrl_res *res;
	struct resctrl_resource *r;

	if (is_mon_exclusive_q_exist(rmid) ||
		is_rmid_mon_wait_q_exist(rmid))
		return -EINVAL;

	entry = __rmid_entry(rmid);
	if (!entry)
		return -EINVAL;

	for_each_supported_resctrl_exports(res) {
		r = &res->resctrl_res;
		if (!r->mon_enabled)
			continue;

		mon = mon_alloc(r->rid);
		if (mon < 0) {
			entry->mon[r->rid] = 0;
			has_mon_wait = true;
		} else {
			entry->mon[r->rid] = mon;
		}
	}

	if (has_mon_wait)
		put_mon_wait_q(entry);
	else
		put_mon_exclusive_q(entry);

	return 0;
}

void deassoc_rmid_with_mon(u32 rmid)
{
	bool has_mon_wait;
	struct mpam_resctrl_res *res;
	struct resctrl_resource *r;
	struct rmid_entry *entry = __rmid_entry(rmid);
	struct rmid_entry *wait, *tmp;

	if (!entry)
		return;

	if (!is_mon_wait_q_exist(rmid) &&
		!is_mon_exclusive_q_exist(rmid))
		return;

	if (is_mon_wait_q_exist(rmid))
		mon_wait_q_del(entry);
	else
		mon_exclusive_q_del(entry);

	list_for_each_entry_safe(wait, tmp, &rmid_mon_wait_all, mon_wait_q) {
		has_mon_wait = false;
		for_each_supported_resctrl_exports(res) {
			r = &res->resctrl_res;
			if (!r->mon_enabled)
				continue;

			if (!wait->mon[r->rid]) {
				wait->mon[r->rid] = entry->mon[r->rid];
				entry->mon[r->rid] = 0;
			}

			if (!wait->mon[r->rid])
				has_mon_wait = true;
		}
		if (!has_mon_wait) {
			mon_wait_q_del(wait);
			put_mon_exclusive_q(wait);
		}
	}

	for_each_supported_resctrl_exports(res) {
		r = &res->resctrl_res;
		if (!r->mon_enabled)
			continue;

		if (entry->mon[r->rid])
			mon_free(entry->mon[r->rid], r->rid);
	}
}

u32 get_rmid_mon(u32 rmid, enum resctrl_resource_level rid)
{
	struct rmid_entry *entry = __rmid_entry(rmid);

	if (!entry)
		return 0;

	if (!is_mon_wait_q_exist(rmid) && !is_mon_exclusive_q_exist(rmid))
		return 0;

	return entry->mon[rid];
}
