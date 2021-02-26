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

static int pmg_free_map;
void pmg_init(void)
{
	u16 num_pmg = USHRT_MAX;
	struct mpam_resctrl_res *res;
	struct resctrl_resource *r;
	struct raw_resctrl_resource *rr;

	/* Use the max num_pmg among all resources */
	for_each_supported_resctrl_exports(res) {
		r = &res->resctrl_res;
		rr = r->res;
		num_pmg = min(num_pmg, rr->num_pmg);
	}

	pmg_free_map = BIT_MASK(num_pmg) - 1;

	/* pmg 0 is always reserved for the default group */
	pmg_free_map &= ~1;
}

static int alloc_pmg(void)
{
	u32 pmg = ffs(pmg_free_map);

	if (pmg == 0)
		return -ENOSPC;

	pmg--;
	pmg_free_map &= ~(1 << pmg);

	return pmg;
}

static void free_pmg(u32 pmg)
{
	pmg_free_map |= 1 << pmg;
}

int alloc_rmid(void)
{
	return alloc_pmg();
}

void free_rmid(u32 id)
{
	free_pmg(id);
}

/*
 * A simple LRU monitor allocation machanism, each
 * monitor free map occupies two section, one for
 * allocation and another for recording.
 */
static int mon_free_map[2];
static u8 alloc_idx, record_idx;

void mon_init(void)
{
	int num_mon;
	u32 times, flag;

	num_mon = mpam_resctrl_max_mon_num();

	hw_alloc_times_validate(times, flag);
	/* for cdp on or off */
	num_mon = rounddown(num_mon, times);

	mon_free_map[0] = BIT_MASK(num_mon) - 1;
	mon_free_map[1] = 0;

	alloc_idx = 0;
	record_idx = 1;
}

int resctrl_lru_request_mon(void)
{
	u32 mon = 0;
	u32 times, flag;

	hw_alloc_times_validate(times, flag);

	mon = ffs(mon_free_map[alloc_idx]);
	if (mon == 0)
		return -ENOSPC;

	mon--;
	mon_free_map[alloc_idx] &= ~(GENMASK(mon + times - 1, mon));
	mon_free_map[record_idx] |= GENMASK(mon + times - 1, mon);

	if (!mon_free_map[alloc_idx]) {
		alloc_idx = record_idx;
		record_idx ^= 0x1;
	}

	return mon;
}
