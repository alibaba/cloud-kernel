// SPDX-License-Identifier: GPL-2.0+
/*
 * Common code for ARM v8 MPAM
 *
 * Copyright (C) 2017 Intel Corporation
 * Copyright (C) 2018-2019 Huawei Technologies Co., Ltd
 *
 * Author:
 *   Vikas Shivappa <vikas.shivappa@intel.com>
 *   Xie XiuQi <xiexiuqi@huawei.com>
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
#include <linux/resctrlfs.h>

#include <asm/resctrl.h>

/*
 * Global boolean for rdt_monitor which is true if any
 * resource monitoring is enabled.
 */
bool rdt_mon_capable;

static int pmg_free_map;
void mon_init(void);
void pmg_init(void)
{
	/* use L3's num_pmg as system num_pmg */
	struct raw_resctrl_resource *rr =
		resctrl_resources_all[MPAM_RESOURCE_CACHE].res;
	int num_pmg = rr->num_pmg;

	mon_init();

	pmg_free_map = BIT_MASK(num_pmg) - 1;

	/* pmg 0 is always reserved for the default group */
	pmg_free_map &= ~1;
}

int alloc_pmg(void)
{
	u32 pmg = ffs(pmg_free_map);

	if (pmg == 0)
		return -ENOSPC;

	pmg--;
	pmg_free_map &= ~(1 << pmg);

	return pmg;
}

void free_pmg(u32 pmg)
{
	pmg_free_map |= 1 << pmg;
}

static int mon_free_map;
void mon_init(void)
{
	struct resctrl_resource *r;
	struct raw_resctrl_resource *rr;
	int num_mon = INT_MAX;

	for_each_resctrl_resource(r) {
		if (r->mon_enabled) {
			rr = r->res;
			num_mon = min(num_mon, rr->num_mon);
		}
	}

	mon_free_map = BIT_MASK(num_mon) - 1;
}

int alloc_mon(void)
{
	u32 mon = ffs(mon_free_map);

	if (mon == 0)
		return -ENOSPC;

	mon--;
	mon_free_map &= ~(1 << mon);

	return mon;
}

void free_mon(u32 mon)
{
	mon_free_map |= 1 << mon;
}

/*
 * As of now the RMIDs allocation is global.
 * However we keep track of which packages the RMIDs
 * are used to optimize the limbo list management.
 */
int alloc_rmid(void)
{
	return alloc_pmg();
}

void free_rmid(u32 pmg)
{
	free_pmg(pmg);
}
