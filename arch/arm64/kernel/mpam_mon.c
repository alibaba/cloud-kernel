/*
 * Resource Director Technology(RDT)
 * - Monitoring code
 *
 * Copyright (C) 2017 Intel Corporation
 *
 * Author:
 *    Vikas Shivappa <vikas.shivappa@intel.com>
 *
 * This replaces the cqm.c based on perf but we reuse a lot of
 * code and datastructures originally from Peter Zijlstra and Matt Fleming.
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
 * More information about RDT be found in the Intel (R) x86 Architecture
 * Software Developer Manual June 2016, volume 3, section 17.17.
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

void pmg_init(void)
{
	int pmg_max = 16;

	pmg_free_map = BIT_MASK(pmg_max) - 1;

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

int mpam_get_mon_config(struct resctrl_resource *r)
{
	r->mon_capable = true;
	r->mon_enabled = true;

	return 0;
}
