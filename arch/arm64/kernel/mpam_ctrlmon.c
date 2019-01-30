/*
 * Resource Director Technology(RDT)
 * - Cache Allocation code.
 *
 * Copyright (C) 2016 Intel Corporation
 *
 * Authors:
 *    Fenghua Yu <fenghua.yu@intel.com>
 *    Tony Luck <tony.luck@intel.com>
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

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/kernfs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/resctrlfs.h>

#include <asm/resctrl.h>


ssize_t resctrl_group_schemata_write(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off)
{
	return 0;
}

int resctrl_group_schemata_show(struct kernfs_open_file *of,
			   struct seq_file *s, void *v)
{
	seq_printf(s, "resctrl_group_schemata_show\n");
	return 0;
}
