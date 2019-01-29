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

/*
 * Check whether a cache bit mask is valid. The SDM says:
 *	Please note that all (and only) contiguous '1' combinations
 *	are allowed (e.g. FFFFH, 0FF0H, 003CH, etc.).
 * Additionally Haswell requires at least two bits set.
 */
static bool cbm_validate(char *buf, unsigned long *data, struct raw_resctrl_resource *r)
{
	u64 val;
	int ret;

	ret = kstrtou64(buf, 16, &val);
	if (ret) {
		rdt_last_cmd_printf("non-hex character in mask %s\n", buf);
		return false;
	}

#if 0
	if (val == 0 || val > r->default_ctrl) {
		rdt_last_cmd_puts("mask out of range\n");
		return false;
	}
#endif

	*data = val;
	return true;
}

/*
 * Read one cache bit mask (hex). Check that it is valid for the current
 * resource type.
 */
int parse_cbm(char *buf, struct raw_resctrl_resource *r, struct rdt_domain *d)
{
	unsigned long data;

	if (d->have_new_ctrl) {
		rdt_last_cmd_printf("duplicate domain %d\n", d->id);
		return -EINVAL;
	}

	if (!cbm_validate(buf, &data, r))
		return -EINVAL;

	d->new_ctrl = data;
	d->have_new_ctrl = true;

	return 0;
}

/*
 * For each domain in this resource we expect to find a series of:
 * id=mask
 * separated by ";". The "id" is in decimal, and must match one of
 * the "id"s for this resource.
 */
static int parse_line(char *line, struct resctrl_resource *r)
{
	struct raw_resctrl_resource *rr = (struct raw_resctrl_resource *)r->res;
	char *dom = NULL, *id;
	struct rdt_domain *d;
	unsigned long dom_id;


next:
	if (!line || line[0] == '\0')
		return 0;
	dom = strsep(&line, ";");
	id = strsep(&dom, "=");
	if (!dom || kstrtoul(id, 10, &dom_id)) {
		rdt_last_cmd_puts("Missing '=' or non-numeric domain\n");
		return -EINVAL;
	}
	dom = strim(dom);
	list_for_each_entry(d, &r->domains, list) {
		if (d->id == dom_id) {
			if (rr->parse_ctrlval(dom, (struct raw_resctrl_resource *)&r->res, d))
				return -EINVAL;
			goto next;
		}
	}
	return -EINVAL;
}

static int update_domains(struct resctrl_resource *r, int partid)
{
	struct raw_resctrl_resource *rr;
	struct rdt_domain *d;

	rr = (struct raw_resctrl_resource *)r->res;
	list_for_each_entry(d, &r->domains, list) {
		if (d->have_new_ctrl && d->new_ctrl != d->ctrl_val[partid]) {
			d->ctrl_val[partid] = d->new_ctrl;
			rr->msr_update(d, partid);
		}
	}

	return 0;
}

static int resctrl_group_parse_resource(char *resname, char *tok, int closid)
{
	struct resctrl_resource *r;
	struct raw_resctrl_resource *rr;

	for_each_resctrl_resource(r) {
		if (r->alloc_enabled) {
			rr = (struct raw_resctrl_resource *)r->res;
			if (!strcmp(resname, r->name) && closid < rr->num_partid)
				return parse_line(tok, r);
		}
	}
	rdt_last_cmd_printf("unknown/unsupported resource name '%s'\n", resname);
	return -EINVAL;
}

ssize_t resctrl_group_schemata_write(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off)
{
	struct rdtgroup *rdtgrp;
	struct rdt_domain *dom;
	struct resctrl_resource *r;
	char *tok, *resname;
	int closid, ret = 0;

	/* Valid input requires a trailing newline */
	if (nbytes == 0 || buf[nbytes - 1] != '\n')
		return -EINVAL;
	buf[nbytes - 1] = '\0';

	rdtgrp = resctrl_group_kn_lock_live(of->kn);
	if (!rdtgrp) {
		resctrl_group_kn_unlock(of->kn);
		return -ENOENT;
	}
	rdt_last_cmd_clear();

	closid = rdtgrp->closid;

	for_each_resctrl_resource(r) {
		if (r->alloc_enabled) {
			list_for_each_entry(dom, &r->domains, list)
				dom->have_new_ctrl = false;
		}
	}

	while ((tok = strsep(&buf, "\n")) != NULL) {
		resname = strim(strsep(&tok, ":"));
		if (!tok) {
			rdt_last_cmd_puts("Missing ':'\n");
			ret = -EINVAL;
			goto out;
		}
		if (tok[0] == '\0') {
			rdt_last_cmd_printf("Missing '%s' value\n", resname);
			ret = -EINVAL;
			goto out;
		}
		ret = resctrl_group_parse_resource(resname, tok, closid);
		if (ret)
			goto out;
	}

	for_each_resctrl_resource(r) {
		if (r->alloc_enabled) {
			ret = update_domains(r, closid);
			if (ret)
				goto out;
		}
	}

out:
	resctrl_group_kn_unlock(of->kn);
	return ret ?: nbytes;
}

static void show_doms(struct seq_file *s, struct resctrl_resource *r, int partid)
{
	struct raw_resctrl_resource *rr = (struct raw_resctrl_resource *)r->res;
	struct rdt_domain *dom;
	bool sep = false;

	seq_printf(s, "%*s:", max_name_width, r->name);
	list_for_each_entry(dom, &r->domains, list) {
		if (sep)
			seq_puts(s, ";");
		seq_printf(s, rr->format_str, dom->id, max_data_width,
			   dom->ctrl_val[partid]);
		sep = true;
	}
	seq_puts(s, "\n");
}

int resctrl_group_schemata_show(struct kernfs_open_file *of,
			   struct seq_file *s, void *v)
{
	struct rdtgroup *rdtgrp;
	struct resctrl_resource *r;
	struct raw_resctrl_resource *rr;
	int ret = 0;
	u32 partid;

	rdtgrp = resctrl_group_kn_lock_live(of->kn);
	if (rdtgrp) {
		partid = rdtgrp->closid;
		for_each_resctrl_resource(r) {
			if (r->alloc_enabled) {
				rr = (struct raw_resctrl_resource *)r->res;
				if (partid < rr->num_partid)
					show_doms(s, r, partid);
			}
		}
	} else {
		ret = -ENOENT;
	}
	resctrl_group_kn_unlock(of->kn);
	return ret;
}
