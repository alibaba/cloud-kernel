// SPDX-License-Identifier: GPL-2.0+
/*
 * Common code for ARM v8 MPAM
 *  - allocation and monitor management
 *
 * Copyright (C) 2016 Intel Corporation
 * Copyright (C) 2018-2019 Huawei Technologies Co., Ltd
 *
 * Authors:
 *   Fenghua Yu <fenghua.yu@intel.com>
 *   Tony Luck <tony.luck@intel.com>
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

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/kernfs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/resctrlfs.h>

#include <asm/mpam.h>
#include <asm/mpam_resource.h>
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

/* define bw_min as 5 percentage, that are 5% ~ 100% which cresponding masks: */
static u32 bw_max_mask[20] = {
	 3,	/*  3/64:  5% */
	 6,	/*  6/64: 10% */
	10,	/* 10/64: 15% */
	13,	/* 13/64: 20% */
	16,	/* 16/64: 25% */
	19,	/* ... */
	22,
	26,
	29,
	32,
	35,
	38,
	42,
	45,
	48,
	51,
	54,
	58,
	61,
	63	/* 100% */
};

static bool bw_validate(char *buf, unsigned long *data, struct raw_resctrl_resource *r)
{
	unsigned long bw;
	int ret, idx;

	ret = kstrtoul(buf, 10, &bw);
	if (ret) {
		rdt_last_cmd_printf("non-hex character in mask %s\n", buf);
		return false;
	}

	bw = bw < 5 ? 5 : bw;
	bw = bw > 100 ? 100 : bw;

	idx = roundup(bw, 5) / 5 - 1;

	*data = bw_max_mask[idx];
	return true;
}

int parse_bw(char *buf, struct raw_resctrl_resource *r, struct rdt_domain *d)
{
	unsigned long data;

	if (d->have_new_ctrl) {
		rdt_last_cmd_printf("duplicate domain %d\n", d->id);
		return -EINVAL;
	}

	if (!bw_validate(buf, &data, r))
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

static int update_domains(struct resctrl_resource *r, struct rdtgroup *g)
{
	struct raw_resctrl_resource *rr;
	struct rdt_domain *d;
	int partid = g->closid;

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
			ret = update_domains(r, rdtgrp);
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
			   rr->msr_read(dom, partid));
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

static inline char *kernfs_node_name(struct kernfs_open_file *of)
{
	return (char *)(of ? of->kn->name : NULL);
}

static inline void put_resource_name(char *res)
{
	kfree(res);
}

/*
 * pick resource name from mon data name
 * eg. from mon_L3_01 we got L3
 * */
static inline char *get_resource_name(char *name)
{
	char *s, *p, *res;

	if (!name)
		return NULL;

	s = name + 4;	/* skip "mon_" prefix */
	p = strrchr(name, '_');
	res = kmemdup_nul(s, p - s, GFP_KERNEL);
	if (!res)
		res = NULL;

	return res;
}

int resctrl_group_mondata_show(struct seq_file *m, void *arg)
{
	struct kernfs_open_file *of = m->private;
	struct rdtgroup *rdtgrp;
	struct rdt_domain *d;
	struct resctrl_resource *r;
	struct raw_resctrl_resource *rr;
	union mon_data_bits md;
	int ret = 0;
	char *resname = get_resource_name(kernfs_node_name(of));
	u64 usage;

	if (!resname)
		return -ENOMEM;

	rdtgrp = resctrl_group_kn_lock_live(of->kn);
	if (!rdtgrp) {
		ret = -ENOENT;
		goto out;
	}

	md.priv = of->kn->priv;

	r = &resctrl_resources_all[md.u.rid];
	rr = r->res;

	/* show monitor data */
	d = mpam_find_domain(r, md.u.domid, NULL);
	if (IS_ERR_OR_NULL(d)) {
		pr_warn("Could't find domain id %d\n", md.u.domid);
		ret = -ENOENT;
		goto out;
	}

	usage = rr->mon_read(d, rdtgrp);
	seq_printf(m, "%llu\n", usage);

out:
	put_resource_name(resname);
	resctrl_group_kn_unlock(of->kn);
	return ret;
}

static struct kernfs_ops kf_mondata_ops = {
	.atomic_write_len	= PAGE_SIZE,
	.seq_show		= resctrl_group_mondata_show,
};

/* set uid and gid of resctrl_group dirs and files to that of the creator */
static int resctrl_group_kn_set_ugid(struct kernfs_node *kn)
{
	struct iattr iattr = { .ia_valid = ATTR_UID | ATTR_GID,
				.ia_uid = current_fsuid(),
				.ia_gid = current_fsgid(), };

	if (uid_eq(iattr.ia_uid, GLOBAL_ROOT_UID) &&
	    gid_eq(iattr.ia_gid, GLOBAL_ROOT_GID))
		return 0;

	return kernfs_setattr(kn, &iattr);
}

static int mkdir_mondata_subdir(struct kernfs_node *parent_kn,
				struct rdt_domain *d,
				struct resctrl_resource *r, struct resctrl_group *prgrp)
{
	struct raw_resctrl_resource *rr = (struct raw_resctrl_resource *)r->res;
	union mon_data_bits md;
	struct kernfs_node *kn;
	char name[32];
	int ret = 0;


	md.u.rid = r->rid;
	md.u.domid = d->id;
	md.u.partid = prgrp->closid;
	md.u.pmg = prgrp->mon.rmid;

	snprintf(name, sizeof(name), "mon_%s_%02d", r->name, d->id);
	kn = __kernfs_create_file(parent_kn, name, 0444,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, 0,
				  &kf_mondata_ops, md.priv, NULL, NULL);
	if (IS_ERR(kn))
		return PTR_ERR(kn);

	ret = resctrl_group_kn_set_ugid(kn);
	if (ret) {
		pr_info("%s: create name %s, error ret %d\n", __func__, name, ret);
		kernfs_remove(kn);
		return ret;
	}

	/* [FIXME] Could we remove the MATCH_* param ? */
	rr->mon_write(d, prgrp, true);

	return ret;
}

static int mkdir_mondata_subdir_alldom(struct kernfs_node *parent_kn,
				       struct resctrl_resource *r,
				       struct resctrl_group *prgrp)
{
	struct rdt_domain *dom;
	int ret;

	list_for_each_entry(dom, &r->domains, list) {
		ret = mkdir_mondata_subdir(parent_kn, dom, r, prgrp);
		if (ret)
			return ret;
	}

	return 0;
}

int
mongroup_create_dir(struct kernfs_node *parent_kn, struct resctrl_group *prgrp,
		    char *name, struct kernfs_node **dest_kn)
{
	struct kernfs_node *kn;
	int ret;

	/* create the directory */
	kn = kernfs_create_dir(parent_kn, name, parent_kn->mode, prgrp);
	if (IS_ERR(kn)) {
		pr_info("%s: create dir %s, error\n", __func__, name);
		return PTR_ERR(kn);
	}

	if (dest_kn)
		*dest_kn = kn;

	/*
	 * This extra ref will be put in kernfs_remove() and guarantees
	 * that @rdtgrp->kn is always accessible.
	 */
	kernfs_get(kn);

	ret = resctrl_group_kn_set_ugid(kn);
	if (ret)
		goto out_destroy;

	kernfs_activate(kn);

	return 0;

out_destroy:
	kernfs_remove(kn);
	return ret;
}


/*
 * This creates a directory mon_data which contains the monitored data.
 *
 * mon_data has one directory for each domain whic are named
 * in the format mon_<domain_name>_<domain_id>. For ex: A mon_data
 * with L3 domain looks as below:
 * ./mon_data:
 * mon_L3_00
 * mon_L3_01
 * mon_L3_02
 * ...
 *
 * Each domain directory has one file per event:
 * ./mon_L3_00/:
 * llc_occupancy
 *
 */
int mkdir_mondata_all(struct kernfs_node *parent_kn,
			     struct resctrl_group *prgrp,
			     struct kernfs_node **dest_kn)
{
	struct resctrl_resource *r;
	struct kernfs_node *kn;
	int ret;

	/*
	 * Create the mon_data directory first.
	 */
	ret = mongroup_create_dir(parent_kn, prgrp, "mon_data", &kn);
	if (ret)
		return ret;

	if (dest_kn)
		*dest_kn = kn;

	/*
	 * Create the subdirectories for each domain. Note that all events
	 * in a domain like L3 are grouped into a resource whose domain is L3
	 */
	for_each_resctrl_resource(r) {
		if (r->mon_enabled) {
			/* HHA does not support monitor by pmg */
			if ((prgrp->type == RDTMON_GROUP) &&
			    (r->rid == MPAM_RESOURCE_MC))
				continue;

			ret = mkdir_mondata_subdir_alldom(kn, r, prgrp);
			if (ret)
				goto out_destroy;
		}
	}

	kernfs_activate(kn);

	return 0;

out_destroy:
	kernfs_remove(kn);
	return ret;
}

int resctrl_mkdir_ctrlmon_mondata(struct kernfs_node *parent_kn,
				  struct resctrl_group *prgrp,
				  struct kernfs_node **dest_kn)
{
	int ret;

	/* disalbe monitor by default for mpam. */
	if (prgrp->type == RDTCTRL_GROUP)
		return 0;

	ret = alloc_mon();
	if (ret < 0) {
		rdt_last_cmd_puts("out of monitors\n");
		return ret;
	}
	prgrp->mon.mon = ret;

	ret = alloc_mon_id();
	if (ret < 0) {
		rdt_last_cmd_puts("out of PMGs\n");
		free_mon(prgrp->mon.mon);
		return ret;
	}

	prgrp->mon.rmid = ret;

	ret = mkdir_mondata_all(parent_kn, prgrp, dest_kn);
	if (ret) {
		rdt_last_cmd_puts("kernfs subdir error\n");
		free_mon(ret);
	}
	return ret;
}
