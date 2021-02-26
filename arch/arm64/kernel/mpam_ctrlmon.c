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

/*
 * [FIXME]
 * use pmg as monitor id
 * just use match_pardid only.
 */
static u64 mbwu_read(struct rdt_domain *d, struct rdtgroup *g)
{
	u32 pmg = g->mon.rmid;

	mpam_writel(pmg, d->base + MSMON_CFG_MON_SEL);
	return mpam_readl(d->base + MSMON_MBWU);
}

static u64 csu_read(struct rdt_domain *d, struct rdtgroup *g)
{
	u32 pmg = g->mon.rmid;

	mpam_writel(pmg, d->base + MSMON_CFG_MON_SEL);
	return mpam_readl(d->base + MSMON_CSU);
}

int resctrl_group_mondata_show(struct seq_file *m, void *arg)
{
	struct kernfs_open_file *of = m->private;
	struct rdtgroup *rdtgrp;
	struct rdt_domain *d;
	int ret = 0;

	rdtgrp = resctrl_group_kn_lock_live(of->kn);

	d = of->kn->priv;

	/* for debug */
	seq_printf(m, "group: partid: %d, pmg: %d",
		   rdtgrp->closid, rdtgrp->mon.rmid);

	/* show monitor data */

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

#if 0	/* used at remove cpu*/
/*
 * Remove all subdirectories of mon_data of ctrl_mon groups
 * and monitor groups with given domain id.
 */
void rmdir_mondata_subdir_allrdtgrp(struct resctrl_resource *r, unsigned int dom_id)
{
	struct resctrl_group *prgrp, *crgrp;
	char name[32];

	if (!r->mon_enabled)
		return;

	list_for_each_entry(prgrp, &resctrl_all_groups, resctrl_group_list) {
		sprintf(name, "mon_%s_%02d", r->name, dom_id);
		kernfs_remove_by_name(prgrp->mon.mon_data_kn, name);

		list_for_each_entry(crgrp, &prgrp->mon.crdtgrp_list, mon.crdtgrp_list)
			kernfs_remove_by_name(crgrp->mon.mon_data_kn, name);
	}
}
#endif

static int mkdir_mondata_subdir(struct kernfs_node *parent_kn,
				struct rdt_domain *d,
				struct resctrl_resource *r, struct resctrl_group *prgrp)
{
#if 1
	struct kernfs_node *kn;
	char name[32];
	int ret;

	sprintf(name, "mon_%s_%02d", r->name, d->id);

	kn = __kernfs_create_file(parent_kn, name, 0444,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, 0,
				  &kf_mondata_ops, d, NULL, NULL);
	if (IS_ERR(kn))
		return PTR_ERR(kn);

	ret = resctrl_group_kn_set_ugid(kn);
	if (ret) {
		kernfs_remove(kn);
		return ret;
	}

	return ret;
#if 0
	/* create the directory */
	kn = kernfs_create_dir(parent_kn, name, parent_kn->mode, prgrp);
	if (IS_ERR(kn))
		return PTR_ERR(kn);

	/*
	 * This extra ref will be put in kernfs_remove() and guarantees
	 * that kn is always accessible.
	 */
	kernfs_get(kn);
	ret = resctrl_group_kn_set_ugid(kn);
	if (ret)
		goto out_destroy;
#endif


#if 0
	ret = mon_addfile(kn, mevt->name, d);
	if (ret)
		goto out_destroy;

	kernfs_activate(kn);
	return 0;

out_destroy:
	kernfs_remove(kn);
	return ret;
#endif
#else
	return 0;
#endif
}

/*
 * Add all subdirectories of mon_data for "ctrl_mon" groups
 * and "monitor" groups with given domain id.
 */
void mkdir_mondata_subdir_allrdtgrp(struct resctrl_resource *r,
				    struct rdt_domain *d)
{
	struct kernfs_node *parent_kn;
	struct resctrl_group *prgrp, *crgrp;
	struct list_head *head;

	if (!r->mon_enabled)
		return;

	list_for_each_entry(prgrp, &resctrl_all_groups, resctrl_group_list) {
		parent_kn = prgrp->mon.mon_data_kn;
		mkdir_mondata_subdir(parent_kn, d, r, prgrp);

		head = &prgrp->mon.crdtgrp_list;
		list_for_each_entry(crgrp, head, mon.crdtgrp_list) {
			parent_kn = crgrp->mon.mon_data_kn;
			mkdir_mondata_subdir(parent_kn, d, r, crgrp);
		}
	}
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
	if (IS_ERR(kn))
		return PTR_ERR(kn);

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
	ret = mongroup_create_dir(parent_kn, NULL, "mon_data", &kn);
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
