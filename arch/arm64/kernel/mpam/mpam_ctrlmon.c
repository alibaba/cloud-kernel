// SPDX-License-Identifier: GPL-2.0+
/*
 * Common code for ARM v8 MPAM
 *  - allocation and monitor management
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

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/kernfs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/resctrlfs.h>

#include <asm/mpam.h>
#include <asm/mpam_resource.h>
#include <asm/resctrl.h>
#include "mpam_internal.h"

/* schemata content list */
LIST_HEAD(resctrl_all_schema);

/* Init schemata content */
static int add_schema(enum resctrl_conf_type t, struct resctrl_resource *r)
{
	char *suffix = "";
	struct resctrl_schema *s;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	s->res = r;
	s->conf_type = t;

	switch (t) {
	case CDP_CODE:
		suffix = "CODE";
		break;
	case CDP_DATA:
		suffix = "DATA";
		break;
	case CDP_BOTH:
		suffix = "";
		break;
	default:
		return -EINVAL;
	}

	WARN_ON_ONCE(strlen(r->name) + strlen(suffix) + 1 > RESCTRL_NAME_LEN);
	snprintf(s->name, sizeof(s->name), "%s%s", r->name, suffix);

	INIT_LIST_HEAD(&s->list);
	list_add_tail(&s->list, &resctrl_all_schema);

	return 0;
}

int schemata_list_init(void)
{
	int ret;
	struct mpam_resctrl_res *res;
	struct resctrl_resource *r;

	for_each_supported_resctrl_exports(res) {
		r = &res->resctrl_res;
		if (!r || !r->alloc_capable)
			continue;

		if (r->cdp_enable) {
			ret = add_schema(CDP_CODE, r);
			ret |= add_schema(CDP_DATA, r);
		} else {
			ret = add_schema(CDP_BOTH, r);
		}
		if (ret)
			break;
	}

	return ret;
}

/*
 * During resctrl_kill_sb(), the mba_sc state is reset before
 * schemata_list_destroy() is called: unconditionally try to free the
 * array.
 */
void schemata_list_destroy(void)
{
	struct resctrl_schema *s, *tmp;

	list_for_each_entry_safe(s, tmp, &resctrl_all_schema, list) {
		list_del(&s->list);
		kfree(s);
	}
}

static int resctrl_group_update_domains(struct rdtgroup *rdtgrp,
			struct resctrl_resource *r)
{
	int i;
	u32 partid;
	struct rdt_domain *d;
	struct raw_resctrl_resource *rr;
	struct resctrl_staged_config *cfg;

	rr = r->res;
	list_for_each_entry(d, &r->domains, list) {
		cfg = d->staged_cfg;
		for (i = 0; i < ARRAY_SIZE(d->staged_cfg); i++) {
			if (!cfg[i].have_new_ctrl)
				continue;

			partid = hw_closid_val(cfg[i].hw_closid);
			/* apply cfg */
			if (d->ctrl_val[partid] == cfg[i].new_ctrl)
				continue;

			d->ctrl_val[partid] = cfg[i].new_ctrl;
			d->have_new_ctrl = true;

			rr->msr_update(r, d, NULL, partid);
		}
	}

	return 0;
}

/*
 * For each domain in this resource we expect to find a series of:
 * id=mask
 * separated by ";". The "id" is in decimal, and must match one of
 * the "id"s for this resource.
 */
static int parse_line(char *line, struct resctrl_resource *r,
			enum resctrl_conf_type t, u32 closid)
{
	struct raw_resctrl_resource *rr = r->res;
	char *dom = NULL;
	char *id;
	struct rdt_domain *d;
	unsigned long dom_id;
	hw_closid_t hw_closid;

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
			resctrl_cdp_map(clos, closid, t, hw_closid);
			if (rr->parse_ctrlval(dom, rr, &d->staged_cfg[t], hw_closid))
				return -EINVAL;
			goto next;
		}
	}
	return -EINVAL;
}

static int
resctrl_group_parse_schema_resource(char *resname, char *tok, u32 closid)
{
	struct resctrl_resource *r;
	struct resctrl_schema *s;
	enum resctrl_conf_type t;

	list_for_each_entry(s, &resctrl_all_schema, list) {
		r = s->res;

		if (!r)
			continue;

		if (r->alloc_enabled) {
			if (!strcmp(resname, s->name) &&
				closid < mpam_sysprops_num_partid()) {
				t = conf_name_to_conf_type(s->name);
				return parse_line(tok, r, t, closid);
			}
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
	struct mpam_resctrl_res *res;
	enum resctrl_conf_type conf_type;
	struct resctrl_staged_config *cfg;
	char *tok, *resname;
	u32 closid;
	int ret = 0;

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

	for_each_supported_resctrl_exports(res) {
		r = &res->resctrl_res;

		if (r->alloc_enabled) {
			list_for_each_entry(dom, &r->domains, list) {
				dom->have_new_ctrl = false;
				for_each_conf_type(conf_type) {
					cfg = &dom->staged_cfg[conf_type];
					cfg->have_new_ctrl = false;
				}
			}
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
		ret = resctrl_group_parse_schema_resource(resname, tok, closid);
		if (ret)
			goto out;
	}

	for_each_supported_resctrl_exports(res) {
		r = &res->resctrl_res;
		if (r->alloc_enabled) {
			ret = resctrl_group_update_domains(rdtgrp, r);
			if (ret)
				goto out;
		}
	}

out:
	resctrl_group_kn_unlock(of->kn);
	return ret ?: nbytes;
}

/**
 * MPAM resources such as L2 may have too many domains for arm64,
 * at this time we should rearrange this display for brevity and
 * harmonious interaction.
 *
 * Before rearrangement: L2:0=ff;1=ff;2=fc;3=ff;4=f;....;255=ff
 * After rearrangement:  L2:S;2=fc;S;4=f;S
 * Those continuous fully sharable domains will be combined into
 * a single "S" simply.
 */
static void show_doms(struct seq_file *s, struct resctrl_resource *r,
		char *schema_name, int partid)
{
	struct raw_resctrl_resource *rr = r->res;
	struct rdt_domain *dom;
	bool sep = false;
	bool rg = false;
	bool prev_auto_fill = false;
	u32 reg_val;

	if (r->dom_num > RESCTRL_SHOW_DOM_MAX_NUM)
		rg = true;

	seq_printf(s, "%*s:", max_name_width, schema_name);
	list_for_each_entry(dom, &r->domains, list) {
		reg_val = rr->msr_read(dom, partid);

		if (rg && reg_val == r->default_ctrl &&
				prev_auto_fill == true)
			continue;

		if (sep)
			seq_puts(s, ";");
		if (rg && reg_val == r->default_ctrl) {
			prev_auto_fill = true;
			seq_puts(s, "S");
		} else {
			seq_printf(s, rr->format_str, dom->id,
				max_data_width, reg_val);
		}
		sep = true;
	}
	seq_puts(s, "\n");
}

int resctrl_group_schemata_show(struct kernfs_open_file *of,
			struct seq_file *s, void *v)
{
	struct rdtgroup *rdtgrp;
	struct resctrl_resource *r;
	struct resctrl_schema *rs;
	int ret = 0;
	hw_closid_t hw_closid;
	u32 partid;

	rdtgrp = resctrl_group_kn_lock_live(of->kn);
	if (rdtgrp) {
		list_for_each_entry(rs, &resctrl_all_schema, list) {
			r = rs->res;
			if (!r)
				continue;
			if (r->alloc_enabled) {
				resctrl_cdp_map(clos, rdtgrp->closid,
					rs->conf_type, hw_closid);
				partid = hw_closid_val(hw_closid);
				if (partid < mpam_sysprops_num_partid())
					show_doms(s, r, rs->name, partid);
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

	r = mpam_resctrl_get_resource(md.u.rid);
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

	/* Could we remove the MATCH_* param ? */
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
	struct mpam_resctrl_res *res;
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
	for_each_supported_resctrl_exports(res) {
		r = &res->resctrl_res;

		if (r->mon_enabled) {
			/* HHA does not support monitor by pmg */
			if ((prgrp->type == RDTMON_GROUP) &&
			    (r->rid == RDT_RESOURCE_MC))
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

/* Initialize MBA resource with default values. */
static void rdtgroup_init_mba(struct resctrl_resource *r, u32 closid)
{
	struct resctrl_staged_config *cfg;
	struct rdt_domain *d;

	list_for_each_entry(d, &r->domains, list) {
		cfg = &d->staged_cfg[CDP_BOTH];
		cfg->new_ctrl = r->default_ctrl;
		resctrl_cdp_map(clos, closid, CDP_BOTH, cfg->hw_closid);
		cfg->have_new_ctrl = true;
	}
}

/*
 * Initialize cache resources with default values.
 *
 * A new resctrl group is being created on an allocation capable (CAT)
 * supporting system. Set this group up to start off with all usable
 * allocations.
 *
 * If there are no more shareable bits available on any domain then
 * the entire allocation will fail.
 */
static int rdtgroup_init_cat(struct resctrl_schema *s, u32 closid)
{
	struct resctrl_staged_config *cfg;
	enum resctrl_conf_type t = s->conf_type;
	struct rdt_domain *d;
	struct resctrl_resource *r;
	u32 used_b = 0;
	u32 unused_b = 0;
	unsigned long tmp_cbm;

	r = s->res;
	if (WARN_ON(!r))
		return -EINVAL;

	list_for_each_entry(d, &s->res->domains, list) {
		cfg = &d->staged_cfg[t];
		cfg->have_new_ctrl = false;
		cfg->new_ctrl = r->cache.shareable_bits;
		used_b = r->cache.shareable_bits;

		unused_b = used_b ^ (BIT_MASK(r->cache.cbm_len) - 1);
		unused_b &= BIT_MASK(r->cache.cbm_len) - 1;
		cfg->new_ctrl |= unused_b;

		/* Ensure cbm does not access out-of-bound */
		tmp_cbm = cfg->new_ctrl;
		if (bitmap_weight(&tmp_cbm, r->cache.cbm_len) <
			r->cache.min_cbm_bits) {
			rdt_last_cmd_printf("No space on %s:%d\n",
				r->name, d->id);
			return -ENOSPC;
		}

		resctrl_cdp_map(clos, closid, t, cfg->hw_closid);
		cfg->have_new_ctrl = true;
	}

	return 0;
}

/* Initialize the resctrl group's allocations. */
int resctrl_group_init_alloc(struct rdtgroup *rdtgrp)
{
	struct resctrl_schema *s;
	struct resctrl_resource *r;
	int ret;

	list_for_each_entry(s, &resctrl_all_schema, list) {
		r = s->res;
		if (r->rid == RDT_RESOURCE_MC) {
			rdtgroup_init_mba(r, rdtgrp->closid);
		} else {
			ret = rdtgroup_init_cat(s, rdtgrp->closid);
			if (ret < 0)
				return ret;
		}

		ret = resctrl_group_update_domains(rdtgrp, r);
		if (ret < 0) {
			rdt_last_cmd_puts("Failed to initialize allocations\n");
			return ret;
		}
	}

	return 0;
}
