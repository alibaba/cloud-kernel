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
#include <asm/mpam.h>

#include "mpam_resource.h"
#include "mpam_internal.h"

/* schemata content list */
LIST_HEAD(resctrl_all_schema);

/* Init schemata content */
static int add_schema(enum resctrl_conf_type t, struct resctrl_resource *r)
{
	int ret = 0;
	char *suffix = "";
	struct resctrl_schema *s;
	struct raw_resctrl_resource *rr;
	struct resctrl_schema_ctrl *sc, *tmp;
	enum resctrl_ctrl_type type;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	s->res = r;
	s->conf_type = t;

	/*
	 * code and data is separated for resources LxCache but
	 * not for MB(Memory Bandwidth), it's necessary to set
	 * cdp_mc_both to let resctrl know operating the two closid/
	 * monitor simultaneously when configuring/monitoring.
	 */
	if (is_resctrl_cdp_enabled())
		s->cdp_mc_both = !r->cdp_enable;

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
		kfree(s);
		return -EINVAL;
	}

	WARN_ON_ONCE(strlen(r->name) + strlen(suffix) + 1 > RESCTRL_NAME_LEN);
	snprintf(s->name, sizeof(s->name), "%s%s", r->name, suffix);

	INIT_LIST_HEAD(&s->list);
	list_add_tail(&s->list, &resctrl_all_schema);

	/*
	 * Initialize extension ctrl type with MPAM capabilities,
	 * e.g. priority/hardlimit.
	 */
	rr = r->res;
	INIT_LIST_HEAD(&s->schema_ctrl_list);
	for_each_extend_ctrl_type(type) {
		struct resctrl_ctrl_feature *feature =
			&rr->ctrl_features[type];

		if (!rr->ctrl_features[type].enabled ||
			!rr->ctrl_features[type].max_wd)
			continue;

		sc = kzalloc(sizeof(*sc), GFP_KERNEL);
		if (!sc) {
			ret = -ENOMEM;
			goto err;
		}
		sc->ctrl_type = type;

		WARN_ON_ONCE(strlen(r->name) + strlen(suffix) +
			strlen(feature->ctrl_suffix) + 1 > RESCTRL_NAME_LEN);
		snprintf(sc->name, sizeof(sc->name), "%s%s%s", r->name,
			suffix, feature->ctrl_suffix);

		list_add_tail(&sc->list, &s->schema_ctrl_list);
	}

	return 0;

err:
	list_for_each_entry_safe(sc, tmp, &s->schema_ctrl_list, list) {
		list_del(&sc->list);
		kfree(sc);
	}
	list_del(&s->list);
	kfree(s);
	return ret;
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
	struct resctrl_schema_ctrl *sc, *sc_tmp;

	list_for_each_entry_safe(s, tmp, &resctrl_all_schema, list) {
		list_for_each_entry_safe(sc, sc_tmp, &s->schema_ctrl_list, list) {
			list_del(&sc->list);
			kfree(sc);
		}
		list_del(&s->list);
		kfree(s);
	}
}

static void
resctrl_dom_ctrl_config(bool cdp_both_ctrl, struct resctrl_resource *r,
			struct rdt_domain *dom, struct msr_param *para)
{
	struct raw_resctrl_resource *rr;

	rr = r->res;
	rr->msr_update(r, dom, para);

	if (cdp_both_ctrl) {
		resctrl_cdp_mpamid_map_val(para->closid->reqpartid, CDP_DATA,
			para->closid->reqpartid);
		rr->msr_update(r, dom, para);
	}
}

static void resctrl_group_update_domain_ctrls(struct rdtgroup *rdtgrp,
			struct resctrl_resource *r, struct rdt_domain *dom)
{
	int i;
	struct resctrl_staged_config *cfg;
	enum resctrl_ctrl_type type;
	struct sd_closid closid;
	struct list_head *head;
	struct rdtgroup *entry;
	struct msr_param para;
	bool update_on, cdp_both_ctrl;

	cfg = dom->staged_cfg;
	para.closid = &closid;

	for (i = 0; i < ARRAY_SIZE(dom->staged_cfg); i++) {
		if (!cfg[i].have_new_ctrl)
			continue;
		update_on = false;
		cdp_both_ctrl = cfg[i].cdp_both_ctrl;
		/*
		 * for ctrl group configuration, hw_closid of cfg[i] equals
		 * to rdtgrp->closid.intpartid.
		 */
		closid.intpartid = hw_closid_val(cfg[i].hw_closid);
		for_each_ctrl_type(type) {
			/* if ctrl group's config has changed, refresh it first. */
			if (dom->ctrl_val[closid.intpartid] != cfg[i].new_ctrl) {
				/*
				 * duplicate ctrl group's configuration indexed
				 * by intpartid from domain ctrl_val array.
				 */
				resctrl_cdp_mpamid_map_val(rdtgrp->closid.reqpartid,
						cfg[i].conf_type, closid.reqpartid);

				dom->ctrl_val[type][closid.intpartid] =
					cfg[i].new_ctrl[type];
				dom->have_new_ctrl = true;
				update_on = true;
			}
		}
		if (update_on)
			resctrl_dom_ctrl_config(cdp_both_ctrl, r, dom, &para);

		/*
		 * we should synchronize all child mon groups'
		 * configuration from this ctrl rdtgrp
		 */
		head = &rdtgrp->mon.crdtgrp_list;
		list_for_each_entry(entry, head, mon.crdtgrp_list) {
			resctrl_cdp_mpamid_map_val(entry->closid.reqpartid,
					cfg[i].conf_type, closid.reqpartid);
			resctrl_dom_ctrl_config(cdp_both_ctrl, r, dom, &para);
		}
	}
}

static int resctrl_group_update_domains(struct rdtgroup *rdtgrp,
			struct resctrl_resource *r)
{
	struct rdt_domain *d;

	list_for_each_entry(d, &r->domains, list)
		resctrl_group_update_domain_ctrls(rdtgrp, r, d);

	return 0;
}

/*
 * For each domain in this resource we expect to find a series of:
 * id=mask
 * separated by ";". The "id" is in decimal, and must match one of
 * the "id"s for this resource.
 */
static int
parse_line(char *line, struct resctrl_resource *r,
		enum resctrl_conf_type conf_type,
		enum resctrl_ctrl_type ctrl_type, u32 closid)
{
	struct raw_resctrl_resource *rr = r->res;
	char *dom = NULL;
	char *id;
	struct rdt_domain *d;
	unsigned long dom_id;
	hw_closid_t hw_closid;

	if (!rr->ctrl_features[ctrl_type].enabled)
		return -EINVAL;

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
			resctrl_cdp_mpamid_map(closid, conf_type, hw_closid);
			if (rr->parse_ctrlval(dom, r,
				&d->staged_cfg[conf_type], ctrl_type))
				return -EINVAL;
			d->staged_cfg[conf_type].hw_closid = hw_closid;
			d->staged_cfg[conf_type].conf_type = conf_type;
			d->staged_cfg[conf_type].ctrl_type = ctrl_type;
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
	struct resctrl_schema_ctrl *sc;

	list_for_each_entry(s, &resctrl_all_schema, list) {
		r = s->res;

		if (!r)
			continue;

		if (r->alloc_enabled) {
			if (closid >= mpam_sysprops_num_partid())
				continue;
			t = conf_name_to_conf_type(s->name);
			if (!strcmp(resname, s->name))
				return parse_line(tok, r, t,
					SCHEMA_COMM, closid);

			list_for_each_entry(sc, &s->schema_ctrl_list, list) {
				if (!strcmp(resname, sc->name))
					return parse_line(tok, r, t,
						    sc->ctrl_type,
						    closid);
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

	closid = rdtgrp->closid.intpartid;

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

	ret = resctrl_update_groups_config(rdtgrp);
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
		char *schema_name, enum resctrl_ctrl_type type,
		struct sd_closid *closid)
{
	struct raw_resctrl_resource *rr = r->res;
	struct rdt_domain *dom;
	struct msr_param para;
	bool sep = false;
	bool rg = false;
	bool prev_auto_fill = false;
	u32 reg_val;

	if (!rr->ctrl_features[type].enabled)
		return;

	para.closid = closid;
	para.type = type;

	if (r->dom_num > RESCTRL_SHOW_DOM_MAX_NUM)
		rg = true;

	seq_printf(s, "%*s:", max_name_width, schema_name);
	list_for_each_entry(dom, &r->domains, list) {
		reg_val = rr->msr_read(r, dom, &para);

		if (reg_val == rr->ctrl_features[SCHEMA_COMM].default_ctrl &&
			rg && prev_auto_fill == true)
			continue;

		if (sep)
			seq_puts(s, ";");
		if (rg && reg_val == rr->ctrl_features[SCHEMA_COMM].default_ctrl) {
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
	struct sd_closid closid;
	struct resctrl_schema_ctrl *sc;

	rdtgrp = resctrl_group_kn_lock_live(of->kn);
	if (rdtgrp) {
		list_for_each_entry(rs, &resctrl_all_schema, list) {
			r = rs->res;
			if (!r)
				continue;
			if (r->alloc_enabled) {
				resctrl_cdp_mpamid_map_val(rdtgrp->closid.intpartid,
					rs->conf_type, closid.intpartid);

				resctrl_cdp_mpamid_map_val(rdtgrp->closid.reqpartid,
					rs->conf_type, closid.reqpartid);

				show_doms(s, r, rs->name, SCHEMA_COMM, &closid);
				list_for_each_entry(sc, &rs->schema_ctrl_list, list) {
					show_doms(s, r, sc->name, sc->ctrl_type, &closid);
				}
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

static u64 resctrl_dom_mon_data(struct resctrl_resource *r,
		struct rdt_domain *d, void *md_priv)
{
	u64 ret;
	union mon_data_bits md;
	struct raw_resctrl_resource *rr;

	md.priv = md_priv;
	rr = r->res;
	ret = rr->mon_read(d, md.priv);
	if (md.u.cdp_both_mon) {
		resctrl_cdp_mpamid_map_val(md.u.partid, CDP_DATA, md.u.partid);
		ret += rr->mon_read(d, md.priv);
	}

	return ret;
}

int resctrl_group_mondata_show(struct seq_file *m, void *arg)
{
	struct kernfs_open_file *of = m->private;
	struct rdtgroup *rdtgrp;
	struct rdt_domain *d;
	struct resctrl_resource *r;
	union mon_data_bits md;
	int ret = 0;
	char *resname = get_resource_name(kernfs_node_name(of));
	u64 usage;
	int pmg;

	if (!resname)
		return -ENOMEM;

	rdtgrp = resctrl_group_kn_lock_live(of->kn);
	if (!rdtgrp) {
		ret = -ENOENT;
		goto out;
	}

	md.priv = of->kn->priv;

	r = mpam_resctrl_get_resource(md.u.rid);

	/* show monitor data */
	d = mpam_find_domain(r, md.u.domid, NULL);
	if (IS_ERR_OR_NULL(d)) {
		pr_warn("Could't find domain id %d\n", md.u.domid);
		ret = -ENOENT;
		goto out;
	}

	usage = resctrl_dom_mon_data(r, d, md.priv);

	/*
	 * if this rdtgroup is ctrlmon group, also collect it's
	 * mon groups' monitor data.
	 */
	if (rdtgrp->type == RDTCTRL_GROUP) {
		struct list_head *head;
		struct rdtgroup *entry;
		hw_closid_t hw_closid;
		enum resctrl_conf_type type = CDP_CODE;

		resctrl_cdp_mpamid_map(rdtgrp->closid.reqpartid,
			CDP_CODE, hw_closid);
		/* CDP_CODE share the same closid with CDP_BOTH */
		if (md.u.partid != hw_closid_val(hw_closid))
			type = CDP_DATA;

		head = &rdtgrp->mon.crdtgrp_list;
		list_for_each_entry(entry, head, mon.crdtgrp_list) {
			resctrl_cdp_mpamid_map_val(entry->closid.reqpartid,
				type, md.u.partid);

			ret = mpam_rmid_to_partid_pmg(entry->mon.rmid,
				NULL, &pmg);
			if (ret)
				return ret;

			md.u.pmg = pmg;
			resctrl_cdp_mpamid_map_val(get_rmid_mon(entry->mon.rmid,
				r->rid), type, md.u.mon);

			usage += resctrl_dom_mon_data(r, d, md.priv);
		}
	}

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

static int resctrl_mkdir_mondata_dom(struct kernfs_node *parent_kn,
			struct rdt_domain *d, struct resctrl_schema *s,
			struct resctrl_group *prgrp)

{
	struct resctrl_resource *r;
	struct raw_resctrl_resource *rr;
	union mon_data_bits md;
	struct kernfs_node *kn;
	char name[32];
	int ret = 0;
	int pmg;

	r = s->res;
	rr = r->res;

	md.u.rid = r->rid;
	md.u.domid = d->id;
	/* monitoring use reqpartid (reqpartid) */
	resctrl_cdp_mpamid_map_val(prgrp->closid.reqpartid, s->conf_type,
			md.u.partid);
	resctrl_cdp_mpamid_map_val(get_rmid_mon(prgrp->mon.rmid, r->rid),
			s->conf_type, md.u.mon);

	ret = mpam_rmid_to_partid_pmg(prgrp->mon.rmid, NULL, &pmg);
	if (ret)
		return ret;
	md.u.pmg = pmg;

	md.u.cdp_both_mon = s->cdp_mc_both;

	snprintf(name, sizeof(name), "mon_%s_%02d", s->name, d->id);
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
	rr->mon_write(d, md.priv);

	return ret;
}

static int resctrl_mkdir_mondata_subdir_alldom(struct kernfs_node *parent_kn,
			struct resctrl_schema *s, struct resctrl_group *prgrp)
{
	struct resctrl_resource *r;
	struct rdt_domain *dom;
	int ret;

	r = s->res;
	list_for_each_entry(dom, &r->domains, list) {
		ret = resctrl_mkdir_mondata_dom(parent_kn, dom, s, prgrp);
		if (ret)
			return ret;
	}

	return 0;
}

int resctrl_mkdir_mondata_all_subdir(struct kernfs_node *parent_kn,
			struct resctrl_group *prgrp)
{
	struct resctrl_schema *s;
	struct resctrl_resource *r;
	int ret;

	/*
	 * Create the subdirectories for each domain. Note that all events
	 * in a domain like L3 are grouped into a resource whose domain is L3
	 */
	list_for_each_entry(s, &resctrl_all_schema, list) {
		r = s->res;

		if (r->mon_enabled) {
			struct raw_resctrl_resource *rr;

			rr = r->res;

			ret = resctrl_mkdir_mondata_subdir_alldom(parent_kn,
					s, prgrp);
			if (ret)
				break;
		}
	}

	return ret;
}

static int resctrl_group_mkdir_info_resdir(struct resctrl_resource *r,
		char *name,unsigned long fflags, struct kernfs_node *kn_info)
{
	struct kernfs_node *kn_subdir;
	int ret;

	kn_subdir = kernfs_create_dir(kn_info, name,
				      kn_info->mode, r);
	if (IS_ERR(kn_subdir))
		return PTR_ERR(kn_subdir);

	kernfs_get(kn_subdir);
	ret = resctrl_group_kn_set_ugid(kn_subdir);
	if (ret)
		return ret;

	ret = resctrl_group_add_files(kn_subdir, fflags);
	if (!ret)
		kernfs_activate(kn_subdir);

	return ret;
}

int resctrl_group_create_info_dir(struct kernfs_node *parent_kn,
		struct kernfs_node **kn_info)
{
	struct resctrl_schema *s;
	struct resctrl_resource *r;
	struct raw_resctrl_resource *rr;
	unsigned long fflags;
	char name[32];
	int ret;

	/* create the directory */
	*kn_info = kernfs_create_dir(parent_kn, "info", parent_kn->mode, NULL);
	if (IS_ERR(*kn_info))
		return PTR_ERR(*kn_info);
	kernfs_get(*kn_info);

	ret = resctrl_group_add_files(*kn_info, RF_TOP_INFO);
	if (ret)
		goto out_destroy;

	list_for_each_entry(s, &resctrl_all_schema, list) {
		r = s->res;
		if (!r)
			continue;
		rr = r->res;
		if (r->alloc_enabled) {
			fflags =  rr->fflags | RF_CTRL_INFO;
			ret = resctrl_group_mkdir_info_resdir(r, s->name,
				fflags, *kn_info);
			if (ret)
				goto out_destroy;
		}
	}

	list_for_each_entry(s, &resctrl_all_schema, list) {
		r = s->res;
		if (!r)
			continue;
		rr = r->res;
		if (r->mon_enabled) {
			fflags =  rr->fflags | RF_MON_INFO;
			snprintf(name, sizeof(name), "%s_MON", s->name);
			ret = resctrl_group_mkdir_info_resdir(r, name,
				fflags, *kn_info);
			if (ret)
				goto out_destroy;
		}
	}

	/*
	 m This extra ref will be put in kernfs_remove() and guarantees
	 * that @rdtgrp->kn is always accessible.
	 */
	kernfs_get(*kn_info);

	ret = resctrl_group_kn_set_ugid(*kn_info);
	if (ret)
		goto out_destroy;

	kernfs_activate(*kn_info);

	return 0;

out_destroy:
	kernfs_remove(*kn_info);
	return ret;
}



/* Initialize MBA resource with default values. */
static void rdtgroup_init_mba(struct resctrl_schema *s, u32 closid)
{
	struct resctrl_staged_config *cfg;
	struct resctrl_resource *r;
	struct raw_resctrl_resource *rr;
	struct rdt_domain *d;
	enum resctrl_ctrl_type t;

	r = s->res;
	if (WARN_ON(!r))
		return;
	rr = r->res;

	list_for_each_entry(d, &s->res->domains, list) {
		cfg = &d->staged_cfg[CDP_BOTH];
		cfg->cdp_both_ctrl = s->cdp_mc_both;
		cfg->new_ctrl[SCHEMA_COMM] = rr->ctrl_features[SCHEMA_COMM].default_ctrl;
		resctrl_cdp_mpamid_map(closid, CDP_BOTH, cfg->hw_closid);
		cfg->have_new_ctrl = true;
		/* Set extension ctrl default value, e.g. priority/hardlimit */
		for_each_extend_ctrl_type(t) {
			cfg->new_ctrl[t] = rr->ctrl_features[t].default_ctrl;
		}
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
	enum resctrl_conf_type conf_type = s->conf_type;
	enum resctrl_ctrl_type ctrl_type;
	struct rdt_domain *d;
	struct resctrl_resource *r;
	struct raw_resctrl_resource *rr;
	u32 used_b = 0;
	u32 unused_b = 0;
	unsigned long tmp_cbm;

	r = s->res;
	if (WARN_ON(!r))
		return -EINVAL;
	rr = r->res;

	list_for_each_entry(d, &s->res->domains, list) {
		cfg = &d->staged_cfg[conf_type];
		cfg->cdp_both_ctrl = s->cdp_mc_both;
		cfg->have_new_ctrl = false;
		cfg->new_ctrl[SCHEMA_COMM] = r->cache.shareable_bits;
		used_b = r->cache.shareable_bits;

		unused_b = used_b ^ (BIT_MASK(r->cache.cbm_len) - 1);
		unused_b &= BIT_MASK(r->cache.cbm_len) - 1;
		cfg->new_ctrl[SCHEMA_COMM] |= unused_b;

		/* Ensure cbm does not access out-of-bound */
		tmp_cbm = cfg->new_ctrl[SCHEMA_COMM];
		if (bitmap_weight(&tmp_cbm, r->cache.cbm_len) <
			r->cache.min_cbm_bits) {
			rdt_last_cmd_printf("No space on %s:%d\n",
				r->name, d->id);
			return -ENOSPC;
		}

		resctrl_cdp_mpamid_map(closid, conf_type, cfg->hw_closid);
		cfg->have_new_ctrl = true;

		/*
		 * Set extension ctrl default value, e.g. priority/hardlimit
		 * with MPAM capabilities.
		 */
		for_each_extend_ctrl_type(ctrl_type) {
			cfg->new_ctrl[ctrl_type] =
				rr->ctrl_features[ctrl_type].default_ctrl;
		}
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
			rdtgroup_init_mba(s, rdtgrp->closid.intpartid);
		} else {
			ret = rdtgroup_init_cat(s, rdtgrp->closid.intpartid);
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

int resctrl_update_groups_config(struct rdtgroup *rdtgrp)
{
	int ret = 0;
	struct resctrl_resource *r;
	struct mpam_resctrl_res *res;

	for_each_supported_resctrl_exports(res) {
		r = &res->resctrl_res;
		if (r->alloc_enabled) {
			ret = resctrl_group_update_domains(rdtgrp, r);
			if (ret)
				break;
		}
	}

	return ret;
}
