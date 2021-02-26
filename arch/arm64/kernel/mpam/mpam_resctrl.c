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

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/slab.h>
#include <linux/err.h>
#include <linux/cacheinfo.h>
#include <linux/cpuhotplug.h>
#include <linux/task_work.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/arm_mpam.h>

#include <asm/mpam_sched.h>
#include <asm/mpam_resource.h>
#include <asm/io.h>

#include "mpam_device.h"
#include "mpam_internal.h"

/* Mutex to protect rdtgroup access. */
DEFINE_MUTEX(resctrl_group_mutex);

/*
 * The cached intel_pqr_state is strictly per CPU and can never be
 * updated from a remote CPU. Functions which modify the state
 * are called with interrupts disabled and no preemption, which
 * is sufficient for the protection.
 */
DEFINE_PER_CPU(struct intel_pqr_state, pqr_state);

/*
 * Used to store the max resource name width and max resource data width
 * to display the schemata in a tabular format
 */
int max_name_width, max_data_width;

/*
 * Global boolean for rdt_alloc which is true if any
 * resource allocation is enabled.
 */
bool rdt_alloc_capable;

/*
 * Indicate the max number of monitor supported.
 */
static u32 max_mon_num;

/*
 * Indicate if had mount cdpl2/cdpl3 option.
 */
static bool resctrl_cdp_enabled;

/*
 * Hi1620 2P Base Address Map
 *
 * AFF2 | NODE | DIE   | Base Address
 * ------------------------------------
 *   01 |    0 | P0 TB | 0x000098xxxxxx
 *   03 |    1 | P0 TA | 0x000090xxxxxx
 *   05 |    2 | P1 TB | 0x200098xxxxxx
 *   07 |    3 | P2 TA | 0x200090xxxxxx
 *
 *   AFF2: MPIDR.AFF2
 */

int mpam_resctrl_set_default_cpu(unsigned int cpu)
{
    /* The cpu is set in default rdtgroup after online. */
	cpumask_set_cpu(cpu, &resctrl_group_default.cpu_mask);
	return 0;
}

void mpam_resctrl_clear_default_cpu(unsigned int cpu)
{
	/* The cpu is set in default rdtgroup after online. */
	cpumask_clear_cpu(cpu, &resctrl_group_default.cpu_mask);
}

bool is_resctrl_cdp_enabled(void)
{
	return !!resctrl_cdp_enabled;
}

static void
resctrl_ctrl_extend_bits_set(u32 *bitmap, enum resctrl_ctrl_type type)
{
	*bitmap |= BIT(type);
}

static void resctrl_ctrl_extend_bits_clear(u32 *bitmap)
{
	*bitmap = 0;
}

bool resctrl_ctrl_extend_bits_match(u32 bitmap, enum resctrl_ctrl_type type)
{
	return bitmap & BIT(type);
}

static void
mpam_resctrl_update_component_cfg(struct resctrl_resource *r,
	struct rdt_domain *d, struct sd_closid *closid);

static void
common_wrmsr(struct resctrl_resource *r, struct rdt_domain *d,
	struct msr_param *para);

static u64 cache_rdmsr(struct rdt_domain *d, struct msr_param *para);
static u64 mbw_rdmsr(struct rdt_domain *d, struct msr_param *para);

static u64 cache_rdmon(struct rdt_domain *d, void *md_priv);
static u64 mbw_rdmon(struct rdt_domain *d, void *md_priv);

static int common_wrmon(struct rdt_domain *d, void *md_priv);

static int parse_cache(char *buf, struct raw_resctrl_resource *r,
	struct resctrl_staged_config *cfg, enum resctrl_ctrl_type ctrl_type);
static int parse_bw(char *buf, struct raw_resctrl_resource *r,
	struct resctrl_staged_config *cfg, enum resctrl_ctrl_type ctrl_type);

struct raw_resctrl_resource raw_resctrl_resources_all[] = {
	[RDT_RESOURCE_L3] = {
		.msr_update     = common_wrmsr,
		.msr_read       = cache_rdmsr,
		.parse_ctrlval  = parse_cache,
		.format_str     = "%d=%0*x",
		.mon_read       = cache_rdmon,
		.mon_write      = common_wrmon,
	},
	[RDT_RESOURCE_L2] = {
		.msr_update     = common_wrmsr,
		.msr_read       = cache_rdmsr,
		.parse_ctrlval  = parse_cache,
		.format_str     = "%d=%0*x",
		.mon_read       = cache_rdmon,
		.mon_write      = common_wrmon,
	},
	[RDT_RESOURCE_MC] = {
		.msr_update     = common_wrmsr,
		.msr_read       = mbw_rdmsr,
		.parse_ctrlval  = parse_bw,
		.format_str     = "%d=%0*d",
		.mon_read       = mbw_rdmon,
		.mon_write      = common_wrmon,
	},
};

struct raw_resctrl_resource *
mpam_get_raw_resctrl_resource(enum resctrl_resource_level level)
{
	if (level >= RDT_NUM_RESOURCES)
		return NULL;

	return &raw_resctrl_resources_all[level];
}

/*
 * Read one cache schema row. Check that it is valid for the current
 * resource type.
 */
static int
parse_cache(char *buf, struct raw_resctrl_resource *r,
		struct resctrl_staged_config *cfg,
		enum resctrl_ctrl_type type)
{
	unsigned long data;

	if (cfg->have_new_ctrl) {
		rdt_last_cmd_printf("duplicate domain\n");
		return -EINVAL;
	}

	switch (type) {
	case SCHEMA_COMM:
		if (kstrtoul(buf, 16, &data))
			return -EINVAL;
		break;
	case SCHEMA_PRI:
		if (kstrtoul(buf, 10, &data))
			return -EINVAL;
		break;
	case SCHEMA_HDL:
		if (kstrtoul(buf, 10, &data))
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	cfg->new_ctrl[type] = data;
	cfg->have_new_ctrl = true;

	return 0;
}

/* define bw_min as 5 percentage, that are 5% ~ 100% which cresponding masks: */
static u32 bw_max_mask[20] = {
	3, /*  3/64:  5% */
	6, /*  6/64: 10% */
	10, /* 10/64: 15% */
	13, /* 13/64: 20% */
	16, /* 16/64: 25% */
	19, /* ... */
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
	63  /* 100% */
};

static bool bw_validate(char *buf, unsigned long *data,
			struct raw_resctrl_resource *r)
{
	unsigned long bw;
	int ret;

	ret = kstrtoul(buf, 10, &bw);
	if (ret) {
		rdt_last_cmd_printf("non-hex character in mask %s\n", buf);
		return false;
	}

	bw = bw < 5 ? 5 : bw;
	bw = bw > 100 ? 100 : bw;
	*data = roundup(bw, 5);

	return true;
}

static int
parse_bw(char *buf, struct raw_resctrl_resource *r,
		struct resctrl_staged_config *cfg,
		enum resctrl_ctrl_type type)
{
	unsigned long data;

	if (cfg->have_new_ctrl) {
		rdt_last_cmd_printf("duplicate domain\n");
		return -EINVAL;
	}

	switch (type) {
	case SCHEMA_COMM:
		if (!bw_validate(buf, &data, r))
			return -EINVAL;
		break;
	case SCHEMA_PRI:
		if (kstrtoul(buf, 10, &data))
			return -EINVAL;
		break;
	case SCHEMA_HDL:
		if (kstrtoul(buf, 10, &data))
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	cfg->new_ctrl[type] = data;
	cfg->have_new_ctrl = true;

	return 0;
}

static void
common_wrmsr(struct resctrl_resource *r, struct rdt_domain *d,
			struct msr_param *para)
{
	struct sync_args args;
	struct mpam_resctrl_dom *dom;

	dom = container_of(d, struct mpam_resctrl_dom, resctrl_dom);

	mpam_resctrl_update_component_cfg(r, d, para->closid);

	/*
	 * so far we have accomplished configuration replication,
	 * it is ready to apply this configuration.
	 */
	args.closid = *para->closid;
	mpam_component_config(dom->comp, &args);
}

static u64 cache_rdmsr(struct rdt_domain *d, struct msr_param *para)
{
	u32 result;
	struct sync_args args;
	struct mpam_resctrl_dom *dom;

	args.closid = *para->closid;

	switch (para->type) {
	case SCHEMA_COMM:
		args.reg = MPAMCFG_CPBM;
		break;
	case SCHEMA_PRI:
		args.reg = MPAMCFG_PRI;
	default:
		return 0;
	}

	dom = container_of(d, struct mpam_resctrl_dom, resctrl_dom);
	mpam_component_get_config(dom->comp, &args, &result);

	switch (para->type) {
	case SCHEMA_PRI:
		result = MPAMCFG_PRI_GET(result);
		break;
	default:
		break;
	}

	return result;
}

static u64 mbw_rdmsr(struct rdt_domain *d, struct msr_param *para)
{
	u32 result;
	struct sync_args args;
	struct mpam_resctrl_dom *dom;

	args.closid = *para->closid;

	/*
	 * software default set memory bandwidth by
	 * MPAMCFG_MBW_MAX but not MPAMCFG_MBW_PBM.
	 */
	switch (para->type) {
	case SCHEMA_COMM:
		args.reg = MPAMCFG_MBW_MAX;
		break;
	case SCHEMA_HDL:
		args.reg = MPAMCFG_MBW_MAX;
		break;
	case SCHEMA_PRI:
		args.reg = MPAMCFG_PRI;
		break;
	default:
		return 0;
	}

	dom = container_of(d, struct mpam_resctrl_dom, resctrl_dom);
	mpam_component_get_config(dom->comp, &args, &result);

	switch (para->type) {
	case SCHEMA_COMM:
		result = roundup((MBW_MAX_GET(result) * 100) / 64, 5);
		break;
	case SCHEMA_PRI:
		result = MPAMCFG_PRI_GET(result);
		break;
	case SCHEMA_HDL:
		result = MBW_MAX_GET_HDL(result);
		break;
	default:
		break;
	}

	return result;
}

/*
 * use pmg as monitor id
 * just use match_pardid only.
 */
static u64 cache_rdmon(struct rdt_domain *d, void *md_priv)
{
	int err;
	u64 result;
	union mon_data_bits md;
	struct sync_args args;
	struct mpam_resctrl_dom *dom;
	unsigned long timeout;

	md.priv = md_priv;

	/* monitoring only need reqpartid */
	args.closid.reqpartid = md.u.partid;
	args.mon = md.u.mon;
	args.pmg = md.u.pmg;
	args.match_pmg = true;
	args.eventid = QOS_L3_OCCUP_EVENT_ID;

	dom = container_of(d, struct mpam_resctrl_dom, resctrl_dom);

	/**
	 * We should judge if return is OK, it is possible affected
	 * by NRDY bit.
	 */
	timeout = READ_ONCE(jiffies) + (1*SEC_CONVERSION);
	do {
		if (time_after(READ_ONCE(jiffies), timeout)) {
			err = -ETIMEDOUT;
			break;
		}
		err = mpam_component_mon(dom->comp, &args, &result);
		/* Currently just report it */
		WARN_ON(err && (err != -EBUSY));
	} while (err == -EBUSY);

	return result;
}
/*
 * use pmg as monitor id
 * just use match_pardid only.
 */
static u64 mbw_rdmon(struct rdt_domain *d, void *md_priv)
{
	int err;
	u64 result;
	union mon_data_bits md;
	struct sync_args args;
	struct mpam_resctrl_dom *dom;
	unsigned long timeout;

	md.priv = md_priv;

	/* monitoring only need reqpartid */
	args.closid.reqpartid = md.u.partid;
	args.mon = md.u.mon;
	args.pmg = md.u.pmg;
	args.match_pmg = true;
	args.eventid = QOS_L3_MBM_LOCAL_EVENT_ID;

	dom = container_of(d, struct mpam_resctrl_dom, resctrl_dom);

	/**
	 * We should judge if return is OK, it is possible affected
	 * by NRDY bit.
	 */
	timeout = READ_ONCE(jiffies) + (1*SEC_CONVERSION);
	do {
		if (time_after(READ_ONCE(jiffies), timeout)) {
			err = -ETIMEDOUT;
			break;
		}
		err = mpam_component_mon(dom->comp, &args, &result);
		/* Currently just report it */
		WARN_ON(err && (err != -EBUSY));
	} while (err == -EBUSY);

	return result;
}

static int
common_wrmon(struct rdt_domain *d, void *md_priv)
{
	u64 result;
	union mon_data_bits md;
	struct sync_args args;
	struct mpam_resctrl_dom *dom;

	md.priv = md_priv;
	/* monitoring only need reqpartid */
	args.closid.reqpartid = md.u.partid;
	args.mon = md.u.mon;
	args.pmg = md.u.pmg;

	args.match_pmg = true;

	dom = container_of(d, struct mpam_resctrl_dom, resctrl_dom);

	/**
	 * We needn't judge if return is OK, we just want to configure
	 * monitor info.
	 */
	mpam_component_mon(dom->comp, &args, &result);

	return 0;
}

/*
 * Notifing resctrl_id_init() should be called after calling parse_
 * resctrl_group_fs_options() to guarantee resctrl_cdp_enabled() active.
 *
 * Using a global CLOSID across all resources has some advantages and
 * some drawbacks:
 * + We can simply set "current->closid" to assign a task to a resource
 *   group.
 * + Context switch code can avoid extra memory references deciding which
 *   CLOSID to load into the PQR_ASSOC MSR
 * - We give up some options in configuring resource groups across multi-socket
 *   systems.
 * - Our choices on how to configure each resource become progressively more
 *   limited as the number of resources grows.
 */

static unsigned long *intpartid_free_map, *reqpartid_free_map;
static int num_intpartid, num_reqpartid;

static void mpam_resctrl_closid_collect(void)
{
	struct mpam_resctrl_res *res;
	struct raw_resctrl_resource *rr;

	/*
	 * num_reqpartid refers to the maximum partid number
	 * that system width provides.
	 */
	num_reqpartid = mpam_sysprops_num_partid();
	/*
	 * we make intpartid the closid, this is because when
	 * system platform supports intpartid narrowing, this
	 * intpartid concept represents the resctrl maximum
	 * group we can create, so it should be less than
	 * maximum reqpartid number and maximum closid number
	 * allowed by resctrl sysfs provided by @Intel-RDT.
	 */
	num_intpartid = mpam_sysprops_num_partid();
	num_intpartid = min(num_reqpartid, RESCTRL_MAX_CLOSID);

	/*
	 * as we know we make intpartid the closid given to
	 * resctrl, we should know if any resource supports
	 * intpartid narrowing.
	 */
	for_each_supported_resctrl_exports(res) {
		rr = res->resctrl_res.res;
		if (!rr->num_intpartid)
			continue;
		num_intpartid = min(num_intpartid, (int)rr->num_intpartid);
	}
}

static inline int local_closid_bitmap_init(int bits_num, unsigned long **ptr)
{
	int pos;
	u32 times, flag;

	hw_alloc_times_validate(times, flag);

	if (flag)
		bits_num = rounddown(bits_num, 2);

	if (!*ptr) {
		*ptr = bitmap_zalloc(bits_num, GFP_KERNEL);
		if (!*ptr)
			return -ENOMEM;
	}

	bitmap_set(*ptr, 0, bits_num);

	/* CLOSID 0 is always reserved for the default group */
	pos = find_first_bit(*ptr, bits_num);
	bitmap_clear(*ptr, pos, times);

	return 0;
}

int closid_bitmap_init(void)
{
	int ret;

	mpam_resctrl_closid_collect();
	if (!num_intpartid || !num_reqpartid)
		return -EINVAL;

	if (intpartid_free_map)
		kfree(intpartid_free_map);
	if (reqpartid_free_map)
		kfree(reqpartid_free_map);

	ret = local_closid_bitmap_init(num_intpartid, &intpartid_free_map);
	if (ret)
		goto out;

	ret = local_closid_bitmap_init(num_reqpartid, &reqpartid_free_map);
	if (ret)
		goto out;

	return 0;
out:
	return ret;
}

/*
 * If cdp enabled, allocate two closid once time, then return first
 * allocated id.
 */
static int closid_bitmap_alloc(int bits_num, unsigned long *ptr)
{
	int pos;
	u32 times, flag;

	hw_alloc_times_validate(times, flag);

	pos = find_first_bit(ptr, bits_num);
	if (pos == bits_num)
		return -ENOSPC;

	bitmap_clear(ptr, pos, times);

	return pos;
}

static void closid_bitmap_free(int pos, unsigned long *ptr)
{
	u32 times, flag;

	hw_alloc_times_validate(times, flag);
	bitmap_set(ptr, pos, times);
}

/*
 * Choose a width for the resource name and resource data based on the
 * resource that has widest name and cbm.
 */
static __init void mpam_init_padding(void)
{
	int cl;
	struct mpam_resctrl_res *res;
	struct resctrl_resource *r;
	struct raw_resctrl_resource *rr;

	for_each_supported_resctrl_exports(res) {
		r = &res->resctrl_res;

		cl = strlen(r->name);
		if (cl > max_name_width)
			max_name_width = cl;

		rr = r->res;
		if (!rr)
			continue;
		cl = rr->data_width;
		if (cl > max_data_width)
			max_data_width = cl;
	}
}

void post_resctrl_mount(void)
{
	if (rdt_alloc_capable)
		static_branch_enable_cpuslocked(&resctrl_alloc_enable_key);
	if (rdt_mon_capable)
		static_branch_enable_cpuslocked(&resctrl_mon_enable_key);

	if (rdt_alloc_capable || rdt_mon_capable)
		static_branch_enable_cpuslocked(&resctrl_enable_key);
}

void release_rdtgroupfs_options(void)
{
}

static void disable_cdp(void)
{
	struct mpam_resctrl_res *res;
	struct resctrl_resource *r;

	for_each_supported_resctrl_exports(res) {
		r = &res->resctrl_res;
		r->cdp_enable = false;
	}

	resctrl_cdp_enabled = false;
}

static int try_to_enable_cdp(enum resctrl_resource_level level)
{
	struct resctrl_resource *r = mpam_resctrl_get_resource(level);

	if (!r || !r->cdp_capable)
		return -EINVAL;

	r->cdp_enable = true;

	resctrl_cdp_enabled = true;
	return 0;
}

static int cdpl3_enable(void)
{
	return try_to_enable_cdp(RDT_RESOURCE_L3);
}

static int cdpl2_enable(void)
{
	return try_to_enable_cdp(RDT_RESOURCE_L2);
}

static void basic_ctrl_enable(void)
{
	struct mpam_resctrl_res *res;
	struct resctrl_resource *r;

	for_each_supported_resctrl_exports(res) {
		r = &res->resctrl_res;
		/* At least SCHEMA_COMM is supported */
		resctrl_ctrl_extend_bits_set(&r->ctrl_extend_bits, SCHEMA_COMM);
	}
}

static int extend_ctrl_enable(enum resctrl_ctrl_type type)
{
	bool match = false;
	struct resctrl_resource *r;
	struct raw_resctrl_resource *rr;
	struct mpam_resctrl_res *res;

	for_each_supported_resctrl_exports(res) {
		r = &res->resctrl_res;
		rr = r->res;
		if ((type == SCHEMA_PRI && rr->pri_wd) ||
			(type == SCHEMA_HDL && rr->hdl_wd)) {
			resctrl_ctrl_extend_bits_set(&r->ctrl_extend_bits, type);
			match = true;
		}
	}

	if (!match)
		return -EINVAL;

	return 0;
}

static void extend_ctrl_disable(void)
{
	struct resctrl_resource *r;
	struct mpam_resctrl_res *res;

	for_each_supported_resctrl_exports(res) {
		r = &res->resctrl_res;
		resctrl_ctrl_extend_bits_clear(&r->ctrl_extend_bits);
	}
}

int parse_rdtgroupfs_options(char *data)
{
	char *token;
	char *o = data;
	int ret = 0;

	disable_cdp();
	extend_ctrl_disable();

	while ((token = strsep(&o, ",")) != NULL) {
		if (!*token) {
			ret = -EINVAL;
			goto out;
		}

		if (!strcmp(token, "cdpl3")) {
			ret = cdpl3_enable();
			if (ret)
				goto out;
		} else if (!strcmp(token, "cdpl2")) {
			ret = cdpl2_enable();
			if (ret)
				goto out;
		} else if (!strcmp(token, "priority")) {
			ret = extend_ctrl_enable(SCHEMA_PRI);
			if (ret)
				goto out;
		} else if (!strcmp(token, "hardlimit")) {
			ret = extend_ctrl_enable(SCHEMA_HDL);
			if (ret)
				goto out;
		} else {
			ret = -EINVAL;
			goto out;
		}
	}

	basic_ctrl_enable();

	return 0;

out:
	pr_err("Invalid mount option \"%s\"\n", token);

	return ret;
}

/*
 * This is safe against intel_resctrl_sched_in() called from __switch_to()
 * because __switch_to() is executed with interrupts disabled. A local call
 * from update_closid_rmid() is proteced against __switch_to() because
 * preemption is disabled.
 */
void update_cpu_closid_rmid(void *info)
{
	struct rdtgroup *r = info;

	if (r) {
		this_cpu_write(pqr_state.default_closid, r->closid.reqpartid);
		this_cpu_write(pqr_state.default_rmid, r->mon.rmid);
	}

	/*
	 * We cannot unconditionally write the MSR because the current
	 * executing task might have its own closid selected. Just reuse
	 * the context switch code.
	 */
	mpam_sched_in();
}

/*
 * Update the PGR_ASSOC MSR on all cpus in @cpu_mask,
 *
 * Per task closids/rmids must have been set up before calling this function.
 */
void
update_closid_rmid(const struct cpumask *cpu_mask, struct rdtgroup *r)
{
	int cpu = get_cpu();

	if (cpumask_test_cpu(cpu, cpu_mask))
		update_cpu_closid_rmid(r);
	smp_call_function_many(cpu_mask, update_cpu_closid_rmid, r, 1);
	put_cpu();
}

struct task_move_callback {
	struct callback_head	work;
	struct rdtgroup		*rdtgrp;
};

static void move_myself(struct callback_head *head)
{
	struct task_move_callback *callback;
	struct rdtgroup *rdtgrp;

	callback = container_of(head, struct task_move_callback, work);
	rdtgrp = callback->rdtgrp;

	/*
	 * If resource group was deleted before this task work callback
	 * was invoked, then assign the task to root group and free the
	 * resource group.
	 */
	if (atomic_dec_and_test(&rdtgrp->waitcount) &&
	    (rdtgrp->flags & RDT_DELETED)) {
		current->closid = 0;
		current->rmid = 0;
		kfree(rdtgrp);
	}

	preempt_disable();
	/* update PQR_ASSOC MSR to make resource group go into effect */
	mpam_sched_in();
	preempt_enable();

	kfree(callback);
}

int __resctrl_group_move_task(struct task_struct *tsk,
				struct rdtgroup *rdtgrp)
{
	struct task_move_callback *callback;
	int ret;

	callback = kzalloc(sizeof(*callback), GFP_KERNEL);
	if (!callback)
		return -ENOMEM;
	callback->work.func = move_myself;
	callback->rdtgrp = rdtgrp;

	/*
	 * Take a refcount, so rdtgrp cannot be freed before the
	 * callback has been invoked.
	 */
	atomic_inc(&rdtgrp->waitcount);
	ret = task_work_add(tsk, &callback->work, true);
	if (ret) {
		/*
		 * Task is exiting. Drop the refcount and free the callback.
		 * No need to check the refcount as the group cannot be
		 * deleted before the write function unlocks resctrl_group_mutex.
		 */
		atomic_dec(&rdtgrp->waitcount);
		kfree(callback);
		rdt_last_cmd_puts("task exited\n");
	} else {
		/*
		 * For ctrl_mon groups move both closid and rmid.
		 * For monitor groups, can move the tasks only from
		 * their parent CTRL group.
		 */
		if (rdtgrp->type == RDTCTRL_GROUP) {
			tsk->closid = TASK_CLOSID_SET(rdtgrp->closid.intpartid,
				rdtgrp->closid.reqpartid);
			tsk->rmid = rdtgrp->mon.rmid;
		} else if (rdtgrp->type == RDTMON_GROUP) {
			if (rdtgrp->mon.parent->closid.intpartid ==
				TASK_CLOSID_PR_GET(tsk->closid)) {
				tsk->closid = TASK_CLOSID_SET(rdtgrp->closid.intpartid,
					rdtgrp->closid.reqpartid);
				tsk->rmid = rdtgrp->mon.rmid;
			} else {
				rdt_last_cmd_puts("Can't move task to different control group\n");
				ret = -EINVAL;
			}
		}
	}
	return ret;
}

static int resctrl_group_seqfile_show(struct seq_file *m, void *arg)
{
	struct kernfs_open_file *of = m->private;
	struct rftype *rft = of->kn->priv;

	if (rft->seq_show)
		return rft->seq_show(of, m, arg);
	return 0;
}

static ssize_t resctrl_group_file_write(struct kernfs_open_file *of, char *buf,
				   size_t nbytes, loff_t off)
{
	struct rftype *rft = of->kn->priv;

	if (rft->write)
		return rft->write(of, buf, nbytes, off);

	return -EINVAL;
}

struct kernfs_ops resctrl_group_kf_single_ops = {
	.atomic_write_len	= PAGE_SIZE,
	.write			= resctrl_group_file_write,
	.seq_show		= resctrl_group_seqfile_show,
};

static bool is_cpu_list(struct kernfs_open_file *of)
{
	struct rftype *rft = of->kn->priv;

	return rft->flags & RFTYPE_FLAGS_CPUS_LIST;
}

static int resctrl_group_cpus_show(struct kernfs_open_file *of,
			      struct seq_file *s, void *v)
{
	struct rdtgroup *rdtgrp;
	int ret = 0;

	rdtgrp = resctrl_group_kn_lock_live(of->kn);

	if (rdtgrp) {
		seq_printf(s, is_cpu_list(of) ? "%*pbl\n" : "%*pb\n",
			   cpumask_pr_args(&rdtgrp->cpu_mask));
	} else {
		ret = -ENOENT;
	}
	resctrl_group_kn_unlock(of->kn);

	return ret;
}

static void cpumask_rdtgrp_clear(struct rdtgroup *r, struct cpumask *m)
{
	struct rdtgroup *crgrp;

	cpumask_andnot(&r->cpu_mask, &r->cpu_mask, m);
	/* update the child mon group masks as well*/
	list_for_each_entry(crgrp, &r->mon.crdtgrp_list, mon.crdtgrp_list)
		cpumask_and(&crgrp->cpu_mask, &r->cpu_mask, &crgrp->cpu_mask);
}

int cpus_ctrl_write(struct rdtgroup *rdtgrp, cpumask_var_t newmask,
			   cpumask_var_t tmpmask, cpumask_var_t tmpmask1)
{
	struct rdtgroup *r, *crgrp;
	struct list_head *head;

	/* Check whether cpus are dropped from this group */
	cpumask_andnot(tmpmask, &rdtgrp->cpu_mask, newmask);
	if (cpumask_weight(tmpmask)) {
		/* Can't drop from default group */
		if (rdtgrp == &resctrl_group_default) {
			rdt_last_cmd_puts("Can't drop CPUs from default group\n");
			return -EINVAL;
		}

		/* Give any dropped cpus to rdtgroup_default */
		cpumask_or(&resctrl_group_default.cpu_mask,
				&resctrl_group_default.cpu_mask, tmpmask);
		update_closid_rmid(tmpmask, &resctrl_group_default);
	}

	/*
	 * If we added cpus, remove them from previous group and
	 * the prev group's child groups that owned them
	 * and update per-cpu closid/rmid.
	 */
	cpumask_andnot(tmpmask, newmask, &rdtgrp->cpu_mask);
	if (cpumask_weight(tmpmask)) {
		list_for_each_entry(r, &resctrl_all_groups, resctrl_group_list) {
			if (r == rdtgrp)
				continue;
			cpumask_and(tmpmask1, &r->cpu_mask, tmpmask);
			if (cpumask_weight(tmpmask1))
				cpumask_rdtgrp_clear(r, tmpmask1);
		}
		update_closid_rmid(tmpmask, rdtgrp);
	}

	/* Done pushing/pulling - update this group with new mask */
	cpumask_copy(&rdtgrp->cpu_mask, newmask);

	/*
	 * Clear child mon group masks since there is a new parent mask
	 * now and update the rmid for the cpus the child lost.
	 */
	head = &rdtgrp->mon.crdtgrp_list;
	list_for_each_entry(crgrp, head, mon.crdtgrp_list) {
		cpumask_and(tmpmask, &rdtgrp->cpu_mask, &crgrp->cpu_mask);
		update_closid_rmid(tmpmask, rdtgrp);
		cpumask_clear(&crgrp->cpu_mask);
	}

	return 0;
}

static int resctrl_num_partid_show(struct kernfs_open_file *of,
				   struct seq_file *seq, void *v)
{
	struct resctrl_resource *r = of->kn->parent->priv;
	struct raw_resctrl_resource *rr = r->res;
	u16 num_partid;

	num_partid = rr->num_partid;

	seq_printf(seq, "%d\n", num_partid);

	return 0;
}

static int resctrl_num_pmg_show(struct kernfs_open_file *of,
				struct seq_file *seq, void *v)
{
	struct resctrl_resource *r = of->kn->parent->priv;
	struct raw_resctrl_resource *rr = r->res;
	u16 num_pmg;

	num_pmg = rr->num_pmg;

	seq_printf(seq, "%d\n", num_pmg);

	return 0;
}

static int resctrl_num_mon_show(struct kernfs_open_file *of,
				struct seq_file *seq, void *v)
{
	struct resctrl_resource *r = of->kn->parent->priv;
	struct raw_resctrl_resource *rr = r->res;
	u16 num_mon;

	num_mon = rr->num_mon;

	seq_printf(seq, "%d\n", num_mon);

	return 0;
}

int cpus_mon_write(struct rdtgroup *rdtgrp, cpumask_var_t newmask,
		   cpumask_var_t tmpmask)
{
	struct rdtgroup *prgrp = rdtgrp->mon.parent, *crgrp;
	struct list_head *head;

	/* Check whether cpus belong to parent ctrl group */
	cpumask_andnot(tmpmask, newmask, &prgrp->cpu_mask);
	if (cpumask_weight(tmpmask)) {
		rdt_last_cmd_puts("can only add CPUs to mongroup that belong to parent\n");
		return -EINVAL;
	}

	/* Check whether cpus are dropped from this group */
	cpumask_andnot(tmpmask, &rdtgrp->cpu_mask, newmask);
	if (cpumask_weight(tmpmask)) {
		/* Give any dropped cpus to parent rdtgroup */
		cpumask_or(&prgrp->cpu_mask, &prgrp->cpu_mask, tmpmask);
		update_closid_rmid(tmpmask, prgrp);
	}

	/*
	 * If we added cpus, remove them from previous group that owned them
	 * and update per-cpu rmid
	 */
	cpumask_andnot(tmpmask, newmask, &rdtgrp->cpu_mask);
	if (cpumask_weight(tmpmask)) {
		head = &prgrp->mon.crdtgrp_list;
		list_for_each_entry(crgrp, head, mon.crdtgrp_list) {
			if (crgrp == rdtgrp)
				continue;
			cpumask_andnot(&crgrp->cpu_mask, &crgrp->cpu_mask,
				tmpmask);
		}
		update_closid_rmid(tmpmask, rdtgrp);
	}

	/* Done pushing/pulling - update this group with new mask */
	cpumask_copy(&rdtgrp->cpu_mask, newmask);

	return 0;
}

static ssize_t resctrl_group_cpus_write(struct kernfs_open_file *of,
				   char *buf, size_t nbytes, loff_t off)
{
	cpumask_var_t tmpmask, newmask, tmpmask1;
	struct rdtgroup *rdtgrp;
	int ret;

	if (!buf)
		return -EINVAL;

	if (!zalloc_cpumask_var(&tmpmask, GFP_KERNEL))
		return -ENOMEM;
	if (!zalloc_cpumask_var(&newmask, GFP_KERNEL)) {
		free_cpumask_var(tmpmask);
		return -ENOMEM;
	}
	if (!zalloc_cpumask_var(&tmpmask1, GFP_KERNEL)) {
		free_cpumask_var(tmpmask);
		free_cpumask_var(newmask);
		return -ENOMEM;
	}

	rdtgrp = resctrl_group_kn_lock_live(of->kn);
	rdt_last_cmd_clear();
	if (!rdtgrp) {
		ret = -ENOENT;
		rdt_last_cmd_puts("directory was removed\n");
		goto unlock;
	}

	if (is_cpu_list(of))
		ret = cpulist_parse(buf, newmask);
	else
		ret = cpumask_parse(buf, newmask);

	if (ret) {
		rdt_last_cmd_puts("bad cpu list/mask\n");
		goto unlock;
	}

	/* check that user didn't specify any offline cpus */
	cpumask_andnot(tmpmask, newmask, cpu_online_mask);
	if (cpumask_weight(tmpmask)) {
		ret = -EINVAL;
		rdt_last_cmd_puts("can only assign online cpus\n");
		goto unlock;
	}

	if (rdtgrp->type == RDTCTRL_GROUP)
		ret = cpus_ctrl_write(rdtgrp, newmask, tmpmask, tmpmask1);
	else if (rdtgrp->type == RDTMON_GROUP)
		ret = cpus_mon_write(rdtgrp, newmask, tmpmask);
	else
		ret = -EINVAL;

unlock:
	resctrl_group_kn_unlock(of->kn);
	free_cpumask_var(tmpmask);
	free_cpumask_var(newmask);
	free_cpumask_var(tmpmask1);

	return ret ?: nbytes;
}


static int resctrl_group_task_write_permission(struct task_struct *task,
					  struct kernfs_open_file *of)
{
	const struct cred *tcred = get_task_cred(task);
	const struct cred *cred = current_cred();
	int ret = 0;

	/*
	 * Even if we're attaching all tasks in the thread group, we only
	 * need to check permissions on one of them.
	 */
	if (!uid_eq(cred->euid, GLOBAL_ROOT_UID) &&
	    !uid_eq(cred->euid, tcred->uid) &&
	    !uid_eq(cred->euid, tcred->suid)) {
		rdt_last_cmd_printf("No permission to move task %d\n", task->pid);
		ret = -EPERM;
	}

	put_cred(tcred);
	return ret;
}

static int resctrl_group_move_task(pid_t pid, struct rdtgroup *rdtgrp,
			      struct kernfs_open_file *of)
{
	struct task_struct *tsk;
	int ret;

	rcu_read_lock();
	if (pid) {
		tsk = find_task_by_vpid(pid);
		if (!tsk) {
			rcu_read_unlock();
			rdt_last_cmd_printf("No task %d\n", pid);
			return -ESRCH;
		}
	} else {
		tsk = current;
	}

	get_task_struct(tsk);
	rcu_read_unlock();

	ret = resctrl_group_task_write_permission(tsk, of);
	if (!ret)
		ret = __resctrl_group_move_task(tsk, rdtgrp);

	put_task_struct(tsk);
	return ret;
}

static struct seq_buf last_cmd_status;
static char last_cmd_status_buf[512];

void rdt_last_cmd_clear(void)
{
	lockdep_assert_held(&resctrl_group_mutex);
	seq_buf_clear(&last_cmd_status);
}

void rdt_last_cmd_puts(const char *s)
{
	lockdep_assert_held(&resctrl_group_mutex);
	seq_buf_puts(&last_cmd_status, s);
}

void rdt_last_cmd_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	lockdep_assert_held(&resctrl_group_mutex);
	seq_buf_vprintf(&last_cmd_status, fmt, ap);
	va_end(ap);
}

static int rdt_last_cmd_status_show(struct kernfs_open_file *of,
				    struct seq_file *seq, void *v)
{
	int len;

	mutex_lock(&resctrl_group_mutex);
	len = seq_buf_used(&last_cmd_status);
	if (len)
		seq_printf(seq, "%.*s", len, last_cmd_status_buf);
	else
		seq_puts(seq, "ok\n");
	mutex_unlock(&resctrl_group_mutex);
	return 0;
}

static ssize_t resctrl_group_tasks_write(struct kernfs_open_file *of,
				    char *buf, size_t nbytes, loff_t off)
{
	struct rdtgroup *rdtgrp;
	int ret = 0;
	pid_t pid;

	if (kstrtoint(strstrip(buf), 0, &pid) || pid < 0)
		return -EINVAL;
	rdtgrp = resctrl_group_kn_lock_live(of->kn);
	rdt_last_cmd_clear();

	if (rdtgrp)
		ret = resctrl_group_move_task(pid, rdtgrp, of);
	else
		ret = -ENOENT;

	resctrl_group_kn_unlock(of->kn);

	return ret ?: nbytes;
}

static void show_resctrl_tasks(struct rdtgroup *r, struct seq_file *s)
{
	struct task_struct *p, *t;

	rcu_read_lock();
	for_each_process_thread(p, t) {
		if ((r->type == RDTMON_GROUP &&
			TASK_CLOSID_CUR_GET(t->closid) == r->closid.reqpartid &&
			t->rmid == r->mon.rmid) ||
			(r->type == RDTCTRL_GROUP &&
			TASK_CLOSID_PR_GET(t->closid) == r->closid.intpartid))
			seq_printf(s, "group:(gid:%d mon:%d) task:(pid:%d gid:%d rmid:%d)\n",
				r->closid.reqpartid, r->mon.mon, t->pid,
				(int)TASK_CLOSID_CUR_GET(t->closid), t->rmid);
	}
	rcu_read_unlock();
}

static int resctrl_group_tasks_show(struct kernfs_open_file *of,
			       struct seq_file *s, void *v)
{
	struct rdtgroup *rdtgrp;
	int ret = 0;

	rdtgrp = resctrl_group_kn_lock_live(of->kn);
	if (rdtgrp)
		show_resctrl_tasks(rdtgrp, s);
	else
		ret = -ENOENT;
	resctrl_group_kn_unlock(of->kn);

	return ret;
}

/* rdtgroup information files for one cache resource. */
static struct rftype res_specific_files[] = {
	{
		.name           = "num_partids",
		.mode           = 0444,
		.kf_ops         = &resctrl_group_kf_single_ops,
		.seq_show       = resctrl_num_partid_show,
		.fflags         = RF_CTRL_INFO,
	},
	{
		.name           = "num_pmgs",
		.mode           = 0444,
		.kf_ops         = &resctrl_group_kf_single_ops,
		.seq_show       = resctrl_num_pmg_show,
		.fflags         = RF_MON_INFO,
	},
	{
		.name           = "num_monitors",
		.mode           = 0444,
		.kf_ops         = &resctrl_group_kf_single_ops,
		.seq_show       = resctrl_num_mon_show,
		.fflags         = RF_MON_INFO,
	},
	{
		.name		= "last_cmd_status",
		.mode		= 0444,
		.kf_ops		= &resctrl_group_kf_single_ops,
		.seq_show	= rdt_last_cmd_status_show,
		.fflags		= RF_TOP_INFO,
	},
	{
		.name		= "cpus",
		.mode		= 0644,
		.kf_ops		= &resctrl_group_kf_single_ops,
		.write		= resctrl_group_cpus_write,
		.seq_show	= resctrl_group_cpus_show,
		.fflags		= RFTYPE_BASE,
	},
	{
		.name		= "cpus_list",
		.mode		= 0644,
		.kf_ops		= &resctrl_group_kf_single_ops,
		.write		= resctrl_group_cpus_write,
		.seq_show	= resctrl_group_cpus_show,
		.flags		= RFTYPE_FLAGS_CPUS_LIST,
		.fflags		= RFTYPE_BASE,
	},
	{
		.name		= "tasks",
		.mode		= 0644,
		.kf_ops		= &resctrl_group_kf_single_ops,
		.write		= resctrl_group_tasks_write,
		.seq_show	= resctrl_group_tasks_show,
		.fflags		= RFTYPE_BASE,
	},
	{
		.name		= "schemata",
		.mode		= 0644,
		.kf_ops		= &resctrl_group_kf_single_ops,
		.write		= resctrl_group_schemata_write,
		.seq_show	= resctrl_group_schemata_show,
		.fflags		= RF_CTRL_BASE,
	}
};

struct rdt_domain *mpam_find_domain(struct resctrl_resource *r, int id,
		struct list_head **pos)
{
	struct rdt_domain *d;
	struct list_head *l;

	if (id < 0)
		return ERR_PTR(id);

	list_for_each(l, &r->domains) {
		d = list_entry(l, struct rdt_domain, list);
		/* When id is found, return its domain. */
		if (id == d->id)
			return d;
		/* Stop searching when finding id's position in sorted list. */
		if (id < d->id)
			break;
	}

	if (pos)
		*pos = l;

	return NULL;
}

enum mpam_enable_type __read_mostly mpam_enabled;
static int __init mpam_setup(char *str)
{
	if (!strcmp(str, "=acpi"))
		mpam_enabled = MPAM_ENABLE_ACPI;

	return 1;
}
__setup("mpam", mpam_setup);

int __init mpam_resctrl_init(void)
{
	mpam_init_padding();

	register_resctrl_specific_files(res_specific_files,
			ARRAY_SIZE(res_specific_files));

	seq_buf_init(&last_cmd_status, last_cmd_status_buf,
			sizeof(last_cmd_status_buf));

	return resctrl_group_init();
}

/*
 * __intel_rdt_sched_in() - Writes the task's CLOSid/RMID to IA32_PQR_MSR
 *
 * Following considerations are made so that this has minimal impact
 * on scheduler hot path:
 * - This will stay as no-op unless we are running on an Intel SKU
 *   which supports resource control or monitoring and we enable by
 *   mounting the resctrl file system.
 * - Caches the per cpu CLOSid/RMID values and does the MSR write only
 *   when a task with a different CLOSid/RMID is scheduled in.
 * - We allocate RMIDs/CLOSids globally in order to keep this as
 *   simple as possible.
 * Must be called with preemption disabled.
 */
void __mpam_sched_in(void)
{
	struct intel_pqr_state *state = this_cpu_ptr(&pqr_state);
	u64 closid = state->default_closid;
	u64 partid_d, partid_i;
	u64 pmg = state->default_rmid;

	/*
	 * If this task has a closid/rmid assigned, use it.
	 * Else use the closid/rmid assigned to this cpu.
	 */
	if (static_branch_likely(&resctrl_alloc_enable_key)) {
		if (current->closid)
			closid = TASK_CLOSID_CUR_GET(current->closid);
	}

	if (static_branch_likely(&resctrl_mon_enable_key)) {
		if (current->rmid)
			pmg = current->rmid;
	}

	if (closid != state->cur_closid || pmg != state->cur_rmid) {
		u64 reg;

		if (resctrl_cdp_enabled) {
			hw_closid_t hw_closid;

			resctrl_cdp_map(clos, closid, CDP_DATA, hw_closid);
			partid_d = hw_closid_val(hw_closid);

			resctrl_cdp_map(clos, closid, CDP_CODE, hw_closid);
			partid_i = hw_closid_val(hw_closid);

			/*
			 * when cdp enabled, we use partid_i to label cur_closid
			 * of cpu state instead of partid_d, because each task/
			 * rdtgrp's closid is labeled by CDP_BOTH/CDP_CODE but not
			 * CDP_DATA.
			 */
			state->cur_closid = partid_i;
			state->cur_rmid = pmg;

			/* set in EL0 */
			reg = mpam_read_sysreg_s(SYS_MPAM0_EL1, "SYS_MPAM0_EL1");
			reg = PARTID_D_SET(reg, partid_d);
			reg = PARTID_I_SET(reg, partid_i);
			reg = PMG_SET(reg, pmg);
			mpam_write_sysreg_s(reg, SYS_MPAM0_EL1, "SYS_MPAM0_EL1");

			/* set in EL1 */
			reg = mpam_read_sysreg_s(SYS_MPAM1_EL1, "SYS_MPAM1_EL1");
			reg = PARTID_D_SET(reg, partid_d);
			reg = PARTID_I_SET(reg, partid_i);
			reg = PMG_SET(reg, pmg);
			mpam_write_sysreg_s(reg, SYS_MPAM1_EL1, "SYS_MPAM1_EL1");
		} else {
			state->cur_closid = closid;
			state->cur_rmid = pmg;

			/* set in EL0 */
			reg = mpam_read_sysreg_s(SYS_MPAM0_EL1, "SYS_MPAM0_EL1");
			reg = PARTID_SET(reg, closid);
			reg = PMG_SET(reg, pmg);
			mpam_write_sysreg_s(reg, SYS_MPAM0_EL1, "SYS_MPAM0_EL1");

			/* set in EL1 */
			reg = mpam_read_sysreg_s(SYS_MPAM1_EL1, "SYS_MPAM1_EL1");
			reg = PARTID_SET(reg, closid);
			reg = PMG_SET(reg, pmg);
			mpam_write_sysreg_s(reg, SYS_MPAM1_EL1, "SYS_MPAM1_EL1");
		}
	}
}

static void
mpam_update_from_resctrl_cfg(struct mpam_resctrl_res *res,
			u32 resctrl_cfg, enum resctrl_ctrl_type ctrl_type,
			struct mpam_config *mpam_cfg)
{
	switch (ctrl_type) {
	case SCHEMA_COMM:
		if (res == &mpam_resctrl_exports[RDT_RESOURCE_MC]) {
			u64 range;

			/* For MBA cfg is a percentage of .. */
			if (res->resctrl_mba_uses_mbw_part) {
				/* .. the number of bits we can set */
				range = res->class->mbw_pbm_bits;
				mpam_cfg->mbw_pbm =
					(resctrl_cfg * range) / MAX_MBA_BW;
				mpam_set_feature(mpam_feat_mbw_part, &mpam_cfg->valid);
			} else {
				/* .. the number of fractions we can represent */
				mpam_cfg->mbw_max =
					bw_max_mask[(resctrl_cfg / 5 - 1) %
					ARRAY_SIZE(bw_max_mask)];

				mpam_set_feature(mpam_feat_mbw_max, &mpam_cfg->valid);
			}
		} else {
			/*
			 * Nothing clever here as mpam_resctrl_pick_caches()
			 * capped the size at RESCTRL_MAX_CBM.
			 */
			mpam_cfg->cpbm = resctrl_cfg;
			mpam_set_feature(mpam_feat_cpor_part, &mpam_cfg->valid);
		}
		break;
	case SCHEMA_PRI:
		mpam_cfg->dspri = resctrl_cfg;
		mpam_cfg->intpri = resctrl_cfg;
		mpam_set_feature(mpam_feat_dspri_part, &mpam_cfg->valid);
		mpam_set_feature(mpam_feat_intpri_part, &mpam_cfg->valid);
		break;
	case SCHEMA_HDL:
		mpam_cfg->hdl = resctrl_cfg;
		mpam_set_feature(mpam_feat_part_hdl, &mpam_cfg->valid);
		break;
	default:
		break;
	}
}

/*
 * copy all ctrl type at once looks more efficient, as it
 * only needs refresh devices' state once time through
 * mpam_component_config, this feature will be checked
 * again when appling configuration.
 */
static void
mpam_resctrl_update_component_cfg(struct resctrl_resource *r,
		struct rdt_domain *d, struct sd_closid *closid)
{
	struct mpam_resctrl_dom *dom;
	struct mpam_resctrl_res *res;
	struct mpam_config *slave_mpam_cfg;
	enum resctrl_ctrl_type type;
	u32 intpartid = closid->intpartid;
	u32 reqpartid = closid->reqpartid;
	u32 resctrl_cfg;

	lockdep_assert_held(&resctrl_group_mutex);

	/* Out of range */
	if (intpartid >= mpam_sysprops_num_partid() ||
		reqpartid >= mpam_sysprops_num_partid())
		return;

	res = container_of(r, struct mpam_resctrl_res, resctrl_res);
	dom = container_of(d, struct mpam_resctrl_dom, resctrl_dom);

	/*
	 * now reqpartid is used for duplicating master's configuration,
	 * mpam_cfg[intpartid] needn't duplicate this setting,
	 * it is because only reqpartid stands for each rdtgroup's
	 * mpam_cfg index id.
	 */
	slave_mpam_cfg = &dom->comp->cfg[reqpartid];
	if (WARN_ON_ONCE(!slave_mpam_cfg))
		return;
	slave_mpam_cfg->valid = 0;

	for_each_ctrl_type(type) {
		/*
		 * we don't need check if we have enabled this ctrl type, because
		 * this ctrls also should be applied an default configuration and
		 * this feature type would be rechecked when configuring mpam devices.
		 */
		resctrl_cfg = d->ctrl_val[type][intpartid];
		mpam_update_from_resctrl_cfg(res, resctrl_cfg,
			type, slave_mpam_cfg);
	}
}

static void mpam_reset_cfg(struct mpam_resctrl_res *res,
		struct mpam_resctrl_dom *dom, struct rdt_domain *d)

{
	int i;
	struct resctrl_resource *r = &res->resctrl_res;
	enum resctrl_ctrl_type type;

	for (i = 0; i != mpam_sysprops_num_partid(); i++) {
		for_each_ctrl_type(type) {
			mpam_update_from_resctrl_cfg(res, r->default_ctrl[type],
				type, &dom->comp->cfg[i]);
			d->ctrl_val[type][i] = r->default_ctrl[type];
		}
	}
}

void resctrl_resource_reset(void)
{
	struct mpam_resctrl_res *res;
	struct mpam_resctrl_dom *dom;
	struct rdt_domain *d;

	for_each_supported_resctrl_exports(res) {
		if (!res->resctrl_res.alloc_capable)
			continue;

		list_for_each_entry(d, &res->resctrl_res.domains, list) {
			dom = container_of(d, struct mpam_resctrl_dom,
					resctrl_dom);
			mpam_reset_cfg(res, dom, d);
		}
	}

	mpam_reset_devices();

	/*
	 * reset CDP configuration used in recreating schema list nodes.
	 */
	resctrl_cdp_enabled = false;
}

u16 mpam_resctrl_max_mon_num(void)
{
	struct mpam_resctrl_res *res;
	u16 mon_num = USHRT_MAX;
	struct raw_resctrl_resource *rr;

	if (max_mon_num)
		return max_mon_num;

	for_each_supported_resctrl_exports(res) {
		rr = res->resctrl_res.res;
		mon_num = min(mon_num, rr->num_mon);
	}

	if (mon_num == USHRT_MAX)
		mon_num = 0;

	max_mon_num = mon_num;

	return mon_num;
}

int resctrl_id_init(void)
{
	int ret;

	ret = closid_bitmap_init();
	if (ret)
		goto out;

	pmg_init();
	mon_init();

out:
	return ret;
}

int resctrl_id_alloc(enum closid_type type)
{
	if (type == CLOSID_INT)
		return closid_bitmap_alloc(num_intpartid, intpartid_free_map);
	else if (type == CLOSID_REQ)
		return closid_bitmap_alloc(num_reqpartid, reqpartid_free_map);

	return -ENOSPC;
}

void resctrl_id_free(enum closid_type type, int id)
{
	if (type == CLOSID_INT)
		return closid_bitmap_free(id, intpartid_free_map);
	else if (type == CLOSID_REQ)
		return closid_bitmap_free(id, reqpartid_free_map);
}
