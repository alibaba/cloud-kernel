// SPDX-License-Identifier: GPL-2.0+
/*
 * Common code for ARM v8 MPAM
 *
 * Copyright (C) 2016 Intel Corporation
 * Copyright (C) 2018-2019 Huawei Technologies Co., Ltd
 *
 * Authors:
 *   Fenghua Yu <fenghua.yu@intel.com>
 *   Tony Luck <tony.luck@intel.com>
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

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/slab.h>
#include <linux/err.h>
#include <linux/cacheinfo.h>
#include <linux/cpuhotplug.h>
#include <linux/task_work.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/resctrlfs.h>

#include <asm/mpam_sched.h>
#include <asm/mpam_resource.h>
#include <asm/resctrl.h>
#include <asm/io.h>

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

char *mpam_types_str[] = {
	"MPAM_RESOURCE_SMMU",
	"MPAM_RESOURCE_CACHE",
	"MPAM_RESOURCE_MC",
};

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

#define MPAM_BASE(suffix, offset) ((suffix) << 24 | (offset) << 16)
#define MPAM_NODE(n, t, suffix, offset)			\
	{						\
		.name	= #n,				\
		.type	= t,				\
		.addr	= MPAM_BASE(suffix, (offset)),	\
		.cpus_list = "0",			\
	}

struct mpam_node mpam_node_all[] = {
	MPAM_NODE(L3TALL0, MPAM_RESOURCE_CACHE, 0x000098ULL, 0xB9),
	MPAM_NODE(L3TALL1, MPAM_RESOURCE_CACHE, 0x000090ULL, 0xB9),
	MPAM_NODE(L3TALL2, MPAM_RESOURCE_CACHE, 0x200098ULL, 0xB9),
	MPAM_NODE(L3TALL3, MPAM_RESOURCE_CACHE, 0x200090ULL, 0xB9),

	MPAM_NODE(HHAALL0, MPAM_RESOURCE_MC, 0x000098ULL, 0xC1),
	MPAM_NODE(HHAALL1, MPAM_RESOURCE_MC, 0x000090ULL, 0xC1),
	MPAM_NODE(HHAALL2, MPAM_RESOURCE_MC, 0x200098ULL, 0xC1),
	MPAM_NODE(HHAALL3, MPAM_RESOURCE_MC, 0x200090ULL, 0xC1),
};

void mpam_nodes_unmap(void)
{
	int i;
	size_t num_nodes = ARRAY_SIZE(mpam_node_all);
	struct mpam_node *n;

	for (i = 0; i < num_nodes; i++) {
		n = &mpam_node_all[i];
		if (n->base) {
			iounmap(n->base);
			n->base = NULL;
		}
	}
}

int mpam_nodes_init(void)
{
	int i, ret = 0;
	size_t num_nodes = ARRAY_SIZE(mpam_node_all);
	struct mpam_node *n;

	for (i = 0; i < num_nodes; i++) {
		n = &mpam_node_all[i];
		ret |= cpulist_parse(n->cpus_list, &n->cpu_mask);
		n->base = ioremap(n->addr, 0x10000);
		if (!n->base) {
			mpam_nodes_unmap();
			return -ENOMEM;
		}
	}

	return ret;
}

static void
cat_wrmsr(struct rdt_domain *d, int partid);
static void
bw_wrmsr(struct rdt_domain *d, int partid);

u64 cat_rdmsr(struct rdt_domain *d, int partid);
u64 bw_rdmsr(struct rdt_domain *d, int partid);

static u64 mbwu_read(struct rdt_domain *d, struct rdtgroup *g);
static u64 csu_read(struct rdt_domain *d, struct rdtgroup *g);

static int mbwu_write(struct rdt_domain *d, struct rdtgroup *g, bool enable);
static int csu_write(struct rdt_domain *d, struct rdtgroup *g, bool enable);

#define domain_init(id) LIST_HEAD_INIT(resctrl_resources_all[id].domains)

struct raw_resctrl_resource raw_resctrl_resources_all[] = {
	[MPAM_RESOURCE_CACHE] = {
		.msr_update		= cat_wrmsr,
		.msr_read		= cat_rdmsr,
		.parse_ctrlval		= parse_cbm,
		.format_str		= "%d=%0*x",
		.mon_read		= csu_read,
		.mon_write		= csu_write,
	},
	[MPAM_RESOURCE_MC] = {
		.msr_update		= bw_wrmsr,
		.msr_read		= bw_rdmsr,
		.parse_ctrlval		= parse_bw,	/* [FIXME] add parse_bw() helper */
		.format_str		= "%d=%0*d",
		.mon_read		= mbwu_read,
		.mon_write		= mbwu_write,
	},
};

struct resctrl_resource resctrl_resources_all[] = {
	[MPAM_RESOURCE_CACHE] = {
		.rid			= MPAM_RESOURCE_CACHE,
		.name			= "L3",
		.domains		= domain_init(MPAM_RESOURCE_CACHE),
		.res			= &raw_resctrl_resources_all[MPAM_RESOURCE_CACHE],
		.fflags			= RFTYPE_RES_CACHE,
		.alloc_enabled		= 1,
	},
	[MPAM_RESOURCE_MC] = {
		.rid			= MPAM_RESOURCE_MC,
		.name			= "MB",
		.domains		= domain_init(MPAM_RESOURCE_MC),
		.res			= &raw_resctrl_resources_all[MPAM_RESOURCE_MC],
		.fflags			= RFTYPE_RES_MC,
		.alloc_enabled		= 1,
	},
};

static void
cat_wrmsr(struct rdt_domain *d, int partid)
{
	mpam_writel(partid, d->base + MPAMCFG_PART_SEL);
	mpam_writel(d->ctrl_val[partid], d->base + MPAMCFG_CPBM);
}

static void
bw_wrmsr(struct rdt_domain *d, int partid)
{
	u64 val = MBW_MAX_SET(d->ctrl_val[partid]);

	mpam_writel(partid, d->base + MPAMCFG_PART_SEL);
	mpam_writel(val, d->base + MPAMCFG_MBW_MAX);
}

u64 cat_rdmsr(struct rdt_domain *d, int partid)
{
	mpam_writel(partid, d->base + MPAMCFG_PART_SEL);
	return mpam_readl(d->base + MPAMCFG_CPBM);
}

u64 bw_rdmsr(struct rdt_domain *d, int partid)
{
	u64 max;

	mpam_writel(partid, d->base + MPAMCFG_PART_SEL);
	max = mpam_readl(d->base + MPAMCFG_MBW_MAX);

	max = MBW_MAX_GET(max);
	return roundup((max * 100) / 64, 5);
}

/*
 * [FIXME]
 * use pmg as monitor id
 * just use match_pardid only.
 */
static u64 mbwu_read(struct rdt_domain *d, struct rdtgroup *g)
{
	u32 mon = g->mon.mon;

	mpam_writel(mon, d->base + MSMON_CFG_MON_SEL);
	return mpam_readl(d->base + MSMON_MBWU);
}

static u64 csu_read(struct rdt_domain *d, struct rdtgroup *g)
{
	u32 mon = g->mon.mon;

	mpam_writel(mon, d->base + MSMON_CFG_MON_SEL);
	return mpam_readl(d->base + MSMON_CSU);
}

static int mbwu_write(struct rdt_domain *d, struct rdtgroup *g, bool enable)
{
	u32 mon, partid, pmg, ctl, flt, cur_ctl, cur_flt;

	mon = g->mon.mon;
	mpam_writel(mon, d->base + MSMON_CFG_MON_SEL);
	if (enable) {
		partid = g->closid;
		pmg = g->mon.rmid;
		ctl = MSMON_MATCH_PARTID|MSMON_MATCH_PMG;
		flt = MSMON_CFG_FLT_SET(pmg, partid);
		cur_flt = mpam_readl(d->base + MSMON_CFG_MBWU_FLT);
		cur_ctl = mpam_readl(d->base + MSMON_CFG_MBWU_CTL);

		if (cur_ctl != (ctl | MSMON_CFG_CTL_EN | MSMON_CFG_MBWU_TYPE) ||
		    cur_flt != flt) {
			mpam_writel(flt, d->base + MSMON_CFG_MBWU_FLT);
			mpam_writel(ctl, d->base + MSMON_CFG_MBWU_CTL);
			mpam_writel(0, d->base + MSMON_MBWU);
			ctl |= MSMON_CFG_CTL_EN;
			mpam_writel(ctl, d->base + MSMON_CFG_MBWU_CTL);
		}
	} else {
		ctl = 0;
		mpam_writel(ctl, d->base + MSMON_CFG_MBWU_CTL);
	}

	return 0;
}

static int csu_write(struct rdt_domain *d, struct rdtgroup *g, bool enable)
{
	u32 mon, partid, pmg, ctl, flt, cur_ctl, cur_flt;

	mon = g->mon.mon;
	mpam_writel(mon, d->base + MSMON_CFG_MON_SEL);
	if (enable) {
		partid = g->closid;
		pmg = g->mon.rmid;
		ctl = MSMON_MATCH_PARTID|MSMON_MATCH_PMG;
		flt = MSMON_CFG_FLT_SET(pmg, partid);
		cur_flt = mpam_readl(d->base + MSMON_CFG_CSU_FLT);
		cur_ctl = mpam_readl(d->base + MSMON_CFG_CSU_CTL);

		if (cur_ctl != (ctl | MSMON_CFG_CTL_EN | MSMON_CFG_CSU_TYPE) ||
		    cur_flt != flt) {
			mpam_writel(flt, d->base + MSMON_CFG_CSU_FLT);
			mpam_writel(ctl, d->base + MSMON_CFG_CSU_CTL);
			mpam_writel(0, d->base + MSMON_CSU);
			ctl |= MSMON_CFG_CTL_EN;
			mpam_writel(ctl, d->base + MSMON_CFG_CSU_CTL);
		}
	} else {
		ctl = 0;
		mpam_writel(ctl, d->base + MSMON_CFG_CSU_CTL);
	}

	return 0;
}
/*
 * Trivial allocator for CLOSIDs. Since h/w only supports a small number,
 * we can keep a bitmap of free CLOSIDs in a single integer.
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
static int closid_free_map;

void closid_init(void)
{
	struct resctrl_resource *r;
	struct raw_resctrl_resource *rr;
	int num_closid = INT_MAX;

	for_each_resctrl_resource(r) {
		if (r->alloc_enabled) {
			rr = r->res;
			num_closid = min(num_closid, rr->num_partid);
		}
	}
	closid_free_map = BIT_MASK(num_closid) - 1;

	/* CLOSID 0 is always reserved for the default group */
	closid_free_map &= ~1;
}

int closid_alloc(void)
{
	u32 closid = ffs(closid_free_map);

	if (closid == 0)
		return -ENOSPC;
	closid--;
	closid_free_map &= ~(1 << closid);

	return closid;
}

void closid_free(int closid)
{
	closid_free_map |= 1 << closid;
}

static int mpam_online_cpu(unsigned int cpu)
{
	cpumask_set_cpu(cpu, &resctrl_group_default.cpu_mask);
	return 0;
}

/* [FIXME] remove related resource when cpu offline */
static int mpam_offline_cpu(unsigned int cpu)
{
	return 0;
}

/*
 * Choose a width for the resource name and resource data based on the
 * resource that has widest name and cbm.
 */
static __init void mpam_init_padding(void)
{
	struct resctrl_resource *r;
	struct raw_resctrl_resource *rr;
	int cl;

	for_each_resctrl_resource(r) {
		if (r->alloc_enabled) {
			rr = (struct raw_resctrl_resource *)r->res;
			cl = strlen(r->name);
			if (cl > max_name_width)
				max_name_width = cl;

			if (rr->data_width > max_data_width)
				max_data_width = rr->data_width;
		}
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

static int reset_all_ctrls(struct resctrl_resource *r)
{
	return 0;
}

void resctrl_resource_reset(void)
{
	struct resctrl_resource *r;

	/*Put everything back to default values. */
	for_each_resctrl_resource(r) {
		if (r->alloc_enabled)
			reset_all_ctrls(r);
	}
}

void release_rdtgroupfs_options(void)
{
}

int parse_rdtgroupfs_options(char *data)
{
	return 0;
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
		this_cpu_write(pqr_state.default_closid, r->closid);
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
			tsk->closid = rdtgrp->closid;
			tsk->rmid = rdtgrp->mon.rmid;
		} else if (rdtgrp->type == RDTMON_GROUP) {
			if (rdtgrp->mon.parent->closid == tsk->closid) {
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
	struct raw_resctrl_resource *rr = (struct raw_resctrl_resource *)r->res;

	seq_printf(seq, "%d\n", rr->num_partid);

	return 0;
}

static int resctrl_num_pmg_show(struct kernfs_open_file *of,
				struct seq_file *seq, void *v)
{
	struct resctrl_resource *r = of->kn->parent->priv;
	struct raw_resctrl_resource *rr = (struct raw_resctrl_resource *)r->res;

	seq_printf(seq, "%d\n", rr->num_pmg);

	return 0;
}

static int resctrl_num_mon_show(struct kernfs_open_file *of,
				struct seq_file *seq, void *v)
{
	struct resctrl_resource *r = of->kn->parent->priv;
	struct raw_resctrl_resource *rr = (struct raw_resctrl_resource *)r->res;

	seq_printf(seq, "%d\n", rr->num_mon);

	return 0;
}

int cpus_mon_write(struct rdtgroup *rdtgrp, cpumask_var_t newmask,
		   cpumask_var_t tmpmask)
{
	pr_info("unsupported on mon_groups, please use ctrlmon groups\n");
	return -EINVAL;
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
		if ((r->type == RDTCTRL_GROUP && t->closid == r->closid) ||
		    (r->type == RDTMON_GROUP && t->closid == r->closid &&
		     t->rmid == r->mon.rmid))
			seq_printf(s, "%d: partid = %d, pmg = %d, (group: partid %d, pmg %d, mon %d)\n",
				   t->pid, t->closid, t->rmid,
				   r->closid, r->mon.rmid, r->mon.mon);
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

int resctrl_ctrlmon_enable(struct kernfs_node *parent_kn,
			  struct resctrl_group *prgrp,
			  struct kernfs_node **dest_kn)
{
	int ret;

	/* only for RDTCTRL_GROUP */
	if (prgrp->type == RDTMON_GROUP)
		return 0;

	ret = alloc_mon();
	if (ret < 0) {
		rdt_last_cmd_puts("out of monitors\n");
		pr_info("out of monitors: ret %d\n", ret);
		return ret;
	}
	prgrp->mon.mon = ret;
	prgrp->mon.rmid = 0;

	ret = mkdir_mondata_all(parent_kn, prgrp, dest_kn);
	if (ret) {
		rdt_last_cmd_puts("kernfs subdir error\n");
		free_mon(ret);
	}

	return ret;
}

void resctrl_ctrlmon_disable(struct kernfs_node *kn_mondata,
			    struct resctrl_group *prgrp)
{
	struct resctrl_resource *r;
	struct raw_resctrl_resource *rr;
	struct rdt_domain *dom;
	int mon = prgrp->mon.mon;

	/* only for RDTCTRL_GROUP */
	if (prgrp->type == RDTMON_GROUP)
		return;

	/* disable monitor before free mon */
	for_each_resctrl_resource(r) {
		if (r->mon_enabled) {
			rr = (struct raw_resctrl_resource *)r->res;

			list_for_each_entry(dom, &r->domains, list) {
				rr->mon_write(dom, prgrp, false);
			}
		}
	}

	free_mon(mon);
	kernfs_remove(kn_mondata);

	return;
}

static ssize_t resctrl_group_ctrlmon_write(struct kernfs_open_file *of,
				    char *buf, size_t nbytes, loff_t off)
{
	struct rdtgroup *rdtgrp;
	int ret = 0;
	int ctrlmon;

	if (kstrtoint(strstrip(buf), 0, &ctrlmon) || ctrlmon < 0)
		return -EINVAL;
	rdtgrp = resctrl_group_kn_lock_live(of->kn);
	rdt_last_cmd_clear();

	if (!rdtgrp) {
		ret = -ENOENT;
		goto unlock;
	}

	if ((rdtgrp->flags & RDT_CTRLMON) && !ctrlmon) {
		/* [FIXME] disable & remove mon_data dir */
		rdtgrp->flags &= ~RDT_CTRLMON;
		resctrl_ctrlmon_disable(rdtgrp->mon.mon_data_kn, rdtgrp);
	} else if (!(rdtgrp->flags & RDT_CTRLMON) && ctrlmon) {
		ret = resctrl_ctrlmon_enable(rdtgrp->kn, rdtgrp,
					     &rdtgrp->mon.mon_data_kn);
		if (!ret)
			rdtgrp->flags |= RDT_CTRLMON;
	} else {
		ret = -ENOENT;
	}

unlock:
	resctrl_group_kn_unlock(of->kn);
	return ret ?: nbytes;
}

static int resctrl_group_ctrlmon_show(struct kernfs_open_file *of,
			       struct seq_file *s, void *v)
{
	struct rdtgroup *rdtgrp;
	int ret = 0;

	rdtgrp = resctrl_group_kn_lock_live(of->kn);
	if (rdtgrp)
		seq_printf(s, "%d", !!(rdtgrp->flags & RDT_CTRLMON));
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
	},
	{
		.name		= "ctrlmon",
		.mode		= 0644,
		.kf_ops		= &resctrl_group_kf_single_ops,
		.write		= resctrl_group_ctrlmon_write,
		.seq_show	= resctrl_group_ctrlmon_show,
		.fflags		= RF_CTRL_BASE,
	},
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

static void mpam_domains_destroy(struct resctrl_resource *r)
{
	struct list_head *pos, *q;
	struct rdt_domain *d;

	list_for_each_safe(pos, q, &r->domains) {
		d = list_entry(pos, struct rdt_domain, list);
		list_del(pos);
		if (d) {
			kfree(d->ctrl_val);
			kfree(d);
		}
	}
}

static void mpam_domains_init(struct resctrl_resource *r)
{
	int i, id = 0;
	size_t num_nodes = ARRAY_SIZE(mpam_node_all);
	struct mpam_node *n;
	struct list_head *add_pos = NULL;
	struct rdt_domain *d;
	struct raw_resctrl_resource *rr = (struct raw_resctrl_resource *)r->res;
	u32 val;

	for (i = 0; i < num_nodes; i++) {
		n = &mpam_node_all[i];
		if (r->rid != n->type)
			continue;

		d = mpam_find_domain(r, id, &add_pos);
		if (IS_ERR(d)) {
			mpam_domains_destroy(r);
			pr_warn("Could't find cache id %d\n", id);
			return;
		}

		if (!d)
			d = kzalloc(sizeof(*d), GFP_KERNEL);
		else
			continue;

		if (!d) {
			mpam_domains_destroy(r);
			return;
		}

		d->id = id;
		d->base = n->base;
		cpumask_copy(&d->cpu_mask, &n->cpu_mask);
		rr->default_ctrl = n->default_ctrl;

		val = mpam_readl(d->base + MPAMF_IDR);
		rr->num_partid = MPAMF_IDR_PARTID_MAX_GET(val) + 1;
		rr->num_pmg = MPAMF_IDR_PMG_MAX_GET(val) + 1;

		r->mon_capable = MPAMF_IDR_HAS_MSMON(val);
		r->mon_enabled = MPAMF_IDR_HAS_MSMON(val);

		if (r->rid == MPAM_RESOURCE_CACHE) {
			r->alloc_capable = MPAMF_IDR_HAS_CPOR_PART(val);
			r->alloc_enabled = MPAMF_IDR_HAS_CPOR_PART(val);

			val = mpam_readl(d->base + MPAMF_CSUMON_IDR);
			rr->num_mon = MPAMF_IDR_NUM_MON(val);
		} else if (r->rid == MPAM_RESOURCE_MC) {
			r->alloc_capable = MPAMF_IDR_HAS_MBW_PART(val);
			r->alloc_enabled = MPAMF_IDR_HAS_MBW_PART(val);

			val = mpam_readl(d->base + MPAMF_MBWUMON_IDR);
			rr->num_mon = MPAMF_IDR_NUM_MON(val);
		}

		r->alloc_capable = 1;
		r->alloc_enabled = 1;
		r->mon_capable = 1;
		r->mon_enabled = 1;

		d->cpus_list = n->cpus_list;

		d->ctrl_val = kmalloc_array(rr->num_partid, sizeof(*d->ctrl_val), GFP_KERNEL);
		if (!d->ctrl_val) {
			kfree(d);
			mpam_domains_destroy(r);

			return;
		}

		if (add_pos)
			list_add_tail(&d->list, add_pos);

		id++;
	}
}

int __read_mostly mpam_enabled;
static int __init mpam_setup(char *str)
{
	mpam_enabled = 1;
	return 1;
}
__setup("mpam", mpam_setup);

static int __init mpam_late_init(void)
{
	struct resctrl_resource *r;
	int state, ret;

	if (!mpam_enabled)
		return 0;

	if (!cpus_have_const_cap(ARM64_HAS_MPAM))
		return -ENODEV;

	rdt_alloc_capable = 1;
	rdt_mon_capable = 1;

	mpam_init_padding();

	ret = mpam_nodes_init();
	if (ret) {
		pr_err("internal error: bad cpu list\n");
		return ret;
	}

	mpam_domains_init(&resctrl_resources_all[MPAM_RESOURCE_CACHE]);
	mpam_domains_init(&resctrl_resources_all[MPAM_RESOURCE_MC]);

	state = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
				  "arm64/mpam:online:",
				  mpam_online_cpu, mpam_offline_cpu);
	if (state < 0)
		return state;

	register_resctrl_specific_files(res_specific_files, ARRAY_SIZE(res_specific_files));

	seq_buf_init(&last_cmd_status, last_cmd_status_buf,
		     sizeof(last_cmd_status_buf));

	ret = resctrl_group_init();
	if (ret) {
		cpuhp_remove_state(state);
		return ret;
	}

	for_each_resctrl_resource(r) {
		if (r->alloc_capable)
			pr_info("MPAM %s allocation detected\n", r->name);
	}

	for_each_resctrl_resource(r) {
		if (r->mon_capable)
			pr_info("MPAM %s monitoring detected\n", r->name);
	}

	return 0;
}

late_initcall(mpam_late_init);

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
	u64 partid = state->default_closid;
	u64 pmg = state->default_rmid;

	/*
	 * If this task has a closid/rmid assigned, use it.
	 * Else use the closid/rmid assigned to this cpu.
	 */
	if (static_branch_likely(&resctrl_alloc_enable_key)) {
		if (current->closid)
			partid = current->closid;
	}

	if (static_branch_likely(&resctrl_mon_enable_key)) {
		if (current->rmid)
			pmg = current->rmid;
	}

	if (partid != state->cur_closid || pmg != state->cur_rmid) {
		u64 reg;
		state->cur_closid = partid;
		state->cur_rmid = pmg;

		/* set in EL0 */
		reg = mpam_read_sysreg_s(SYS_MPAM0_EL1, "SYS_MPAM0_EL1");
		reg = PARTID_SET(reg, partid);
		reg = PMG_SET(reg, pmg);
		mpam_write_sysreg_s(reg, SYS_MPAM0_EL1, "SYS_MPAM0_EL1");

		/* set in EL1 */
		reg = mpam_read_sysreg_s(SYS_MPAM1_EL1, "SYS_MPAM1_EL1");
		reg = PARTID_SET(reg, partid);
		reg = PMG_SET(reg, pmg);
		mpam_write_sysreg_s(reg, SYS_MPAM1_EL1, "SYS_MPAM1_EL1");
	}
}
