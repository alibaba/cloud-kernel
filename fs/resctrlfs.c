// SPDX-License-Identifier: GPL-2.0
/*
 * User interface for ARM v8 MPAM
 *
 * Copyright (C) 2018-2019 Huawei Technologies Co., Ltd
 *
 * Author:
 *   Fenghua Yu <fenghua.yu@intel.com>
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

#include <linux/cpu.h>
#include <linux/fs.h>
#include <linux/sysfs.h>
#include <linux/kernfs.h>
#include <linux/seq_buf.h>
#include <linux/seq_file.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/resctrlfs.h>

#include <uapi/linux/magic.h>

#include <asm/resctrl.h>

DEFINE_STATIC_KEY_FALSE(resctrl_enable_key);
DEFINE_STATIC_KEY_FALSE(resctrl_mon_enable_key);
DEFINE_STATIC_KEY_FALSE(resctrl_alloc_enable_key);
static struct kernfs_root *resctrl_root;
struct resctrl_group resctrl_group_default;
LIST_HEAD(resctrl_all_groups);

/* Kernel fs node for "info" directory under root */
static struct kernfs_node *kn_info;

/* Kernel fs node for "mon_groups" directory under root */
static struct kernfs_node *kn_mongrp;

/* Kernel fs node for "mon_data" directory under root */
static struct kernfs_node *kn_mondata;

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

static int resctrl_group_add_file(struct kernfs_node *parent_kn, struct rftype *rft)
{
	struct kernfs_node *kn;
	int ret;

	kn = __kernfs_create_file(parent_kn, rft->name, rft->mode,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
				  0, rft->kf_ops, rft, NULL, NULL);
	if (IS_ERR(kn))
		return PTR_ERR(kn);

	ret = resctrl_group_kn_set_ugid(kn);
	if (ret) {
		kernfs_remove(kn);
		return ret;
	}

	return 0;
}

static struct rftype *res_common_files;
static size_t res_common_files_len;

int register_resctrl_specific_files(struct rftype *files, size_t len)
{
	if (res_common_files) {
		pr_err("Only allowed register specific files once\n");
		return -EINVAL;
	}

	if (!files) {
		pr_err("Invalid input files\n");
		return -EINVAL;
	}

	res_common_files = files;
	res_common_files_len = len;

	return 0;
}

static int __resctrl_group_add_files(struct kernfs_node *kn, unsigned long fflags,
				     struct rftype *rfts, int len)
{
	struct rftype *rft;
	int ret = 0;

	lockdep_assert_held(&resctrl_group_mutex);

	for (rft = rfts; rft < rfts + len; rft++) {
		if (rft->enable && !rft->enable(NULL))
			continue;

		if ((fflags & rft->fflags) == rft->fflags) {
			ret = resctrl_group_add_file(kn, rft);
			if (ret)
				goto error;
		}
	}

	return 0;
error:
	pr_warn("Failed to add %s, err=%d\n", rft->name, ret);
	while (--rft >= rfts) {
		if ((fflags & rft->fflags) == rft->fflags)
			kernfs_remove_by_name(kn, rft->name);
	}
	return ret;
}

static int resctrl_group_add_files(struct kernfs_node *kn, unsigned long fflags)
{
	int ret = 0;

	if (res_common_files)
		ret = __resctrl_group_add_files(kn, fflags, res_common_files,
						res_common_files_len);

	return ret;
}

static int resctrl_group_mkdir_info_resdir(struct resctrl_resource *r, char *name,
				      unsigned long fflags)
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

static int resctrl_group_create_info_dir(struct kernfs_node *parent_kn)
{
	struct resctrl_resource *r;
	unsigned long fflags;
	char name[32];
	int ret;

	/* create the directory */
	kn_info = kernfs_create_dir(parent_kn, "info", parent_kn->mode, NULL);
	if (IS_ERR(kn_info))
		return PTR_ERR(kn_info);
	kernfs_get(kn_info);

	ret = resctrl_group_add_files(kn_info, RF_TOP_INFO);
	if (ret)
		goto out_destroy;

	for_each_resctrl_resource(r) {
		if (r->alloc_enabled) {
			fflags =  r->fflags | RF_CTRL_INFO;
			ret = resctrl_group_mkdir_info_resdir(r, r->name, fflags);
			if (ret)
				goto out_destroy;
		}
	}

	for_each_resctrl_resource(r) {
		if (r->mon_enabled) {
			fflags =  r->fflags | RF_MON_INFO;
			snprintf(name, sizeof(name), "%s_MON", r->name);
			ret = resctrl_group_mkdir_info_resdir(r, name, fflags);
			if (ret)
				goto out_destroy;
		}
	}

	/*
	 m This extra ref will be put in kernfs_remove() and guarantees
	 * that @rdtgrp->kn is always accessible.
	 */
	kernfs_get(kn_info);

	ret = resctrl_group_kn_set_ugid(kn_info);
	if (ret)
		goto out_destroy;

	kernfs_activate(kn_info);

	return 0;

out_destroy:
	kernfs_remove(kn_info);
	return ret;
}

/*
 * We don't allow resctrl_group directories to be created anywhere
 * except the root directory. Thus when looking for the resctrl_group
 * structure for a kernfs node we are either looking at a directory,
 * in which case the resctrl_group structure is pointed at by the "priv"
 * field, otherwise we have a file, and need only look to the parent
 * to find the resctrl_group.
 */
static struct resctrl_group *kernfs_to_resctrl_group(struct kernfs_node *kn)
{
	if (kernfs_type(kn) == KERNFS_DIR) {
		/*
		 * All the resource directories use "kn->priv"
		 * to point to the "struct resctrl_group" for the
		 * resource. "info" and its subdirectories don't
		 * have resctrl_group structures, so return NULL here.
		 */
		if (kn == kn_info || kn->parent == kn_info)
			return NULL;
		else
			return kn->priv;
	} else {
		return kn->parent->priv;
	}
}

struct resctrl_group *resctrl_group_kn_lock_live(struct kernfs_node *kn)
{
	struct resctrl_group *rdtgrp = kernfs_to_resctrl_group(kn);

	if (!rdtgrp)
		return NULL;

	atomic_inc(&rdtgrp->waitcount);
	kernfs_break_active_protection(kn);

	mutex_lock(&resctrl_group_mutex);

	/* Was this group deleted while we waited? */
	if (rdtgrp->flags & RDT_DELETED)
		return NULL;

	return rdtgrp;
}

void resctrl_group_kn_unlock(struct kernfs_node *kn)
{
	struct resctrl_group *rdtgrp = kernfs_to_resctrl_group(kn);

	if (!rdtgrp)
		return;

	mutex_unlock(&resctrl_group_mutex);

	if (atomic_dec_and_test(&rdtgrp->waitcount) &&
	    (rdtgrp->flags & RDT_DELETED)) {
		kernfs_unbreak_active_protection(kn);
		kernfs_put(rdtgrp->kn);
		kfree(rdtgrp);
	} else {
		kernfs_unbreak_active_protection(kn);
	}
}

static struct dentry *resctrl_mount(struct file_system_type *fs_type,
				int flags, const char *unused_dev_name,
				void *data)
{
	struct dentry *dentry;
	int ret;

	cpus_read_lock();
	mutex_lock(&resctrl_group_mutex);
	/*
	 * resctrl file system can only be mounted once.
	 */
	if (static_branch_unlikely(&resctrl_enable_key)) {
		dentry = ERR_PTR(-EBUSY);
		goto out;
	}

	ret = parse_resctrl_group_fs_options(data);
	if (ret) {
		dentry = ERR_PTR(ret);
		goto out_options;
	}

	resctrl_id_init();

	ret = resctrl_group_create_info_dir(resctrl_group_default.kn);
	if (ret) {
		dentry = ERR_PTR(ret);
		goto out_options;
	}

	if (resctrl_mon_capable) {
		ret = mongroup_create_dir(resctrl_group_default.kn,
					  NULL, "mon_groups",
					  &kn_mongrp);
		if (ret) {
			dentry = ERR_PTR(ret);
			goto out_info;
		}
		kernfs_get(kn_mongrp);

#ifndef CONFIG_ARM64 /* [FIXME] arch specific code */
		ret = mkdir_mondata_all(resctrl_group_default.kn,
					&resctrl_group_default, &kn_mondata);
		if (ret) {
			dentry = ERR_PTR(ret);
			goto out_mongrp;
		}
		kernfs_get(kn_mondata);
		resctrl_group_default.mon.mon_data_kn = kn_mondata;
#endif
	}

	dentry = kernfs_mount(fs_type, flags, resctrl_root,
			      RDTGROUP_SUPER_MAGIC, NULL);
	if (IS_ERR(dentry))
		goto out_mondata;

	post_resctrl_mount();

	goto out;

out_mondata:
#ifndef CONFIG_ARM64 /* [FIXME] arch specific code */
	if (resctrl_mon_capable)
		kernfs_remove(kn_mondata);
out_mongrp:
#endif
	if (resctrl_mon_capable)
		kernfs_remove(kn_mongrp);
out_info:
	kernfs_remove(kn_info);
out_options:
	release_resctrl_group_fs_options();
out:
	rdt_last_cmd_clear();
	mutex_unlock(&resctrl_group_mutex);
	cpus_read_unlock();

	return dentry;
}

static bool is_closid_match(struct task_struct *t, struct resctrl_group *r)
{
	return (resctrl_alloc_capable &&
		(r->type == RDTCTRL_GROUP) && (t->closid == r->closid));
}

static bool is_rmid_match(struct task_struct *t, struct resctrl_group *r)
{
	return (resctrl_mon_capable &&
		(r->type == RDTMON_GROUP) && (t->rmid == r->mon.rmid));
}

/*
 * Move tasks from one to the other group. If @from is NULL, then all tasks
 * in the systems are moved unconditionally (used for teardown).
 *
 * If @mask is not NULL the cpus on which moved tasks are running are set
 * in that mask so the update smp function call is restricted to affected
 * cpus.
 */
static void resctrl_move_group_tasks(struct resctrl_group *from, struct resctrl_group *to,
				 struct cpumask *mask)
{
	struct task_struct *p, *t;

	read_lock(&tasklist_lock);
	for_each_process_thread(p, t) {
		if (!from || is_closid_match(t, from) ||
		    is_rmid_match(t, from)) {
			t->closid = to->closid;
			t->rmid = to->mon.rmid;

#ifdef CONFIG_SMP
			/*
			 * This is safe on x86 w/o barriers as the ordering
			 * of writing to task_cpu() and t->on_cpu is
			 * reverse to the reading here. The detection is
			 * inaccurate as tasks might move or schedule
			 * before the smp function call takes place. In
			 * such a case the function call is pointless, but
			 * there is no other side effect.
			 */
			if (mask && t->on_cpu)
				cpumask_set_cpu(task_cpu(t), mask);
#endif
		}
	}
	read_unlock(&tasklist_lock);
}

static void free_all_child_rdtgrp(struct resctrl_group *rdtgrp)
{
	struct resctrl_group *sentry, *stmp;
	struct list_head *head;

	head = &rdtgrp->mon.crdtgrp_list;
	list_for_each_entry_safe(sentry, stmp, head, mon.crdtgrp_list) {
		free_mon_id(sentry->mon.rmid);
		list_del(&sentry->mon.crdtgrp_list);
		kfree(sentry);
	}
}

/*
 * Forcibly remove all of subdirectories under root.
 */
static void rmdir_all_sub(void)
{
	struct resctrl_group *rdtgrp, *tmp;

	/* Move all tasks to the default resource group */
	resctrl_move_group_tasks(NULL, &resctrl_group_default, NULL);

	list_for_each_entry_safe(rdtgrp, tmp, &resctrl_all_groups, resctrl_group_list) {
		/* Free any child rmids */
		free_all_child_rdtgrp(rdtgrp);

		/* Remove each resctrl_group other than root */
		if (rdtgrp == &resctrl_group_default)
			continue;

		/*
		 * Give any CPUs back to the default group. We cannot copy
		 * cpu_online_mask because a CPU might have executed the
		 * offline callback already, but is still marked online.
		 */
		cpumask_or(&resctrl_group_default.cpu_mask,
			   &resctrl_group_default.cpu_mask, &rdtgrp->cpu_mask);

		free_mon_id(rdtgrp->mon.rmid);

		kernfs_remove(rdtgrp->kn);
		list_del(&rdtgrp->resctrl_group_list);
		kfree(rdtgrp);
	}
	/* Notify online CPUs to update per cpu storage and PQR_ASSOC MSR */
	update_closid_rmid(cpu_online_mask, &resctrl_group_default);

	kernfs_remove(kn_info);
	kernfs_remove(kn_mongrp);
	kernfs_remove(kn_mondata);
}

static void resctrl_kill_sb(struct super_block *sb)
{

	cpus_read_lock();
	mutex_lock(&resctrl_group_mutex);

	resctrl_resource_reset();

	rmdir_all_sub();
	static_branch_disable_cpuslocked(&resctrl_alloc_enable_key);
	static_branch_disable_cpuslocked(&resctrl_mon_enable_key);
	static_branch_disable_cpuslocked(&resctrl_enable_key);
	kernfs_kill_sb(sb);
	mutex_unlock(&resctrl_group_mutex);
	cpus_read_unlock();
}

static struct file_system_type resctrl_fs_type = {
	.name    = "resctrl",
	.mount   = resctrl_mount,
	.kill_sb = resctrl_kill_sb,
};

static int mkdir_resctrl_prepare(struct kernfs_node *parent_kn,
			     struct kernfs_node *prgrp_kn,
			     const char *name, umode_t mode,
			     enum rdt_group_type rtype, struct resctrl_group **r)
{
	struct resctrl_group *prdtgrp, *rdtgrp;
	struct kernfs_node *kn;
	uint files = 0;
	int ret;

	prdtgrp = resctrl_group_kn_lock_live(prgrp_kn);
	rdt_last_cmd_clear();
	if (!prdtgrp) {
		ret = -ENODEV;
		rdt_last_cmd_puts("directory was removed\n");
		goto out_unlock;
	}

	/* allocate the resctrl_group. */
	rdtgrp = kzalloc(sizeof(*rdtgrp), GFP_KERNEL);
	if (!rdtgrp) {
		ret = -ENOSPC;
		rdt_last_cmd_puts("kernel out of memory\n");
		goto out_unlock;
	}
	*r = rdtgrp;
	rdtgrp->mon.parent = prdtgrp;
	rdtgrp->type = rtype;
	INIT_LIST_HEAD(&rdtgrp->mon.crdtgrp_list);

	/* kernfs creates the directory for rdtgrp */
	kn = kernfs_create_dir(parent_kn, name, mode, rdtgrp);
	if (IS_ERR(kn)) {
		ret = PTR_ERR(kn);
		rdt_last_cmd_puts("kernfs create error\n");
		goto out_free_rgrp;
	}
	rdtgrp->kn = kn;

	/*
	 * kernfs_remove() will drop the reference count on "kn" which
	 * will free it. But we still need it to stick around for the
	 * resctrl_group_kn_unlock(kn} call below. Take one extra reference
	 * here, which will be dropped inside resctrl_group_kn_unlock().
	 */
	kernfs_get(kn);

	ret = resctrl_group_kn_set_ugid(kn);
	if (ret) {
		rdt_last_cmd_puts("kernfs perm error\n");
		goto out_destroy;
	}

	files = RFTYPE_BASE | BIT(RF_CTRLSHIFT + rtype);
	ret = resctrl_group_add_files(kn, files);
	if (ret) {
		rdt_last_cmd_puts("kernfs fill error\n");
		goto out_destroy;
	}

	if (resctrl_mon_capable) {
#ifdef CONFIG_ARM64
		ret = resctrl_mkdir_ctrlmon_mondata(kn, rdtgrp, &rdtgrp->mon.mon_data_kn);
		if (ret < 0) {
			rdt_last_cmd_puts("out of monitors or PMGs\n");
			goto out_destroy;
		}

#else
		ret = alloc_mon_id();
		if (ret < 0) {
			rdt_last_cmd_puts("out of RMIDs\n");
			goto out_destroy;
		}
		rdtgrp->mon.rmid = ret;

		ret = mkdir_mondata_all(kn, rdtgrp, &rdtgrp->mon.mon_data_kn);
		if (ret) {
			rdt_last_cmd_puts("kernfs subdir error\n");
			goto out_idfree;
		}
#endif
	}
	kernfs_activate(kn);

	/*
	 * The caller unlocks the prgrp_kn upon success.
	 */
	return 0;

#ifndef CONFIG_ARM64
out_idfree:
	free_mon_id(rdtgrp->mon.rmid);
#endif
out_destroy:
	kernfs_remove(rdtgrp->kn);
out_free_rgrp:
	kfree(rdtgrp);
out_unlock:
	resctrl_group_kn_unlock(prgrp_kn);
	return ret;
}

static void mkdir_resctrl_prepare_clean(struct resctrl_group *rgrp)
{
	kernfs_remove(rgrp->kn);
	free_mon_id(rgrp->mon.rmid);
	kfree(rgrp);
}

/*
 * Create a monitor group under "mon_groups" directory of a control
 * and monitor group(ctrl_mon). This is a resource group
 * to monitor a subset of tasks and cpus in its parent ctrl_mon group.
 */
static int resctrl_group_mkdir_mon(struct kernfs_node *parent_kn,
			      struct kernfs_node *prgrp_kn,
			      const char *name,
			      umode_t mode)
{
	struct resctrl_group *rdtgrp, *prgrp;
	int ret;

	ret = mkdir_resctrl_prepare(parent_kn, prgrp_kn, name, mode, RDTMON_GROUP,
				&rdtgrp);
	if (ret)
		return ret;

	prgrp = rdtgrp->mon.parent;
	rdtgrp->closid = prgrp->closid;

	/*
	 * Add the rdtgrp to the list of rdtgrps the parent
	 * ctrl_mon group has to track.
	 */
	list_add_tail(&rdtgrp->mon.crdtgrp_list, &prgrp->mon.crdtgrp_list);

	resctrl_group_kn_unlock(prgrp_kn);
	return ret;
}

/*
 * These are resctrl_groups created under the root directory. Can be used
 * to allocate and monitor resources.
 */
static int resctrl_group_mkdir_ctrl_mon(struct kernfs_node *parent_kn,
				   struct kernfs_node *prgrp_kn,
				   const char *name, umode_t mode)
{
	struct resctrl_group *rdtgrp;
	struct kernfs_node *kn;
	u32 closid;
	int ret;

	ret = mkdir_resctrl_prepare(parent_kn, prgrp_kn, name, mode, RDTCTRL_GROUP,
				&rdtgrp);
	if (ret)
		return ret;

	kn = rdtgrp->kn;
	ret = resctrl_id_alloc();
	if (ret < 0) {
		rdt_last_cmd_puts("out of CLOSIDs\n");
		goto out_common_fail;
	}
	closid = ret;
	ret = 0;

	rdtgrp->closid = closid;

	ret = rdtgroup_init_alloc(rdtgrp);
	if (ret < 0)
		goto out_id_free;

	list_add(&rdtgrp->resctrl_group_list, &resctrl_all_groups);

	if (resctrl_mon_capable) {
		/*
		 * Create an empty mon_groups directory to hold the subset
		 * of tasks and cpus to monitor.
		 */
		ret = mongroup_create_dir(kn, NULL, "mon_groups", NULL);
		if (ret) {
			rdt_last_cmd_puts("kernfs subdir error\n");
			goto out_id_free;
		}
	}

	goto out_unlock;

out_id_free:
	resctrl_id_free(closid);
	list_del(&rdtgrp->resctrl_group_list);
out_common_fail:
	mkdir_resctrl_prepare_clean(rdtgrp);
out_unlock:
	resctrl_group_kn_unlock(prgrp_kn);
	return ret;
}

/*
 * We allow creating mon groups only with in a directory called "mon_groups"
 * which is present in every ctrl_mon group. Check if this is a valid
 * "mon_groups" directory.
 *
 * 1. The directory should be named "mon_groups".
 * 2. The mon group itself should "not" be named "mon_groups".
 *   This makes sure "mon_groups" directory always has a ctrl_mon group
 *   as parent.
 */
static bool is_mon_groups(struct kernfs_node *kn, const char *name)
{
	return (!strcmp(kn->name, "mon_groups") &&
		strcmp(name, "mon_groups"));
}

static int resctrl_group_mkdir(struct kernfs_node *parent_kn, const char *name,
			  umode_t mode)
{
	/* Do not accept '\n' to avoid unparsable situation. */
	if (strchr(name, '\n'))
		return -EINVAL;

	/*
	 * If the parent directory is the root directory and RDT
	 * allocation is supported, add a control and monitoring
	 * subdirectory
	 */
	if (resctrl_alloc_capable && parent_kn == resctrl_group_default.kn)
		return resctrl_group_mkdir_ctrl_mon(parent_kn, parent_kn, name, mode);

	/*
	 * If RDT monitoring is supported and the parent directory is a valid
	 * "mon_groups" directory, add a monitoring subdirectory.
	 */
	if (resctrl_mon_capable && is_mon_groups(parent_kn, name))
		return resctrl_group_mkdir_mon(parent_kn, parent_kn->parent, name, mode);

	return -EPERM;
}

static void resctrl_group_rm_mon(struct resctrl_group *rdtgrp,
			      cpumask_var_t tmpmask)
{
	struct resctrl_group *prdtgrp = rdtgrp->mon.parent;
	int cpu;

#ifdef CONFIG_ARM64 /* [FIXME] arch specific code */
	free_mon(rdtgrp->mon.mon);
#endif

	/* Give any tasks back to the parent group */
	resctrl_move_group_tasks(rdtgrp, prdtgrp, tmpmask);

	/* Update per cpu rmid of the moved CPUs first */
	for_each_cpu(cpu, &rdtgrp->cpu_mask)
		per_cpu(pqr_state.default_rmid, cpu) = prdtgrp->mon.rmid;
	/*
	 * Update the MSR on moved CPUs and CPUs which have moved
	 * task running on them.
	 */
	cpumask_or(tmpmask, tmpmask, &rdtgrp->cpu_mask);
	update_closid_rmid(tmpmask, NULL);

	rdtgrp->flags |= RDT_DELETED;
	free_mon_id(rdtgrp->mon.rmid);

	/*
	 * Remove the rdtgrp from the parent ctrl_mon group's list
	 */
	WARN_ON(list_empty(&prdtgrp->mon.crdtgrp_list));
	list_del(&rdtgrp->mon.crdtgrp_list);
}

static int resctrl_group_rmdir_mon(struct kernfs_node *kn, struct resctrl_group *rdtgrp,
			      cpumask_var_t tmpmask)
{
	resctrl_group_rm_mon(rdtgrp, tmpmask);

	/*
	 * one extra hold on this, will drop when we kfree(rdtgrp)
	 * in resctrl_group_kn_unlock()
	 */
	kernfs_get(kn);
	kernfs_remove(rdtgrp->kn);

	return 0;
}

static void resctrl_group_rm_ctrl(struct resctrl_group *rdtgrp, cpumask_var_t tmpmask)
{
	int cpu;

	/* Give any tasks back to the default group */
	resctrl_move_group_tasks(rdtgrp, &resctrl_group_default, tmpmask);

	/* Give any CPUs back to the default group */
	cpumask_or(&resctrl_group_default.cpu_mask,
		   &resctrl_group_default.cpu_mask, &rdtgrp->cpu_mask);

	/* Update per cpu closid and rmid of the moved CPUs first */
	for_each_cpu(cpu, &rdtgrp->cpu_mask) {
		per_cpu(pqr_state.default_closid, cpu) = resctrl_group_default.closid;
		per_cpu(pqr_state.default_rmid, cpu) = resctrl_group_default.mon.rmid;
	}

	/*
	 * Update the MSR on moved CPUs and CPUs which have moved
	 * task running on them.
	 */
	cpumask_or(tmpmask, tmpmask, &rdtgrp->cpu_mask);
	update_closid_rmid(tmpmask, NULL);

	rdtgrp->flags |= RDT_DELETED;
	resctrl_id_free(rdtgrp->closid);
	free_mon_id(rdtgrp->mon.rmid);

	/*
	 * Free all the child monitor group rmids.
	 */
	free_all_child_rdtgrp(rdtgrp);

	list_del(&rdtgrp->resctrl_group_list);
}

static int resctrl_group_rmdir_ctrl(struct kernfs_node *kn, struct resctrl_group *rdtgrp,
			       cpumask_var_t tmpmask)
{
#ifdef CONFIG_ARM64 /* [FIXME] arch specific code */
	if (rdtgrp->flags & RDT_CTRLMON)
		return -EPERM;
#endif

	resctrl_group_rm_ctrl(rdtgrp, tmpmask);

	/*
	 * one extra hold on this, will drop when we kfree(rdtgrp)
	 * in resctrl_group_kn_unlock()
	 */
	kernfs_get(kn);
	kernfs_remove(rdtgrp->kn);

	return 0;
}

static int resctrl_group_rmdir(struct kernfs_node *kn)
{
	struct kernfs_node *parent_kn = kn->parent;
	struct resctrl_group *rdtgrp;
	cpumask_var_t tmpmask;
	int ret = 0;

	if (!zalloc_cpumask_var(&tmpmask, GFP_KERNEL))
		return -ENOMEM;

	rdtgrp = resctrl_group_kn_lock_live(kn);
	if (!rdtgrp) {
		ret = -EPERM;
		goto out;
	}

	/*
	 * If the resctrl_group is a ctrl_mon group and parent directory
	 * is the root directory, remove the ctrl_mon group.
	 *
	 * If the resctrl_group is a mon group and parent directory
	 * is a valid "mon_groups" directory, remove the mon group.
	 */
	if (rdtgrp->type == RDTCTRL_GROUP && parent_kn == resctrl_group_default.kn)
		ret = resctrl_group_rmdir_ctrl(kn, rdtgrp, tmpmask);
	else if (rdtgrp->type == RDTMON_GROUP &&
		 is_mon_groups(parent_kn, kn->name))
		ret = resctrl_group_rmdir_mon(kn, rdtgrp, tmpmask);
	else
		ret = -EPERM;

out:
	resctrl_group_kn_unlock(kn);
	free_cpumask_var(tmpmask);
	return ret;
}

static int resctrl_group_show_options(struct seq_file *seq, struct kernfs_root *kf)
{
	return __resctrl_group_show_options(seq);
}

static struct kernfs_syscall_ops resctrl_group_kf_syscall_ops = {
	.mkdir		= resctrl_group_mkdir,
	.rmdir		= resctrl_group_rmdir,
	.show_options	= resctrl_group_show_options,
};

static void resctrl_group_default_init(struct resctrl_group *r)
{
	r->closid = 0;
	r->mon.rmid = 0;
	r->type = RDTCTRL_GROUP;
}

static int __init resctrl_group_setup_root(void)
{
	int ret;

	resctrl_root = kernfs_create_root(&resctrl_group_kf_syscall_ops,
				      KERNFS_ROOT_CREATE_DEACTIVATED,
				      &resctrl_group_default);
	if (IS_ERR(resctrl_root))
		return PTR_ERR(resctrl_root);

	mutex_lock(&resctrl_group_mutex);

	resctrl_group_default_init(&resctrl_group_default);
	INIT_LIST_HEAD(&resctrl_group_default.mon.crdtgrp_list);

	list_add(&resctrl_group_default.resctrl_group_list, &resctrl_all_groups);

	ret = resctrl_group_add_files(resctrl_root->kn, RF_CTRL_BASE);
	if (ret) {
		kernfs_destroy_root(resctrl_root);
		goto out;
	}

	resctrl_group_default.kn = resctrl_root->kn;
	kernfs_activate(resctrl_group_default.kn);

out:
	mutex_unlock(&resctrl_group_mutex);

	return ret;
}

/*
 * resctrl_group_init - resctrl_group initialization
 *
 * Setup resctrl file system including set up root, create mount point,
 * register resctrl_group filesystem, and initialize files under root directory.
 *
 * Return: 0 on success or -errno
 */
int __init resctrl_group_init(void)
{
	int ret = 0;

	ret = resctrl_group_setup_root();
	if (ret)
		return ret;

	ret = sysfs_create_mount_point(fs_kobj, "resctrl");
	if (ret)
		goto cleanup_root;

	ret = register_filesystem(&resctrl_fs_type);
	if (ret)
		goto cleanup_mountpoint;

	return 0;

cleanup_mountpoint:
	sysfs_remove_mount_point(fs_kobj, "resctrl");
cleanup_root:
	kernfs_destroy_root(resctrl_root);

	return ret;
}
