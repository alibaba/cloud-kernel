/*
 *  Housekeeping management. Manage the targets for routine code that can run on
 *  any CPU: unbound workqueues, timers, kthreads and any offloadable work.
 *
 * Copyright (C) 2017 Red Hat, Inc., Frederic Weisbecker
 * Copyright (C) 2017-2018 SUSE, Frederic Weisbecker
 *
 */
#include "sched.h"

DEFINE_STATIC_KEY_FALSE(housekeeping_overriden);
EXPORT_SYMBOL_GPL(housekeeping_overriden);
static cpumask_var_t housekeeping_mask;
static unsigned int housekeeping_flags;

int housekeeping_any_cpu(enum hk_flags flags)
{
	if (static_branch_unlikely(&housekeeping_overriden))
		if (housekeeping_flags & flags)
			return cpumask_any_and(housekeeping_mask, cpu_online_mask);
	return smp_processor_id();
}
EXPORT_SYMBOL_GPL(housekeeping_any_cpu);

#ifdef CONFIG_CGROUP_SCHED
/*
 * dyn_allowed  -- allowed CPUs for wild tasks.
 *
 * dyn_isolated -- isolated CPUs for wild tasks.
 *
 * dyn_possible -- possible CPUs for dynamical isolation.
 */
static cpumask_var_t dyn_allowed;
static cpumask_var_t dyn_isolated;
static cpumask_var_t dyn_possible;

static bool dyn_isolcpus_ready;

DEFINE_STATIC_KEY_FALSE(dyn_isolcpus_enabled);
EXPORT_SYMBOL_GPL(dyn_isolcpus_enabled);
#endif

const struct cpumask *housekeeping_cpumask(enum hk_flags flags)
{
#ifdef CONFIG_CGROUP_SCHED
	if (static_branch_unlikely(&dyn_isolcpus_enabled))
		if (flags & HK_FLAG_DOMAIN)
			return dyn_allowed;
#endif

	if (static_branch_unlikely(&housekeeping_overriden))
		if (housekeeping_flags & flags)
			return housekeeping_mask;

	return cpu_possible_mask;
}
EXPORT_SYMBOL_GPL(housekeeping_cpumask);

void housekeeping_affine(struct task_struct *t, enum hk_flags flags)
{
	if (static_branch_unlikely(&housekeeping_overriden))
		if (housekeeping_flags & flags)
			set_cpus_allowed_ptr(t, housekeeping_mask);
}
EXPORT_SYMBOL_GPL(housekeeping_affine);

bool housekeeping_test_cpu(int cpu, enum hk_flags flags)
{
#ifdef CONFIG_CGROUP_SCHED
	if (static_branch_unlikely(&dyn_isolcpus_enabled))
		if (flags & HK_FLAG_DOMAIN)
			return cpumask_test_cpu(cpu, dyn_allowed);
#endif

	if (static_branch_unlikely(&housekeeping_overriden))
		if (housekeeping_flags & flags)
			return cpumask_test_cpu(cpu, housekeeping_mask);
	return true;
}
EXPORT_SYMBOL_GPL(housekeeping_test_cpu);

#ifdef CONFIG_CGROUP_SCHED
static inline void free_dyn_masks(void)
{
	free_cpumask_var(dyn_allowed);
	free_cpumask_var(dyn_isolated);
	free_cpumask_var(dyn_possible);
}
#endif

void __init housekeeping_init(void)
{
#ifdef CONFIG_CGROUP_SCHED
	if (zalloc_cpumask_var(&dyn_allowed, GFP_KERNEL) &&
	    zalloc_cpumask_var(&dyn_isolated, GFP_KERNEL) &&
	    zalloc_cpumask_var(&dyn_possible, GFP_KERNEL)) {
		cpumask_copy(dyn_allowed, cpu_possible_mask);
		cpumask_copy(dyn_possible, cpu_possible_mask);
		dyn_isolcpus_ready = true;
	} else
		free_dyn_masks();
#endif

	if (!housekeeping_flags)
		return;

	static_branch_enable(&housekeeping_overriden);

	if (housekeeping_flags & HK_FLAG_TICK)
		sched_tick_offload_init();

	/* We need at least one CPU to handle housekeeping work */
	WARN_ON_ONCE(cpumask_empty(housekeeping_mask));
#ifdef CONFIG_CGROUP_SCHED
	if (housekeeping_flags & HK_FLAG_DOMAIN) {
		cpumask_copy(dyn_allowed, housekeeping_mask);
		cpumask_copy(dyn_possible, housekeeping_mask);
	}
#endif
}

static int __init housekeeping_setup(char *str, enum hk_flags flags)
{
	cpumask_var_t non_housekeeping_mask;
	int err;

	alloc_bootmem_cpumask_var(&non_housekeeping_mask);
	err = cpulist_parse(str, non_housekeeping_mask);
	if (err < 0 || cpumask_last(non_housekeeping_mask) >= nr_cpu_ids) {
		pr_warn("Housekeeping: nohz_full= or isolcpus= incorrect CPU range\n");
		free_bootmem_cpumask_var(non_housekeeping_mask);
		return 0;
	}

	if (!housekeeping_flags) {
		alloc_bootmem_cpumask_var(&housekeeping_mask);
		cpumask_andnot(housekeeping_mask,
			       cpu_possible_mask, non_housekeeping_mask);
		if (cpumask_empty(housekeeping_mask))
			cpumask_set_cpu(smp_processor_id(), housekeeping_mask);
	} else {
		cpumask_var_t tmp;

		alloc_bootmem_cpumask_var(&tmp);
		cpumask_andnot(tmp, cpu_possible_mask, non_housekeeping_mask);
		if (!cpumask_equal(tmp, housekeeping_mask)) {
			pr_warn("Housekeeping: nohz_full= must match isolcpus=\n");
			free_bootmem_cpumask_var(tmp);
			free_bootmem_cpumask_var(non_housekeeping_mask);
			return 0;
		}
		free_bootmem_cpumask_var(tmp);
	}

	if ((flags & HK_FLAG_TICK) && !(housekeeping_flags & HK_FLAG_TICK)) {
		if (IS_ENABLED(CONFIG_NO_HZ_FULL)) {
			tick_nohz_full_setup(non_housekeeping_mask);
		} else {
			pr_warn("Housekeeping: nohz unsupported."
				" Build with CONFIG_NO_HZ_FULL\n");
			free_bootmem_cpumask_var(non_housekeeping_mask);
			return 0;
		}
	}

	housekeeping_flags |= flags;

	free_bootmem_cpumask_var(non_housekeeping_mask);

	return 1;
}

static int __init housekeeping_nohz_full_setup(char *str)
{
	unsigned int flags;

	flags = HK_FLAG_TICK | HK_FLAG_WQ | HK_FLAG_TIMER | HK_FLAG_RCU | HK_FLAG_MISC;

	return housekeeping_setup(str, flags);
}
__setup("nohz_full=", housekeeping_nohz_full_setup);

static int __init housekeeping_isolcpus_setup(char *str)
{
	unsigned int flags = 0;

	while (isalpha(*str)) {
		if (!strncmp(str, "nohz,", 5)) {
			str += 5;
			flags |= HK_FLAG_TICK;
			continue;
		}

		if (!strncmp(str, "domain,", 7)) {
			str += 7;
			flags |= HK_FLAG_DOMAIN;
			continue;
		}

		pr_warn("isolcpus: Error, unknown flag\n");
		return 0;
	}

	/* Default behaviour for isolcpus without flags */
	if (!flags)
		flags |= HK_FLAG_DOMAIN;

	return housekeeping_setup(str, flags);
}
__setup("isolcpus=", housekeeping_isolcpus_setup);

#ifdef CONFIG_CGROUP_SCHED
static int dyn_isolcpus_show(struct seq_file *s, void *p)
{
	seq_printf(s, "%*pbl\n", cpumask_pr_args(dyn_isolated));

	return 0;
}

static int dyn_isolcpus_open(struct inode *inode, struct file *file)
{
	return single_open(file, dyn_isolcpus_show, NULL);
}

void wilds_cpus_allowed(struct cpumask *pmask)
{
	if (static_branch_unlikely(&dyn_isolcpus_enabled))
		cpumask_and(pmask, pmask, dyn_allowed);
}

void update_wilds_cpumask(cpumask_var_t new_allowed, cpumask_var_t old_allowed)
{
	struct css_task_iter it;
	struct task_struct *task;
	struct task_group *tg = &root_task_group;

	css_task_iter_start(&tg->css, 0, &it);
	while ((task = css_task_iter_next(&it))) {
		if (task->flags & PF_KTHREAD)
			continue;

		if (!cpumask_equal(&task->cpus_allowed, old_allowed))
			continue;

		set_cpus_allowed_ptr(task, new_allowed);
	}
	css_task_iter_end(&it);
}

static DEFINE_MUTEX(dyn_isolcpus_mutex);

static ssize_t write_dyn_isolcpus(struct file *file, const char __user *buf,
					size_t count, loff_t *ppos)
{
	int ret = count;
	cpumask_var_t isolated;
	cpumask_var_t new_allowed;
	cpumask_var_t old_allowed;

	mutex_lock(&dyn_isolcpus_mutex);

	if (!zalloc_cpumask_var(&isolated, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto out;
	}

	if (!zalloc_cpumask_var(&new_allowed, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto free_isolated;
	}

	if (!zalloc_cpumask_var(&old_allowed, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto free_new_allowed;
	}

	if (cpumask_parselist_user(buf, count, isolated)) {
		ret = -EINVAL;
		goto free_all;
	}

	if (!cpumask_subset(isolated, dyn_possible)) {
		ret = -EINVAL;
		goto free_all;
	}

	/* At least reserve one for wild tasks to run */
	cpumask_andnot(new_allowed, dyn_possible, isolated);
	if (!cpumask_intersects(new_allowed, cpu_online_mask)) {
		ret = -EINVAL;
		goto free_all;
	}

	cpumask_copy(old_allowed, dyn_allowed);
	cpumask_copy(dyn_allowed, new_allowed);
	cpumask_copy(dyn_isolated, isolated);

	if (cpumask_empty(dyn_isolated))
		static_branch_disable(&dyn_isolcpus_enabled);
	else
		static_branch_enable(&dyn_isolcpus_enabled);

	update_wilds_cpumask(new_allowed, old_allowed);

	rebuild_sched_domains();
	workqueue_set_unbound_cpumask(new_allowed);

free_all:
	free_cpumask_var(old_allowed);
free_new_allowed:
	free_cpumask_var(new_allowed);
free_isolated:
	free_cpumask_var(isolated);
out:
	mutex_unlock(&dyn_isolcpus_mutex);

	return ret;
}

static const struct file_operations proc_dyn_isolcpus_operations = {
	.open		= dyn_isolcpus_open,
	.read		= seq_read,
	.write		= write_dyn_isolcpus,
	.llseek		= noop_llseek,
};

static int __init dyn_isolcpus_init(void)
{
	if (dyn_isolcpus_ready &&
	    !proc_create("dyn_isolcpus", 0200, NULL,
				&proc_dyn_isolcpus_operations)) {
		dyn_isolcpus_ready = false;
		free_dyn_masks();
	}

	if (!dyn_isolcpus_ready)
		pr_err("Initialize Dynamical Isolation Failed\n");

	return 0;
}
early_initcall(dyn_isolcpus_init);
#endif
