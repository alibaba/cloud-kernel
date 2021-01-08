// SPDX-License-Identifier: GPL-2.0
/*
 * CPU accounting code for task groups.
 *
 * Based on the work by Paul Menage (menage@google.com) and Balbir Singh
 * (balbir@in.ibm.com).
 */
#include "sched.h"

/* Time spent by the tasks of the CPU accounting group executing in ... */
enum cpuacct_stat_index {
	CPUACCT_STAT_USER,	/* ... user mode */
	CPUACCT_STAT_SYSTEM,	/* ... kernel mode */

	CPUACCT_STAT_NSTATS,
};

static const char * const cpuacct_stat_desc[] = {
	[CPUACCT_STAT_USER] = "user",
	[CPUACCT_STAT_SYSTEM] = "system",
};

struct cpuacct_usage {
	u64	usages[CPUACCT_STAT_NSTATS];
	struct prev_cputime prev_cputime1; /* utime and stime */
	struct prev_cputime prev_cputime2; /* user and nice */
} ____cacheline_aligned;

#ifdef CONFIG_SCHED_SLI
/* Maintain various statistics */
struct cpuacct_alistats {
	u64		nr_migrations;
} ____cacheline_aligned;
#endif

enum sched_lat_stat_item {
	SCHED_LAT_WAIT,
	SCHED_LAT_BLOCK,
	SCHED_LAT_IOBLOCK,
	SCHED_LAT_CGROUP_WAIT,
	SCHED_LAT_NR_STAT
};

/*
 * [0, 1ms)
 * [1, 4ms)
 * [4, 7ms)
 * [7, 10ms)
 * [10, 100ms)
 * [100, 500ms)
 * [500, 1000ms)
 * [1000, 5000ms)
 * [5000, 10000ms)
 * [10000ms, INF)
 * total(ms)
 */
/* Scheduler latency histogram distribution, in milliseconds */
enum sched_lat_count_t {
	SCHED_LAT_0_1,
	SCHED_LAT_1_4,
	SCHED_LAT_4_7,
	SCHED_LAT_7_10,
	SCHED_LAT_10_20,
	SCHED_LAT_20_30,
	SCHED_LAT_30_40,
	SCHED_LAT_40_50,
	SCHED_LAT_50_100,
	SCHED_LAT_100_500,
	SCHED_LAT_500_1000,
	SCHED_LAT_1000_5000,
	SCHED_LAT_5000_10000,
	SCHED_LAT_10000_INF,
	SCHED_LAT_TOTAL,
	SCHED_LAT_NR,
	SCHED_LAT_NR_COUNT,
};

struct sched_cgroup_lat_stat_cpu {
	unsigned long item[SCHED_LAT_NR_STAT][SCHED_LAT_NR_COUNT];
};

static inline enum sched_lat_count_t get_sched_lat_count_idx(u64 msecs)
{
        if (msecs < 1)
                return SCHED_LAT_0_1;
        if (msecs < 10)
                return SCHED_LAT_0_1 + (msecs + 2) / 3;
        if (msecs < 50)
                return SCHED_LAT_7_10 + msecs / 10;
        if (msecs < 100)
                return SCHED_LAT_50_100;
        if (msecs < 1000)
                return SCHED_LAT_100_500 + (msecs / 500);
        if (msecs < 10000)
                return SCHED_LAT_1000_5000 + (msecs / 5000);

        return SCHED_LAT_10000_INF;
}

/* track CPU usage of a group of tasks and its child groups */
struct cpuacct {
	struct cgroup_subsys_state	css;
	/* cpuusage holds pointer to a u64-type object on every CPU */
	struct cpuacct_usage __percpu	*cpuusage;
#ifdef CONFIG_SCHED_SLI
	struct cpuacct_alistats __percpu *alistats;
	struct sched_cgroup_lat_stat_cpu __percpu *lat_stat_cpu;
#endif
	struct kernel_cpustat __percpu	*cpustat;

	ALI_HOTFIX_RESERVE(1)
	ALI_HOTFIX_RESERVE(2)
	ALI_HOTFIX_RESERVE(3)
	ALI_HOTFIX_RESERVE(4)
};

static inline struct cpuacct *cgroup_ca(struct cgroup *cgrp)
{
	return container_of(global_cgroup_css(cgrp, cpuacct_cgrp_id),
				struct cpuacct, css);
}

static inline struct cpuacct *css_ca(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct cpuacct, css) : NULL;
}

/* Return CPU accounting group to which this task belongs */
static inline struct cpuacct *task_ca(struct task_struct *tsk)
{
	return css_ca(task_css(tsk, cpuacct_cgrp_id));
}

static inline struct cpuacct *parent_ca(struct cpuacct *ca)
{
	return css_ca(ca->css.parent);
}

static DEFINE_PER_CPU(struct cpuacct_usage, root_cpuacct_cpuusage);
#ifdef CONFIG_SCHED_SLI
static DEFINE_PER_CPU(struct cpuacct_alistats, root_alistats);
static DEFINE_PER_CPU(struct sched_cgroup_lat_stat_cpu, root_lat_stat_cpu);
#endif
static struct cpuacct root_cpuacct = {
	.cpustat	= &kernel_cpustat,
	.cpuusage	= &root_cpuacct_cpuusage,
#ifdef CONFIG_SCHED_SLI
	.alistats	= &root_alistats,
	.lat_stat_cpu   = &root_lat_stat_cpu,
#endif
};

#ifdef CONFIG_SCHED_SLI
static DEFINE_STATIC_KEY_TRUE(cpuacct_no_sched_lat);
static int cpuacct_sched_lat_enabled_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", !static_key_enabled(&cpuacct_no_sched_lat));
	return 0;
}

static int cpuacct_sched_lat_enabled_open(struct inode *inode,
						struct file *file)
{
	return single_open(file, cpuacct_sched_lat_enabled_show, NULL);
}

static ssize_t cpuacct_sched_lat_enabled_write(struct file *file,
						const char __user *ubuf,
						size_t count, loff_t *ppos)
{
	char val = -1;
	int ret = count;

	if (count < 1 || *ppos) {
		ret = -EINVAL;
		goto out;
	}

	if (copy_from_user(&val, ubuf, 1)) {
		ret = -EFAULT;
		goto out;
	}

	switch (val) {
	case '0':
		static_branch_enable(&cpuacct_no_sched_lat);
		break;
	case '1':
		static_branch_disable(&cpuacct_no_sched_lat);
		break;
	default:
		ret = -EINVAL;
	}

out:
	return ret;
}

static const struct file_operations cpuacct_sched_lat_enabled_fops = {
	.open           = cpuacct_sched_lat_enabled_open,
	.read           = seq_read,
	.write          = cpuacct_sched_lat_enabled_write,
	.llseek         = seq_lseek,
	.release        = single_release,
};

static int __init init_cpuacct_sched_lat_enabled(void)
{
	struct proc_dir_entry *ca_dir, *sched_lat_enabled_file;

	ca_dir = proc_mkdir("cpusli", NULL);
	if (!ca_dir)
		return -ENOMEM;

	sched_lat_enabled_file = proc_create("sched_lat_enabled", 0600,
				ca_dir, &cpuacct_sched_lat_enabled_fops);
	if (!sched_lat_enabled_file) {
		remove_proc_entry("cpusli", NULL);
		return -ENOMEM;
	}

	return 0;
}
__initcall(init_cpuacct_sched_lat_enabled);

void task_ca_increase_nr_migrations(struct task_struct *tsk)
{
	struct cpuacct *ca;

	rcu_read_lock();
	ca = task_ca(tsk);
	if (ca)
		this_cpu_ptr(ca->alistats)->nr_migrations++;
	rcu_read_unlock();
}

void task_ca_update_block(struct task_struct *tsk, u64 runtime)
{
	int idx;
	enum sched_lat_stat_item s;
	struct cpuacct *ca;
	unsigned int msecs;

	if (static_branch_likely(&cpuacct_no_sched_lat))
		return;

	rcu_read_lock();
	ca = task_ca(tsk);
	if (!ca) {
		rcu_read_unlock();
		return;
	}
	if (tsk->in_iowait)
		s = SCHED_LAT_IOBLOCK;
	else
		s = SCHED_LAT_BLOCK;

	msecs = runtime >> 20; /* Proximately to speed up */
	idx = get_sched_lat_count_idx(msecs);
	this_cpu_inc(ca->lat_stat_cpu->item[s][idx]);
	this_cpu_inc(ca->lat_stat_cpu->item[s][SCHED_LAT_NR]);
	this_cpu_add(ca->lat_stat_cpu->item[s][SCHED_LAT_TOTAL], runtime);
	rcu_read_unlock();
}

void cpuacct_update_latency(struct sched_entity *se, u64 delta)
{
	int idx;
	enum sched_lat_stat_item s;
	struct cpuacct *ca;
	unsigned int msecs;
	struct task_group *tg;

	if (static_branch_likely(&cpuacct_no_sched_lat))
		return;

	rcu_read_lock();
	tg = se->cfs_rq->tg;
	ca = cgroup_ca(tg->css.cgroup);
	if (!ca) {
		rcu_read_unlock();
		return;
	}
	if (entity_is_task(se))
		s = SCHED_LAT_WAIT;
	else
		s = SCHED_LAT_CGROUP_WAIT;

	msecs = delta >> 20; /* Proximately to speed up */
	idx = get_sched_lat_count_idx(msecs);
	this_cpu_inc(ca->lat_stat_cpu->item[s][idx]);
	this_cpu_inc(ca->lat_stat_cpu->item[s][SCHED_LAT_NR]);
	this_cpu_add(ca->lat_stat_cpu->item[s][SCHED_LAT_TOTAL], delta);
	rcu_read_unlock();
}
#endif

static void cpuacct_free(void **ptr)
{
	struct cpuacct *ca = *ptr;

	free_percpu(ca->cpustat);
	free_percpu(ca->cpuusage);
#ifdef CONFIG_SCHED_SLI
	free_percpu(ca->alistats);
	free_percpu(ca->lat_stat_cpu);
#endif
	kfree(ca);
}

static void cpuacct_init(struct cpuacct *ca)
{
	int i;

	for_each_possible_cpu(i) {
		prev_cputime_init(&per_cpu_ptr(ca->cpuusage, i)->prev_cputime1);
		prev_cputime_init(&per_cpu_ptr(ca->cpuusage, i)->prev_cputime2);
	}
}

/* Create a new CPU accounting group */
static struct cgroup_subsys_state *
cpuacct_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct cpuacct *ca;

	if (!parent_css)
		return &root_cpuacct.css;

	ca = kzalloc(sizeof(*ca), GFP_KERNEL);
	if (!ca)
		goto out;

	ca->cpuusage = alloc_percpu(struct cpuacct_usage);
	if (!ca->cpuusage)
		goto out_free_ca;

	ca->cpustat = alloc_percpu(struct kernel_cpustat);
	if (!ca->cpustat)
		goto out_free_cpuusage;

#ifdef CONFIG_SCHED_SLI
	ca->alistats = alloc_percpu(struct cpuacct_alistats);
	if (!ca->alistats)
		goto out_free_cpustat;

	ca->lat_stat_cpu = alloc_percpu(struct sched_cgroup_lat_stat_cpu);
	if (!ca->lat_stat_cpu)
		goto out_free_alistats;
#endif

	cpuacct_init(ca);

	return &ca->css;

#ifdef CONFIG_SCHED_SLI
out_free_alistats:
	free_percpu(ca->alistats);
out_free_cpustat:
	free_percpu(ca->cpustat);
#endif
out_free_cpuusage:
	free_percpu(ca->cpuusage);
out_free_ca:
	kfree(ca);
out:
	return ERR_PTR(-ENOMEM);
}

/* Destroy an existing CPU accounting group */
static void cpuacct_css_free(struct cgroup_subsys_state *css)
{
	struct cpuacct *ca = css_ca(css);

	cpuacct_free((void **)&ca);
}

static u64 cpuacct_cpuusage_read(struct cpuacct *ca, int cpu,
				 enum cpuacct_stat_index index)
{
	struct cpuacct_usage *cpuusage = per_cpu_ptr(ca->cpuusage, cpu);
	u64 data;

	/*
	 * We allow index == CPUACCT_STAT_NSTATS here to read
	 * the sum of suages.
	 */
	BUG_ON(index > CPUACCT_STAT_NSTATS);

#ifndef CONFIG_64BIT
	/*
	 * Take rq->lock to make 64-bit read safe on 32-bit platforms.
	 */
	raw_spin_lock_irq(&cpu_rq(cpu)->lock);
#endif

	if (index == CPUACCT_STAT_NSTATS) {
		int i = 0;

		data = 0;
		for (i = 0; i < CPUACCT_STAT_NSTATS; i++)
			data += cpuusage->usages[i];
	} else {
		data = cpuusage->usages[index];
	}

#ifndef CONFIG_64BIT
	raw_spin_unlock_irq(&cpu_rq(cpu)->lock);
#endif

	return data;
}

static void cpuacct_cpuusage_write(struct cpuacct *ca, int cpu, u64 val)
{
	struct cpuacct_usage *cpuusage = per_cpu_ptr(ca->cpuusage, cpu);
	int i;

#ifndef CONFIG_64BIT
	/*
	 * Take rq->lock to make 64-bit write safe on 32-bit platforms.
	 */
	raw_spin_lock_irq(&cpu_rq(cpu)->lock);
#endif

	for (i = 0; i < CPUACCT_STAT_NSTATS; i++)
		cpuusage->usages[i] = val;

#ifndef CONFIG_64BIT
	raw_spin_unlock_irq(&cpu_rq(cpu)->lock);
#endif
}

/* Return total CPU usage (in nanoseconds) of a group */
static u64 __cpuusage_read(struct cgroup_subsys_state *css,
			   enum cpuacct_stat_index index)
{
	struct cpuacct *ca = css_ca(css);
	u64 totalcpuusage = 0;
	int i;

	for_each_possible_cpu(i)
		totalcpuusage += cpuacct_cpuusage_read(ca, i, index);

	return totalcpuusage;
}

static u64 cpuusage_user_read(struct cgroup_subsys_state *css,
			      struct cftype *cft)
{
	return __cpuusage_read(css, CPUACCT_STAT_USER);
}

static u64 cpuusage_sys_read(struct cgroup_subsys_state *css,
			     struct cftype *cft)
{
	return __cpuusage_read(css, CPUACCT_STAT_SYSTEM);
}

static u64 cpuusage_read(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return __cpuusage_read(css, CPUACCT_STAT_NSTATS);
}

static int cpuusage_write(struct cgroup_subsys_state *css, struct cftype *cft,
			  u64 val)
{
	struct cpuacct *ca = css_ca(css);
	int cpu;

	/*
	 * Only allow '0' here to do a reset.
	 */
	if (val)
		return -EINVAL;

	for_each_possible_cpu(cpu)
		cpuacct_cpuusage_write(ca, cpu, 0);

	return 0;
}

static int __cpuacct_percpu_seq_show(struct seq_file *m,
				     enum cpuacct_stat_index index)
{
	struct cpuacct *ca = css_ca(seq_css(m));
	u64 percpu;
	int i;

	for_each_possible_cpu(i) {
		percpu = cpuacct_cpuusage_read(ca, i, index);
		seq_printf(m, "%llu ", (unsigned long long) percpu);
	}
	seq_printf(m, "\n");
	return 0;
}

static int cpuacct_percpu_user_seq_show(struct seq_file *m, void *V)
{
	return __cpuacct_percpu_seq_show(m, CPUACCT_STAT_USER);
}

static int cpuacct_percpu_sys_seq_show(struct seq_file *m, void *V)
{
	return __cpuacct_percpu_seq_show(m, CPUACCT_STAT_SYSTEM);
}

static int cpuacct_percpu_seq_show(struct seq_file *m, void *V)
{
	return __cpuacct_percpu_seq_show(m, CPUACCT_STAT_NSTATS);
}

static int cpuacct_all_seq_show(struct seq_file *m, void *V)
{
	struct cpuacct *ca = css_ca(seq_css(m));
	int index;
	int cpu;

	seq_puts(m, "cpu");
	for (index = 0; index < CPUACCT_STAT_NSTATS; index++)
		seq_printf(m, " %s", cpuacct_stat_desc[index]);
	seq_puts(m, "\n");

	for_each_possible_cpu(cpu) {
		struct cpuacct_usage *cpuusage = per_cpu_ptr(ca->cpuusage, cpu);

		seq_printf(m, "%d", cpu);

		for (index = 0; index < CPUACCT_STAT_NSTATS; index++) {
#ifndef CONFIG_64BIT
			/*
			 * Take rq->lock to make 64-bit read safe on 32-bit
			 * platforms.
			 */
			raw_spin_lock_irq(&cpu_rq(cpu)->lock);
#endif

			seq_printf(m, " %llu", cpuusage->usages[index]);

#ifndef CONFIG_64BIT
			raw_spin_unlock_irq(&cpu_rq(cpu)->lock);
#endif
		}
		seq_puts(m, "\n");
	}
	return 0;
}

static int cpuacct_stats_show(struct seq_file *sf, void *v)
{
	struct cpuacct *ca = css_ca(seq_css(sf));
	s64 val[CPUACCT_STAT_NSTATS];
	int cpu;
	int stat;

	memset(val, 0, sizeof(val));
	for_each_possible_cpu(cpu) {
		u64 *cpustat = per_cpu_ptr(ca->cpustat, cpu)->cpustat;

		val[CPUACCT_STAT_USER]   += cpustat[CPUTIME_USER];
		val[CPUACCT_STAT_USER]   += cpustat[CPUTIME_NICE];
		val[CPUACCT_STAT_SYSTEM] += cpustat[CPUTIME_SYSTEM];
		val[CPUACCT_STAT_SYSTEM] += cpustat[CPUTIME_IRQ];
		val[CPUACCT_STAT_SYSTEM] += cpustat[CPUTIME_SOFTIRQ];
	}

	for (stat = 0; stat < CPUACCT_STAT_NSTATS; stat++) {
		seq_printf(sf, "%s %lld\n",
			   cpuacct_stat_desc[stat],
			   (long long)nsec_to_clock_t(val[stat]));
	}

	return 0;
}

#ifdef CONFIG_SCHED_SLI
#ifndef arch_idle_time
#define arch_idle_time(cpu) 0
#endif

static inline struct task_group *cgroup_tg(struct cgroup *cgrp)
{
	return container_of(global_cgroup_css(cgrp, cpu_cgrp_id),
				struct task_group, css);
}

void cgroup_idle_start(struct sched_entity *se)
{
	unsigned long flags;
	u64 clock;

	if (!schedstat_enabled())
		return;

	clock = __rq_clock_broken(se->cfs_rq->rq);

	local_irq_save(flags);

	write_seqcount_begin(&se->idle_seqcount);
	__schedstat_set(se->cg_idle_start, clock);
	write_seqcount_end(&se->idle_seqcount);

	spin_lock(&se->iowait_lock);
	if (schedstat_val(se->cg_nr_iowait))
		__schedstat_set(se->cg_iowait_start, clock);
	spin_unlock(&se->iowait_lock);

	local_irq_restore(flags);
}

void cgroup_idle_end(struct sched_entity *se)
{
	unsigned long flags;
	u64 clock;
	u64 idle_start, iowait_start;

	if (!schedstat_enabled())
		return;

	clock = __rq_clock_broken(se->cfs_rq->rq);

	local_irq_save(flags);

	write_seqcount_begin(&se->idle_seqcount);
	idle_start = schedstat_val(se->cg_idle_start);
	__schedstat_add(se->cg_idle_sum, clock - idle_start);
	__schedstat_set(se->cg_idle_start, 0);
	write_seqcount_end(&se->idle_seqcount);

	spin_lock(&se->iowait_lock);
	if (schedstat_val(se->cg_nr_iowait)) {
		iowait_start = schedstat_val(se->cg_iowait_start);
		__schedstat_add(se->cg_iowait_sum, clock - iowait_start);
		__schedstat_set(se->cg_iowait_start, 0);
	}
	spin_unlock(&se->iowait_lock);

	local_irq_restore(flags);
}

void cpuacct_cpuset_changed(struct cgroup *cgrp, struct cpumask *deleted,
			struct cpumask *added)
{
	struct task_group *tg;
	struct sched_entity *se;
	int cpu;

	if (!schedstat_enabled())
		return;

	rcu_read_lock();
	tg = cgroup_tg(cgrp);

	if (!tg) {
		rcu_read_unlock();
		return;
	}

	if (added) {
		/* Mark newly added cpus as newly-idle */
		for_each_cpu(cpu, added) {
			se = tg->se[cpu];
			cgroup_idle_start(se);
			__schedstat_add(se->cg_ineffective_sum,
				__rq_clock_broken(cpu_rq(cpu)) -
					se->cg_ineffective_start);
			__schedstat_set(se->cg_ineffective_start, 0);
		}
	}

	if (deleted) {
		/* Mark ineffective_cpus as idle-invalid */
		for_each_cpu(cpu, deleted) {
			se = tg->se[cpu];
			cgroup_idle_end(se);
			/* Use __rq_clock_broken to avoid warning */
			__schedstat_set(se->cg_ineffective_start,
				__rq_clock_broken(cpu_rq(cpu)));
		}
	}

	rcu_read_unlock();
}

static inline unsigned long nr_uninterruptible(void)
{
	unsigned long i, sum = 0;

	for_each_possible_cpu(i)
		sum += cpu_rq(i)->nr_uninterruptible;

	/*
	 * Since we read the counters lockless, it might be slightly
	 * inaccurate. Do not allow it to go below zero though:
	 */
	if (unlikely((long)sum < 0))
		sum = 0;

	return sum;
}

#ifdef CONFIG_CFS_BANDWIDTH
static inline bool tg_cfs_throttled(struct task_group *tg, int cpu)
{
	return tg->cfs_rq[cpu]->throttle_count;
}
#else
static inline bool tg_cfs_throttled(struct task_group *tg, int cpu)
{
	return false;
}
#endif

#ifdef CONFIG_RT_GROUP_SCHED
static inline bool tg_rt_throttled(struct task_group *tg, int cpu)
{
	return tg->rt_rq[cpu]->rt_throttled && !tg->rt_rq[cpu]->rt_nr_boosted;
}
#endif

static unsigned long ca_running(struct cpuacct *ca, int cpu)
{
	unsigned long nr_running = 0;
	struct cgroup *cgrp = ca->css.cgroup;
	struct task_group *tg;

	/* Make sure it is only called for non-root cpuacct */
	if (ca == &root_cpuacct)
		return 0;

	rcu_read_lock();
	tg = cgroup_tg(cgrp);
	if (unlikely(!tg))
		goto out;

	if (!tg_cfs_throttled(tg, cpu))
		nr_running += tg->cfs_rq[cpu]->h_nr_running;
#ifdef CONFIG_RT_GROUP_SCHED
	if (!tg_rt_throttled(tg, cpu))
		nr_running += tg->rt_rq[cpu]->rt_nr_running;
#endif
	/* SCHED_DEADLINE doesn't support cgroup yet */

out:
	rcu_read_unlock();
	return nr_running;
}

static unsigned long ca_uninterruptible(struct cpuacct *ca, int cpu)
{
	unsigned long nr = 0;
	struct cgroup *cgrp = ca->css.cgroup;
	struct task_group *tg;

	/* Make sure it is only called for non-root cpuacct */
	if (ca == &root_cpuacct)
		return nr;

	rcu_read_lock();
	tg = cgroup_tg(cgrp);
	if (unlikely(!tg))
		goto out_rcu_unlock;

	nr = tg->cfs_rq[cpu]->nr_uninterruptible;
#ifdef CONFIG_RT_GROUP_SCHED
	nr += tg->rt_rq[cpu]->nr_uninterruptible;
#endif

out_rcu_unlock:
	rcu_read_unlock();
	return nr;
}

static void __cpuacct_get_usage_result(struct cpuacct *ca, int cpu,
		struct task_group *tg, struct cpuacct_usage_result *res)
{
	struct kernel_cpustat *kcpustat;
	struct cpuacct_usage *cpuusage;
	struct task_cputime cputime;
	u64 tick_user, tick_nice, tick_sys, left, right;
	struct sched_entity *se;

	kcpustat = per_cpu_ptr(ca->cpustat, cpu);
	if (unlikely(!tg)) {
		memset(res, 0, sizeof(*res));
		return;
	}

	se = tg->se[cpu];
	cpuusage = per_cpu_ptr(ca->cpuusage, cpu);
	tick_user = kcpustat->cpustat[CPUTIME_USER];
	tick_nice = kcpustat->cpustat[CPUTIME_NICE];
	tick_sys = kcpustat->cpustat[CPUTIME_SYSTEM];

	/* Calculate system run time */
	cputime.sum_exec_runtime = cpuusage->usages[CPUACCT_STAT_USER] +
			cpuusage->usages[CPUACCT_STAT_SYSTEM];
	cputime.utime = tick_user + tick_nice;
	cputime.stime = tick_sys;
	cputime_adjust(&cputime, &cpuusage->prev_cputime1, &left, &right);
	res->system = right;

	/* Calculate user and nice run time */
	cputime.sum_exec_runtime = left; /* user + nice */
	cputime.utime = tick_user;
	cputime.stime = tick_nice;
	cputime_adjust(&cputime, &cpuusage->prev_cputime2, &left, &right);
	res->user = left;
	res->nice = right;

	res->irq = kcpustat->cpustat[CPUTIME_IRQ];
	res->softirq = kcpustat->cpustat[CPUTIME_SOFTIRQ];
	if (se && schedstat_enabled()) {
		unsigned int seq;
		unsigned long flags;
		u64 idle_start, ineff, ineff_start, elapse, complement;
		u64 clock, iowait_start;

		do {
			seq = read_seqcount_begin(&se->idle_seqcount);
			res->idle = schedstat_val(se->cg_idle_sum);
			idle_start = schedstat_val(se->cg_idle_start);
			clock = cpu_clock(cpu);
			if (idle_start && clock > idle_start)
				res->idle += clock - idle_start;
		} while (read_seqcount_retry(&se->idle_seqcount, seq));

		ineff = schedstat_val(se->cg_ineffective_sum);
		ineff_start = schedstat_val(se->cg_ineffective_start);
		if (ineff_start)
			__schedstat_add(ineff, clock - ineff_start);

		spin_lock_irqsave(&se->iowait_lock, flags);
		res->iowait = schedstat_val(se->cg_iowait_sum);
		iowait_start = schedstat_val(se->cg_iowait_start);
		if (iowait_start)
			__schedstat_add(res->iowait, clock - iowait_start);
		spin_unlock_irqrestore(&se->iowait_lock, flags);

		res->steal = 0;

		elapse = clock - schedstat_val(se->cg_init_time);
		complement = res->idle + se->sum_exec_raw + ineff;
		if (elapse > complement)
			res->steal = elapse - complement;

		res->idle -= res->iowait;
	} else {
		res->idle = res->iowait = res->steal = 0;
	}
	res->guest = kcpustat->cpustat[CPUTIME_GUEST];
	res->guest_nice = kcpustat->cpustat[CPUTIME_GUEST_NICE];
}

static int cpuacct_proc_stats_show(struct seq_file *sf, void *v)
{
	struct cpuacct *ca = css_ca(seq_css(sf));
	struct cgroup *cgrp = seq_css(sf)->cgroup;
	u64 user, nice, system, idle, iowait, irq, softirq, steal, guest;
	u64 nr_migrations = 0;
	struct cpuacct_alistats *alistats;
	unsigned long nr_run = 0, nr_uninter = 0;
	int cpu;

	user = nice = system = idle = iowait =
		irq = softirq = steal = guest = 0;

	if (ca != &root_cpuacct) {
		struct cpuacct_usage_result res;

		for_each_possible_cpu(cpu) {
			if (!housekeeping_cpu(cpu, HK_FLAG_DOMAIN))
				continue;

			rcu_read_lock();
			__cpuacct_get_usage_result(ca, cpu,
					cgroup_tg(cgrp), &res);
			rcu_read_unlock();

			user += res.user;
			nice += res.nice;
			system += res.system;
			irq += res.irq;
			softirq += res.softirq;
			steal += res.steal;
			guest += res.guest;
			guest += res.guest_nice;
			iowait += res.iowait;
			idle += res.idle;

			alistats = per_cpu_ptr(ca->alistats, cpu);
			nr_migrations += alistats->nr_migrations;
			nr_run += ca_running(ca, cpu);
			nr_uninter += ca_uninterruptible(ca, cpu);
		}
	} else {
		struct kernel_cpustat *kcpustat;

		for_each_possible_cpu(cpu) {
			kcpustat = per_cpu_ptr(ca->cpustat, cpu);
			user += kcpustat->cpustat[CPUTIME_USER];
			nice += kcpustat->cpustat[CPUTIME_NICE];
			system += kcpustat->cpustat[CPUTIME_SYSTEM];
			irq += kcpustat->cpustat[CPUTIME_IRQ];
			softirq += kcpustat->cpustat[CPUTIME_SOFTIRQ];
			guest += kcpustat->cpustat[CPUTIME_GUEST];
			guest += kcpustat->cpustat[CPUTIME_GUEST_NICE];
			idle += get_idle_time(cpu);
			iowait += get_iowait_time(cpu);
			steal += kcpustat_cpu(cpu).cpustat[CPUTIME_STEAL];
			alistats = per_cpu_ptr(ca->alistats, cpu);
			nr_migrations += alistats->nr_migrations;
		}

		nr_run = nr_running();
		nr_uninter = nr_uninterruptible();
	}

	seq_printf(sf, "user %lld\n", nsec_to_clock_t(user));
	seq_printf(sf, "nice %lld\n", nsec_to_clock_t(nice));
	seq_printf(sf, "system %lld\n", nsec_to_clock_t(system));
	seq_printf(sf, "idle %lld\n", nsec_to_clock_t(idle));
	seq_printf(sf, "iowait %lld\n", nsec_to_clock_t(iowait));
	seq_printf(sf, "irq %lld\n", nsec_to_clock_t(irq));
	seq_printf(sf, "softirq %lld\n", nsec_to_clock_t(softirq));
	seq_printf(sf, "steal %lld\n", nsec_to_clock_t(steal));
	seq_printf(sf, "guest %lld\n", nsec_to_clock_t(guest));

	seq_printf(sf, "nr_migrations %lld\n", (u64)nr_migrations);
	seq_printf(sf, "nr_running %lld\n", (u64)nr_run);
	if ((long) nr_uninter < 0)
		nr_uninter = 0;
	seq_printf(sf, "nr_uninterruptible %lld\n", (u64)nr_uninter);

	return 0;
}

#define SCHED_LAT_STAT_SMP_WRITE(name, sidx)				\
static void smp_write_##name(void *info)				\
{									\
	struct cpuacct *ca = (struct cpuacct *)info;		\
	int i;								\
									\
	for (i = SCHED_LAT_0_1; i < SCHED_LAT_NR_COUNT; i++)		\
		this_cpu_write(ca->lat_stat_cpu->item[sidx][i], 0);	\
}									\

SCHED_LAT_STAT_SMP_WRITE(sched_wait_latency, SCHED_LAT_WAIT);
SCHED_LAT_STAT_SMP_WRITE(sched_wait_cgroup_latency, SCHED_LAT_CGROUP_WAIT);
SCHED_LAT_STAT_SMP_WRITE(sched_block_latency, SCHED_LAT_BLOCK);
SCHED_LAT_STAT_SMP_WRITE(sched_ioblock_latency, SCHED_LAT_IOBLOCK);

smp_call_func_t smp_sched_lat_write_funcs[] = {
	smp_write_sched_wait_latency,
	smp_write_sched_wait_cgroup_latency,
	smp_write_sched_block_latency,
	smp_write_sched_ioblock_latency
};

static int sched_lat_stat_write(struct cgroup_subsys_state *css,
				struct cftype *cft, u64 val)
{
	struct cpuacct *ca = css_ca(css);
	enum sched_lat_stat_item idx = cft->private;
	smp_call_func_t func = smp_sched_lat_write_funcs[idx];

	if (val != 0)
		return -EINVAL;

	func((void *)ca);
	smp_call_function(func, (void *)ca, 1);

	return 0;
}

static u64 sched_lat_stat_gather(struct cpuacct *ca,
				 enum sched_lat_stat_item sidx,
				 enum sched_lat_count_t cidx)
{
	u64 sum = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		sum += per_cpu_ptr(ca->lat_stat_cpu, cpu)->item[sidx][cidx];

	return sum;
}

static int sched_lat_stat_show(struct seq_file *sf, void *v)
{
	struct cpuacct *ca = css_ca(seq_css(sf));
	enum sched_lat_stat_item s = seq_cft(sf)->private;

	/* CFS scheduling latency cgroup and task histgrams */
	seq_printf(sf, "0-1ms: \t%llu\n",
		sched_lat_stat_gather(ca, s, SCHED_LAT_0_1));
	seq_printf(sf, "1-4ms: \t%llu\n",
		sched_lat_stat_gather(ca, s, SCHED_LAT_1_4));
	seq_printf(sf, "4-7ms: \t%llu\n",
		sched_lat_stat_gather(ca, s, SCHED_LAT_4_7));
	seq_printf(sf, "7-10ms: \t%llu\n",
		sched_lat_stat_gather(ca, s, SCHED_LAT_7_10));
	seq_printf(sf, "10-20ms: \t%llu\n",
		sched_lat_stat_gather(ca, s, SCHED_LAT_10_20));
	seq_printf(sf, "20-30ms: \t%llu\n",
		sched_lat_stat_gather(ca, s, SCHED_LAT_20_30));
	seq_printf(sf, "30-40ms: \t%llu\n",
		sched_lat_stat_gather(ca, s, SCHED_LAT_30_40));
	seq_printf(sf, "40-50ms: \t%llu\n",
		sched_lat_stat_gather(ca, s, SCHED_LAT_40_50));
	seq_printf(sf, "50-100ms: \t%llu\n",
		sched_lat_stat_gather(ca, s, SCHED_LAT_50_100));
	seq_printf(sf, "100-500ms: \t%llu\n",
		sched_lat_stat_gather(ca, s, SCHED_LAT_100_500));
	seq_printf(sf, "500-1000ms: \t%llu\n",
		sched_lat_stat_gather(ca, s, SCHED_LAT_500_1000));
	seq_printf(sf, "1000-5000ms: \t%llu\n",
		sched_lat_stat_gather(ca, s, SCHED_LAT_1000_5000));
	seq_printf(sf, "5000-10000ms: \t%llu\n",
		sched_lat_stat_gather(ca, s, SCHED_LAT_5000_10000));
	seq_printf(sf, ">=10000ms: \t%llu\n",
		sched_lat_stat_gather(ca, s, SCHED_LAT_10000_INF));
	seq_printf(sf, "total(ms): \t%llu\n",
		sched_lat_stat_gather(ca, s, SCHED_LAT_TOTAL) / 1000000);
	seq_printf(sf, "nr: \t%llu\n",
		sched_lat_stat_gather(ca, s, SCHED_LAT_NR));

	return 0;
}
#endif

static struct cftype files[] = {
	{
		.name = "usage",
		.read_u64 = cpuusage_read,
		.write_u64 = cpuusage_write,
	},
	{
		.name = "usage_user",
		.read_u64 = cpuusage_user_read,
	},
	{
		.name = "usage_sys",
		.read_u64 = cpuusage_sys_read,
	},
	{
		.name = "usage_percpu",
		.seq_show = cpuacct_percpu_seq_show,
	},
	{
		.name = "usage_percpu_user",
		.seq_show = cpuacct_percpu_user_seq_show,
	},
	{
		.name = "usage_percpu_sys",
		.seq_show = cpuacct_percpu_sys_seq_show,
	},
	{
		.name = "usage_all",
		.seq_show = cpuacct_all_seq_show,
	},
	{
		.name = "stat",
		.seq_show = cpuacct_stats_show,
	},
#ifdef CONFIG_SCHED_SLI
	{
		.name = "proc_stat",
		.seq_show = cpuacct_proc_stats_show,
	},
	{
		.name = "wait_latency",
		.private = SCHED_LAT_WAIT,
		.write_u64 = sched_lat_stat_write,
		.seq_show = sched_lat_stat_show
	},
	{
		.name = "cgroup_wait_latency",
		.private = SCHED_LAT_CGROUP_WAIT,
		.write_u64 = sched_lat_stat_write,
		.seq_show = sched_lat_stat_show
	},
	{
		.name = "block_latency",
		.private = SCHED_LAT_BLOCK,
		.write_u64 = sched_lat_stat_write,
		.seq_show = sched_lat_stat_show
	},
	{
		.name = "ioblock_latency",
		.private = SCHED_LAT_IOBLOCK,
		.write_u64 = sched_lat_stat_write,
		.seq_show = sched_lat_stat_show
	},
#endif
	{ }	/* terminate */
};

/*
 * charge this task's execution time to its accounting group.
 *
 * called with rq->lock held.
 */
void cpuacct_charge(struct task_struct *tsk, u64 cputime)
{
	struct cpuacct *ca;
	int index = CPUACCT_STAT_SYSTEM;
	struct pt_regs *regs = task_pt_regs(tsk);

	if (regs && user_mode(regs))
		index = CPUACCT_STAT_USER;

	rcu_read_lock();

	for (ca = task_ca(tsk); ca; ca = parent_ca(ca))
		this_cpu_ptr(ca->cpuusage)->usages[index] += cputime;

	rcu_read_unlock();
}

/*
 * Add user/system time to cpuacct.
 *
 * Note: it's the caller that updates the account of the root cgroup.
 */
void cpuacct_account_field(struct task_struct *tsk, int index, u64 val)
{
	struct cpuacct *ca;

	rcu_read_lock();
	for (ca = task_ca(tsk); ca != &root_cpuacct; ca = parent_ca(ca))
		this_cpu_ptr(ca->cpustat)->cpustat[index] += val;
	rcu_read_unlock();
}

struct cgroup_subsys cpuacct_cgrp_subsys = {
	.css_alloc	= cpuacct_css_alloc,
	.css_free	= cpuacct_css_free,
	.legacy_cftypes	= files,
	.early_init	= true,
};

#ifdef CONFIG_PSI

static bool psi_v1_enable;
static int __init setup_psi_v1(char *str)
{
	return kstrtobool(str, &psi_v1_enable) == 0;
}
__setup("psi_v1=", setup_psi_v1);

static int __init cgroup_v1_psi_init(void)
{
	if (!psi_v1_enable) {
		static_branch_enable(&psi_v1_disabled);
		return 0;
	}

	cgroup_add_legacy_cftypes(&cpuacct_cgrp_subsys, cgroup_v1_psi_files);
	return 0;
}

late_initcall_sync(cgroup_v1_psi_init);
#endif

#ifdef CONFIG_RICH_CONTAINER
bool child_cpuacct(struct task_struct *tsk)
{
	struct cpuacct *ca = task_ca(tsk);

	if (ca && ca != &root_cpuacct)
		return true;

	return false;
}

bool check_rich_container(unsigned int cpu, unsigned int *index,
		bool *rich_container, unsigned int *total)
{
	struct cpumask cpuset_allowed;
	struct task_struct *scenario;
	bool in_rich;
	int i, id = 0;

	rcu_read_lock();
	in_rich = in_rich_container(current);
	rcu_read_unlock();
	if (!in_rich)
		return false;

	*rich_container = true;

	read_lock(&tasklist_lock);
	scenario = rich_container_get_scenario();
	get_task_struct(scenario);
	read_unlock(&tasklist_lock);
	rich_container_get_cpus(scenario, &cpuset_allowed);
	put_task_struct(scenario);

	*total = cpumask_weight(&cpuset_allowed);
	if (cpumask_test_cpu(cpu, &cpuset_allowed)) {
		for_each_cpu(i, &cpuset_allowed) {
			if (i == cpu)
				break;
			id++;
		}
		*index = id;
		return false;
	}

	/* Hide this cpu in the container */
	return true;
}

/* 0 - cpu quota; 1 - cpuset.cpus; 2 - cpu.shares */
int sysctl_rich_container_cpuinfo_source;
/* when cpu.shares */
unsigned int sysctl_rich_container_cpuinfo_sharesbase = 1024;

static inline struct task_group *css_tg(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct task_group, css) : NULL;
}

static inline struct task_group *task_tg(struct task_struct *tsk)
{
	return css_tg(task_css(tsk, cpu_cgrp_id));
}

void rich_container_get_cpus(struct task_struct *tsk, struct cpumask *pmask)
{
	struct task_group *tg;
	int i, cpus;

	/* cfs quota source */
	if (sysctl_rich_container_cpuinfo_source == 0) {
		long quota, period;

		rcu_read_lock();
		tg = task_tg(tsk);
		quota = tg_get_cfs_quota(tg);
		period = tg_get_cfs_period(tg);
		rcu_read_unlock();

		if (quota == -1) {
			/* Fallback to use cpuset.cpus if quota not set */
			goto cpuset_source;
		} else {
			/* period can't be 0 */
			cpus = (quota + period - 1) / period;
			cpus = clamp(cpus, 1, (int)num_online_cpus());
			cpumask_clear(pmask);
			for (i = 0; i < cpus; i++)
				cpumask_set_cpu(i, pmask);
		}

		return;
	}

	/* cpu.shares source */
	if (sysctl_rich_container_cpuinfo_source == 2) {
		unsigned long shares;

		rcu_read_lock();
		tg = task_tg(tsk);
		shares = scale_load_down(tg->shares);
		rcu_read_unlock();

		/* sysctl_rich_container_cpuinfo_sharesbase can't be 0 */
		cpus = (shares + sysctl_rich_container_cpuinfo_sharesbase - 1) /
			sysctl_rich_container_cpuinfo_sharesbase;
		cpus = clamp(cpus, 1, (int)num_online_cpus());
		cpumask_clear(pmask);
		for (i = 0; i < cpus; i++)
			cpumask_set_cpu(i, pmask);

		return;
	}

cpuset_source:
	/* cpuset.cpus source */
	cpuset_cpus_allowed(tsk, pmask);
}
#endif
