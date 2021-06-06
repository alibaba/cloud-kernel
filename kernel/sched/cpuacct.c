// SPDX-License-Identifier: GPL-2.0
/*
 * CPU accounting code for task groups.
 *
 * Based on the work by Paul Menage (menage@google.com) and Balbir Singh
 * (balbir@in.ibm.com).
 */
#include <asm/irq_regs.h>
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

/* track CPU usage of a group of tasks and its child groups */
struct cpuacct {
	struct cgroup_subsys_state	css;
	/* cpuusage holds pointer to a u64-type object on every CPU */
	struct cpuacct_usage __percpu	*cpuusage;
	struct kernel_cpustat __percpu	*cpustat;

	unsigned long avenrun[3];

	CK_HOTFIX_RESERVE(1)
	CK_HOTFIX_RESERVE(2)
	CK_HOTFIX_RESERVE(3)
	CK_HOTFIX_RESERVE(4)
};

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
static struct cpuacct root_cpuacct = {
	.cpustat	= &kernel_cpustat,
	.cpuusage	= &root_cpuacct_cpuusage,
};

/* Create a new CPU accounting group */
static struct cgroup_subsys_state *
cpuacct_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct cpuacct *ca;
	int i;

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

	for_each_possible_cpu(i) {
		prev_cputime_init(&per_cpu_ptr(ca->cpuusage, i)->prev_cputime1);
		prev_cputime_init(&per_cpu_ptr(ca->cpuusage, i)->prev_cputime2);
	}

	return &ca->css;

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

	free_percpu(ca->cpustat);
	free_percpu(ca->cpuusage);
	kfree(ca);
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

static unsigned long ca_running(struct cpuacct *ca, int cpu);

static void __get_cgroup_avenrun(struct cpuacct *ca, unsigned long *loads,
		unsigned long offset, int shift)
{
	unsigned long *avenrun;

	avenrun = ca->avenrun;
	loads[0] = (avenrun[0] + offset) << shift;
	loads[1] = (avenrun[1] + offset) << shift;
	loads[2] = (avenrun[2] + offset) << shift;
}

void get_cgroup_avenrun(struct task_struct *tsk, unsigned long *loads,
			unsigned long offset, int shift)
{
	__get_cgroup_avenrun(task_ca(tsk), loads, offset, shift);
}

unsigned long task_ca_running(struct task_struct *tsk, int cpu)
{
	return ca_running(task_ca(tsk), cpu);
}

static inline struct task_group *cgroup_tg(struct cgroup *cgrp)
{
	return container_of(global_cgroup_css(cgrp, cpu_cgrp_id),
				struct task_group, css);
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

void cgroup_idle_start(struct sched_entity *se)
{
	unsigned long flags;
	u64 clock;

	if (!schedstat_enabled())
		return;

	clock = __rq_clock_broken(se->cfs_rq->rq);

	local_irq_save(flags);

	write_seqlock(&se->idle_seqlock);
	__schedstat_set(se->cg_idle_start, clock);
	write_sequnlock(&se->idle_seqlock);

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

	write_seqlock(&se->idle_seqlock);
	idle_start = schedstat_val(se->cg_idle_start);
	__schedstat_add(se->cg_idle_sum, clock - idle_start);
	__schedstat_set(se->cg_idle_start, 0);
	write_sequnlock(&se->idle_seqlock);

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

static void cpuacct_calc_load(struct cpuacct *acct)
{
	if (acct != &root_cpuacct) {
		long active = 0;
		int cpu;

		for_each_possible_cpu(cpu) {
			active += ca_running(acct, cpu);
			active += ca_uninterruptible(acct, cpu);
		}
		active = active > 0 ? active * FIXED_1 : 0;
		acct->avenrun[0] = calc_load(acct->avenrun[0], EXP_1, active);
		acct->avenrun[1] = calc_load(acct->avenrun[1], EXP_5, active);
		acct->avenrun[2] = calc_load(acct->avenrun[2], EXP_15, active);
	} else {
		acct->avenrun[0] = avenrun[0];
		acct->avenrun[1] = avenrun[1];
		acct->avenrun[2] = avenrun[2];
	}
}

/*
 * Currently we walk the whole cpuacct tree to perform per-cgroup
 * load calculation, but it can cause overhead if there're too many
 * cgroups.
 *
 * TODO: A better way to avoid the possible overhead.
 *	Consider NO_HZ.
 */
void calc_cgroup_load(void)
{
	struct cgroup_subsys_state *css;
	struct cpuacct *acct;

	rcu_read_lock();
	css_for_each_descendant_pre(css, &root_cpuacct.css) {
		acct = NULL;
		if (css && css_tryget(css))
			acct = container_of(css, struct cpuacct, css);
		rcu_read_unlock();
		if (acct) {
			cpuacct_calc_load(acct);
			css_put(&acct->css);
		}
		rcu_read_lock();
		if (!css)
			break;
	}
	rcu_read_unlock();
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
			seq = read_seqbegin(&se->idle_seqlock);
			res->idle = schedstat_val(se->cg_idle_sum);
			idle_start = schedstat_val(se->cg_idle_start);
			clock = cpu_clock(cpu);
			if (idle_start && clock > idle_start)
				res->idle += clock - idle_start;
		} while (read_seqretry(&se->idle_seqlock, seq));

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

void cpuacct_get_usage_result(struct task_struct *tsk, int cpu,
		struct cpuacct_usage_result *res)
{
	struct cpuacct *ca = task_ca(tsk);
	struct cgroup *cgrp = ca->css.cgroup;
	struct task_group *tg = cgroup_tg(cgrp);

	__cpuacct_get_usage_result(ca, cpu, tg, res);
}

static int cpuacct_proc_stats_show(struct seq_file *sf, void *v)
{
	struct cpuacct *ca = css_ca(seq_css(sf));
	struct cgroup *cgrp = seq_css(sf)->cgroup;
	u64 user, nice, system, idle, iowait, irq, softirq, steal, guest;
	unsigned long load, avnrun[3];
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

			nr_run += ca_running(ca, cpu);
			nr_uninter += ca_uninterruptible(ca, cpu);
		}

		__get_cgroup_avenrun(ca, avnrun, FIXED_1/200, 0);
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
			idle += get_idle_time(kcpustat, cpu);
			iowait += get_iowait_time(kcpustat, cpu);
			steal += kcpustat_cpu(cpu).cpustat[CPUTIME_STEAL];
		}

		nr_run = nr_running();
		nr_uninter = nr_uninterruptible();

		get_avenrun(avnrun, FIXED_1/200, 0);
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

	load = LOAD_INT(avnrun[0]) * 100 + LOAD_FRAC(avnrun[0]);
	seq_printf(sf, "load average(1min) %lld\n", (u64)load);
	load = LOAD_INT(avnrun[1]) * 100 + LOAD_FRAC(avnrun[1]);
	seq_printf(sf, "load average(5min) %lld\n", (u64)load);
	load = LOAD_INT(avnrun[2]) * 100 + LOAD_FRAC(avnrun[2]);
	seq_printf(sf, "load average(15min) %lld\n", (u64)load);

	seq_printf(sf, "nr_running %lld\n", (u64)nr_run);
	if ((long) nr_uninter < 0)
		nr_uninter = 0;
	seq_printf(sf, "nr_uninterruptible %lld\n", (u64)nr_uninter);

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
	struct pt_regs *regs = get_irq_regs() ? : task_pt_regs(tsk);

	if (regs && user_mode(regs))
		index = CPUACCT_STAT_USER;

	rcu_read_lock();

	for (ca = task_ca(tsk); ca; ca = parent_ca(ca))
		__this_cpu_add(ca->cpuusage->usages[index], cputime);

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
		__this_cpu_add(ca->cpustat->cpustat[index], val);
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
	struct task_struct *init_tsk;
	bool in_rich;
	int i, id = 0;

	rcu_read_lock();
	in_rich = in_rich_container(current);
	rcu_read_unlock();
	if (!in_rich)
		return false;

	*rich_container = true;

	read_lock(&tasklist_lock);
	init_tsk = task_active_pid_ns(current)->child_reaper;
	get_task_struct(init_tsk);
	read_unlock(&tasklist_lock);
	cpuset_cpus_allowed(init_tsk, &cpuset_allowed);
	put_task_struct(init_tsk);

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
#endif
