// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/pid_namespace.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/stat.h>
#include <linux/seq_file.h>
#include <linux/seqlock.h>
#include <linux/time.h>
#include <linux/cpuset.h>

static int loadavg_proc_show(struct seq_file *m, void *v)
{
	unsigned long avnrun[3], nr_r = 0;
	struct cpumask cpuset_allowed;
	int i;

	rcu_read_lock();
	if (in_rich_container(current)) {
		struct task_struct *init_tsk;

		read_lock(&tasklist_lock);
		init_tsk = task_active_pid_ns(current)->child_reaper;
		get_task_struct(init_tsk);
		read_unlock(&tasklist_lock);
		get_cgroup_avenrun(init_tsk, avnrun, FIXED_1/200, 0, false);

		cpuset_cpus_allowed(init_tsk, &cpuset_allowed);
		for_each_cpu(i, &cpuset_allowed)
			nr_r += task_ca_running(init_tsk, i);
		put_task_struct(init_tsk);
	} else {
		get_avenrun(avnrun, FIXED_1/200, 0);
		nr_r = nr_running();
	}
	rcu_read_unlock();

	seq_printf(m, "%lu.%02lu %lu.%02lu %lu.%02lu %ld/%d %d\n",
		LOAD_INT(avnrun[0]), LOAD_FRAC(avnrun[0]),
		LOAD_INT(avnrun[1]), LOAD_FRAC(avnrun[1]),
		LOAD_INT(avnrun[2]), LOAD_FRAC(avnrun[2]),
		nr_r, nr_threads,
		idr_get_cursor(&task_active_pid_ns(current)->idr) - 1);
	return 0;
}

static int __init proc_loadavg_init(void)
{
	proc_create_single("loadavg", 0, NULL, loadavg_proc_show);
	return 0;
}
fs_initcall(proc_loadavg_init);
