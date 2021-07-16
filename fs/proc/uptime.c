// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/time.h>
#include <linux/kernel_stat.h>
#include <linux/sched/task.h>
#include <linux/pid_namespace.h>

static int uptime_proc_show(struct seq_file *m, void *v)
{
	struct timespec64 uptime;
	struct timespec64 idle;
	u64 nsec;
	u32 rem;
	int i;

	ktime_get_boottime_ts64(&uptime);

	nsec = 0;
	rcu_read_lock();
	if (in_rich_container(current)) {
		enum rich_container_source from;
		struct task_struct *init_tsk;
		struct cpuacct_usage_result res;

		read_lock(&tasklist_lock);
		init_tsk = task_active_pid_ns(current)->child_reaper;
		get_task_struct(init_tsk);
		read_unlock(&tasklist_lock);

		rich_container_source(&from);
		for_each_possible_cpu(i) {
			rich_container_get_usage(from, init_tsk, i, &res);
			nsec += res.idle;
		}
		uptime = timespec64_sub(uptime,
				ns_to_timespec64(init_tsk->start_time));
		put_task_struct(init_tsk);
	} else {
		for_each_possible_cpu(i)
			nsec +=
			(__force u64) kcpustat_cpu(i).cpustat[CPUTIME_IDLE];
	}
	rcu_read_unlock();

	idle.tv_sec = div_u64_rem(nsec, NSEC_PER_SEC, &rem);
	idle.tv_nsec = rem;
	seq_printf(m, "%lu.%02lu %lu.%02lu\n",
			(unsigned long) uptime.tv_sec,
			(uptime.tv_nsec / (NSEC_PER_SEC / 100)),
			(unsigned long) idle.tv_sec,
			(idle.tv_nsec / (NSEC_PER_SEC / 100)));
	return 0;
}

static int __init proc_uptime_init(void)
{
	proc_create_single("uptime", 0, NULL, uptime_proc_show);
	return 0;
}
fs_initcall(proc_uptime_init);
