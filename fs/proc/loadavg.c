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

static int loadavg_proc_show(struct seq_file *m, void *v)
{
	unsigned long avnrun[3];

	get_avenrun(avnrun, FIXED_1/200, 0);

	seq_printf(m, "%lu.%02lu %lu.%02lu %lu.%02lu %ld/%d %d\n",
		LOAD_INT(avnrun[0]), LOAD_FRAC(avnrun[0]),
		LOAD_INT(avnrun[1]), LOAD_FRAC(avnrun[1]),
		LOAD_INT(avnrun[2]), LOAD_FRAC(avnrun[2]),
		nr_running(), nr_threads,
		idr_get_cursor(&task_active_pid_ns(current)->idr) - 1);
	return 0;
}

static inline void get_aven_stress(u64 *stress, u64 offset)
{
	stress[0] = stress_avg_total[0] + offset;
	stress[1] = stress_avg_total[1] + offset;
	stress[2] = stress_avg_total[2] + offset;
}

static int cpu_stress_proc_show(struct seq_file *m, void *v)
{
	u64 avn_stress[3];

	get_aven_stress(avn_stress, FIXED_1/200);

	seq_printf(m, "%llu.%02llu %llu.%02llu %llu.%02llu\n",
		LOAD_INT(avn_stress[0]), LOAD_FRAC(avn_stress[0]),
		LOAD_INT(avn_stress[1]), LOAD_FRAC(avn_stress[1]),
		LOAD_INT(avn_stress[2]), LOAD_FRAC(avn_stress[2]));

	return 0;
}

static int __init proc_loadavg_init(void)
{
	proc_create_single("loadavg", 0, NULL, loadavg_proc_show);
	return 0;
}
fs_initcall(proc_loadavg_init);

static int __init proc_cpu_stress_init(void)
{
	proc_create_single("cpu_stress", 0, NULL, cpu_stress_proc_show);

	/* sched_init is called earlier than init_timers so schedule it here */
	schedule_stress();
	return 0;
}
fs_initcall(proc_cpu_stress_init);
