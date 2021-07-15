/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FAULT_EVENT_H
#define _FAULT_EVENT_H
#include <linux/sched.h>

enum FAULT_CLASS {
	SLIGHT_FAULT,
	NORMAL_FAULT,
	FATAL_FAULT,
	FAULT_CLASSS_MAX
};

enum FAULT_EVENT {
	/*kernel fault events*/
	FE_SOFTLOCKUP,
	FE_RCUSTALL,
	FE_HUNGTASK,
	FE_OOM_GLOBAL,
	FE_OOM_CGROUP,
	FE_ALLOCFAIL,
	FE_LIST_CORRUPT,
	FE_MM_STATE,
	FE_IO_ERR,
	FE_EXT4_ERR,
	FE_MCE,
	FE_SIGNAL,
	FE_WARN,
	FE_PANIC,
	FE_MAX
};

struct fault_event {
	enum FAULT_EVENT type;
	char *name;
	char *module;
	atomic_t count;
};

extern unsigned int sysctl_fault_event_enable;
extern unsigned int sysctl_fault_event_print;
extern unsigned int sysctl_panic_on_fatal_event;

extern bool fault_monitor_enable(void);
extern void report_fault_event(int cpu, struct task_struct *tsk,
		enum FAULT_CLASS class, enum FAULT_EVENT event,
		const char *msg);
#endif
