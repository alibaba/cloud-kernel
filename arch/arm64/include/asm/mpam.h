/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_MPAM_H
#define _ASM_ARM64_MPAM_H

#include <linux/sched.h>
#include <linux/kernfs.h>
#include <linux/jump_label.h>

#include <linux/seq_buf.h>
#include <linux/seq_file.h>

DECLARE_STATIC_KEY_FALSE(resctrl_enable_key);
DECLARE_STATIC_KEY_FALSE(resctrl_mon_enable_key);

extern bool rdt_alloc_capable;
extern bool rdt_mon_capable;

enum rdt_group_type {
	RDTCTRL_GROUP = 0,
	RDTMON_GROUP,
	RDT_NUM_GROUP,
};

/**
 * struct mongroup - store mon group's data in resctrl fs.
 * @mon_data_kn		kernlfs node for the mon_data directory
 * @parent:			parent rdtgrp
 * @crdtgrp_list:		child rdtgroup node list
 * @rmid:			rmid for this rdtgroup
 */
struct mongroup {
	struct kernfs_node	*mon_data_kn;
	struct rdtgroup		*parent;
	struct list_head	crdtgrp_list;
	u32			rmid;
};

/**
 * struct rdtgroup - store rdtgroup's data in resctrl file system.
 * @kn:				kernfs node
 * @resctrl_group_list:		linked list for all rdtgroups
 * @closid:			closid for this rdtgroup
 * @cpu_mask:			CPUs assigned to this rdtgroup
 * @flags:			status bits
 * @waitcount:			how many cpus expect to find this
 *				group when they acquire resctrl_group_mutex
 * @type:			indicates type of this rdtgroup - either
 *				monitor only or ctrl_mon group
 * @mon:			mongroup related data
 */
struct rdtgroup {
	struct kernfs_node	*kn;
	struct list_head	resctrl_group_list;
	u32			closid;
	struct cpumask		cpu_mask;
	int			flags;
	atomic_t		waitcount;
	enum rdt_group_type	type;
	struct mongroup		mon;
};

/* rdtgroup.flags */
#define	RDT_DELETED		1

/**
 * struct rdt_domain - group of cpus sharing an RDT resource
 * @list:	all instances of this resource
 * @id:		unique id for this instance
 * @cpu_mask:	which cpus share this resource
 * @rmid_busy_llc:
 *		bitmap of which limbo RMIDs are above threshold
 * @mbm_total:	saved state for MBM total bandwidth
 * @mbm_local:	saved state for MBM local bandwidth
 * @mbm_over:	worker to periodically read MBM h/w counters
 * @cqm_limbo:	worker to periodically read CQM h/w counters
 * @mbm_work_cpu:
 *		worker cpu for MBM h/w counters
 * @cqm_work_cpu:
 *		worker cpu for CQM h/w counters
 * @ctrl_val:	array of cache or mem ctrl values (indexed by CLOSID)
 * @new_ctrl:	new ctrl value to be loaded
 * @have_new_ctrl: did user provide new_ctrl for this domain
 */
struct rdt_domain {
	struct list_head	list;
	int			id;
	struct cpumask		cpu_mask;
};

extern struct mutex resctrl_group_mutex;

extern struct resctrl_resource resctrl_resources_all[];

int __init resctrl_group_init(void);

enum {
	MPAM_RESOURCE_L3,
	MPAM_RESOURCE_L3DATA,
	MPAM_RESOURCE_L3CODE,
	MPAM_RESOURCE_L2,
	MPAM_RESOURCE_L2DATA,
	MPAM_RESOURCE_L2CODE,

	/* Must be the last */
	MPAM_NUM_RESOURCES,
};

void rdt_last_cmd_clear(void);
void rdt_last_cmd_puts(const char *s);
void rdt_last_cmd_printf(const char *fmt, ...);

int alloc_rmid(void);
void free_rmid(u32 rmid);
int resctrl_group_mondata_show(struct seq_file *m, void *arg);
void rmdir_mondata_subdir_allrdtgrp(struct resctrl_resource *r,
				    unsigned int dom_id);
void mkdir_mondata_subdir_allrdtgrp(struct resctrl_resource *r,
				    struct rdt_domain *d);

void closid_init(void);
int closid_alloc(void);
void closid_free(int closid);

int cdp_enable(int level, int data_type, int code_type);
void resctrl_resource_reset(void);
void release_rdtgroupfs_options(void);
int parse_rdtgroupfs_options(char *data);

static inline int __resctrl_group_show_options(struct seq_file *seq)
{
	if (resctrl_resources_all[MPAM_RESOURCE_L3DATA].alloc_enabled)
		seq_puts(seq, ",cdp");
	return 0;
}

void post_resctrl_mount(void);
#endif /* _ASM_ARM64_MPAM_H */
