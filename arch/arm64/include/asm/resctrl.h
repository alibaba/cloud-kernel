#ifndef _ASM_ARM64_RESCTRL_H
#define _ASM_ARM64_RESCTRL_H

#include <asm/mpam_sched.h>

#define resctrl_group rdtgroup
#define resctrl_alloc_capable rdt_alloc_capable
#define resctrl_mon_capable rdt_mon_capable

enum resctrl_resource_level {
	RDT_RESOURCE_SMMU,
	RDT_RESOURCE_L3,
	RDT_RESOURCE_L2,
	RDT_RESOURCE_MC,

	/* Must be the last */
	RDT_NUM_RESOURCES,
};

enum rdt_event_id {
	QOS_L3_OCCUP_EVENT_ID           = 0x01,
	QOS_L3_MBM_TOTAL_EVENT_ID       = 0x02,
	QOS_L3_MBM_LOCAL_EVENT_ID       = 0x03,

	QOS_CAT_CPBM_EVENT_ID           = 0x04,
	QOS_CAT_INTPRI_EVENT_ID         = 0x05,
	QOS_CAT_DSPRI_EVENT_ID          = 0x06,
	QOS_MBA_MAX_EVENT_ID            = 0x07,
	QOS_MBA_INTPRI_EVENT_ID         = 0x08,
	QOS_MBA_DSPRI_EVENT_ID          = 0x09,
	QOS_MBA_HDL_EVENT_ID            = 0x0a,
	/* Must be the last */
	RESCTRL_NUM_EVENT_IDS,
};

enum rdt_group_type {
	RDTCTRL_GROUP = 0,
	RDTMON_GROUP,
	RDT_NUM_GROUP,
};

/**
 * struct mongroup - store mon group's data in resctrl fs.
 * @mon_data_kn     kernlfs node for the mon_data directory
 * @parent:         parent rdtgrp
 * @crdtgrp_list:       child rdtgroup node list
 * @rmid:           rmid for this rdtgroup
 * @mon:            monnitor id
 */
struct mongroup {
	struct kernfs_node  *mon_data_kn;
	struct rdtgroup     *parent;
	struct list_head    crdtgrp_list;
	u32         rmid;
	u32         mon;
	int         init;
};

/**
 * struct sd_closid - software defined closid
 * @intpartid:  closid for this rdtgroup only for allocation
 * @weak_closid:    closid for synchronizing configuration and monitoring
 */
struct sd_closid {
	u32         intpartid;
	u32         reqpartid;
};

/**
 * struct rdtgroup - store rdtgroup's data in resctrl file system.
 * @kn:             kernfs node
 * @resctrl_group_list:     linked list for all rdtgroups
 * @cpu_mask:           CPUs assigned to this rdtgroup
 * @flags:          status bits
 * @waitcount:          how many cpus expect to find this
 *              group when they acquire resctrl_group_mutex
 * @type:           indicates type of this rdtgroup - either
 *              monitor only or ctrl_mon group
 * @mon:            mongroup related data
 */
struct rdtgroup {
	struct kernfs_node  *kn;
	struct list_head    resctrl_group_list;
	struct sd_closid    closid;
	struct cpumask      cpu_mask;
	int         flags;
	atomic_t        waitcount;
	enum rdt_group_type type;
	struct mongroup     mon;
};

int schemata_list_init(void);

void schemata_list_destroy(void);

int resctrl_lru_request_mon(void);

int alloc_rmid(void);
void free_rmid(u32 id);

enum closid_type {
	CLOSID_INT    = 0x1,
	CLOSID_REQ      = 0x2,
	CLOSID_NUM_TYPES,
};
int resctrl_id_init(void);
int resctrl_id_alloc(enum closid_type);
void resctrl_id_free(enum closid_type, int id);

void update_cpu_closid_rmid(void *info);
void update_closid_rmid(const struct cpumask *cpu_mask, struct resctrl_group *r);
int __resctrl_group_move_task(struct task_struct *tsk,
				struct resctrl_group *rdtgrp);

extern bool rdt_alloc_capable;
extern bool rdt_mon_capable;

/* rdtgroup.flags */
#define	RDT_DELETED		BIT(0)

void rdt_last_cmd_clear(void);
void rdt_last_cmd_puts(const char *s);
void rdt_last_cmd_printf(const char *fmt, ...);

extern struct mutex resctrl_group_mutex;

void release_rdtgroupfs_options(void);
int parse_rdtgroupfs_options(char *data);

void resctrl_resource_reset(void);

#define release_resctrl_group_fs_options release_rdtgroupfs_options
#define parse_resctrl_group_fs_options parse_rdtgroupfs_options

int mpam_get_mon_config(struct resctrl_resource *r);

int resctrl_group_init_alloc(struct rdtgroup *rdtgrp);

static inline int __resctrl_group_show_options(struct seq_file *seq)
{
	return 0;
}

int resctrl_mkdir_mondata_all_subdir(struct kernfs_node *parent_kn,
			struct resctrl_group *prgrp);

struct resctrl_resource *
mpam_resctrl_get_resource(enum resctrl_resource_level level);

int resctrl_update_groups_config(struct rdtgroup *rdtgrp);

#define RESCTRL_MAX_CLOSID 32

/*
 * left 16 bits of closid store parent(master)'s
 * closid, the reset store current group's closid,
 * this used for judging if tasks are allowed to move
 * another ctrlmon/mon group, it is because when
 * a mon group is permited to allocated another
 * closid different from it's parent, only closid
 * is not sufficient to do that.
 */
#define TASK_CLOSID_SET(prclosid, closid)    \
		((prclosid << 16) | closid)

#define TASK_CLOSID_CUR_GET(closid)   \
		(closid & GENMASK(15, 0))
#define TASK_CLOSID_PR_GET(closid)    \
		((closid & GENMASK(31, 16)) >> 16)

#endif /* _ASM_ARM64_RESCTRL_H */
