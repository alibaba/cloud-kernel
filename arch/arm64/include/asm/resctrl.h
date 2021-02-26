#ifndef _ASM_ARM64_RESCTRL_H
#define _ASM_ARM64_RESCTRL_H

#include <asm/mpam_sched.h>
#include <asm/mpam.h>

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
 * struct rdtgroup - store rdtgroup's data in resctrl file system.
 * @kn:             kernfs node
 * @resctrl_group_list:     linked list for all rdtgroups
 * @closid:         closid for this rdtgroup
 * #endif
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
	u32         closid;
	struct cpumask      cpu_mask;
	int         flags;
	atomic_t        waitcount;
	enum rdt_group_type type;
	struct mongroup     mon;
};

int schemata_list_init(void);

void schemata_list_destroy(void);

static inline int alloc_mon_id(void)
{

	return alloc_rmid();
}

static inline void free_mon_id(u32 id)
{
	free_rmid(id);
}

void pmg_init(void);
static inline void resctrl_id_init(void)
{
	closid_init();
	pmg_init();
}

static inline int resctrl_id_alloc(void)
{
	return closid_alloc();
}

static inline void resctrl_id_free(int id)
{
	closid_free(id);
}

void update_cpu_closid_rmid(void *info);
void update_closid_rmid(const struct cpumask *cpu_mask, struct resctrl_group *r);
int __resctrl_group_move_task(struct task_struct *tsk,
				struct resctrl_group *rdtgrp);

ssize_t resctrl_group_schemata_write(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off);

int resctrl_group_schemata_show(struct kernfs_open_file *of,
				struct seq_file *s, void *v);

#define release_resctrl_group_fs_options release_rdtgroupfs_options
#define parse_resctrl_group_fs_options parse_rdtgroupfs_options

int mpam_get_mon_config(struct resctrl_resource *r);

int mkdir_mondata_all(struct kernfs_node *parent_kn,
			     struct resctrl_group *prgrp,
			     struct kernfs_node **dest_kn);

int
mongroup_create_dir(struct kernfs_node *parent_kn, struct resctrl_group *prgrp,
		    char *name, struct kernfs_node **dest_kn);

int resctrl_group_init_alloc(struct rdtgroup *rdtgrp);

struct resctrl_resource *
mpam_resctrl_get_resource(enum resctrl_resource_level level);

#endif /* _ASM_ARM64_RESCTRL_H */
