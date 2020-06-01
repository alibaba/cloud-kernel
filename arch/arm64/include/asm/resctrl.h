#ifndef _ASM_ARM64_RESCTRL_H
#define _ASM_ARM64_RESCTRL_H

#include <asm/mpam_sched.h>
#include <asm/mpam.h>

#define resctrl_group rdtgroup
#define resctrl_alloc_capable rdt_alloc_capable
#define resctrl_mon_capable rdt_mon_capable

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

#define for_each_resctrl_resource(r)					\
	for (r = resctrl_resources_all;					\
	     r < resctrl_resources_all + MPAM_NUM_RESOURCES;		\
	     r++)							\

int mpam_get_mon_config(struct resctrl_resource *r);

int mkdir_mondata_all(struct kernfs_node *parent_kn,
			     struct resctrl_group *prgrp,
			     struct kernfs_node **dest_kn);

int
mongroup_create_dir(struct kernfs_node *parent_kn, struct resctrl_group *prgrp,
		    char *name, struct kernfs_node **dest_kn);

int rdtgroup_init_alloc(struct rdtgroup *rdtgrp);

#endif /* _ASM_ARM64_RESCTRL_H */
