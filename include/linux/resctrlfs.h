/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RESCTRLFS_H
#define _RESCTRLFS_H

#include <linux/sched.h>
#include <linux/kernfs.h>
#include <linux/jump_label.h>

#include <linux/seq_buf.h>
#include <linux/seq_file.h>

struct resctrl_resource {
	int			rid;
	bool			alloc_enabled;
	bool			mon_enabled;
	bool			alloc_capable;
	bool			mon_capable;
	char			*name;
	struct list_head	domains;
	struct list_head	evt_list;
	unsigned long		fflags;

	void *res;
};

DECLARE_STATIC_KEY_FALSE(resctrl_enable_key);

/* rftype.flags */
#define RFTYPE_FLAGS_CPUS_LIST	1

/*
 * Define the file type flags for base and info directories.
 */
#define RFTYPE_INFO			BIT(0)
#define RFTYPE_BASE			BIT(1)
#define RF_CTRLSHIFT			4
#define RF_MONSHIFT			5
#define RF_TOPSHIFT			6
#define RFTYPE_CTRL			BIT(RF_CTRLSHIFT)
#define RFTYPE_MON			BIT(RF_MONSHIFT)
#define RFTYPE_TOP			BIT(RF_TOPSHIFT)
#define RFTYPE_RES_SMMU			BIT(7)
#define RFTYPE_RES_CACHE		BIT(8)
#define RFTYPE_RES_MB			BIT(9)
#define RFTYPE_RES_MC			BIT(10)
#define RF_CTRL_INFO			(RFTYPE_INFO | RFTYPE_CTRL)
#define RF_MON_INFO			(RFTYPE_INFO | RFTYPE_MON)
#define RF_TOP_INFO			(RFTYPE_INFO | RFTYPE_TOP)
#define RF_CTRL_BASE			(RFTYPE_BASE | RFTYPE_CTRL)

/* List of all resource groups */
extern struct list_head resctrl_all_groups;

/**
 * struct rftype - describe each file in the resctrl file system
 * @name:	File name
 * @mode:	Access mode
 * @kf_ops:	File operations
 * @flags:	File specific RFTYPE_FLAGS_* flags
 * @fflags:	File specific RF_* or RFTYPE_* flags
 * @seq_show:	Show content of the file
 * @write:	Write to the file
 */
struct rftype {
	char			*name;
	umode_t			mode;
	struct kernfs_ops	*kf_ops;
	unsigned long		flags;
	unsigned long		fflags;

	bool (*enable)(void *arg);

	int (*seq_show)(struct kernfs_open_file *of,
			struct seq_file *sf, void *v);
	/*
	 * write() is the generic write callback which maps directly to
	 * kernfs write operation and overrides all other operations.
	 * Maximum write size is determined by ->max_write_len.
	 */
	ssize_t (*write)(struct kernfs_open_file *of,
			 char *buf, size_t nbytes, loff_t off);
};

DECLARE_STATIC_KEY_FALSE(resctrl_alloc_enable_key);
extern struct rdtgroup resctrl_group_default;

int __init resctrl_group_init(void);

int register_resctrl_specific_files(struct rftype *files, size_t len);
extern struct kernfs_ops resctrl_group_kf_single_ops;

extern struct rdtgroup *resctrl_group_kn_lock_live(struct kernfs_node *kn);
void resctrl_group_kn_unlock(struct kernfs_node *kn);

void post_resctrl_mount(void);

#endif
