#ifndef _ASM_ARM64_RESCTRL_H
#define _ASM_ARM64_RESCTRL_H

#include <linux/resctrlfs.h>
#include <asm/mpam_sched.h>
#include <asm/mpam.h>

#if defined(CONFIG_RESCTRL) && defined(CONFIG_MPAM)

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
	QOS_CAT_CMAX_EVENT_ID           = 0x05,
	QOS_CAT_INTPRI_EVENT_ID         = 0x06,
	QOS_CAT_DSPRI_EVENT_ID          = 0x07,
	QOS_MBA_MAX_EVENT_ID            = 0x08,
	QOS_MBA_MIN_EVENT_ID            = 0x09,
	QOS_MBA_PBM_EVENT_ID            = 0x0a,
	QOS_MBA_INTPRI_EVENT_ID         = 0x0b,
	QOS_MBA_DSPRI_EVENT_ID          = 0x0c,
	QOS_MBA_HDL_EVENT_ID            = 0x0d,
	/* Must be the last */
	RESCTRL_NUM_EVENT_IDS,
};

enum rdt_group_type {
	RDTCTRL_GROUP = 0,
	RDTMON_GROUP,
	RDT_NUM_GROUP,
};

/**
 * struct resctrl_cache - Cache allocation related data
 * @cbm_len:        Length of the cache bit mask
 * @min_cbm_bits:   Minimum number of consecutive bits to be set
 * @shareable_bits: Bitmask of shareable resource with other
 *          executing entities
 */
struct resctrl_cache {
	u32     cbm_len;
	u32     shareable_bits;
	u32     min_cbm_bits;
};

/**
 * struct resctrl_membw - Memory bandwidth allocation related data
 * @min_bw:     Minimum memory bandwidth percentage user can request
 * @bw_gran:        Granularity at which the memory bandwidth is allocated
 * @delay_linear:   True if memory B/W delay is in linear scale
 * @ctrl_extend_bits: Indicates if there are extra ctrl capabilities supported.
 *          e.g. priority/hardlimit.
 */
struct resctrl_membw {
	u32     min_bw;
	u32     bw_gran;
	u32     delay_linear;
};

/**
 * struct resctrl_resource - attributes of an RDT resource
 * @rid:		The index of the resource
 * @alloc_enabled:		Is allocation enabled on this machine
 * @mon_enabled:		Is monitoring enabled for this feature
 * @alloc_capable:		Is allocation available on this machine
 * @mon_capable:		Is monitor feature available on this machine
 * @name:		Name to use in "schemata" file
 * @domains:	All domains for this resource
 * @cache:		Cache allocation related data
 * @mbw:		Memory Bandwidth allocation related data
 * @evt_list:	List of monitoring events
 * @fflags:		flags to choose base and info files
 */
struct resctrl_resource {
	int             rid;
	bool            alloc_enabled;
	bool            mon_enabled;
	bool            alloc_capable;
	bool            mon_capable;
	char            *name;
	struct list_head    domains;
	u32             dom_num;
	struct list_head    evt_list;
	unsigned long   fflags;

	struct resctrl_cache cache;
	struct resctrl_membw mbw;

	bool            cdp_capable;
	bool            cdp_enable;
	u32             *default_ctrl;

	u32             ctrl_extend_bits;

	void            *res;
};

/* List of all resource groups */
extern struct list_head resctrl_all_groups;

/**
 * struct mongroup - store mon group's data in resctrl fs.
 * @mon_data_kn     kernlfs node for the mon_data directory
 * @parent:         parent rdtgrp
 * @crdtgrp_list:       child rdtgroup node list
 * @rmid:           rmid for this rdtgroup
 * @init:           init flag
 */
struct mongroup {
	struct kernfs_node  *mon_data_kn;
	struct rdtgroup     *parent;
	struct list_head    crdtgrp_list;
	u32         rmid;
	int         init;
};

/**
 * struct sd_closid - software defined closid
 * @intpartid:  closid for this rdtgroup only for allocation
 * @reqpartid:  closid for synchronizing configuration and monitoring
 */
struct sd_closid {
	u32         intpartid;
	u32         reqpartid;
};

/**
 * struct rdtgroup - store rdtgroup's data in resctrl file system.
 * @kn:             kernfs node
 * @resctrl_group_list:     linked list for all rdtgroups
 * @closid:             software defined closid
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

enum resctrl_ctrl_type {
	SCHEMA_COMM = 0,
	SCHEMA_PRI,
	SCHEMA_HDL,
	SCHEMA_PBM,
	SCHEMA_MAX,
	SCHEMA_MIN,
	SCHEMA_NUM_CTRL_TYPE
};

#define for_each_ctrl_type(t)	\
		for (t = SCHEMA_COMM; t != SCHEMA_NUM_CTRL_TYPE; t++)

#define for_each_extend_ctrl_type(t)	\
		for (t = SCHEMA_PRI; t != SCHEMA_NUM_CTRL_TYPE; t++)

/**
 * struct resctrl_ctrl_feature - ctrl feature member live in schema list
 * @flags:    Does what ctrl types can this feature server for
 * @name:     Name of this ctrl feature
 * @max_wd:   Max width of this feature can be input from outter space
 * @base:     Base of integer from outter space
 * @evt:      rdt_event_id event owned for applying configuration
 * @capable:  Does this feature support
 * @enabled:  Enabled or not.
 * @default_ctrl:  Default ctrl value of this feature
 */
struct resctrl_ctrl_feature {
	enum resctrl_ctrl_type type;
	int        flags;
	const char *name;
	u32        max_wd;
	int        base;
	enum rdt_event_id   evt;
	int        default_ctrl;
	bool       capable;
	bool       enabled;

	const char *ctrl_suffix;
};

struct msr_param {
	enum resctrl_ctrl_type type;
	struct sd_closid *closid;
};

enum resctrl_conf_type {
	CDP_BOTH = 0,
	CDP_CODE,
	CDP_DATA,
	CDP_NUM_CONF_TYPE,
};

static inline int conf_name_to_conf_type(char *name)
{
	enum resctrl_conf_type t;

	if (!strcmp(name, "L3CODE") || !strcmp(name, "L2CODE"))
		t = CDP_CODE;
	else if (!strcmp(name, "L3DATA") || !strcmp(name, "L2DATA"))
		t = CDP_DATA;
	else
		t = CDP_BOTH;
	return t;
}

#define for_each_conf_type(t) \
		for (t = CDP_BOTH; t < CDP_NUM_CONF_TYPE; t++)

typedef struct { u16 val; } hw_mpamid_t;
typedef hw_mpamid_t hw_closid_t;

#define hw_mpamid_val(__x) (__x.val)
#define hw_closid_val(__x) (__x.val)

#define as_hw_mpamid_t(__x) ((hw_mpamid_t){(__x)})

/**
 * When cdp enabled, give (closid + 1) to Cache LxDATA.
 */
#define resctrl_cdp_mpamid_map(__id, __type, __hw_mpamid)    \
do {   \
	if (__type == CDP_CODE) \
		__hw_mpamid = as_hw_mpamid_t(__id); \
	else if (__type == CDP_DATA)     \
		__hw_mpamid = as_hw_mpamid_t(__id + 1); \
	else    \
		__hw_mpamid = as_hw_mpamid_t(__id); \
} while (0)

#define resctrl_cdp_mpamid_map_val(__id, __type, __hw_mpamid_val)	\
do {	\
	if (__type == CDP_CODE) \
		__hw_mpamid_val = __id; \
	else if (__type == CDP_DATA)     \
		__hw_mpamid_val = __id + 1; \
	else    \
		__hw_mpamid_val = __id; \
} while (0)

bool is_resctrl_cdp_enabled(void);

#define hw_alloc_validate(__flag) \
do {   \
	if (is_resctrl_cdp_enabled()) \
		__flag = true;  \
	else    \
		__flag = false; \
} while (0)

#define hw_alloc_times_validate(__times, __flag) \
do {   \
	hw_alloc_validate(__flag); \
	if (__flag) \
		__times = 2;    \
	else    \
		__times = 1;    \
} while (0)

/**
 * struct resctrl_staged_config - parsed configuration to be applied
 * @hw_closid:      raw closid for this configuration, regardless of CDP
 * @new_ctrl:       new ctrl value to be loaded
 * @have_new_ctrl:  did user provide new_ctrl for this domain
 * @new_ctrl_type:  CDP property of the new ctrl
 * @cdp_both_ctrl:   did cdp both control if cdp enabled
 */
struct resctrl_staged_config {
	hw_closid_t     hw_closid;
	u32             new_ctrl[SCHEMA_NUM_CTRL_TYPE];
	bool            have_new_ctrl;
	enum resctrl_conf_type  conf_type;
	enum resctrl_ctrl_type  ctrl_type;
	bool            cdp_both_ctrl;
};

/* later move to resctrl common directory */
#define RESCTRL_NAME_LEN    15

struct resctrl_schema_ctrl {
	struct list_head       list;
	char name[RESCTRL_NAME_LEN];
	enum resctrl_ctrl_type     ctrl_type;
};

/**
 * @list:   Member of resctrl's schema list
 * @name:   Name visible in the schemata file
 * @conf_type:  Type of configuration, e.g. code/data/both
 * @res:    The rdt_resource for this entry
 * @schemata_ctrl_list:   Type of ctrl configuration. e.g. priority/hardlimit
 * @cdp_mc_both:   did cdp both mon/ctrl if cdp enabled
 */
struct resctrl_schema {
	struct list_head        list;
	char                name[RESCTRL_NAME_LEN];
	enum resctrl_conf_type      conf_type;
	struct resctrl_resource     *res;
	struct list_head        schema_ctrl_list;
	bool                cdp_mc_both;
};

int schemata_list_init(void);

void schemata_list_destroy(void);

/**
 * struct rdt_domain - group of cpus sharing an RDT resource
 * @list:	all instances of this resource
 * @id:		unique id for this instance
 * @cpu_mask:	which cpus share this resource
 * @base        MMIO base address
 * @ctrl_val:	array of cache or mem ctrl values (indexed by CLOSID)
 * @have_new_ctrl: did user provide new_ctrl for this domain
 */
struct rdt_domain {
	struct list_head	list;
	int			id;
	struct cpumask		cpu_mask;
	void __iomem		*base;

	/* arch specific fields */
	u32			*ctrl_val[SCHEMA_NUM_CTRL_TYPE];
	bool			have_new_ctrl;

	/* for debug */
	char			*cpus_list;

	struct resctrl_staged_config staged_cfg[CDP_NUM_CONF_TYPE];
};

/*
 * Internal struct of resctrl_resource structure,
 * for static initialization.
 */
struct raw_resctrl_resource {
	u16		num_partid;
	u16		num_intpartid;
	u16		num_pmg;

	u16		extend_ctrls_wd[SCHEMA_NUM_CTRL_TYPE];

	void (*msr_update)(struct resctrl_resource *r, struct rdt_domain *d,
					struct msr_param *para);
	u64 (*msr_read)(struct resctrl_resource *r, struct rdt_domain *d,
					struct msr_param *para);

	int			data_width;
	const char		*format_str;
	int (*parse_ctrlval)(char *buf, struct resctrl_resource *r,
			struct resctrl_staged_config *cfg, enum resctrl_ctrl_type ctrl_type);

	u16			num_mon;
	u64 (*mon_read)(struct rdt_domain *d, void *md_priv);
	int (*mon_write)(struct rdt_domain *d, void *md_priv);
	unsigned long       fflags;

	struct resctrl_ctrl_feature ctrl_features[SCHEMA_NUM_CTRL_TYPE];
};

int rmid_alloc(int entry_idx);
void rmid_free(int rmid);

int resctrl_id_init(void);
int closid_alloc(void);
void closid_free(int closid);

void update_cpu_closid_rmid(void *info);
void update_closid_rmid(const struct cpumask *cpu_mask,
				struct resctrl_group *r);
int __resctrl_group_move_task(struct task_struct *tsk,
				struct resctrl_group *rdtgrp);

extern bool rdt_alloc_capable;
extern bool rdt_mon_capable;

/* rdtgroup.flags */
#define	RDT_DELETED		BIT(0)

void rdt_last_cmd_clear(void);
void rdt_last_cmd_puts(const char *s);
void rdt_last_cmd_printf(const char *fmt, ...);

void resctrl_resource_reset(void);

int resctrl_group_init_alloc(struct rdtgroup *rdtgrp);

static inline int __resctrl_group_show_options(struct seq_file *seq)
{
	return 0;
}

int resctrl_update_groups_config(struct rdtgroup *rdtgrp);

#define RESCTRL_MAX_CLOSID 32

int __init resctrl_group_init(void);

void post_resctrl_mount(void);

extern struct mutex resctrl_group_mutex;
DECLARE_STATIC_KEY_FALSE(resctrl_alloc_enable_key);
extern struct rdtgroup resctrl_group_default;
int resctrl_mkdir_mondata_all_subdir(struct kernfs_node *parent_kn,
		struct resctrl_group *prgrp);

int resctrl_group_create_info_dir(struct kernfs_node *parent_kn,
		struct kernfs_node **kn_info);

int register_resctrl_specific_files(struct rftype *files, size_t len);
extern struct kernfs_ops resctrl_group_kf_single_ops;

extern struct rdtgroup *resctrl_group_kn_lock_live(struct kernfs_node *kn);
void resctrl_group_kn_unlock(struct kernfs_node *kn);

void release_rdtgroupfs_options(void);
int parse_rdtgroupfs_options(char *data);

int resctrl_group_add_files(struct kernfs_node *kn, unsigned long fflags);

static inline void resctrl_cdp_update_cpus_state(struct resctrl_group *rdtgrp)
{
	int cpu;

	/*
	 * If cdp on, tasks in resctrl default group with closid=0
	 * and rmid=0 don't know how to fill proper partid_i/pmg_i
	 * and partid_d/pmg_d into MPAMx_ELx sysregs by mpam_sched_in()
	 * called by __switch_to(), it's because current cpu's default
	 * closid and rmid are also equal to 0 and make the operation
	 * modifying configuration passed. Update per cpu default closid
	 * of none-zero value, call update_closid_rmid() to update each
	 * cpu's mpam proper MPAMx_ELx sysregs for setting partid and
	 * pmg when mounting resctrl sysfs, which is a practical method;
	 * Besides, to support cpu online and offline we should set
	 * cur_closid to 0.
	 */
	for_each_cpu(cpu, &rdtgrp->cpu_mask) {
		per_cpu(pqr_state.default_closid, cpu) = ~0;
		per_cpu(pqr_state.cur_closid, cpu) = 0;
	}

	update_closid_rmid(&rdtgrp->cpu_mask, NULL);
}


#define RESCTRL_MAX_CBM 32

struct resctrl_fs_context {
	struct kernfs_fs_context        kfc;
	bool enable_cdpl3;
	bool enable_cdpl2;
	bool enable_mbMax;
	bool enable_mbMin;
	bool enable_mbHdl;
	bool enable_mbPrio;
	bool enable_caPbm;
	bool enable_caMax;
	bool enable_caPrio;
};

static inline struct resctrl_fs_context *resctrl_fc2context(struct fs_context *fc)
{
	struct kernfs_fs_context *kfc = fc->fs_private;

	return container_of(kfc, struct resctrl_fs_context, kfc);
}

/*
 * This is only for avoiding unnecessary cost in mpam_sched_in()
 *  called by __switch_to() if using mpam_rmid_to_partid_pmg()
 * to get partid and pmg, we just simply shift and get their
 * two easily when we want.
 */
static inline void resctrl_navie_rmid_partid_pmg(u32 rmid, int *partid, int *pmg)
{
	*partid = rmid >> 16;
	*pmg = (rmid << 16) >> 16;
}

static inline u32 resctrl_navie_rmid(u32 rmid)
{
	int ret, partid, pmg;

	ret = mpam_rmid_to_partid_pmg(rmid, (int *)&partid, (int *)&pmg);
	if (ret)
		return 0;

	return (partid << 16) | pmg;
}

/*
 * closid.reqpartid is used as part of mapping to rmid, now
 * we only need to map intpartid to closid.
 */
static inline u32 resctrl_navie_closid(struct sd_closid closid)
{
	return closid.intpartid;
}

void extend_ctrl_disable(void);
void basic_ctrl_enable(void);
void disable_cdp(void);

int cdpl2_enable(void);
int cdpl3_enable(void);
int extend_ctrl_enable(char *tok);
#define DEFINE_INLINE_CTRL_FEATURE_ENABLE_FUNC(name)    \
	static inline int name##_enable(void) \
	{   \
		return extend_ctrl_enable(#name);	\
	}
DEFINE_INLINE_CTRL_FEATURE_ENABLE_FUNC(mbMax);
DEFINE_INLINE_CTRL_FEATURE_ENABLE_FUNC(mbMin);
DEFINE_INLINE_CTRL_FEATURE_ENABLE_FUNC(mbHdl);
DEFINE_INLINE_CTRL_FEATURE_ENABLE_FUNC(mbPrio);
DEFINE_INLINE_CTRL_FEATURE_ENABLE_FUNC(caPbm);
DEFINE_INLINE_CTRL_FEATURE_ENABLE_FUNC(caMax);
DEFINE_INLINE_CTRL_FEATURE_ENABLE_FUNC(caPrio);

#endif
#endif /* _ASM_ARM64_RESCTRL_H */
