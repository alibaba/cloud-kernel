/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_MPAM_H
#define _ASM_ARM64_MPAM_H

#include <linux/sched.h>
#include <linux/kernfs.h>
#include <linux/jump_label.h>

#include <linux/seq_buf.h>
#include <linux/seq_file.h>
#include <linux/resctrlfs.h>

/* MPAM register */
#define SYS_MPAM0_EL1			sys_reg(3, 0, 10, 5, 1)
#define SYS_MPAM1_EL1			sys_reg(3, 0, 10, 5, 0)
#define SYS_MPAM2_EL2			sys_reg(3, 4, 10, 5, 0)
#define SYS_MPAM3_EL3			sys_reg(3, 6, 10, 5, 0)
#define SYS_MPAM1_EL12			sys_reg(3, 5, 10, 5, 0)
#define SYS_MPAMHCR_EL2			sys_reg(3, 4, 10, 4, 0)
#define SYS_MPAMVPMV_EL2		sys_reg(3, 4, 10, 4, 1)
#define SYS_MPAMVPMn_EL2(n)		sys_reg(3, 4, 10, 6, n)
#define SYS_MPAMIDR_EL1			sys_reg(3, 0, 10, 4, 4)

#define MPAM_MASK(n)			((1UL << n) - 1)
/* plan to use GENMASK(n, 0) instead */

/*
 * MPAMx_ELn:
 * 15:0		PARTID_I
 * 31:16	PARTID_D
 * 39:32	PMG_I
 * 47:40	PMG_D
 * 48		TRAPMPAM1EL1
 * 49		TRAPMPAM0EL1
 * 61:49	Reserved
 * 62		TRAPLOWER
 * 63		MPAMEN
 */
#define PARTID_BITS			(16)
#define PMG_BITS			(8)
#define PARTID_MASK			MPAM_MASK(PARTID_BITS)
#define PMG_MASK			MPAM_MASK(PMG_BITS)

#define PARTID_I_SHIFT			(0)
#define PARTID_D_SHIFT			(PARTID_I_SHIFT + PARTID_BITS)
#define PMG_I_SHIFT			(PARTID_D_SHIFT + PARTID_BITS)
#define PMG_D_SHIFT			(PMG_I_SHIFT + PMG_BITS)

#define PARTID_I_MASK			(PARTID_MASK << PARTID_I_SHIFT)
#define PARTID_D_MASK			(PARTID_MASK << PARTID_D_SHIFT)
#define PARTID_I_CLR(r)			((r) & ~PARTID_I_MASK)
#define PARTID_D_CLR(r)			((r) & ~PARTID_D_MASK)
#define PARTID_CLR(r)			(PARTID_I_CLR(r) & PARTID_D_CLR(r))

#define PARTID_I_SET(r, id)		(PARTID_I_CLR(r) | ((id) << PARTID_I_SHIFT))
#define PARTID_D_SET(r, id)		(PARTID_D_CLR(r) | ((id) << PARTID_D_SHIFT))
#define PARTID_SET(r, id)		(PARTID_CLR(r) | ((id) << PARTID_I_SHIFT) | ((id) << PARTID_D_SHIFT))

#define PMG_I_MASK			(PMG_MASK << PMG_I_SHIFT)
#define PMG_D_MASK			(PMG_MASK << PMG_D_SHIFT)
#define PMG_I_CLR(r)			((r) & ~PMG_I_MASK)
#define PMG_D_CLR(r)			((r) & ~PMG_D_MASK)
#define PMG_CLR(r)			(PMG_I_CLR(r) & PMG_D_CLR(r))

#define PMG_I_SET(r, id)		(PMG_I_CLR(r) | ((id) << PMG_I_SHIFT))
#define PMG_D_SET(r, id)		(PMG_D_CLR(r) | ((id) << PMG_D_SHIFT))
#define PMG_SET(r, id)			(PMG_CLR(r) | ((id) << PMG_I_SHIFT) | ((id) << PMG_D_SHIFT))

#define TRAPMPAM1EL1_SHIFT		(PMG_D_SHIFT + PMG_BITS)
#define TRAPMPAM0EL1_SHIFT		(TRAPMPAM1EL1_SHIFT + 1)
#define TRAPLOWER_SHIFT			(TRAPMPAM0EL1_SHIFT + 13)
#define MPAMEN_SHIFT			(TRAPLOWER_SHIFT + 1)

/*
 * MPAMHCR_EL2:
 * 0		EL0_VPMEN
 * 1		EL1_VPMEN
 * 7:2		Reserved
 * 8		GSTAPP_PLK
 * 30:9		Reserved
 * 31		TRAP_MPAMIDR_EL1
 * 63:32	Reserved
 */
#define EL0_VPMEN_SHIFT			(0)
#define EL1_VPMEN_SHIFT			(EL0_VPMEN_SHIFT + 1)
#define GSTAPP_PLK_SHIFT		(8)
#define TRAP_MPAMIDR_EL1_SHIFT		(31)

/*
 * MPAMIDR_EL1:
 * 15:0		PARTID_MAX
 * 16		Reserved
 * 17		HAS_HCR
 * 20:18	VPMR_MAX
 * 31:21	Reserved
 * 39:32	PMG_MAX
 * 63:40	Reserved
 */
#define VPMR_MAX_BITS			(3)
#define PARTID_MAX_SHIFT		(0)
#define PARTID_MAX_MASK		(MPAM_MASK(PARTID_BITS) << PARTID_MAX_SHIFT)
#define HAS_HCR_SHIFT			(PARTID_MAX_SHIFT + PARTID_BITS + 1)
#define VPMR_MAX_SHIFT			(HAS_HCR_SHIFT + 1)
#define PMG_MAX_SHIFT			(VPMR_MAX_SHIFT + VPMR_MAX_BITS + 11)
#define PMG_MAX_MASK			(MPAM_MASK(PMG_BITS) << PMG_MAX_SHIFT)
#define VPMR_MASK			MPAM_MASK(VPMR_MAX_BITS)

/*
 * MPAMVPMV_EL2:
 * 31:0		VPM_V
 * 63:32	Reserved
 */
#define VPM_V_BITS			32

DECLARE_STATIC_KEY_FALSE(resctrl_enable_key);
DECLARE_STATIC_KEY_FALSE(resctrl_mon_enable_key);

extern int max_name_width, max_data_width;

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

#define hw_closid_t hw_mpamid_t
#define hw_monid_t hw_mpamid_t
#define hw_closid_val(__x) (__x.val)
#define hw_monid_val(__x) (__x.val)

#define as_hw_t(__name, __x) \
			((hw_##__name##id_t){(__x)})
#define hw_val(__name, __x) \
			hw_##__name##id_val(__x)

/**
 * When cdp enabled, give (closid + 1) to Cache LxDATA.
 */
#define resctrl_cdp_map(__name, __closid, __type, __result)    \
do {   \
	if (__type == CDP_CODE) \
		__result = as_hw_t(__name, __closid); \
	else if (__type == CDP_DATA)     \
		__result = as_hw_t(__name, __closid + 1); \
	else    \
		__result = as_hw_t(__name, __closid); \
} while (0)

bool is_resctrl_cdp_enabled(void);

#define hw_alloc_times_validate(__times, __flag) \
do {   \
	__flag = is_resctrl_cdp_enabled();	\
	__times = flag ? 2 : 1;	\
} while (0)


/**
 * struct resctrl_staged_config - parsed configuration to be applied
 * @hw_closid:      raw closid for this configuration, regardless of CDP
 * @new_ctrl:       new ctrl value to be loaded
 * @have_new_ctrl:  did user provide new_ctrl for this domain
 * @new_ctrl_type:  CDP property of the new ctrl
 */
struct resctrl_staged_config {
	hw_closid_t     hw_closid;
	u32             new_ctrl;
	bool            have_new_ctrl;
	enum resctrl_conf_type  conf_type;
};

/* later move to resctrl common directory */
#define RESCTRL_NAME_LEN    7

/**
 * @list:   Member of resctrl's schema list
 * @name:   Name visible in the schemata file
 * @conf_type:  Type of configuration, e.g. code/data/both
 * @res:    The rdt_resource for this entry
 */
struct resctrl_schema {
	struct list_head        list;
	char                    name[RESCTRL_NAME_LEN];
	enum resctrl_conf_type      conf_type;
	struct resctrl_resource     *res;
};

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
	void __iomem		*base;

	/* arch specific fields */
	u32			*ctrl_val;
	u32			new_ctrl;
	bool			have_new_ctrl;

	/* for debug */
	char			*cpus_list;

	struct resctrl_staged_config staged_cfg[CDP_NUM_CONF_TYPE];
};

#define RESCTRL_SHOW_DOM_MAX_NUM 8

int __init resctrl_group_init(void);

int resctrl_group_mondata_show(struct seq_file *m, void *arg);
void rmdir_mondata_subdir_allrdtgrp(struct resctrl_resource *r,
				    unsigned int dom_id);

int cdp_enable(int level, int data_type, int code_type);

void post_resctrl_mount(void);

#define mpam_read_sysreg_s(reg, name) read_sysreg_s(reg)
#define mpam_write_sysreg_s(v, r, n) write_sysreg_s(v, r)
#define mpam_readl(addr) readl(addr)
#define mpam_writel(v, addr) writel(v, addr)

struct sd_closid;

struct msr_param {
	struct sd_closid *closid;
};

/**
 * struct resctrl_resource - attributes of an RDT resource
 * @rid:		The index of the resource
 * @alloc_enabled:	Is allocation enabled on this machine
 * @mon_enabled:		Is monitoring enabled for this feature
 * @alloc_capable:	Is allocation available on this machine
 * @mon_capable:		Is monitor feature available on this machine
 * @name:		Name to use in "schemata" file
 * @num_closid:		Number of CLOSIDs available
 * @cache_level:	Which cache level defines scope of this resource
 * @msr_base:		Base MSR address for CBMs
 * @msr_update:		Function pointer to update QOS MSRs
 * @data_width:		Character width of data when displaying
 * @domains:		All domains for this resource
 * @cache:		Cache allocation related data
 * @format_str:		Per resource format string to show domain value
 * @parse_ctrlval:	Per resource function pointer to parse control values
 * @evt_list:			List of monitoring events
 * @num_rmid:			Number of RMIDs available
 * @mon_scale:			cqm counter * mon_scale = occupancy in bytes
 * @fflags:			flags to choose base and info files
 */

struct raw_resctrl_resource {
	u16                 num_partid;
	u16                 num_intpartid;
	u16                 num_pmg;

	u16                 pri_wd;
	u16                 hdl_wd;

	void (*msr_update)(struct resctrl_resource *r, struct rdt_domain *d,
			struct list_head *opt_list, struct msr_param *para);
	u64 (*msr_read)(struct rdt_domain *d, struct msr_param *para);

	int			data_width;
	const char		*format_str;
	int (*parse_ctrlval)(char *buf, struct raw_resctrl_resource *r,
			struct resctrl_staged_config *cfg);

	u16                num_mon;
	u64 (*mon_read)(struct rdt_domain *d, void *md_priv);
	int (*mon_write)(struct rdt_domain *d, void *md_priv);
};

/* 64bit arm64 specified */
union mon_data_bits {
	void *priv;
	struct {
		u8	rid;
		u8	domid;
		u8	partid;
		u8	pmg;
		u8	mon;
	} u;
};

ssize_t resctrl_group_schemata_write(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off);

int resctrl_group_schemata_show(struct kernfs_open_file *of,
				struct seq_file *s, void *v);

struct rdt_domain *mpam_find_domain(struct resctrl_resource *r, int id,
		struct list_head **pos);

int resctrl_group_alloc_mon(struct rdtgroup *grp);

u16 mpam_resctrl_max_mon_num(void);

void pmg_init(void);
void mon_init(void);

#endif /* _ASM_ARM64_MPAM_H */
