/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_MPAM_INTERNAL_H
#define _ASM_ARM64_MPAM_INTERNAL_H

#include <asm/resctrl.h>

typedef u32 mpam_features_t;

struct mpam_component;
struct rdt_domain;
struct mpam_class;
struct raw_resctrl_resource;
struct resctrl_resource;
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
#define PARTID_MAX_MASK			(MPAM_MASK(PARTID_BITS) << PARTID_MAX_SHIFT)
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

#define RESCTRL_SHOW_DOM_MAX_NUM 8

#define mpam_read_sysreg_s(reg, name) read_sysreg_s(reg)
#define mpam_write_sysreg_s(v, r, n) write_sysreg_s(v, r)
#define mpam_readl(addr) readl(addr)
#define mpam_writel(v, addr) writel(v, addr)

/* 64bit arm64 specified */
union mon_data_bits {
	void *priv;
	struct {
		u8	rid;
		u8	domid;
		u8	partid;
		u8	pmg;
		u8	mon;
		u8	cdp_both_mon;
	} u;
};

ssize_t resctrl_group_schemata_write(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off);

int resctrl_group_schemata_show(struct kernfs_open_file *of,
				struct seq_file *s, void *v);

struct rdt_domain *mpam_find_domain(struct resctrl_resource *r, int id,
		struct list_head **pos);

extern bool rdt_alloc_capable;
extern bool rdt_mon_capable;

extern struct list_head mpam_classes;

#define MAX_MBA_BW  100u
#define GRAN_MBA_BW 2u

#define MPAM_ERRCODE_NONE                       0
#define MPAM_ERRCODE_PARTID_SEL_RANGE           1
#define MPAM_ERRCODE_REQ_PARTID_RANGE           2
#define MPAM_ERRCODE_MSMONCFG_ID_RANGE          3
#define MPAM_ERRCODE_REQ_PMG_RANGE              4
#define MPAM_ERRCODE_MONITOR_RANGE              5
#define MPAM_ERRCODE_INTPARTID_RANGE            6
#define MPAM_ERRCODE_UNEXPECTED_INTERNAL        7
#define _MPAM_NUM_ERRCODE                       8

struct mpam_resctrl_dom {
	struct mpam_component   *comp;

	struct rdt_domain   resctrl_dom;
};

struct mpam_resctrl_res {
	struct mpam_class   *class;

	bool resctrl_mba_uses_mbw_part;

	struct resctrl_resource resctrl_res;
};

struct sync_args {
	u8  domid;
	u8  pmg;
	struct sd_closid closid;
	u32 mon;
	bool match_pmg;
	enum rdt_event_id eventid;
};

struct mpam_device_sync {
	struct mpam_component *comp;

	struct sync_args *args;

	bool config_mon;
	atomic64_t mon_value;

	struct cpumask updated_on;

	atomic64_t cfg_value;
	int error;
};

#define for_each_resctrl_exports(r) \
		for (r = &mpam_resctrl_exports[0]; \
			r < &mpam_resctrl_exports[0] + \
			ARRAY_SIZE(mpam_resctrl_exports); r++)

#define for_each_supported_resctrl_exports(r) \
		for_each_resctrl_exports(r) \
			if (r->class)

/*
 * MPAM component config Structure
 */
struct mpam_config {

	/*
	 * The biggest config we could pass around is 4K, but resctrl's max
	 * cbm is u32, so we only need the full-size config during reset.
	 * Just in case a cache with a >u32 bitmap is exported for another
	 * reason, we need to track which bits of the configuration are valid.
	 */
	mpam_features_t valid;

	u32             cpbm;
	u32             mbw_pbm;
	u16             mbw_max;

	/*
	 *  dspri is downstream priority, intpri is internal priority.
	 */
	u16             dspri;
	u16             intpri;

	/*
	 * hardlimit or not
	 */
	bool            hdl;
};

/* Bits for mpam_features_t */
enum mpam_device_features {
	mpam_feat_ccap_part = 0,
	mpam_feat_cpor_part,
	mpam_feat_mbw_part,
	mpam_feat_mbw_min,
	mpam_feat_mbw_max,
	mpam_feat_mbw_prop,
	mpam_feat_intpri_part,
	mpam_feat_intpri_part_0_low,
	mpam_feat_dspri_part,
	mpam_feat_dspri_part_0_low,
	mpam_feat_msmon,
	mpam_feat_msmon_csu,
	mpam_feat_msmon_csu_capture,
	mpam_feat_msmon_mbwu,
	mpam_feat_msmon_mbwu_capture,
	mpam_feat_msmon_capt,
	mpam_feat_part_nrw,
	/* this feature always enabled */
	mpam_feat_part_hdl,
	MPAM_FEATURE_LAST,
};

static inline bool mpam_has_feature(enum mpam_device_features feat,
				mpam_features_t supported)
{
	return (1<<feat) & supported;
}

static inline void mpam_set_feature(enum mpam_device_features feat,
				mpam_features_t *supported)
{
	*supported |= (1<<feat);
}

static inline void mpam_clear_feature(enum mpam_device_features feat,
				mpam_features_t *supported)
{
	*supported &= ~(1<<feat);
}

#define MPAM_ARCHITECTURE_V1    0x10

static inline bool mpam_has_part_sel(mpam_features_t supported)
{
	mpam_features_t mask = (1<<mpam_feat_ccap_part) |
		(1<<mpam_feat_cpor_part) | (1<<mpam_feat_mbw_part) |
		(1<<mpam_feat_mbw_max) | (1<<mpam_feat_intpri_part) |
		(1<<mpam_feat_dspri_part);
	/* or HAS_PARTID_NRW or HAS_IMPL_IDR */

	return supported & mask;
}

/**
 * Reset component devices if args is NULL
 */
int mpam_component_config(struct mpam_component *comp,
			struct sync_args *args);

void mpam_reset_devices(void);

int mpam_component_mon(struct mpam_component *comp,
			struct sync_args *args, u64 *result);

void mpam_component_get_config(struct mpam_component *comp,
			struct sync_args *args, u32 *result);

u16 mpam_sysprops_num_partid(void);
u16 mpam_sysprops_num_pmg(void);

void mpam_class_list_lock_held(void);

extern struct mpam_resctrl_res mpam_resctrl_exports[RDT_NUM_RESOURCES];
extern struct mpam_resctrl_res mpam_resctrl_events[RESCTRL_NUM_EVENT_IDS];

int mpam_resctrl_cpu_online(unsigned int cpu);

int mpam_resctrl_cpu_offline(unsigned int cpu);

int mpam_resctrl_setup(void);

struct raw_resctrl_resource *
mpam_get_raw_resctrl_resource(u32 level);

int __init mpam_resctrl_init(void);

int mpam_resctrl_set_default_cpu(unsigned int cpu);
void mpam_resctrl_clear_default_cpu(unsigned int cpu);

int assoc_rmid_with_mon(u32 rmid);
void deassoc_rmid_with_mon(u32 rmid);
u32 get_rmid_mon(u32 rmid, enum resctrl_resource_level rid);
int rmid_mon_ptrs_init(u32 nr_rmids);

struct resctrl_resource *
mpam_resctrl_get_resource(enum resctrl_resource_level level);

#endif
