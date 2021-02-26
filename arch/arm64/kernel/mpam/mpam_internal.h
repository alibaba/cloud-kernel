/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_MPAM_INTERNAL_H
#define _ASM_ARM64_MPAM_INTERNAL_H

#include <linux/resctrlfs.h>

typedef u32 mpam_features_t;

struct mpam_component;
struct rdt_domain;
struct mpam_class;
struct raw_resctrl_resource;

extern bool rdt_alloc_capable;
extern bool rdt_mon_capable;

extern struct list_head mpam_classes;

#define MAX_MBA_BW  100u

struct mpam_resctrl_dom {
	struct mpam_component   *comp;

	struct rdt_domain   resctrl_dom;
};

struct mpam_resctrl_res {
	struct mpam_class   *class;

	bool resctrl_mba_uses_mbw_part;

	struct resctrl_resource resctrl_res;
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

	u32             intpartid;
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

u16 mpam_sysprops_num_partid(void);
u16 mpam_sysprops_num_pmg(void);

void mpam_class_list_lock_held(void);

int mpam_resctrl_cpu_online(unsigned int cpu);

int mpam_resctrl_cpu_offline(unsigned int cpu);

int mpam_resctrl_setup(void);

struct raw_resctrl_resource *
mpam_get_raw_resctrl_resource(u32 level);

int __init mpam_resctrl_init(void);

int mpam_resctrl_set_default_cpu(unsigned int cpu);
void mpam_resctrl_clear_default_cpu(unsigned int cpu);

#endif
