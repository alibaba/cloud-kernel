/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_MPAM_INTERNAL_H
#define _ASM_ARM64_MPAM_INTERNAL_H

typedef u32 mpam_features_t;

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

#endif
