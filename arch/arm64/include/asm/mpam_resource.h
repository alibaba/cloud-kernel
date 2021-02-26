/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_MPAM_RESOURCE_H
#define _ASM_ARM64_MPAM_RESOURCE_H

#include <linux/bitops.h>

#define MPAMF_IDR		0x0000
#define MPAMF_SIDR		0x0008
#define MPAMF_MSMON_IDR		0x0080
#define MPAMF_IMPL_IDR		0x0028
#define MPAMF_CPOR_IDR		0x0030
#define MPAMF_CCAP_IDR		0x0038
#define MPAMF_MBW_IDR		0x0040
#define MPAMF_PRI_IDR		0x0048
#define MPAMF_CSUMON_IDR	0x0088
#define MPAMF_MBWUMON_IDR	0x0090
#define MPAMF_PARTID_NRW_IDR	0x0050
#define MPAMF_IIDR		0x0018
#define MPAMF_AIDR		0x0020
#define MPAMCFG_PART_SEL	0x0100
#define MPAMCFG_CPBM		0x1000
#define MPAMCFG_CMAX		0x0108
#define MPAMCFG_MBW_MIN		0x0200
#define MPAMCFG_MBW_MAX		0x0208
#define MPAMCFG_MBW_WINWD	0x0220
#define MPAMCFG_MBW_PBM		0x2000
#define MPAMCFG_PRI		0x0400
#define MPAMCFG_MBW_PROP	0x0500
#define MPAMCFG_INTPARTID	0x0600
#define MSMON_CFG_MON_SEL	0x0800
#define MSMON_CFG_CSU_FLT	0x0810
#define MSMON_CFG_CSU_CTL	0x0818
#define MSMON_CFG_MBWU_FLT	0x0820
#define MSMON_CFG_MBWU_CTL	0x0828
#define MSMON_CSU		0x0840
#define MSMON_CSU_CAPTURE	0x0848
#define MSMON_MBWU		0x0860
#define MSMON_MBWU_CAPTURE	0x0868
#define MSMON_CAPT_EVNT		0x0808
#define MPAMF_ESR		0x00F8
#define MPAMF_ECR		0x00F0

#define HAS_CCAP_PART		BIT(24)
#define HAS_CPOR_PART		BIT(25)
#define HAS_MBW_PART		BIT(26)
#define HAS_PRI_PART		BIT(27)
#define HAS_IMPL_IDR		BIT(29)
#define HAS_MSMON		BIT(30)

/* MPAMF_IDR */
#define MPAMF_IDR_PMG_MAX_MASK		((BIT(8) - 1) << 16)
#define MPAMF_IDR_PARTID_MAX_MASK	(BIT(16) - 1)
#define MPAMF_IDR_PMG_MAX_GET(v)	((v & MPAMF_IDR_PMG_MAX_MASK) >> 16)
#define MPAMF_IDR_PARTID_MAX_GET(v)	(v & MPAMF_IDR_PARTID_MAX_MASK)

#define MPAMF_IDR_HAS_CCAP_PART(v)	((v) & HAS_CCAP_PART)
#define MPAMF_IDR_HAS_CPOR_PART(v)	((v) & HAS_CPOR_PART)
#define MPAMF_IDR_HAS_MBW_PART(v)	((v) & HAS_MBW_PART)
#define MPAMF_IDR_HAS_MSMON(v)		((v) & HAS_MSMON)

/* MPAMF_x_IDR */
#define NUM_MON_MASK			(BIT(16) - 1)
#define MPAMF_IDR_NUM_MON(v)		((v) & NUM_MON_MASK)

/* TODO */

#define CPBM_WD_MASK		0xFFFF
#define CPBM_MASK		0x7FFF

#define BWA_WD			6		/* hard code for P680 */
#define MBW_MAX_MASK		0xFC00
#define MBW_MAX_HARDLIM		BIT(31)

#define MSMON_MATCH_PMG		BIT(17)
#define MSMON_MATCH_PARTID	BIT(16)

#define MSMON_CFG_CTL_EN        BIT(31)

#define MSMON_CFG_FLT_SET(r, p)		((r) << 16|(p))

#define MBWU_SUBTYPE_DEFAULT		(3 << 20)
#define MSMON_CFG_MBWU_CTL_SET(m)	(BIT(31)|MBWU_SUBTYPE_DEFAULT|(m))

#define MSMON_CFG_CSU_CTL_SET(m)	(BIT(31)|(m))

#define MSMON_CFG_CSU_TYPE  0x43
#define MSMON_CFG_MBWU_TYPE 0x42

/* [FIXME] hard code for hardlim */
#define MBW_MAX_SET(v)		(MBW_MAX_HARDLIM|((v) << (16 - BWA_WD)))
#define MBW_MAX_GET(v)		(((v) & MBW_MAX_MASK) >> (16 - BWA_WD))
/*
 * emulate the mpam nodes
 * These should be reported by ACPI MPAM Table.
 */

struct mpam_node {
	/* MPAM node header */
	u8              type;   /* MPAM_SMMU, MPAM_CACHE, MPAM_MC */
	u64             addr;
	void __iomem	*base;
	struct cpumask  cpu_mask;
	u64		default_ctrl;

	/* for debug */
	char            *cpus_list;
	char		*name;
};

int mpam_nodes_init(void);

#endif /* _ASM_ARM64_MPAM_RESOURCE_H */
