/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_MPAM_RESOURCE_H
#define _ASM_ARM64_MPAM_RESOURCE_H

#include <linux/bitops.h>

#define MPAMF_IDR           0x0000
#define MPAMF_SIDR          0x0008
#define MPAMF_MSMON_IDR     0x0080
#define MPAMF_IMPL_IDR      0x0028
#define MPAMF_CPOR_IDR      0x0030
#define MPAMF_CCAP_IDR      0x0038
#define MPAMF_MBW_IDR       0x0040
#define MPAMF_PRI_IDR       0x0048
#define MPAMF_CSUMON_IDR    0x0088
#define MPAMF_MBWUMON_IDR   0x0090
#define MPAMF_PARTID_NRW_IDR    0x0050
#define MPAMF_IIDR          0x0018
#define MPAMF_AIDR          0x0020
#define MPAMCFG_PART_SEL    0x0100
#define MPAMCFG_CPBM        0x1000
#define MPAMCFG_CMAX        0x0108
#define MPAMCFG_MBW_MIN     0x0200
#define MPAMCFG_MBW_MAX     0x0208
#define MPAMCFG_MBW_WINWD   0x0220
#define MPAMCFG_MBW_PBM     0x2000
#define MPAMCFG_PRI         0x0400
#define MPAMCFG_MBW_PROP    0x0500
#define MPAMCFG_INTPARTID   0x0600
#define MSMON_CFG_MON_SEL   0x0800
#define MSMON_CFG_CSU_FLT   0x0810
#define MSMON_CFG_CSU_CTL   0x0818
#define MSMON_CFG_MBWU_FLT  0x0820
#define MSMON_CFG_MBWU_CTL  0x0828
#define MSMON_CSU           0x0840
#define MSMON_CSU_CAPTURE   0x0848
#define MSMON_MBWU          0x0860
#define MSMON_MBWU_CAPTURE  0x0868
#define MSMON_CAPT_EVNT     0x0808
#define MPAMF_ESR           0x00F8
#define MPAMF_ECR           0x00F0

#define HAS_CCAP_PART       BIT(24)
#define HAS_CPOR_PART       BIT(25)
#define HAS_MBW_PART        BIT(26)
#define HAS_PRI_PART        BIT(27)
#define HAS_IMPL_IDR        BIT(29)
#define HAS_MSMON           BIT(30)
#define HAS_PARTID_NRW      BIT(31)

/* MPAMF_IDR */
#define MPAMF_IDR_PMG_MAX_MASK      ((BIT(8) - 1) << 16)
#define MPAMF_IDR_PMG_MAX_SHIFT     16
#define MPAMF_IDR_PARTID_MAX_MASK   (BIT(16) - 1)
#define MPAMF_IDR_PMG_MAX_GET(v)    ((v & MPAMF_IDR_PMG_MAX_MASK) >> 16)
#define MPAMF_IDR_PARTID_MAX_GET(v) (v & MPAMF_IDR_PARTID_MAX_MASK)

#define MPAMF_IDR_HAS_CCAP_PART(v)  ((v) & HAS_CCAP_PART)
#define MPAMF_IDR_HAS_CPOR_PART(v)  ((v) & HAS_CPOR_PART)
#define MPAMF_IDR_HAS_MBW_PART(v)   ((v) & HAS_MBW_PART)
#define MPAMF_IDR_HAS_MSMON(v)      ((v) & HAS_MSMON)
#define MPAMF_IDR_PARTID_MASK       GENMASK(15, 0)
#define MPAMF_IDR_PMG_MASK          GENMASK(23, 16)
#define MPAMF_IDR_PMG_SHIFT         16
#define MPAMF_IDR_HAS_PARTID_NRW(v) ((v) & HAS_PARTID_NRW)
#define NUM_MON_MASK                (BIT(16) - 1)
#define MPAMF_IDR_NUM_MON(v)        ((v) & NUM_MON_MASK)

#define CPBM_WD_MASK        0xFFFF
#define CPBM_MASK           0x7FFF

#define BWA_WD              6		/* hard code for P680 */
#define MBW_MAX_MASK        0xFC00
#define MBW_MAX_HARDLIM     BIT(31)
#define MBW_MAX_SET(v)      (MBW_MAX_HARDLIM|((v) << (16 - BWA_WD)))
#define MBW_MAX_GET(v)      (((v) & MBW_MAX_MASK) >> (16 - BWA_WD))

#define MSMON_MATCH_PMG     BIT(17)
#define MSMON_MATCH_PARTID  BIT(16)
#define MSMON_CFG_CTL_EN    BIT(31)
#define MSMON_CFG_FLT_SET(r, p)     ((r) << 16|(p))
#define MBWU_SUBTYPE_DEFAULT        (3 << 20)
#define MSMON_CFG_MBWU_CTL_SET(m)   (BIT(31)|MBWU_SUBTYPE_DEFAULT|(m))
#define MSMON_CFG_CSU_CTL_SET(m)    (BIT(31)|(m))
#define MSMON_CFG_CSU_TYPE          0x43
#define MSMON_CFG_MBWU_TYPE         0x42

/*
 * Size of the memory mapped registers: 4K of feature page then 2 x 4K
 * bitmap registers
 */
#define SZ_MPAM_DEVICE  (3 * SZ_4K)

/*
 * MSMON_CSU - Memory system performance monitor cache storage usage monitor
 *            register
 * MSMON_CSU_CAPTURE -  Memory system performance monitor cache storage usage
 *                     capture register
 * MSMON_MBWU  - Memory system performance monitor memory bandwidth usage
 *               monitor register
 * MSMON_MBWU_CAPTURE - Memory system performance monitor memory bandwidth usage
 *                     capture register
 */
#define MSMON___VALUE          GENMASK(30, 0)
#define MSMON___NRDY           BIT(31)

/*
 * MSMON_CAPT_EVNT - Memory system performance monitoring capture event
 *                  generation register
 */
#define MSMON_CAPT_EVNT_NOW    BIT(0)
/*
 * MPAMCFG_MBW_MAX SET - temp Hard code
 */
#define MPAMCFG_PRI_DSPRI_SHIFT			16

/* MPAMF_PRI_IDR - MPAM features priority partitioning ID register */
#define MPAMF_PRI_IDR_HAS_INTPRI        BIT(0)
#define MPAMF_PRI_IDR_INTPRI_0_IS_LOW   BIT(1)
#define MPAMF_PRI_IDR_INTPRI_WD_SHIFT   4
#define MPAMF_PRI_IDR_INTPRI_WD         GENMASK(9, 4)
#define MPAMF_PRI_IDR_HAS_DSPRI         BIT(16)
#define MPAMF_PRI_IDR_DSPRI_0_IS_LOW    BIT(17)
#define MPAMF_PRI_IDR_DSPRI_WD_SHIFT    20
#define MPAMF_PRI_IDR_DSPRI_WD          GENMASK(25, 20)

/* MPAMF_CSUMON_IDR - MPAM cache storage usage monitor ID register */
#define MPAMF_CSUMON_IDR_NUM_MON        GENMASK(15, 0)
#define MPAMF_CSUMON_IDR_HAS_CAPTURE    BIT(31)

/* MPAMF_MBWUMON_IDR - MPAM memory bandwidth usage monitor ID register */
#define MPAMF_MBWUMON_IDR_NUM_MON       GENMASK(15, 0)
#define MPAMF_MBWUMON_IDR_HAS_CAPTURE   BIT(31)

/* MPAMF_CPOR_IDR - MPAM features cache portion partitioning ID register */
#define MPAMF_CPOR_IDR_CPBM_WD          GENMASK(15, 0)

/* MPAMF_CCAP_IDR - MPAM features cache capacity partitioning ID register */
#define MPAMF_CCAP_IDR_CMAX_WD          GENMASK(5, 0)

/* MPAMF_MBW_IDR - MPAM features memory bandwidth partitioning ID register */
#define MPAMF_MBW_IDR_BWA_WD            GENMASK(5, 0)
#define MPAMF_MBW_IDR_HAS_MIN           BIT(10)
#define MPAMF_MBW_IDR_HAS_MAX           BIT(11)
#define MPAMF_MBW_IDR_HAS_PBM           BIT(12)

#define MPAMF_MBW_IDR_HAS_PROP          BIT(13)
#define MPAMF_MBW_IDR_WINDWR            BIT(14)
#define MPAMF_MBW_IDR_BWPBM_WD          GENMASK(28, 16)
#define MPAMF_MBW_IDR_BWPBM_WD_SHIFT	16

/* MPAMF_PARTID_NRW_IDR - MPAM features partid narrow ID register */
#define MPAMF_PARTID_NRW_IDR_MASK	 (BIT(16) - 1)

#define MSMON_CFG_CTL_TYPE           GENMASK(7, 0)
#define MSMON_CFG_CTL_MATCH_PARTID   BIT(16)
#define MSMON_CFG_CTL_MATCH_PMG      BIT(17)
#define MSMON_CFG_CTL_SUBTYPE        GENMASK(23, 20)
#define MSMON_CFG_CTL_SUBTYPE_SHIFT  20
#define MSMON_CFG_CTL_OFLOW_FRZ      BIT(24)
#define MSMON_CFG_CTL_OFLOW_INTR     BIT(25)
#define MSMON_CFG_CTL_OFLOW_STATUS   BIT(26)
#define MSMON_CFG_CTL_CAPT_RESET     BIT(27)
#define MSMON_CFG_CTL_CAPT_EVNT      GENMASK(30, 28)
#define MSMON_CFG_CTL_CAPT_EVNT_SHIFT		28
#define MSMON_CFG_CTL_EN					BIT(31)

#define MPAMF_IDR_HAS_PRI_PART(v)			(v & BIT(27))

/* MPAMF_MSMON_IDR - MPAM performance monitoring ID register */
#define MPAMF_MSMON_IDR_MSMON_CSU               BIT(16)
#define MPAMF_MSMON_IDR_MSMON_MBWU              BIT(17)
#define MPAMF_MSMON_IDR_HAS_LOCAL_CAPT_EVNT     BIT(31)

/*
 * MSMON_CFG_MBWU_FLT - Memory system performance monitor configure memory
 *                     bandwidth usage monitor filter register
 */
#define MSMON_CFG_MBWU_FLT_PARTID               GENMASK(15, 0)
#define MSMON_CFG_MBWU_FLT_PMG_SHIFT			16
#define MSMON_CFG_MBWU_FLT_PMG                  GENMASK(23, 16)
#define MSMON_CFG_MBWU_TYPE 0x42

/*
 * MSMON_CFG_CSU_FLT - Memory system performance monitor configure cache storage
 *                    usage monitor filter register
 */
#define MSMON_CFG_CSU_FLT_PARTID		GENMASK(15, 0)
#define MSMON_CFG_CSU_FLT_PMG			GENMASK(23, 16)
#define MSMON_CFG_CSU_FLT_PMG_SHIFT		16
#define MSMON_CFG_CSU_TYPE  0x43

/* hard code for mbw_max max-percentage's cresponding masks */
#define MBA_MAX_WD 63u

/*
 * emulate the mpam nodes
 * These should be reported by ACPI MPAM Table.
 */

struct mpam_node {
	/* for label mpam_node instance*/
	u32 component_id;
	/* MPAM node header */
	u8              type;   /* MPAM_SMMU, MPAM_CACHE, MPAM_MC */
	u64             addr;
	void __iomem	*base;
	struct cpumask  cpu_mask;
	u64		default_ctrl;

	/* for debug */
	char            *cpus_list;
	char		*name;
	struct list_head list;
};

int __init mpam_force_init(void);

int __init mpam_nodes_discovery_start(void);

void __init mpam_nodes_discovery_failed(void);

int __init mpam_nodes_discovery_complete(void);

int mpam_create_cache_node(u32 component_id, phys_addr_t hwpage_address);

int mpam_create_memory_node(u32 component_id, phys_addr_t hwpage_address);

#endif /* _ASM_ARM64_MPAM_RESOURCE_H */
