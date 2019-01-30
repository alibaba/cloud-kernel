/* SPDX-License-Identifier: GPL-2.0*/
/* Huawei HiNIC PCI Express Linux driver
 * Copyright(c) 2017 Huawei Technologies Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#ifndef __SML_TABLE_H__
#define __SML_TABLE_H__

#include "hinic_sml_table_pub.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif	/* __cplusplus */

#define    TBL_ID_CTR_DFX_S32_SM_NODE                   11
#define    TBL_ID_CTR_DFX_S32_SM_INST                   20

#define    TBL_ID_CTR_DFX_PAIR_SM_NODE                  10
#define    TBL_ID_CTR_DFX_PAIR_SM_INST                  24

#define    TBL_ID_CTR_DFX_S64_SM_NODE                   11
#define    TBL_ID_CTR_DFX_S64_SM_INST                   21

#if (!defined(__UP_FPGA__) && (!defined(HI1822_MODE_FPGA)) && \
	(!defined(__FPGA__)))

#define    TBL_ID_GLOBAL_SM_NODE                        10
#define    TBL_ID_GLOBAL_SM_INST                        1

#define    TBL_ID_PORT_CFG_SM_NODE                      10
#define    TBL_ID_PORT_CFG_SM_INST                      2

#define    TBL_ID_VLAN_SM_NODE                          10
#define    TBL_ID_VLAN_SM_INST                          3

#define    TBL_ID_MULTICAST_SM_NODE                     10
#define    TBL_ID_MULTICAST_SM_INST                     4

#define    TBL_ID_MISC_RSS_HASH0_SM_NODE                10
#define    TBL_ID_MISC_RSS_HASH0_SM_INST                5

#define    TBL_ID_FIC_VOQ_MAP_SM_NODE                   10
#define    TBL_ID_FIC_VOQ_MAP_SM_INST                   6

#define    TBL_ID_CAR_SM_NODE                           10
#define    TBL_ID_CAR_SM_INST                           7

#define    TBL_ID_IPMAC_FILTER_SM_NODE                  10
#define    TBL_ID_IPMAC_FILTER_SM_INST                  8

#define    TBL_ID_GLOBAL_QUE_MAP_SM_NODE                10
#define    TBL_ID_GLOBAL_QUE_MAP_SM_INST                9

#define    TBL_ID_CTR_VSW_FUNC_MIB_SM_NODE              10
#define    TBL_ID_CTR_VSW_FUNC_MIB_SM_INST              10

#define    TBL_ID_UCODE_EXEC_INFO_SM_NODE               10
#define    TBL_ID_UCODE_EXEC_INFO_SM_INST               11

#define    TBL_ID_RQ_IQ_MAPPING_SM_NODE                 10
#define    TBL_ID_RQ_IQ_MAPPING_SM_INST                 12

#define    TBL_ID_MAC_SM_NODE                           10
#define    TBL_ID_MAC_SM_INST                           21

#define    TBL_ID_MAC_BHEAP_SM_NODE                     10
#define    TBL_ID_MAC_BHEAP_SM_INST                     22

#define    TBL_ID_MAC_MISC_SM_NODE                      10
#define    TBL_ID_MAC_MISC_SM_INST                      23

#define    TBL_ID_FUNC_CFG_SM_NODE                      11
#define    TBL_ID_FUNC_CFG_SM_INST                      1

#define    TBL_ID_TRUNK_FWD_SM_NODE                     11
#define    TBL_ID_TRUNK_FWD_SM_INST                     2

#define    TBL_ID_VLAN_FILTER_SM_NODE                   11
#define    TBL_ID_VLAN_FILTER_SM_INST                   3

#define    TBL_ID_ELB_SM_NODE                           11
#define    TBL_ID_ELB_SM_INST                           4

#define    TBL_ID_MISC_RSS_HASH1_SM_NODE                11
#define    TBL_ID_MISC_RSS_HASH1_SM_INST                5

#define    TBL_ID_RSS_CONTEXT_SM_NODE                   11
#define    TBL_ID_RSS_CONTEXT_SM_INST                   6

#define    TBL_ID_ETHERTYPE_FILTER_SM_NODE              11
#define    TBL_ID_ETHERTYPE_FILTER_SM_INST              7

#define    TBL_ID_VTEP_IP_SM_NODE                       11
#define    TBL_ID_VTEP_IP_SM_INST                       8

#define    TBL_ID_NAT_SM_NODE                           11
#define    TBL_ID_NAT_SM_INST                           9

#define    TBL_ID_BHEAP_LRO_AGING_SM_NODE               11
#define    TBL_ID_BHEAP_LRO_AGING_SM_INST               10

#define    TBL_ID_MISC_LRO_AGING_SM_NODE                11
#define    TBL_ID_MISC_LRO_AGING_SM_INST                11

#define    TBL_ID_BHEAP_CQE_AGING_SM_NODE               11
#define    TBL_ID_BHEAP_CQE_AGING_SM_INST               12

#define    TBL_ID_MISC_CQE_AGING_SM_NODE                11
#define    TBL_ID_MISC_CQE_AGING_SM_INST                13

#define    TBL_ID_DFX_LOG_POINTER_SM_NODE               11
#define    TBL_ID_DFX_LOG_POINTER_SM_INST               14

#define    TBL_ID_CTR_VSW_FUNC_S32_DROP_ERR_SM_NODE     11
#define    TBL_ID_CTR_VSW_FUNC_S32_DROP_ERR_SM_INST     15

#define    TBL_ID_CTR_VSW_FUNC_S32_DFX_SM_NODE          11
#define    TBL_ID_CTR_VSW_FUNC_S32_DFX_SM_INST          16

#define    TBL_ID_CTR_COMM_FUNC_S32_SM_NODE             11
#define    TBL_ID_CTR_COMM_FUNC_S32_SM_INST             17

#define    TBL_ID_CTR_SRIOV_FUNC_PAIR_SM_NODE           11
#define    TBL_ID_CTR_SRIOV_FUNC_PAIR_SM_INST           41

#define    TBL_ID_CTR_SRIOV_FUNC_S32_SM_NODE            11
#define    TBL_ID_CTR_SRIOV_FUNC_S32_SM_INST            42

#define    TBL_ID_CTR_OVS_FUNC_S64_SM_NODE              11
#define    TBL_ID_CTR_OVS_FUNC_S64_SM_INST              43

#define    TBL_ID_CTR_XOE_FUNC_PAIR_SM_NODE             11
#define    TBL_ID_CTR_XOE_FUNC_PAIR_SM_INST             44

#define    TBL_ID_CTR_XOE_FUNC_S32_SM_NODE              11
#define    TBL_ID_CTR_XOE_FUNC_S32_SM_INST              45

#define    TBL_ID_CTR_SYS_GLB_S32_SM_NODE               11
#define    TBL_ID_CTR_SYS_GLB_S32_SM_INST               46

#define    TBL_ID_CTR_VSW_GLB_S32_SM_NODE               11
#define    TBL_ID_CTR_VSW_GLB_S32_SM_INST               47

#define    TBL_ID_CTR_ROCE_GLB_S32_SM_NODE              11
#define    TBL_ID_CTR_ROCE_GLB_S32_SM_INST              48

#define    TBL_ID_CTR_COMM_GLB_S32_SM_NODE              11
#define    TBL_ID_CTR_COMM_GLB_S32_SM_INST              49

#define    TBL_ID_CTR_XOE_GLB_S32_SM_NODE               11
#define    TBL_ID_CTR_XOE_GLB_S32_SM_INST               50

#define    TBL_ID_CTR_OVS_GLB_S64_SM_NODE               11
#define    TBL_ID_CTR_OVS_GLB_S64_SM_INST               51

#define    TBL_ID_RWLOCK_ROCE_SM_NODE                   11
#define    TBL_ID_RWLOCK_ROCE_SM_INST                   30

#define    TBL_ID_CQE_ADDR_SM_NODE                      11
#define    TBL_ID_CQE_ADDR_SM_INST                      31

#else

#define    TBL_ID_GLOBAL_SM_NODE                        10
#define    TBL_ID_GLOBAL_SM_INST                        1

#define    TBL_ID_PORT_CFG_SM_NODE                      10
#define    TBL_ID_PORT_CFG_SM_INST                      2

#define    TBL_ID_VLAN_SM_NODE                          10
#define    TBL_ID_VLAN_SM_INST                          3

#define    TBL_ID_MULTICAST_SM_NODE                     10
#define    TBL_ID_MULTICAST_SM_INST                     4

#define    TBL_ID_MISC_RSS_HASH0_SM_NODE                10
#define    TBL_ID_MISC_RSS_HASH0_SM_INST                5

#define    TBL_ID_FIC_VOQ_MAP_SM_NODE                   10
#define    TBL_ID_FIC_VOQ_MAP_SM_INST                   6

#define    TBL_ID_CAR_SM_NODE                           10
#define    TBL_ID_CAR_SM_INST                           7

#define    TBL_ID_IPMAC_FILTER_SM_NODE                  10
#define    TBL_ID_IPMAC_FILTER_SM_INST                  8

#define    TBL_ID_GLOBAL_QUE_MAP_SM_NODE                10
#define    TBL_ID_GLOBAL_QUE_MAP_SM_INST                9

#define    TBL_ID_CTR_VSW_FUNC_MIB_SM_NODE              10
#define    TBL_ID_CTR_VSW_FUNC_MIB_SM_INST              10

#define    TBL_ID_UCODE_EXEC_INFO_SM_NODE               10
#define    TBL_ID_UCODE_EXEC_INFO_SM_INST               11

#define    TBL_ID_RQ_IQ_MAPPING_SM_NODE                 10
#define    TBL_ID_RQ_IQ_MAPPING_SM_INST                 12

#define    TBL_ID_MAC_SM_NODE                           10
#define    TBL_ID_MAC_SM_INST                           13

#define    TBL_ID_MAC_BHEAP_SM_NODE                     10
#define    TBL_ID_MAC_BHEAP_SM_INST                     14

#define    TBL_ID_MAC_MISC_SM_NODE                      10
#define    TBL_ID_MAC_MISC_SM_INST                      15

#define    TBL_ID_FUNC_CFG_SM_NODE                      10
#define    TBL_ID_FUNC_CFG_SM_INST                      16

#define    TBL_ID_TRUNK_FWD_SM_NODE                     10
#define    TBL_ID_TRUNK_FWD_SM_INST                     17

#define    TBL_ID_VLAN_FILTER_SM_NODE                   10
#define    TBL_ID_VLAN_FILTER_SM_INST                   18

#define    TBL_ID_ELB_SM_NODE                           10
#define    TBL_ID_ELB_SM_INST                           19

#define    TBL_ID_MISC_RSS_HASH1_SM_NODE                10
#define    TBL_ID_MISC_RSS_HASH1_SM_INST                20

#define    TBL_ID_RSS_CONTEXT_SM_NODE                   10
#define    TBL_ID_RSS_CONTEXT_SM_INST                   21

#define    TBL_ID_ETHERTYPE_FILTER_SM_NODE              10
#define    TBL_ID_ETHERTYPE_FILTER_SM_INST              22

#define    TBL_ID_VTEP_IP_SM_NODE                       10
#define    TBL_ID_VTEP_IP_SM_INST                       23

#define    TBL_ID_NAT_SM_NODE                           10
#define    TBL_ID_NAT_SM_INST                           24

#define    TBL_ID_BHEAP_LRO_AGING_SM_NODE               10
#define    TBL_ID_BHEAP_LRO_AGING_SM_INST               25

#define    TBL_ID_MISC_LRO_AGING_SM_NODE                10
#define    TBL_ID_MISC_LRO_AGING_SM_INST                26

#define    TBL_ID_BHEAP_CQE_AGING_SM_NODE               10
#define    TBL_ID_BHEAP_CQE_AGING_SM_INST               27

#define    TBL_ID_MISC_CQE_AGING_SM_NODE                10
#define    TBL_ID_MISC_CQE_AGING_SM_INST                28

#define    TBL_ID_DFX_LOG_POINTER_SM_NODE               10
#define    TBL_ID_DFX_LOG_POINTER_SM_INST               29

#define    TBL_ID_CTR_VSW_FUNC_S32_DROP_ERR_SM_NODE     10
#define    TBL_ID_CTR_VSW_FUNC_S32_DROP_ERR_SM_INST     40

#define    TBL_ID_CTR_VSW_FUNC_S32_DFX_SM_NODE          10
#define    TBL_ID_CTR_VSW_FUNC_S32_DFX_SM_INST          41

#define    TBL_ID_CTR_COMM_FUNC_S32_SM_NODE             10
#define    TBL_ID_CTR_COMM_FUNC_S32_SM_INST             42

#define    TBL_ID_CTR_SRIOV_FUNC_PAIR_SM_NODE           10
#define    TBL_ID_CTR_SRIOV_FUNC_PAIR_SM_INST           43

#define    TBL_ID_CTR_SRIOV_FUNC_S32_SM_NODE            10
#define    TBL_ID_CTR_SRIOV_FUNC_S32_SM_INST            44

#define    TBL_ID_CTR_OVS_FUNC_S64_SM_NODE              10
#define    TBL_ID_CTR_OVS_FUNC_S64_SM_INST              45

#define    TBL_ID_CTR_XOE_FUNC_PAIR_SM_NODE             10
#define    TBL_ID_CTR_XOE_FUNC_PAIR_SM_INST             46

#define    TBL_ID_CTR_XOE_FUNC_S32_SM_NODE              10
#define    TBL_ID_CTR_XOE_FUNC_S32_SM_INST              47

#define    TBL_ID_CTR_SYS_GLB_S32_SM_NODE               10
#define    TBL_ID_CTR_SYS_GLB_S32_SM_INST               48

#define    TBL_ID_CTR_VSW_GLB_S32_SM_NODE               10
#define    TBL_ID_CTR_VSW_GLB_S32_SM_INST               49

#define    TBL_ID_CTR_ROCE_GLB_S32_SM_NODE              10
#define    TBL_ID_CTR_ROCE_GLB_S32_SM_INST              50

#define    TBL_ID_CTR_COMM_GLB_S32_SM_NODE              10
#define    TBL_ID_CTR_COMM_GLB_S32_SM_INST              51

#define    TBL_ID_CTR_XOE_GLB_S32_SM_NODE               10
#define    TBL_ID_CTR_XOE_GLB_S32_SM_INST               52

#define    TBL_ID_CTR_OVS_GLB_S64_SM_NODE               10
#define    TBL_ID_CTR_OVS_GLB_S64_SM_INST               53

#define    TBL_ID_RWLOCK_ROCE_SM_NODE                   10
#define    TBL_ID_RWLOCK_ROCE_SM_INST                   30

#define    TBL_ID_CQE_ADDR_SM_NODE                      10
#define    TBL_ID_CQE_ADDR_SM_INST                      31

#endif

#define TBL_ID_MISC_RSS_HASH_SM_NODE	TBL_ID_MISC_RSS_HASH0_SM_NODE
#define TBL_ID_MISC_RSS_HASH_SM_INST	TBL_ID_MISC_RSS_HASH0_SM_INST

/*rx cqe checksum err*/
#define    NIC_RX_CSUM_IP_CSUM_ERR			BIT(0)
#define    NIC_RX_CSUM_TCP_CSUM_ERR			BIT(1)
#define    NIC_RX_CSUM_UDP_CSUM_ERR			BIT(2)
#define    NIC_RX_CSUM_IGMP_CSUM_ERR			BIT(3)
#define    NIC_RX_CSUM_ICMPV4_CSUM_ERR			BIT(4)
#define    NIC_RX_CSUM_ICMPV6_CSUM_ERR			BIT(5)
#define    NIC_RX_CSUM_SCTP_CRC_ERR			BIT(6)
#define    NIC_RX_CSUM_HW_BYPASS_ERR			BIT(7)

typedef struct tag_log_ctrl {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	u32 mod_name:4;
	u32 log_level:4;
	u32 rsvd:8;
	u32 line_num:16;
#else
	u32 line_num:16;
	u32 rsvd:8;
	u32 log_level:4;
	u32 mod_name:4;
#endif
} log_ctrl;

/**
 * 1. bank GPA address is HOST-based, every host has 4 bank GPA,
 * total size 4*32B
 * 2. Allocated space for storing
 * Two global entry are allocated for storing bank GPA,
 * which are index5 and index6. (Note index start value is 0)
 * The index5 top 32B store the bank GPA of host 0;
 * Remain 32B store the bank GPA of host 1.
 * The index6 top 32B store the bank GPA of host 2,
 * the remain 32B store the bank GPA of host 3.
 * Bank GPA corresponding to the each host is based on the following format)
 */
typedef struct tag_sml_global_bank_gpa {
	u32 bank0_gpa_h32;
	u32 bank0_gpa_l32;

	u32 bank1_gpa_h32;
	u32 bank1_gpa_l32;

	u32 bank2_gpa_h32;
	u32 bank2_gpa_l32;

	u32 bank3_gpa_h32;
	u32 bank3_gpa_l32;
} global_bank_gpa_s;

/**
 * Struct name:		sml_global_table_s
 * @brief:		global_table structure
 * Description:		global configuration table
 */
typedef struct tag_sml_global_table {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 port_mode:1;	/*portmode:0-eth;1-fic */
			/* dualplaneenable:0-disable;1-enable */
			u32 dual_plane_en:1;
			/* fourrouteenable:0-disable;1-enable */
			u32 four_route_en:1;
			/* ficworkmode:0-fabric;1-fullmesh.*/
			u32 fic_work_mode:1;
			/* unicast/multicastmode:0-drop;
			 * 1-broadcastinvlandomain
			 */
			u32 un_mc_mode:1;
			/* maclearnenable:1-enable */
			u32 mac_learn_en:1;
			u32 qcn_en:1;
			u32 esl_run_flag:1;
			/* 1-special protocal pkt to up; 0-to x86 */
			u32 special_pro_to_up_flag:1;
			u32 vf_mask:4;
			u32 dif_ser_type:2;
			u32 rsvd0:1;
			u32 board_num:16;	/*boardnumber */
#else
			u32 board_num:16;	/*boardnumber */
			u32 rsvd0:1;
			u32 dif_ser_type:2;
			u32 vf_mask:4;
			/*1-special protocal pkt to up; 0-to x86 */
			u32 special_pro_to_up_flag:1;
			u32 esl_run_flag:1;
			u32 qcn_en:1;
			u32 mac_learn_en:1;	/*maclearnenable:1-enable */
			/*unicast/multicastmode:0-drop;1-broadcastinvlandomain*/
			u32 un_mc_mode:1;
			/* ficworkmode:0-fabric;1-fullmesh.*/
			u32 fic_work_mode:1;
			/*fourrouteenable:0-disable;1-enable */
			u32 four_route_en:1;
			/*dualplaneenable:0-disable;1-enable */
			u32 dual_plane_en:1;
			u32 port_mode:1;	/*portmode:0-eth;1-fic */
#endif
		} bs;
		u32 value;
	} dw0;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 bc_offset:16;	/*broadcastoffset */
			u32 mc_offset:16;	/*multicastoffset */
#else
			u32 mc_offset:16;	/*multicastoffset */
			u32 bc_offset:16;	/*broadcastoffset */
#endif
		} bs;
		u32 value;
	} dw1;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 net_src_type:8;	/* eth-FWD_PORT, fic-FWD_FIC */
			u32 xrc_pl_dec:1;
			u32 sq_cqn:20;
			u32 qpc_stg:1;
			u32 qpc_state_err:1;
			u32 qpc_wb_flag:1;
#else
			u32 qpc_wb_flag:1;
			u32 qpc_state_err:1;
			u32 qpc_stg:1;
			u32 sq_cqn:20;
			u32 xrc_pl_dec:1;
			u32 net_src_type:8;	/* eth-FWD_PORT, fic-FWD_FIC */
#endif
		} bs;

		u32 value;
	} dw2;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 drop_cause_id:16;
			u32 pkt_len:16;
#else
			u32 pkt_len:16;
			u32 drop_cause_id:16;
#endif
		} bs;

		u32 value;
	} dw3;

	u8 fcoe_vf_table[12];

	union {
		struct {
			/* [31:30]Pipeline number mode. */
			u32 cfg_mode_pn:2;
			/* [29:28]initial default fq mode for traffic
			 * from rx side
			 */
			u32 cfg_mode_init_def_fq:2;
			/* [27:16]base fqid for initial default fqs
			 * (for packest from rx side only).
			 */
			u32 cfg_base_init_def_fq:12;
			/* [15:15]push doorbell as new packet to tile
			 * via command path enable.
			 */
			u32 cfg_psh_msg_en:1;
			/* [14:14]1,enable asc for scanning
			 * active fq.0,disable.
			 */
			u32 enable_asc:1;
			/* [13:13]1,enable pro for commands process.0,disable.*/
			u32 enable_pro:1;
			/* [12:12]1,ngsf mode.0,ethernet mode. */
			u32 cfg_ngsf_mod:1;
			/* [11:11]Stateful process enable. */
			u32 enable_stf:1;
			/* [10:9]initial default fq mode for
			 * traffic from tx side.
			 */
			u32 cfg_mode_init_def_fq_tx:2;
			/* [8:0]maximum allocable oeid configuration. */
			u32 cfg_max_oeid:9;
		} bs;
		u32 value;
	} fq_mode;

	u32 rsvd2[8];
} sml_global_table_s;

/**
 * Struct name:			sml_fic_config_table_s
 * @brief:			global_table structure
 * Description:			global configuration table
 */
typedef struct tag_sml_fic_config_table {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/*dualplaneenable:0-disable;1-enable */
			u32 dual_plane_en:1;
			/*fourrouteenable:0-disable;1-enable */
			u32 four_route_en:1;
			/* ficworkmode:0-fabric;1-fullmesh.*/
			u32 fic_work_mode:1;
			u32 mac_learn_en:1;	/*maclearnenable:1-enable */
			u32 rsvd:12;
			u32 board_num:16;	/*boardnumber */
#else
			u32 board_num:16;	/*boardnumber */
			u32 rsvd:12;
			u32 mac_learn_en:1;
			/* ficworkmode:0-fabric;1-fullmesh.*/
			u32 fic_work_mode:1;
			/* fourrouteenable:0-disable;1-enable */
			u32 four_route_en:1;
			/* dualplaneenable:0-disable;1-enable */
			u32 dual_plane_en:1;
#endif
		} bs;
		u32 value;
	} dw0;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 bc_offset:16;	/*broadcastoffset */
			u32 mc_offset:16;	/*multicastoffset */
#else
			u32 mc_offset:16;	/*multicastoffset */
			u32 bc_offset:16;	/*broadcastoffset */
#endif
		} bs;
		u32 value;
	} dw1;

	u32 rsvd2[14];
} sml_fic_config_table_s;

/**
 * Struct name:	sml_ucode_version_info_table_s
 * @brief:	microcode version information structure
 * Description:	global configuration table entry data structure of index 1
 */
typedef struct tag_sml_ucode_version_info_table {
	u32 ucode_version[4];
	u32 ucode_compile_time[5];
	u32 rsvd[7];
} sml_ucode_version_info_table_s;

/**
 * Struct name:	sml_funcfg_tbl_s
 * @brief:	Function Configuration Table
 * Description:	Function Configuration attribute table
 */
typedef struct tag_sml_funcfg_tbl {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/* function valid: 0-invalid; 1-valid */
			u32 valid:1;
			/* mac learn enable: 0-disable; 1-enable */
			u32 learn_en:1;
			/* lli enable: 0-disable; 1-enable */
			u32 lli_en:1;
			/* rss enable: 0-disable; 1-enable */
			u32 rss_en:1;
			/* rx vlan offload enable: 0-disable; 1-enable */
			u32 rxvlan_offload_en:1;
			/* tso local coalesce enable: 0-disable; 1-enable */
			u32 tso_local_coalesce:1;
			u32 rsvd1:1;
			u32 rsvd2:1;
			/* qos rx car enable: 0-disable; 1-enable */
			u32 qos_rx_car_en:1;
			/* mac filter enable: 0-disable; 1-enable */
			u32 mac_filter_en:1;
			/* ipmac filter enable: 0-disable; 1-enable */
			u32 ipmac_filter_en:1;
			/* ethtype filter enable: 0-disable; 1-enable */
			u32 ethtype_filter_en:1;
			/* mc bc limit enable: 0-disable; 1-enable */
			u32 mc_bc_limit_en:1;
			/* acl tx enable: 0-disable; 1-enable */
			u32 acl_tx_en:1;
			/* acl rx enable: 0-disable; 1-enable */
			u32 acl_rx_en:1;
			/* ovs function enable: 0-disable; 1-enable */
			u32 ovs_func_en:1;
			/* ucode capture enable: 0-disable; 1-enable */
			u32 ucapture_en:1;
			/* fic car enable: 0-disable; 1-enable */
			u32 fic_car_en:1;
			u32 tso_en:1;
			u32 nic_rx_mode:5;	/* nic_rx_mode:
						 * 0b00001: unicast mode
						 * 0b00010: multicast mode
						 * 0b00100: broadcast mode
						 * 0b01000: all multicast mode
						 * 0b10000: promisc mod
						 */
			u32 rsvd4:3;
			u32 def_pri:3;	/* default priority */
			/* host id: [0~3]. support up to 4 Host. */
			u32 host_id:2;
#else
			u32 host_id:2;
			u32 def_pri:3;
			u32 rsvd4:3;
			u32 nic_rx_mode:5;
			u32 tso_en:1;
			u32 fic_car_en:1;
			/* ucode capture enable: 0-disable; 1-enable */
			u32 ucapture_en:1;
			u32 ovs_func_en:1;
			u32 acl_rx_en:1;
			u32 acl_tx_en:1;
			u32 mc_bc_limit_en:1;
			u32 ethtype_filter_en:1;
			u32 ipmac_filter_en:1;
			u32 mac_filter_en:1;
			u32 qos_rx_car_en:1;
			u32 rsvd2:1;
			u32 rsvd1:1;
			u32 tso_local_coalesce:1;
			u32 rxvlan_offload_en:1;
			u32 rss_en:1;
			u32 lli_en:1;
			u32 learn_en:1;
			u32 valid:1;
#endif
		} bs;

		u32 value;
	} dw0;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 mtu:16;	/* mtu value: [64-15500] */
			u32 rsvd1:1;
			/* vlan mode: 0-all; 1-access; 2-trunk;
			 * 3-hybrid(unsupport); 4-qinq port;
			 */
			u32 vlan_mode:3;
			u32 vlan_id:12;	/* vlan id: [0~4095] */
#else
			u32 vlan_id:12;
			u32 vlan_mode:3;
			u32 rsvd1:1;
			u32 mtu:16;
#endif
		} bs;

		u32 value;
	} dw1;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 lli_mode:1;	/* lli mode */
			/* er forward trunk type: 0-ethernet type, 1-fic type */
			u32 er_fwd_trunk_type:1;
			/* er forward trunk mode:
			 * 0-standby; 1-smac; 2-dmac; 3-smacdmac; 4-sip; 5-dip;
			 * 6-sipdip; 7-5tuples; 8-lacp
			 */
			u32 er_fwd_trunk_mode:4;
			/* edge relay mode: 0-VEB; 1-VEPA(unsupport);
			 * 2-Multi-Channel(unsupport)
			 */
			u32 er_mode:2;
			/* edge relay id: [0~15]. support up to 16 er. */
			u32 er_id:4;
			/* er forward type: 2-port; 3-fic;
			 * 4-trunk; other-unsupport
			 */
			u32 er_fwd_type:4;
			/* er forward id:
			 * fwd_type=2: forward ethernet port id
			 * fwd_type=3: forward fic id(tb+tp)
			 * fwd_type=4: forward trunk id
			 */
			u32 er_fwd_id:16;
#else
			u32 er_fwd_id:16;
			u32 er_fwd_type:4;
			u32 er_id:4;
			u32 er_mode:2;
			u32 er_fwd_trunk_mode:4;
			u32 er_fwd_trunk_type:1;
			u32 lli_mode:1;
#endif
		} bs;

		u32 value;
	} dw2;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 pfc_en:1;
			u32 rsvd1:7;
			u32 ovs_invld_tcp_action:1;
			u32 ovs_ip_frag_action:1;
			u32 rsvd2:2;
			u32 roce_en:1;
			u32 iwarp_en:1;
			u32 fcoe_en:1;
			u32 toe_en:1;
			u32 rsvd3:8;
			u32 ethtype_group_id:8;
#else
			u32 ethtype_group_id:8;
			u32 rsvd3:8;
			u32 toe_en:1;
			u32 fcoe_en:1;
			u32 iwarp_en:1;
			u32 roce_en:1;
			u32 rsvd2:2;
			u32 ovs_ip_frag_action:1;
			u32 ovs_invld_tcp_action:1;
			u32 rsvd1:7;
			u32 pfc_en:1;
#endif
		} bs;

		u32 value;
	} dw3;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd1:8;
			u32 vni:24;
#else
			u32 vni:24;
			u32 rsvd1:8;
#endif
		} bs;

		u32 value;
	} dw4;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd1;
#else
			u32 rsvd1;
#endif
		} bs;

		u32 value;
	} dw5;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd1:8;
			u32 rq_thd:13;
			u32 host_car_id:11;	/* host car id */
#else
			u32 host_car_id:11;
			u32 rq_thd:13;
			u32 rsvd1:8;
#endif
		} bs;

		u32 value;
	} dw6;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd1:5;
			u32 fic_uc_car_id:11;	/* fic unicast car id */
			u32 rsvd2:5;
			u32 fic_mc_car_id:11;	/* fic multicast car id */
#else
			u32 fic_mc_car_id:11;
			u32 rsvd2:5;
			u32 fic_uc_car_id:11;
			u32 rsvd1:5;
#endif
		} fic_bs;

		u32 value;
	} dw7;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/* safe group identifier valid: 0-invalid; 1-valid */
			u32 sg_id_valid:1;
			u32 sg_id:10;	/* safe group identifier */
			u32 rsvd9:1;
			/* rq priority enable: 0-disable; 1-enable */
			u32 rq_pri_en:1;
			/* rq priority num: 0-1pri; 1-2pri; 2-4pri; 3-8pri */
			u32 rq_pri_num:3;
			/* one wqe buffer size, default is 2K bytes */
			u32 rx_wqe_buffer_size:16;
#else
			u32 rx_wqe_buffer_size:16;
			u32 rq_pri_num:3;
			u32 rq_pri_en:1;
			u32 rsvd9:1;
			u32 sg_id:10;
			u32 sg_id_valid:1;
#endif
		} bs;

		u32 value;
	} dw8;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/* IPv4 LRO enable: 0-disable; 1-enable; */
			u32 lro_ipv4_en:1;
			/* IPv6 LRO enable: 0-disable; 1-enable; */
			u32 lro_ipv6_en:1;
			/* LRO pkt max wqe buffer number */
			u32 lro_max_wqe_num:6;
			/* Each group occupies 3bits,
			 * 8 group share allocation 24bits,
			 * group 0 corresponds to the low 3bits
			 */
			u32 vlan_pri_map_group:24;
#else
			u32 vlan_pri_map_group:24;
			u32 lro_max_wqe_num:6;
			u32 lro_ipv6_en:1;
			u32 lro_ipv4_en:1;
#endif
		} bs;

		u32 value;
	} dw9;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rss_group_id:4;
			u32 lli_frame_size:12;
			u32 smac_h16:16;
#else
			u32 smac_h16:16;
			u32 lli_frame_size:12;
			u32 rss_group_id:4;
#endif
		} bs;

		u32 value;
	} dw10;

	u32 smac_l32;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 oqid:16;
			u32 vf_map_pf_id:4;
			/*lro change; 0:changing 1:change done */
			u32 lro_change_flag:1;
			u32 rsvd11:1;
			u32 base_qid:10;
#else
			u32 base_qid:10;
			u32 rsvd11:1;
			u32 lro_change_flag:1;
			u32 vf_map_pf_id:4;
			u32 oqid:16;
#endif
		} bs;

		u32 value;
	} dw12;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd1:2;
			u32 cfg_rq_depth:6;
			u32 cfg_q_num:6;
			u32 fc_port_id:4;
			u32 rsvd2:14;
#else
			u32 rsvd2:14;
			u32 fc_port_id:4;
			u32 cfg_q_num:6;
			u32 cfg_rq_depth:6;
			u32 rsvd1:2;
#endif
		} bs;

		u32 value;
	} dw13;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd1;
#else
			u32 rsvd1;
#endif
		} bs;

		u32 value;

	} dw14;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd3:2;
			u32 bond3_hash_policy:3;
			u32 bond3_mode:3;
			u32 rsvd2:2;
			u32 bond2_hash_policy:3;
			u32 bond2_mode:3;
			u32 rsvd1:2;
			u32 bond1_hash_policy:3;
			u32 bond1_mode:3;
			u32 rsvd0:2;
			u32 bond0_hash_policy:3;
			u32 bond0_mode:3;
#else
			u32 bond0_mode:3;
			u32 bond0_hash_policy:3;
			u32 rsvd0:2;
			u32 bond1_mode:3;
			u32 bond1_hash_policy:3;
			u32 rsvd1:2;
			u32 bond2_mode:3;
			u32 bond2_hash_policy:3;
			u32 rsvd2:2;
			u32 bond3_mode:3;
			u32 bond3_hash_policy:3;
			u32 rsvd3:2;
#endif
		} bs;

		u32 value;

	} dw15;
} sml_funcfg_tbl_s;

/**
 * Struct name:			sml_portcfg_tbl_s
 * @brief:			Port Configuration Table
 * Description:			Port Configuration attribute table
 */
typedef struct tag_sml_portcfg_tbl {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 valid:1;	/* valid:0-invalid; 1-valid */
			/* mac learn enable: 0-disable; 1-enable */
			u32 learn_en:1;
			u32 trunk_en:1;	/* trunk enable: 0-disable; 1-enable */
			/* broadcast suppression enable: 0-disable; 1-enable */
			u32 bc_sups_en:1;
			/* unknown multicast suppression enable:
			 * 0-disable; 1-enable
			 */
			u32 un_mc_sups_en:1;
			/* unknown unicast suppression enable:
			 * 0-disable; 1-enable
			 */
			u32 un_uc_sups_en:1;
			u32 ovs_mirror_tx_en:1;
			/* ovs port enable: 0-disable; 1-enable */
			u32 ovs_port_en:1;
			u32 ovs_mirror_rx_en:1;
			u32 qcn_en:1;	/* qcn enable: 0-disable; 1-enable */
			/* ucode capture enable: 0-disable; 1-enable */
			u32 ucapture_en:1;
			u32 ovs_invld_tcp_action:1;
			u32 ovs_ip_frag_action:1;
			u32 def_pri:3;	/* default priority */
			u32 rsvd3:2;
			/* edge relay mode: 0-VEB; 1-VEPA(unsupport);
			 * 2-Multi-Channel(unsupport)
			 */
			u32 er_mode:2;
			/* edge relay identifier: [0~15]. support up to 16 er */
			u32 er_id:4;
			u32 trunk_id:8;	/* trunk identifier: [0~255] */
#else
			u32 trunk_id:8;
			u32 er_id:4;
			u32 er_mode:2;
			u32 rsvd3:2;
			u32 def_pri:3;
			u32 ovs_ip_frag_action:1;
			u32 ovs_invld_tcp_action:1;
			u32 ucapture_en:1;
			u32 qcn_en:1;
			u32 ovs_mirror_rx_en:1;
			u32 ovs_port_en:1;
			u32 ovs_mirror_tx_en:1;
			u32 un_uc_sups_en:1;
			u32 un_mc_sups_en:1;
			u32 bc_sups_en:1;
			u32 trunk_en:1;
			u32 learn_en:1;
			u32 valid:1;
#endif
		} bs;
		u32 value;
	} dw0;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd2:2;
			u32 mtu:14;
			u32 rsvd3:1;
			u32 vlan_mode:3;
			u32 vlan_id:12;
#else
			u32 vlan_id:12;
			u32 vlan_mode:3;
			u32 rsvd3:1;
			u32 mtu:14;
			u32 rsvd2:2;
#endif
		} bs;
		u32 value;
	} dw1;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/* q7_cos : ... : q0_cos = 4bits : ... : 4bits */
			u32 ovs_queue_cos;
#else
			u32 ovs_queue_cos;
#endif
		} bs;
		u32 value;
	} dw2;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd1:10;
			u32 un_mc_car_id:11;
			u32 un_uc_car_id:11;
#else
			u32 un_uc_car_id:11;
			u32 un_mc_car_id:11;
			u32 rsvd1:10;
#endif
		} bs;
		u32 value;
	} dw3;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd6:5;
			u32 bc_car_id:11;
			u32 pf_promiscuous_bitmap:16;
#else
			u32 pf_promiscuous_bitmap:16;
			u32 bc_car_id:11;
			u32 rsvd6:5;
#endif
		} bs;
		u32 value;
	} dw4;

	union {
		struct {
			u32 fc_map;

		} fcoe_bs;
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 start_queue:8;
			u32 queue_size:8;
			u32 mirror_func_id:16;
#else
			u32 mirror_func_id:16;
			u32 queue_size:8;
			u32 start_queue:8;
#endif
		} ovs_mirror_bs;
		u32 value;
	} dw5;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u16 vlan;
			u16 dmac_h16;
#else
			u16 dmac_h16;
			u16 vlan;
#endif
		} fcoe_bs;
		u32 value;
	} dw6;

	union {
		struct {
			u32 dmac_l32;

		} fcoe_bs;
		u32 value;
	} dw7;

} sml_portcfg_tbl_s;

/**
 * Struct name:		sml_taggedlist_tbl_s
 * @brief:		Tagged List Table
 * Description:		VLAN filtering Trunk/Hybrid type tagged list table
 */
typedef struct tag_sml_taggedlist_tbl {
	u32 bitmap[TBL_ID_TAGGEDLIST_BITMAP32_NUM];
} sml_taggedlist_tbl_s;

/**
 * Struct name:		sml_untaggedlist_tbl_s
 * @brief:		Untagged List Table
 * Description:		VLAN filtering Hybrid type Untagged list table
 */
typedef struct tag_sml_untaggedlist_tbl {
	u32 bitmap[TBL_ID_UNTAGGEDLIST_BITMAP32_NUM];
} sml_untaggedlist_tbl_s;

/**
 * Struct name:		sml_trunkfwd_tbl_s
 * @brief:		Trunk Forward Table
 * Description:		port aggregation Eth-Trunk forwarding table
 */
typedef struct tag_sml_trunkfwd_tbl {
	u16 fwd_id[TBL_ID_TRUNKFWD_ENTRY_ELEM_NUM];	/* dw0-dw15 */
} sml_trunkfwd_tbl_s;

/**
 * Struct name:		sml_mac_tbl_head_u
 * @brief:		Mac table request/response head
 * Description:		MAC table, Hash API header
 */
typedef union tag_sml_mac_tbl_head {
	struct {
#if  (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 src:5;
		u32 instance_id:6;
		u32 opid:5;
		u32 A:1;
		u32 S:1;
		u32 rsvd:14;
#elif (__BYTE_ORDER__ == __LITTLE_ENDIAN__)
		u32 rsvd:14;
		u32 S:1;
		u32 A:1;
		u32 opid:5;
		u32 instance_id:6;
		u32 src:5;
#endif
	} req_bs;

	struct {
#if  (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 code:2;
		u32 subcode:2;
		u32 node_index:28;
#elif (__BYTE_ORDER__ == __LITTLE_ENDIAN__)
		u32 node_index:28;
		u32 subcode:2;
		u32 code:2;
#endif
	} rsp_bs;

	u32 value;
} sml_mac_tbl_head_u;

/**
 * Struct name:		sml_mac_tbl_8_4_key_u
 * @brief:		Mac Table Key
 * Description:		MAC table key
 */
typedef union tag_sml_mac_tbl_8_4_key {
	struct {
		u32 val0;
		u32 val1;
	} value;

	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 er_id:4;
		u32 vlan_id:12;
		u32 mac_h16:16;

		u32 mac_m16:16;
		u32 mac_l16:16;
#elif (__BYTE_ORDER__ == __LITTLE_ENDIAN__)
		u32 mac_h16:16;
		u32 vlan_id:12;
		u32 er_id:4;

		u32 mac_l16:16;
		u32 mac_m16:16;
#endif
	} bs;

	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 er_id:4;
		u32 vlan_id:12;
		u32 mac0:8;
		u32 mac1:8;

		u32 mac2:8;
		u32 mac3:8;
		u32 mac4:8;
		u32 mac5:8;
#elif (__BYTE_ORDER__ == __LITTLE_ENDIAN__)
		u32 mac1:8;
		u32 mac0:8;
		u32 vlan_id:12;
		u32 er_id:4;

		u32 mac5:8;
		u32 mac4:8;
		u32 mac3:8;
		u32 mac2:8;
#endif
	} mac_bs;
} sml_mac_tbl_8_4_key_u;

/**
 * Struct name:		sml_mac_tbl_8_4_item_u
 * @brief:		Mac Table Item
 * Description:		xxxxxxxxxxxxxxx
 */
typedef union tag_sml_mac_tbl_8_4_item {
	u32 value;

	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd:10;
		u32 host_id:2;
		u32 fwd_type:4;
		u32 fwd_id:16;
#elif (__BYTE_ORDER__ == __LITTLE_ENDIAN__)
		u32 fwd_id:16;
		u32 fwd_type:4;
		u32 host_id:2;
		u32 rsvd:10;
#endif
	} bs;
} sml_mac_tbl_8_4_item_u;

/**
 * Struct name:		sml_mac_tbl_key_item_s
 * @brief:		Mac Table( 8 + 4 )
 * Description:		MAC table Key + Item
 */
typedef struct tag_sml_mac_tbl_8_4 {
	sml_mac_tbl_head_u head;
	sml_mac_tbl_8_4_key_u key;
	sml_mac_tbl_8_4_item_u item;
} sml_mac_tbl_8_4_s;

/**
 * Struct name:    sml_vtep_tbl_8_20_key_s
 * @brief:         Vtep Table Key
 * Description:    xxxxxxxxxxxxxxx
 */
typedef struct tag_sml_vtep_tbl_8_20_key {
	u32 vtep_remote_ip;
	u32 rsvd;
} sml_vtep_tbl_8_20_key_s;

/**
 * Struct name:    dmac_smac_u
 * @brief:         Dmac & Smac for VxLAN encapsulation
 * Description:    xxxxxxxxxxxxxxx
 */
typedef union tag_dmac_smac {
	u16 mac_addr[6];
	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u16 d_mac0:8;
		u16 d_mac1:8;
		u16 d_mac2:8;
		u16 d_mac3:8;

		u16 d_mac4:8;
		u16 d_mac5:8;
		u16 s_mac0:8;
		u16 s_mac1:8;

		u16 s_mac2:8;
		u16 s_mac3:8;
		u16 s_mac4:8;
		u16 s_mac5:8;
#elif (__BYTE_ORDER__ == __LITTLE_ENDIAN__)
		u16 d_mac1:8;
		u16 d_mac0:8;
		u16 d_mac3:8;
		u16 d_mac2:8;

		u16 d_mac5:8;
		u16 d_mac4:8;
		u16 s_mac1:8;
		u16 s_mac0:8;

		u16 s_mac3:8;
		u16 s_mac2:8;
		u16 s_mac5:8;
		u16 s_mac4:8;
#endif
	} bs;
} dmac_smac_u;

/**
 * Struct name:    sml_vtep_tbl_8_20_item_u
 * @brief:         Vtep Table Item
 * Description:    xxxxxxxxxxxxxxx
 */
typedef struct tag_sml_vtep_tbl_8_20_item {
	dmac_smac_u dmac_smac;
	u32 source_ip;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 er_id:4;
			u32 rsvd:12;
			u32 vlan:16;	/* The PRI*/
#else
			u32 vlan:16;	/* The PRI*/
			u32 rsvd:12;
			u32 er_id:4;
#endif
		} bs;

		u32 value;
	} misc;
} sml_vtep_tbl_8_20_item_s;

/**
 * Struct name:    sml_vtep_tbl_8_20_s
 * @brief:         Vtep Table( 8 + 20)
 * Description:    xxxxxxxxxxxxxxx
 */
typedef struct tag_sml_vtep_tbl_8_20 {
	sml_mac_tbl_head_u head;	/*first 4 bytes , the same as mac tbl */
	sml_vtep_tbl_8_20_key_s key;
	sml_vtep_tbl_8_20_item_s item;
} sml_vtep_tbl_8_20_s;

/**
 * Struct name:    sml_vtep_tbl_8_20_key_s
 * @brief:         Vtep Table Key
 * Description:    xxxxxxxxxxxxxxx
 */
typedef struct tag_sml_vxlan_udp_portcfg_4_8_key {
	u32 udp_dest_port;
	u32 rsvd;
} sml_vxlan_udp_portcfg_4_8_key_s;

/**
 * Struct name:    sml_vtep_tbl_8_20_item_u
 * @brief:         Vtep Table Item
 * Description:    xxxxxxxxxxxxxxx
 */
typedef struct tag_sml_vxlan_udp_portcfg_4_8_item {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 odp_port:12;
			u32 dp_id:2;
			u32 resvd:20;
#else
			u32 resvd:20;
			u32 dp_id:2;
			u32 odp_port:12;
#endif
		} bs;

		u32 value;
	} dw0;
} sml_vxlan_udp_portcfg_4_8_item_s;

/**
 * Struct name:    sml_vxlan_udp_portcfg_4_8_s
 * @brief:         Vxlan Dest Udp Port Table( 8 + 20)
 * Description:    xxxxxxxxxxxxxxx
 */
typedef struct tag_sml_vxlan_udp_portcfg_4_8 {
	sml_mac_tbl_head_u head;	/*first 4 bytes , the same as mac tbl */
	sml_vxlan_udp_portcfg_4_8_key_s key;
	sml_vxlan_udp_portcfg_4_8_item_s item;
} sml_vxlan_udp_portcfg_4_8_s;

/**
 * Struct name:    sml_vtep_er_info_s
 * @brief:         Vtep Er Info Table
 * Description:    xxxxxxxxxxxxxxx
 */
typedef struct tag_sml_vtep_er_info {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 lli_mode:1;
			/* ER bound to the outbound port is Eth-Trunk,
			 * type (FIC/Port)
			 */
			u32 er_fwd_trunk_type:1;
			/* ER bound to the outbound port is Eth-Trunk,
			 * port aggregation mode (Standby/LoadBalance/LACP)
			 */
			u32 er_fwd_trunk_mode:4;
			u32 er_mode:2;	/* ER mode (VEB/VEPA)*/
			/* er_id as LT index but also used as entries,
			 * facilitating service
			 */
			u32 er_id:4;
			/* Type of the ER bound to the outbound port
			 * (Port/FIC/Eth-Trunk)
			 */
			u32 er_fwd_type:4;
			/* ER bound egress ID(PortID/FICID/TrunkID)*/
			u32 er_fwd_id:16;
#else
			u32 er_fwd_id:16;
			u32 er_fwd_type:4;
			u32 er_id:4;
			u32 er_mode:2;
			u32 er_fwd_trunk_mode:4;
			u32 er_fwd_trunk_type:1;
			u32 lli_mode:1;
#endif
		} bs;

		u32 value;
	} dw0;
} sml_vtep_er_info_s;

/**
 * Struct name:    sml_logic_port_cfg_tbl_s
 * @brief:         Logic Port Cfg Table
 * Description:    xxxxxxxxxxxxxxx
 */
typedef struct tag_sm_logic_port_cfg {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/* Input switch port (or DP_MAX_PORTS). */
			u32 odp_port:12;
			u32 dp_id:2;	/* datapath id */
			u32 er_id:4;
			/* logic port MAC Learning enable or disable */
			u32 learn_en:1;
			u32 resvd:13;
#else
			u32 resvd:13;
			/* logic port MAC Learning enable or disable */
			u32 learn_en:1;
			u32 er_id:4;
			u32 dp_id:2;	/* datapath id */
			/* Input switch port (or DP_MAX_PORTS). */
			u32 odp_port:12;
#endif
		} bs;

		u32 value;
	} dw0;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd4:1;
			u32 er_fwd_trunk_type:1;
			u32 er_fwd_trunk_mode:4;
			u32 er_mode:2;
			u32 er_id:4;
			u32 er_fwd_type:4;
			u32 er_fwd_id:16;
#else
			u32 er_fwd_id:16;
			u32 er_fwd_type:4;
			u32 er_id:4;
			u32 er_mode:2;
			u32 er_fwd_trunk_mode:4;
			u32 er_fwd_trunk_type:1;
			u32 rsvd4:1;
#endif
		} bs;

		u32 value;
	} dw1;
} sml_logic_port_cfg_tbl_s;

/* vport stats counter */
typedef struct tag_vport_stats_ctr {
	u16 rx_packets;	/* total packets received       */
	u16 tx_packets;	/* total packets transmitted    */
	u16 rx_bytes;	/* total bytes received         */
	u16 tx_bytes;	/* total bytes transmitted      */
	u16 rx_errors;	/* bad packets received         */
	u16 tx_errors;	/* packet transmit problems     */
	u16 rx_dropped;	/* no space in linux buffers    */
	u16 tx_dropped;	/* no space available in linux  */
} vport_stats_ctr_s;

/**
 * Struct name:    vport_s
 * @brief:         Datapath Cfg Table
 * Description:    xxxxxxxxxxxxxxx
 */
typedef struct tag_vport {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	/* dw0 */
	u32 valid:1;
	u32 learn_en:1;
	u32 type:4;
	u32 dp_id:2;
	/* The type of Vport mapping port, 0:VF, 1:Logic Port */
	u32 mapping_type:4;
	u32 mapping_port:12;	/* odp_port mapping on VF or ER Logic Port */
	u32 rsvd:8;

	/* dw1 */
	u32 srctagl:12;	/* the function used by parent context */
	/* parent context XID used to upcall missed packet to ovs-vswitchd */
	u32 xid:20;

	/* dw2 */
	u32 odp_port:12;	/* on datapath port id */
	/* parent context CID used to upcall missed packet to ovs-vswitchd */
	u32 cid:20;
#else
	/* dw0 */
	u32 rsvd:8;
	u32 mapping_port:12;	/* odp_port mapping on VF or ER Logic Port */
	/* The type of Vport mapping port, 0:VF, 1:Logic Port */
	u32 mapping_type:4;
	u32 dp_id:2;
	u32 type:4;
	u32 learn_en:1;
	u32 valid:1;

	/* dw1 */
	/* parent context XID used to upcall missed packet to ovs-vswitchd */
	u32 xid:20;
	u32 srctagl:12;	/* the function used by parent context */

	/* dw2 */
	/* parent context CID used to upcall missed packet to ovs-vswitchd */
	u32 cid:20;
	u32 odp_port:12;	/* on datapath port id */
#endif

	/* dw3 is er information and it is valid only
	 * when mapping_type=1(logic port)
	 */
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 lli_mode:1;
			/* ER bound to the outbound port is Eth-Trunk,
			 * type (FIC/Port)
			 */
			u32 er_fwd_trunk_type:1;
			/* ER bound to the outbound port is Eth-Trunk,
			 * port aggregation mode (Standby/LoadBalance/LACP)
			 */
			u32 er_fwd_trunk_mode:4;
			u32 er_mode:2;	/* ER mode (VEB/VEPA)*/
			u32 er_id:4;	/* ERID */
			/* Type of the ER bound to the outbound port
			 * (Port/FIC/Eth-Trunk)
			 */
			u32 er_fwd_type:4;
			/*ER bound egress ID(PortID/FICID/TrunkID)*/
			u32 er_fwd_id:16;
#else
			u32 er_fwd_id:16;
			u32 er_fwd_type:4;
			u32 er_id:4;
			u32 er_mode:2;
			u32 er_fwd_trunk_mode:4;
			/* ER bound to the outbound port is Eth-Trunk,
			 * type (FIC/Port)
			 */
			u32 er_fwd_trunk_type:1;
			u32 lli_mode:1;
#endif
		} bs;
		u32 value;
	} dw3;

	/* dw4~dw7 */
	vport_stats_ctr_s stats;	/* vport stats counters */

} vport_s;

/**
 * Struct name:    sml_elb_tbl_elem_u
 * @brief:         ELB Table Elem
 * Description:    ELB leaf table members
 */
typedef union tag_sml_elb_tbl_elem {
	struct {
		u32 fwd_val;
		u32 next_val;
	} value;

	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd0:12;
		u32 fwd_type:4;
		u32 fwd_id:16;

		u32 rsvd1:17;
		u32 elb_index_next:15;
#elif (__BYTE_ORDER__ == __LITTLE_ENDIAN__)
		u32 fwd_id:16;
		u32 fwd_type:4;
		u32 rsvd0:12;

		u32 elb_index_next:15;
		u32 rsvd1:17;
#endif
	} bs;
} sml_elb_tbl_elem_u;

/**
 * Struct name:    sml_elb_tbl_s
 * @brief          ELB Table
 * Description:    ELB leaf table Entry
 */
typedef struct tag_sml_elb_tbl {
	sml_elb_tbl_elem_u elem[TBL_ID_ELB_ENTRY_ELEM_NUM];
} sml_elb_tbl_s;

/**
 * Struct name:    sml_vlan_tbl_elem_u
 * @brief:         VLAN Table Elem
 * Description:    VLAN broadcast table members
 */
typedef union tag_sml_vlan_tbl_elem {
	u16 value;

	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u16 learn_en:1;
		u16 elb_index:15;
#elif (__BYTE_ORDER__ == __LITTLE_ENDIAN__)
		u16 elb_index:15;
		u16 learn_en:1;
#endif
	} bs;
} sml_vlan_tbl_elem_u;

/**
 * Struct name:    sml_vlan_tbl_s
 * @brief:         VLAN Table
 * Entry Description: VLAN broadcast table
 */
typedef struct tag_sml_vlan_tbl {
	sml_vlan_tbl_elem_u elem[TBL_ID_VLAN_ENTRY_ELEM_NUM];
} sml_vlan_tbl_s;

/**
 * Struct name:    sml_multicast_tbl_array_u
 * @brief:         Multicast Table Elem
 * Description: multicast table members
 */
typedef union tag_sml_multicast_tbl_elem {
	struct {
		u32 route_val;
		u32 next_val;
	} value;

	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 rsvd0:12;
		u32 route_fwd_type:4;
		u32 route_fwd_id:16;

		u32 rsvd1:17;
		u32 elb_index:15;
#elif (__BYTE_ORDER__ == __LITTLE_ENDIAN__)
		u32 route_fwd_id:16;
		u32 route_fwd_type:4;
		u32 rsvd0:12;

		u32 elb_index:15;
		u32 rsvd1:17;
#endif
	} bs;
} sml_multicast_tbl_elem_u;

/* Struct name:    sml_multicast_tbl_s
 * @brief:         Multicast Table
 * Entry Description: multicast table
 */
typedef struct tag_sml_multicast_tbl {
	sml_multicast_tbl_elem_u elem[TBL_ID_MULTICAST_ENTRY_ELEM_NUM];
} sml_multicast_tbl_s;

/* Struct name:		sml_observe_port_s
 * @brief:			Observe Port Table
 * Description:		observing port entries defined
 */
typedef struct tag_sml_observe_port {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 valid:1;
			u32 rsvd0:11;
			u32 dst_type:4;
			u32 dst_id:16;
#else
			u32 dst_id:16;
			u32 dst_type:4;
			u32 rsvd0:11;
			u32 valid:1;
#endif
		} bs;
		u32 value;
	} dw0;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd1:4;
			u32 vlan_id:12;
			u32 rsvd2:2;
			u32 cut_len:14;
#else
			u32 cut_len:14;
			u32 rsvd2:2;
			u32 vlan_id:12;
			u32 rsvd1:4;
#endif
		} bs;
		u32 value;
	} dw1;

	u32 rsvd_pad[2];
} sml_observe_port_s;

/* Struct name:    sml_ipmac_tbl_16_12_key_s
 * @brief          ipmac filter table key
 * Description:    ipmac filter key define
 */
typedef struct tag_sml_ipmac_tbl_16_12_key {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	u32 func_id:16;
	u32 mac_h16:16;
#else
	u32 mac_h16:16;
	u32 func_id:16;
#endif

#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	u32 mac_m16:16;
	u32 mac_l16:16;
#else
	u32 mac_l16:16;
	u32 mac_m16:16;
#endif

	u32 ip;
	u32 rsvd;
} sml_ipmac_tbl_16_12_key_s;

/* Struct name:    sml_ipmac_tbl_16_12_item_s
 * @brief          ipmac filter table item
 * Description:    ipmac filter item define
 */
typedef struct tag_sml_ipmac_tbl_16_12_item {
	u32 rsvd[3];
} sml_ipmac_tbl_16_12_item_s;

/* Struct name:    sml_ethtype_tbl_8_4_key_s
 * @brief:         ethtype filter table key
 * Description:    ethtype filter key define
 */
typedef struct tag_sml_ethtype_tbl_8_4_key {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
	u32 group_id:16;
	u32 ethtype:16;
#else
	u32 ethtype:16;
	u32 group_id:16;
#endif

	u32 rsvd;
} sml_ethtype_tbl_8_4_key_s;

/* Struct name:    sml_ethtype_tbl_8_4_item_s
 * @brief          ethtype filter table item
 * Description:    ethtype filter item define
 */
typedef struct tag_sml_ethtype_tbl_8_4_item {
	u32 rsvd;
} sml_ethtype_tbl_8_4_item_s;

/* ACL to dfx record packets*/
typedef enum {
	ACL_PKT_TX = 0,
	ACL_PKT_RX = 1,
} sml_acl_pkt_dir_e;

/* ACL policy table item*/
typedef struct tag_sml_acl_policy_tbl {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 drop:1;
			u32 car_en:1;
			u32 car_id:12;
			u32 counter_type:2;
			u32 counter_id:16;
#else
			u32 counter_id:16;
			u32 counter_type:2;
			u32 car_id:12;
			u32 car_en:1;
			u32 drop:1;
#endif
		} bs;

		u32 value;
	} dw0;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd1:7;
			u32 mirrior_en:1;
			u32 observer_port:10;
			u32 change_dscp:1;
			u32 new_dscp:6;
			u32 change_pkt_pri:1;
			u32 new_pkt_pri:3;
			u32 redirect_en:3;
#else
			u32 redirect_en:3;
			u32 new_pkt_pri:3;
			u32 change_pkt_pri:1;
			u32 new_dscp:6;
			u32 change_dscp:1;
			u32 observer_port:10;
			u32 mirrior_en:1;
			u32 rsvd1:7;
#endif
		} bs;

		u32 value;
	} dw1;

	u32 redirect_data;
	u32 rsvd2;
} sml_acl_policy_tbl_s;

typedef struct tag_sml_acl_ipv4_key {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/* The alignment, match_key_type and
			 * later field is a KEY value
			 */
			u32 padding:16;
			u32 tid0:2;
			u32 match_key_type:3;	/* Matching type*/
			u32 rsvd:11;	/* Reserved field*/
#else
			u32 rsvd:11;
			u32 match_key_type:3;
			u32 tid0:2;
			u32 padding:16;
#endif
		} bs;
		u32 value;
	} dw0;

	/* dw1&dw2 */
	u32 sipv4;
	u32 dipv4;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 l4_sport:16;
			u32 l4_dport:16;
#else
			u32 l4_dport:16;
			u32 l4_sport:16;
#endif
		} bs;
		u32 value;
	} dw3;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 l4_protocol:8;
			u32 rsvd0:8;
			u32 seg_id:10;
			u32 rsvd1:6;
#else
			u32 rsvd1:6;
			u32 seg_id:10;
			u32 rsvd0:8;
			u32 l4_protocol:8;
#endif
		} bs;
		u32 value;
	} dw4;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 tid1:2;
			u32 rsvd:14;
			u32 padding:16;
#else
			u32 padding:16;
			u32 rsvd:14;
			u32 tid1:2;
#endif
		} bs;
		u32 value;
	} dw5;
} sml_acl_ipv4_key_s;

typedef struct tag_sml_acl_ipv6_key {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/* The alignment, match_key_type and
			 * later field is a KEY value
			 */
			u32 padding:16;
			u32 tid0:2;
			u32 match_key_type:3;	/* Matching type*/
			u32 rsvd:11;	/* Reserved field*/
#else
			u32 rsvd:11;
			u32 match_key_type:3;
			u32 tid0:2;
			u32 padding:16;
#endif
		} bs;
		u32 value;
	} dw0;

	/*dw1~dw4 */
	u32 sipv6[4];

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 tid1:2;
			u32 rsvd1:14;
			u32 tid2:2;
			u32 rsvd2:14;
#else
			u32 rsvd2:14;
			u32 tid2:2;
			u32 rsvd1:14;
			u32 tid1:2;
#endif
		} bs;
		u32 value;
	} dw5;

	/*dw6~dw9 */
	u32 dipv6[4];

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 tid3:2;
			u32 rsvd3:14;
			u32 tid4:2;
			u32 rsvd4:14;
#else
			u32 rsvd4:14;
			u32 tid4:2;
			u32 rsvd3:14;
			u32 tid3:2;
#endif
		} bs;
		u32 value;
	} dw10;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 l4_sport:16;
			u32 l4_dport:16;
#else
			u32 l4_dport:16;
			u32 l4_sport:16;
#endif
		} bs;
		u32 value;
	} dw11;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 l4_protocol:8;
			u32 rsvd0:8;
			u32 seg_id:10;
			u32 rsvd1:6;
#else
			u32 rsvd1:6;
			u32 seg_id:10;
			u32 rsvd0:8;
			u32 l4_protocol:8;
#endif
		} bs;
		u32 value;
	} dw12;

	u32 dw13;
	u32 dw14;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 tid5:2;
			u32 rsvd5:14;
			u32 tid6:2;
			u32 rsvd6:14;
#else
			u32 rsvd6:14;
			u32 tid6:2;
			u32 rsvd5:14;
			u32 tid5:2;
#endif
		} bs;
		u32 value;
	} dw15;

	u32 dw16;
	u32 dw17;
	u32 dw18;
	u32 dw19;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 tid7:2;
			u32 rsvd7:30;
#else
			u32 rsvd7:30;
			u32 tid7:2;
#endif
		} bs;
		u32 value;
	} dw20;
} sml_acl_ipv6_key_s;

/**
 * Struct name:    sml_voq_map_table_s
 * @brief:         voq_map_table
 * Description:    xxxxxxxxxxxxxxx
 */
typedef struct tag_sml_voq_map_table {
	u16 voq_base[8];
} sml_voq_map_table_s;

/**
 * Struct name:    sml_rss_context_u
 * @brief:         rss_context
 * Description:    xxxxxxxxxxxxxxx
 */
typedef union tag_sml_rss_context {
	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 udp_ipv4:1;
		u32 udp_ipv6:1;
		u32 ipv4:1;
		u32 tcp_ipv4:1;
		u32 ipv6:1;
		u32 tcp_ipv6:1;
		u32 ipv6_ext:1;
		u32 tcp_ipv6_ext:1;
		u32 valid:1;
		u32 rsvd1:13;
		u32 def_qpn:10;
#else
		u32 def_qpn:10;
		u32 rsvd1:13;
		u32 valid:1;
		u32 tcp_ipv6_ext:1;
		u32 ipv6_ext:1;
		u32 tcp_ipv6:1;
		u32 ipv6:1;
		u32 tcp_ipv4:1;
		u32 ipv4:1;
		u32 udp_ipv6:1;
		u32 udp_ipv4:1;
#endif
	} bs;

	u32 value;
} sml_rss_context_u;

typedef struct tag_sml_rss_context_tbl {
	sml_rss_context_u element[TBL_ID_RSS_CONTEXT_NUM];
} sml_rss_context_tbl_s;

/**
 * Struct name:    sml_rss_hash_u
 * @brief:         rss_hash
 * Description:    xxxxxxxxxxxxxxx
 */
typedef union tag_sml_rss_hash {
	u8 rq_index[256];
} sml_rss_hash_u;

typedef struct tag_sml_rss_hash_tbl {
	sml_rss_hash_u element[TBL_ID_RSS_HASH_NUM];
} sml_rss_hash_tbl_s;

/**
 * Struct name:    sml_lli_5tuple_key_s
 * @brief:         lli_5tuple_key
 * Description:    xxxxxxxxxxxxxxx
 */
typedef struct tag_sml_lli_5tuple_key {
	union {
		struct {
/** Define the struct bits */
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 src:5;
			/* The tile need fill the Dest */
			u32 rt:1;
			u32 key_size:2;
			/* determines which action that engine will take */
			u32 profile_id:3;
			/* indicates that requestor expect
			 * to receive a response data
			 */
			u32 op_id:5;
			u32 a:1;
			u32 rsvd:12;
			u32 vld:1;
			u32 xy:1;
			u32 at:1;
#else
			u32 at:1;
			u32 xy:1;
			u32 vld:1;
			/* indicates that requestor expect to
			 * receive a response data
			 */
			u32 rsvd:12;
			/* determines which action that engine will take*/
			u32 a:1;
			u32 op_id:5;
			u32 profile_id:3;
			u32 key_size:2;
			u32 rt:1;
			u32 src:5;
#endif
		} bs;

/* Define an unsigned member */
		u32 value;
	} dw0;
	union {
		struct {
			u32 rsvd:1;
			/* The tile need fill the Dest */
			u32 address:15;

			u32 table_type:5;
			u32 ip_type:1;
			u32 func_id:10;
		} bs;

		u32 value;
	} misc;

	u32 src_ip[4];
	u32 dst_ip[4];

	u16 src_port;
	u16 dst_port;

	u8 protocol;
	u8 tcp_flag;
	u8 fcoe_rctl;
	u8 fcoe_type;
	u16 eth_type;
} sml_lli_5tuple_key_s;

/**
 * Struct name:    sml_lli_5tuple_rsp_s
 * @brief:         lli_5tuple_rsp
 * Description:    xxxxxxxxxxxxxxx
 */
typedef struct tag_sml_lli_5tuple_rsp {
	union {
		struct {
			u32 state:4;
			u32 rsvd:28;
		} bs;

		u32 value;
	} dw0;

	u32 dw1;

	union {
		struct {
			u32 frame_size:16;
			u32 lli_en:8;
			u32 rsvd:8;
		} bs;

		u32 value;
	} dw2;

	u32 dw3;
} sml_lli_5tuple_rsp_s;

/**
 * Struct name:		l2nic_rx_cqe_s.
 * @brief:		l2nic_rx_cqe_s data structure.
 * Description:
 */
typedef struct tag_l2nic_rx_cqe {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rx_done:1;
			u32 bp_en:1;
			u32 rsvd1:6;
			u32 lro_num:8;
			u32 checksum_err:16;
#else
			u32 checksum_err:16;
			u32 lro_num:8;
			u32 rsvd1:6;
			u32 bp_en:1;
			u32 rx_done:1;
#endif
		} bs;
		u32 value;
	} dw0;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 length:16;
			u32 vlan:16;
#else
			u32 vlan:16;
			u32 length:16;
#endif
		} bs;
		u32 value;
	} dw1;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rss_type:8;
			u32 rsvd0:2;
			u32 vlan_offload_en:1;
			u32 umbcast:2;
			u32 rsvd1:7;
			u32 pkt_types:12;
#else
			u32 pkt_types:12;
			u32 rsvd1:7;
			u32 umbcast:2;
			u32 vlan_offload_en:1;
			u32 rsvd0:2;
			u32 rss_type:8;
#endif
		} bs;
		u32 value;
	} dw2;

	union {
		struct {
			u32 rss_hash_value;
		} bs;
		u32 value;
	} dw3;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 if_1588:1;
			u32 if_tx_ts:1;
			u32 if_rx_ts:1;
			u32 rsvd:1;
			u32 msg_1588_type:4;
			u32 msg_1588_offset:8;
			u32 tx_ts_seq:16;
#else
			u32 tx_ts_seq:16;
			u32 msg_1588_offset:8;
			u32 msg_1588_type:4;
			u32 rsvd:1;
			u32 if_rx_ts:1;
			u32 if_tx_ts:1;
			u32 if_1588:1;
#endif
		} bs;
		u32 value;
	} dw4;

	union {
		struct {
			u32 msg_1588_ts;
		} bs;

		struct {
			u32 rsvd0:12;
			/* for ovs. traffic type: 0-default l2nic pkt,
			 * 1-fallback traffic, 2-miss upcall traffic,
			 * 2-command
			 */
			u32 traffic_type:4;
			/* for ovs. traffic from: vf_id,
			 * only support traffic_type=0(default l2nic)
			 * or 2(miss upcall)
			 */
			u32 traffic_from:16;
		} ovs_bs;

		u32 value;
	} dw5;

	union {
		struct {
			u32 lro_ts;
		} bs;
		u32 value;
	} dw6;

	union {
		struct {
			u32 rsvd0;
		} bs;

		u32 localtag;	/* for ovs */

		u32 value;
	} dw7;
} l2nic_rx_cqe_s;

typedef union tag_sml_global_queue_tbl_elem {
	struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
		u32 src_tag_l:16;
		u32 local_qid:8;
		u32 rsvd:8;
#elif (__BYTE_ORDER__ == __LITTLE_ENDIAN__)
		u32 rsvd:8;
		u32 local_qid:8;
		u32 src_tag_l:16;
#endif
	} bs;

	u32 value;
} sml_global_queue_tbl_elem_u;

typedef struct tag_sml_global_queue_tbl {
	sml_global_queue_tbl_elem_u element[TBL_ID_GLOBAL_QUEUE_NUM];
} sml_global_queue_tbl_s;

typedef struct tag_sml_dfx_log_tbl {
	u32 wr_init_pc_h32;	/* Initial value of write_pc*/
	u32 wr_init_pc_l32;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 state:8;
			u32 func_en:1;
			u32 srctag:12;
			u32 max_num:11;	/* Data block highest value*/
#else
			u32 max_num:11;
			u32 srctag:12;
			u32 func_en:1;
			u32 state:8;
#endif
		} bs;
		u32 value;
	} dw2;

	u32 ci_index;
} sml_dfx_log_tbl_s;

typedef struct tag_sml_glb_capture_tbl {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 valid:1;
			u32 max_num:15;
			u32 rsvd:16;
#else
			u32 rsvd:16;
			u32 max_num:15;
			u32 valid:1;
#endif
		} bs;
		u32 value;
	} dw0;

	u32 discard_addr_h32;
	u32 discard_addr_l32;

	u32 rsvd0;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 valid:1;
			u32 mode:5;
			u32 direct:2;
			u32 offset:8;
			u32 cos:3;
			u32 max_num:13;
#else
			u32 max_num:13;
			u32 cos:3;
			u32 offset:8;
			u32 direct:2;
			u32 mode:5;
			u32 valid:1;
#endif
		} bs;
		u32 value;
	} dw4;

	u32 data_vlan;

	u32 condition_addr_h32;
	u32 condition_addr_l32;

} sml_glb_capture_tbl_s;

typedef struct tag_sml_cqe_addr_tbl {
	u32 cqe_first_addr_h32;
	u32 cqe_first_addr_l32;
	u32 cqe_last_addr_h32;
	u32 cqe_last_addr_l32;

} sml_cqe_addr_tbl_s;

/**
 * Struct name:		sml_ucode_exec_info_tbl_s
 * @brief:		ucode execption info Table
 * Description:		microcode exception information table
 */
typedef struct tag_ucode_exec_info_tbl {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 wptr_cpb_ack_str:4;
			u32 mem_cpb_ack_cnums_dma:4;
			u32 mem_cpb_ack_cmd_mode:2;
			u32 pr_ret_vld:1;
			u32 oeid_pd_pkt:1;
			u32 rptr_cmd:4;
			u32 wptr_cmd:4;
			u32 src_tag_l:12;
#else
			u32 src_tag_l:12;
			u32 wptr_cmd:4;
			u32 rptr_cmd:4;
			u32 oeid_pd_pkt:1;
			u32 pr_ret_vld:1;
			u32 mem_cpb_ack_cmd_mode:2;
			u32 mem_cpb_ack_cnums_dma:4;
			u32 wptr_cpb_ack_str:4;
#endif
		} bs;

		u32 value;
	} dw0;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 fq:16;
			u32 exception_type:4;
			u32 rptr_cpb_ack_str:4;
			u32 header_oeid:8;
#else
			u32 header_oeid:8;
			u32 rptr_cpb_ack_str:4;
			u32 exception_type:4;
			u32 fq:16;
#endif
		} bs;

		u32 value;
	} dw1;

	u32 oeid_pd_data_l32;
	u32 oeid_pd_data_m32;
} sml_ucode_exec_info_s;

typedef struct rq_iq_mapping_tbl {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rqid:16;
			u32 iqid:8;
			u32 rsvd:8;
#else
			u32 rsvd:8;
			u32 iqid:8;
			u32 rqid:16;
#endif
		} bs;
		u32 value;
	} dw[4];
} sml_rq_iq_mapping_tbl_s;

/* nic_ucode_rq_ctx table define
 */
typedef struct nic_ucode_rq_ctx {
	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 max_count:10;
			u32 cqe_tmpl:6;
			u32 pkt_tmpl:6;
			u32 wqe_tmpl:6;
			u32 psge_valid:1;
			u32 rsvd1:1;
			u32 owner:1;
			u32 ceq_en:1;
#else
			u32 ceq_en:1;
			u32 owner:1;
			u32 rsvd1:1;
			u32 psge_valid:1;
			u32 wqe_tmpl:6;
			u32 pkt_tmpl:6;
			u32 cqe_tmpl:6;
			u32 max_count:10;
#endif
		} bs;
		u32 dw0;
	};

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/* Interrupt number that L2NIC engine tell SW
			 * if generate int instead of CEQ
			 */
			u32 int_num:10;
			u32 ceq_count:10;
			/* product index */
			u32 pi:12;
#else
			/* product index */
			u32 pi:12;
			u32 ceq_count:10;
			/* Interrupt number that L2NIC engine tell SW
			 * if generate int instead of CEQ
			 */
			u32 int_num:10;
#endif
		} bs0;
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/* CEQ arm, L2NIC engine will clear it after send ceq,
			 * driver should set it by CMD Q after receive all pkt.
			 */
			u32 ceq_arm:1;
			u32 eq_id:5;
			u32 rsvd2:4;
			u32 ceq_count:10;
			/* product index */
			u32 pi:12;
#else
			/* product index */
			u32 pi:12;
			u32 ceq_count:10;
			u32 rsvd2:4;
			u32 eq_id:5;
			/* CEQ arm, L2NIC engine will clear it after send ceq,
			 * driver should set it by CMD Q after receive all pkt.
			 */
			u32 ceq_arm:1;
#endif
		} bs1;
		u32 dw1;
	};

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			/* consumer index */
			u32 ci:12;
			/* WQE page address of current CI point to, high part */
			u32 ci_wqe_page_addr_hi:20;
#else
			/* WQE page address of current CI point to, high part */
			u32 ci_wqe_page_addr_hi:20;
			/* consumer index */
			u32 ci:12;
#endif
		} bs2;
		u32 dw2;
	};

	/* WQE page address of current CI point to, low part */
	u32 ci_wqe_page_addr_lo;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 prefetch_min:7;
			u32 prefetch_max:11;
			u32 prefetch_cache_threshold:14;
#else
			u32 prefetch_cache_threshold:14;
			u32 prefetch_max:11;
			u32 prefetch_min:7;
#endif
		} bs3;
		u32 dw3;
	};

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd3:31;
			/* ownership of WQE */
			u32 prefetch_owner:1;
#else
			/* ownership of WQE */
			u32 prefetch_owner:1;
			u32 rsvd3:31;
#endif
		} bs4;
		u32 dw4;
	};

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 prefetch_ci:12;
			/* high part */
			u32 prefetch_ci_wqe_page_addr_hi:20;
#else
			/* high part */
			u32 prefetch_ci_wqe_page_addr_hi:20;
			u32 prefetch_ci:12;
#endif
		} bs5;
		u32 dw5;
	};

	/* low part */
	u32 prefetch_ci_wqe_page_addr_lo;
	/* host mem GPA, high part */
	u32 pi_gpa_hi;
	/* host mem GPA, low part */
	u32 pi_gpa_lo;

	union {
		struct {
#if (__BYTE_ORDER__ == __BIG_ENDIAN__)
			u32 rsvd4:9;
			u32 ci_cla_tbl_addr_hi:23;
#else
			u32 ci_cla_tbl_addr_hi:23;
			u32 rsvd4:9;
#endif
		} bs6;
		u32 dw6;
	};

	u32 ci_cla_tbl_addr_lo;

} nic_ucode_rq_ctx_s;

#define LRO_TSO_SPACE_SIZE  (240)	/* (15 * 16) */
#define RQ_CTX_SIZE         (48)

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif				/* __cplusplus */
#endif				/* __L2_TABLE_H__ */
