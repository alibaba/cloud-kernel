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

#ifndef __SML_TABLE_PUB_H__
#define __SML_TABLE_PUB_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif				/* __cplusplus */

/* Un-FPGA(ESL/EMU/EDA) specification */
#if (!defined(__UP_FPGA__) && (!defined(HI1822_MODE_FPGA)))
/* ER specification*/
#define L2_ER_SPEC                  (16)

/* Entry specification*/
#define TBL_ID_FUNC_CFG_SPEC        (512)
#define TBL_ID_PORT_CFG_SPEC        (16)
#define TBL_ID_MAC_SPEC             (4096)
#define TBL_ID_MULTICAST_SPEC       (1024)
#define TBL_ID_TRUNK_SPEC           (256)
#define TBL_ID_ELB_SPEC             (18432)
#define TBL_ID_TAGGEDLIST_SPEC      (80)
#define TBL_ID_UNTAGGEDLIST_SPEC    (16)

/* VLAN specification*/
#define VSW_VLAN_SPEC               (4096)

#else				/* FPGA scenario specifications */

/* ER specification*/
#define L2_ER_SPEC                  (4)

/* Entry specification*/
#define TBL_ID_FUNC_CFG_SPEC        (64)
#define TBL_ID_PORT_CFG_SPEC        (16)
#define TBL_ID_MAC_SPEC             (256)
#define TBL_ID_MULTICAST_SPEC       (32)
#define TBL_ID_TRUNK_SPEC           (16)
#define TBL_ID_ELB_SPEC             (1152)
#define TBL_ID_TAGGEDLIST_SPEC      (20)
#define TBL_ID_UNTAGGEDLIST_SPEC    (4)

/* VLAN specification*/
#define VSW_VLAN_SPEC               (1024)
#endif

/**
 *  Number of entries elements defined
 */
#define TBL_ID_ELB_ENTRY_ELEM_NUM           2
#define TBL_ID_VLAN_ENTRY_ELEM_NUM          8
#define TBL_ID_MULTICAST_ENTRY_ELEM_NUM     2
#define TBL_ID_TRUNKFWD_ENTRY_ELEM_NUM      32
#define TBL_ID_TAGGEDLIST_BITMAP32_NUM      4
#define TBL_ID_UNTAGGEDLIST_BITMAP32_NUM    4
#define TBL_ID_GLOBAL_QUEUE_NUM             4
#define TBL_ID_RSS_CONTEXT_NUM              4
#define TBL_ID_RSS_HASH_NUM                 4

/**
 *  NIC receiving mode defined
 */
#define NIC_RX_MODE_UC          0x01	/* 0b00001 */
#define NIC_RX_MODE_MC          0x02	/* 0b00010 */
#define NIC_RX_MODE_BC          0x04	/* 0b00100 */
#define NIC_RX_MODE_MC_ALL      0x08	/* 0b01000 */
#define NIC_RX_MODE_PROMISC     0x10	/* 0b10000 */

/**
 *  Maximum number of  HCAR
 */
#define QOS_MAX_HCAR_NUM        (12)

/**
 *  VLAN Table, Multicast Table, ELB Table Definitions
 *  The Table index and sub id index
 */
#define VSW_DEFAULT_VLAN0                       (0)
#define INVALID_ELB_INDEX                       (0)

#if (!defined(__UP_FPGA__) && (!defined(HI1822_MODE_FPGA)))
/* Supports ESL/EMU/EDA 16ER * 4K VLAN, 1 entry stored 8 vlan*/
#define GET_VLAN_TABLE_INDEX(er_id, vlan_id)	\
	((((er_id) & 0xF) << 9) | (((vlan_id) & 0xFFF) >> 3))
#else
/*FPGA supports only 4ER * 1K VLAN, 1 entry stored 8 vlan*/
#define GET_VLAN_TABLE_INDEX(er_id, vlan_id)	\
	((((er_id) & 0x3) << 7) | (((vlan_id) & 0x3FF) >> 3))
#endif
#define GET_VLAN_ENTRY_SUBID(vlan_id)           ((vlan_id) & 0x7)

#define GET_MULTICAST_TABLE_INDEX(mc_id)        ((mc_id) >> 1)
#define GET_MULTICAST_ENTRY_SUBID(mc_id)        ((mc_id) & 0x1)

#define GET_ELB_TABLE_INDEX(elb_id)             ((elb_id) >> 1)
#define GET_ELB_ENTRY_SUBID(elb_id)             ((elb_id) & 0x1)

/**
 *  taggedlist_table and untaggedlist_table access offset calculation
 */
#define GET_TAGLIST_TABLE_INDEX(list_id, vlan_id)	\
	(((list_id) << 5) | (((vlan_id) & 0xFFF) >> 7))
#define GET_TAGLIST_TABLE_BITMAP_IDX(vlan_id)       (((vlan_id) >> 5) & 0x3)
#define GET_TAGLIST_TABLE_VLAN_BIT(vlan_id)	\
	(0x1UL << ((vlan_id) & 0x1F))

#define TRUNK_FWDID_NOPORT     0xFFFF

/**
 *  MAC type definition
 */
typedef enum {
	MAC_TYPE_UC = 0,
	MAC_TYPE_BC,
	MAC_TYPE_MC,
	MAC_TYPE_RSV,
} mac_type_e;

/**
 *  Ethernet port definition
 */
typedef enum {
	MAG_ETH_PORT0 = 0,
	MAG_ETH_PORT1,
	MAG_ETH_PORT2,
	MAG_ETH_PORT3,
	MAG_ETH_PORT4,
	MAG_ETH_PORT5,
	MAG_ETH_PORT6,
	MAG_ETH_PORT7,
	MAG_ETH_PORT8,
	MAG_ETH_PORT9,
} mag_eth_port_e;

/**
 *  vlan filter type defined
 */
typedef enum {
	VSW_VLAN_MODE_ALL = 0,
	VSW_VLAN_MODE_ACCESS,
	VSW_VLAN_MODE_TRUNK,
	VSW_VLAN_MODE_HYBRID,
	VSW_VLAN_MODE_QINQ,
	VSW_VLAN_MODE_MAX,
} vsw_vlan_mode_e;

/**
 *  MAC table query forwarding port type definition
 */
typedef enum {
	VSW_FWD_TYPE_FUNCTION = 0,	/* forward type function */
	VSW_FWD_TYPE_VMDQ,	/* forward type function-queue(vmdq) */
	VSW_FWD_TYPE_PORT,	/* forward type port */
	VSW_FWD_TYPE_FIC,	/* forward type fic */
	VSW_FWD_TYPE_TRUNK,	/* forward type trunk */
	VSW_FWD_TYPE_DP,	/* forward type DP */
	VSW_FWD_TYPE_MC,	/* forward type multicast */

	/* START: is not used and has to be removed */
	VSW_FWD_TYPE_BC,	/* forward type broadcast */
	VSW_FWD_TYPE_PF,	/* forward type pf */
	/* END: is not used and has to be removed */

	VSW_FWD_TYPE_NULL,	/* forward type null */
} vsw_fwd_type_e;

/**
 *  Eth-Trunk port aggregation mode
 */
typedef enum {
	VSW_ETRK_MODE_STANDBY,
	VSW_ETRK_MODE_SMAC,
	VSW_ETRK_MODE_DMAC,
	VSW_ETRK_MODE_SMACDMAC,
	VSW_ETRK_MODE_SIP,
	VSW_ETRK_MODE_DIP,
	VSW_ETRK_MODE_SIPDIP,
	VSW_ETRK_MODE_5TUPLES,
	VSW_ETRK_MODE_LACP,
	VSW_ETRK_MODE_MAX,
} vsw_etrk_mode_e;

/**
 *  Eth-Trunk port aggregation mode
 */
typedef enum {
	TRUNK_MODE_STANDBY,
	TRUNK_MODE_SMAC,
	TRUNK_MODE_DMAC,
	TRUNK_MODE_SMACDMAC,
	TRUNK_MODE_SIP,
	TRUNK_MODE_DIP,
	TRUNK_MODE_SIPDIP,
	TRUNK_MODE_5TUPLES,
	TRUNK_MODE_SIPV6,
	TRUNK_MODE_DIPV6,
	TRUNK_MODE_SIPDIPV6,
	TRUNK_MODE_5TUPLESV6,
	TRUNK_MODE_LACP,
} trunk_mode_s;

/* ACL key type */
enum {
	ACL_KEY_IPV4 = 0,
	ACL_KEY_IPV6
};

/* ACL filter action */
enum {
	ACL_ACTION_PERMIT = 0,
	ACL_ACTION_DENY
};

/* ACL action button*/
enum {
	ACL_ACTION_OFF = 0,
	ACL_ACTION_ON,
};

/* ACL statistic action*/
enum {
	ACL_ACTION_NO_COUNTER = 0,
	ACL_ACTION_COUNT_PKT,
	ACL_ACTION_COUNT_PKT_LEN,
};

/* ACL redirect action*/
enum {
	ACL_ACTION_FORWAR_UP = 1,
	ACL_ACTION_FORWAR_PORT,
	ACL_ACTION_FORWAR_NEXT_HOP,
	ACL_ACTION_FORWAR_OTHER,
};

enum {
	CEQ_TIMER_STOP = 0,
	CEQ_TIMER_START,
};

enum {
	CEQ_API_DISPATCH = 0,
	CEQ_API_NOT_DISPATCH,
};

enum {
	CEQ_MODE = 1,
	INT_MODE,
};

enum {
	ER_MODE_VEB,
	ER_MODE_VEPA,
	ER_MODE_MULTI,
	ER_MODE_NULL,
};

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif				/* __cplusplus */
#endif				/* __L2_TABLE_PUB_H__ */
