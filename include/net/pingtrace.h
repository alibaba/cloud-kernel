/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Alibaba Group
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef _PINGTRACE_H
#define _PINGTRACE_H

#include <linux/types.h>

struct sk_buff;

#define PINGTRACE_CODE_MAGIC 1
#define PINGTRACE_HDR_MAGIC 0x7ace

#define PINGTRACE_F_ECHO                1
#define PINGTRACE_F_ECHOREPLY           2
#define PINGTRACE_F_BOTH                3
#define PINGTRACE_F_CALCULATE_CHECKSUM  4

enum pingtrace_function {
	P_L_TX_USER,
	P_L_TX_DEVQUEUE,
	P_L_TX_DEVOUT,
	P_R_RX_ICMPRCV,
	P_R_TX_DEVOUT,
	P_L_RX_IPRCV,
	P_L_RX_SKDATAREADY,
	P_L_RX_WAKEUP,
	P_L_RX_USER,
};

enum PINGTRACE_HDR_FLAGS {
	PINGTRACE_F_DONTADD	=	1,
};

struct pingtrace_timestamp {
	u64 node_id;
	u32 function_id;
	u32 ts;
};

struct pingtrace_hdr {
	u8 version;
	u8 num;
	u16 flags;
	u16 magic;
	u16 reserve;
	u32 id;
	u32 seq;
};

struct pingtrace_pkt {
	struct pingtrace_hdr hdr;
	struct pingtrace_timestamp entries[];
};

DECLARE_STATIC_KEY_FALSE(pingtrace_control);

int skb_pingtrace_check(struct sk_buff *skb, u64 flags);
int skb_pingtrace_add_ts(struct sk_buff *skb, struct net *net, u32 function_id,
			 u64 flags);

#endif /* _PINGTRACE_H */
