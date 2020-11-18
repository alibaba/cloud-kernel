/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 *
 * Copyright (C) 2021 Alibaba Group
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef __LINUX_PING_TRACE_H
#define __LINUX_PING_TRACE_H

#include <linux/types.h>

/* magic number in icmp header's code.
 * Although the value 1 seems not like a magic number,
 * it actually plays the role of magic number,
 * and it connot be modidied now due to some historical reasons.
 */
#define PINGTRACE_CODE_MAGIC 1
#define PINGTRACE_HDR_MAGIC 0x7ace

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
	PINGTRACE_F_DONTADD     =       1,
};

struct pingtrace_timestamp {
	__u32 ns_id;
	__u32 ifindex;
	__u16 user_id;
	__u16 function_id;
	__u32 ts;
};

struct pingtrace_hdr {
	__u8 version;
	__u8 num;
	__u16 flags;
	__u16 magic;
	__u16 reserve;
	__u32 id;
	__u32 seq;
};

struct pingtrace_pkt {
	struct pingtrace_hdr hdr;
	struct pingtrace_timestamp entries[];
};

#endif
