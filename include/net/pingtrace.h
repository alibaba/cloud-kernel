/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2021 Alibaba Group
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef _PINGTRACE_H
#define _PINGTRACE_H

#include <linux/types.h>
#include <uapi/linux/pingtrace.h>

struct sk_buff;

#define PINGTRACE_F_ECHO                1
#define PINGTRACE_F_ECHOREPLY           2
#define PINGTRACE_F_BOTH                3
#define PINGTRACE_F_CALCULATE_CHECKSUM  4

DECLARE_STATIC_KEY_FALSE(pingtrace_control);

bool skb_pingtrace_check(struct sk_buff *skb, u64 flags);
int skb_pingtrace_add_ts(struct sk_buff *skb, struct net *net, u32 function_id,
			 u64 flags);

#endif /* _PINGTRACE_H */
