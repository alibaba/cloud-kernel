/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Alibaba Group
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/mm.h>
#include <linux/debugfs.h>
#include <linux/timer.h>
#include <linux/percpu.h>
#include <linux/version.h>
#include <linux/relay.h>
#include <linux/module.h>
#include <net/tcp.h>

#define TCP_SK_RT(sk)  (inet_csk(sk)->icsk_tcp_rt_priv)

#define LOG_SUBBUF_SIZE   262144
#define STATS_SUBBUF_SIZE 16384
#define PORT_MAX_NUM      6

#define LOG_STATUS_R 'R'
#define LOG_STATUS_W 'W'
#define LOG_STATUS_N 'N'
#define LOG_STATUS_E 'E'
#define LOG_STATUS_P 'P'

enum tcp_rt_type {
	TCPRT_TYPE_NONE,
	TCPRT_TYPE_LOCAL_PORT,
	TCPRT_TYPE_LOCAL_PORT_RANG,
	TCPRT_TYPE_PEER_PORT,
	TCPRT_TYPE_PEER_PORT_RANG,
};

enum tcp_rt_stage {
	TCPRT_STAGE_NONE,
	TCPRT_STAGE_REQUEST,
	TCPRT_STAGE_RESPONSE,
};

enum tcp_rt_stage_peer {
	TCPRT_STAGE_PEER_NONE,
	TCPRT_STAGE_PEER_REQUEST,
	TCPRT_STAGE_PEER_RESPONSE,
};

struct tcp_rt {
	enum tcp_rt_type  type;
	struct timespec64 con_start_time;

	u32              con_start_seq;
	u32              con_rcv_nxt;
	u32              index;
	u32              request_num;

	/* task item */
	struct timespec64    start_time;
	struct timespec64    end_time;

	union {
		u64       frcvtime_us;
		u64       lsenttime_us;
	};
	u64               lrcvtime_us;

	u32               start_seq;
	u32               start_rcv_nxt;

	u32               last_total_retrans;
	u32               last_update_seq;

	int               server_time;
	int               recv_time;
	union {
		u32       recv_data;
		u32       sent_data;
	};

	u8                rcv_reorder;

	enum tcp_rt_stage stage;
	enum tcp_rt_stage_peer stage_peer;
};

struct tcp_rt_stats {
	atomic64_t rt;
	atomic64_t number;
	atomic64_t drop;
	atomic64_t bytes;
	atomic64_t server_time;
	atomic64_t fail;
	atomic64_t packets;
	atomic64_t rtt;
	atomic64_t recv_time;
	atomic64_t recv_data;
};

struct _tcp_rt_stats {
	u64 rt;
	u64 number;
	u64 drop;
	u64 bytes;
	u64 server_time;
	u64 fail;
	u64 packets;
	u64 rtt;
	u64 recv_time;
	u64 recv_data;
};

int tcp_rt_output_init(int log_buf_num, int stats_buf_num,
		       const struct file_operations *fops);
void tcp_rt_output_released(void);
void tcp_rt_log_printk(const struct sock *sk, char flag, bool fin, bool check);
void tcp_rt_timer_output(int port, char *flag, bool alloc);
