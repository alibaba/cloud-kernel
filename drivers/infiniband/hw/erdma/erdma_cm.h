/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * ElasticRDMA driver for Linux
 * Authors: Cheng You <chengyou@linux.alibaba.com>
 *
 * Copyright (c) 2020-2021 Alibaba Group.
 * Copyright (c) 2008-2016, IBM Corporation
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __ERDMA_CM_H__
#define __ERDMA_CM_H__

#include <net/sock.h>
#include <linux/tcp.h>

#include <rdma/iw_cm.h>

enum erdma_cep_state {
	ERDMA_EPSTATE_IDLE = 1,
	ERDMA_EPSTATE_LISTENING,
	ERDMA_EPSTATE_CONNECTING,
	ERDMA_EPSTATE_AWAIT_MPAREQ,
	ERDMA_EPSTATE_RECVD_MPAREQ,
	ERDMA_EPSTATE_AWAIT_MPAREP,
	ERDMA_EPSTATE_RDMA_MODE,
	ERDMA_EPSTATE_CLOSED
};

struct erdma_mpa_info {
	struct mpa_rr	hdr;	/* peer mpa hdr in host byte order */
	char		*pdata;
	int		bytes_rcvd;
	__u32           remote_qpn;
};

struct erdma_llp_info {
	struct socket		*sock;
	struct sockaddr_in	laddr;	/* redundant with socket info above */
	struct sockaddr_in	raddr;	/* dito, consider removal */
	struct erdma_sk_upcalls	sk_def_upcalls;
};

struct erdma_dev;

struct erdma_cep {
	struct iw_cm_id         *cm_id;
	struct erdma_dev        *edev;

	struct list_head	devq;
	/*
	 * The provider_data element of a listener IWCM ID
	 * refers to a list of one or more listener CEPs
	 */
	struct list_head        listenq;
	struct erdma_cep        *listen_cep;
	struct erdma_qp         *qp;
	spinlock_t              lock;
	wait_queue_head_t       waitq;
	struct kref		ref;
	enum erdma_cep_state	state;
	short			in_use;
	struct erdma_cm_work	*mpa_timer;
	struct list_head	work_freelist;
	struct erdma_llp_info	llp;
	struct erdma_mpa_info	mpa;
	int			ord;
	int			ird;
	int			sk_error; /* not (yet) used XXX */

	/* Saved upcalls of socket llp.sock */
	void    (*sk_state_change)(struct sock *sk);
	void    (*sk_data_ready)(struct sock *sk);
	void    (*sk_write_space)(struct sock *sk);
	void    (*sk_error_report)(struct sock *sk);
};

#define MPAREQ_TIMEOUT	(HZ*20)
#define MPAREP_TIMEOUT	(HZ*10)

enum erdma_work_type {
	ERDMA_CM_WORK_ACCEPT	= 1,
	ERDMA_CM_WORK_READ_MPAHDR,
	ERDMA_CM_WORK_CLOSE_LLP,		/* close socket */
	ERDMA_CM_WORK_PEER_CLOSE,		/* socket indicated peer close */
	ERDMA_CM_WORK_MPATIMEOUT
};

struct erdma_cm_work {
	struct delayed_work	work;
	struct list_head	list;
	enum erdma_work_type	type;
	struct erdma_cep	*cep;
};

#define to_sockaddr_in(a) (*(struct sockaddr_in *)(&(a)))

extern int erdma_connect(struct iw_cm_id *id, struct iw_cm_conn_param *param);
extern int erdma_accept(struct iw_cm_id *id, struct iw_cm_conn_param *param);
extern int erdma_reject(struct iw_cm_id *id, const void *pdata, __u8 plen);
extern int erdma_create_listen(struct iw_cm_id *id, int backlog);
extern int erdma_destroy_listen(struct iw_cm_id *id);

extern void erdma_cep_get(struct erdma_cep *ceq);
extern void erdma_cep_put(struct erdma_cep *ceq);
extern int erdma_cm_queue_work(struct erdma_cep *ceq, enum erdma_work_type type);

extern int erdma_cm_init(void);
extern void erdma_cm_exit(void);

/*
 * TCP socket interface
 */
#define sk_to_qp(sk)	(((struct erdma_cep *)((sk)->sk_user_data))->qp)
#define sk_to_cep(sk)	((struct erdma_cep *)((sk)->sk_user_data))

/*
 * Should we use tcp_current_mss()?
 * But its not exported by kernel.
 */
static inline unsigned int get_tcp_mss(struct sock *sk)
{
	return tcp_sk(sk)->mss_cache;
}

#endif
