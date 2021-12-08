/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * ElasticRDMA driver for Linux
 * Authors: Cheng You <chengyou@linux.alibaba.com>
 * Copyright (c) 2020-2021 Alibaba Group.
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
#ifndef _ERDMA_H__
#define _ERDMA_H__

#include <crypto/hash.h>

#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/in.h>
#include <linux/llist.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/resource.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/version.h>

#include <rdma/ib_verbs.h>

#include <uapi/rdma/erdma-abi.h>
#include "erdma_common.h"
#include "iwarp.h"

#define ERDMA_ENABLE_DEBUG
#ifdef ERDMA_ENABLE_DEBUG

/* incomplete definition. the first two fields are scqn and rcqn. */
struct erdma_usr_qp_info {
	__u32    scq;
	__u32    rcq;
};
#endif

/* Now we support max 128 erdma-devices. */
#define ERDMA_MAX_DEVICES           128
#define DRV_MODULE_NAME             "erdma"
#define ERDMA_CHRDEV_NAME           "erdma"
#define ERDMA_HTONL                 htonl

#ifndef ibdev_err
#define ibdev_err(_ibdev, format, arg...) \
	dev_err(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#endif
#ifndef ibdev_dbg
#define ibdev_dbg(_ibdev, format, arg...) \
	dev_dbg(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#endif
#ifndef ibdev_warn
#define ibdev_warn(_ibdev, format, arg...) \
	dev_warn(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#endif
#ifndef ibdev_info
#define ibdev_info(_ibdev, format, arg...) \
	dev_info(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#endif

#ifndef ibdev_err_ratelimited
#define ibdev_err_ratelimited(_ibdev, format, arg...) \
	dev_err_ratelimited(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#endif
#ifndef ibdev_dbg_ratelimited
#define ibdev_dbg_ratelimited(_ibdev, format, arg...) \
	dev_dbg_ratelimited(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#endif
#ifndef ibdev_warn_ratelimited
#define ibdev_warn_ratelimited(_ibdev, format, arg...) \
	dev_warn_ratelimited(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#endif
#ifndef ibdev_info_ratelimited
#define ibdev_info_ratelimited(_ibdev, format, arg...) \
	dev_info_ratelimited(&((struct ib_device *)(_ibdev))->dev, format, ##arg)
#endif

/* Used for  */
struct erdma_objhdr {
	__u32                   id; /* for idr based object lookup */
	struct kref             ref;
	struct erdma_dev        *edev;
};

struct erdma_uobj {
	struct list_head    list;
	void                *addr;
	__u32               size;
	__u32               key;
	__u32               type;
};

struct erdma_ucontext {
	struct ib_ucontext      ib_ucontext;
	struct erdma_dev        *edev;

	__u32                   sdb_type;
	__u32                   sdb_idx;
	__u32                   sdb_page_idx;
	__u32                   sdb_page_off;
	__u64                   sdb;
	__u64                   rdb;
	__u64                   cdb;

	/* List of user mappable queue objects */
	spinlock_t              uobj_lock;
	struct list_head        uobj_list;
	__u32                   uobj_key;
};

struct erdma_pd {
	struct ib_pd            ibpd;
	struct erdma_objhdr     hdr;
};

enum erdma_access_flags {
	SR_MEM_LREAD    = (1<<0),
	SR_MEM_LWRITE   = (1<<1),
	SR_MEM_RREAD    = (1<<2),
	SR_MEM_RWRITE   = (1<<3),

	SR_MEM_FLAGS_LOCAL =
		(SR_MEM_LREAD | SR_MEM_LWRITE),
	SR_MEM_FLAGS_REMOTE =
		(SR_MEM_RWRITE | SR_MEM_RREAD)
};

#define STAG_VALID	1
#define STAG_INVALID	0
#define ERDMA_STAG_MAX	0xffffffff

struct erdma_mr;

/*
 * generic memory representation for registered erdma memory.
 * memory lookup always via higher 24 bit of stag (stag index).
 * the stag is stored as part of the erdma object header (id).
 * object relates to memory window if embedded mr pointer is valid
 */
struct erdma_mem {
	struct erdma_objhdr     hdr;

	struct erdma_mr         *assoc_mr;              /* assoc. MR if MW, NULL if MR */
	__u64                   va;                     /* VA of memory */
	__u64                   len;                    /* amount of memory bytes */

	__u32                   stag_state:1,           /* VALID or INVALID */
				is_zbva:1,              /* zero based virt. addr. */
				mw_bind_enabled:1,      /* check only if MR */
				remote_inval_enabled:1, /* VALID or INVALID */
				consumer_owns_key:1,    /* key/index split ? */
				rsvd:27;

	enum erdma_access_flags perms;	/* local/remote READ & WRITE */
};

#define ERDMA_MEM_IS_MW(m)	((m)->assoc_mr != NULL)

/*
 * MR and MW definition.
 * Used OFA structs ib_mr/ib_mw holding:
 * lkey, rkey, MW reference count on MR
 */
struct erdma_mr {
	struct ib_mr         ibmr;
	struct erdma_mem     mem;
	struct ib_umem       *umem;
	struct erdma_pd      *pd;
	void                 *mtt_va_addr;
	dma_addr_t           mtt_dma_addr;
	__u32                mtt_size;
	__u32                total_mtt_size;
	__u32                mtt_nents;
	bool hw_kicked;
	__u32                prealloc_mtt_nents;
	bool validated;
};

struct erdma_mw {
	struct ib_mw       ibmw;
	struct erdma_mem   mem;
	struct rcu_head    rcu;
};

enum erdma_wr_state {
	SR_WR_IDLE          = 0,
	SR_WR_QUEUED        = 1,      /* processing has not started yet */
	SR_WR_INPROGRESS    = 2,      /* initiated processing of the WR */
	SR_WR_DONE          = 3
};

struct erdma_cq {
	struct ib_cq            ibcq;
	struct erdma_objhdr     hdr;

	spinlock_t              lock;
	struct erdma_cqe        *queue;
	dma_addr_t              qbuf_dma_addr;
	__u32                   depth;
	__u32                   assoc_eqn;
	__u32                   user_cq;

	__u32 ci;
	__u32 owner;
	void *db;

	void *backup_db_addr;
	dma_addr_t backup_db_dma_addr;
#ifdef ERDMA_ENABLE_DEBUG
	__u8                    *snapshot;
#endif
	struct ib_umem          *umem;
	void                    *mtt_buf;

	__u32                   mtt_cnt;
	__u32                   page_size;
	__u32                   mtt_type;
	__u64                   mtt_entry[6];
	__u32					first_page_offset;
};

enum erdma_qp_state {
	ERDMA_QP_STATE_IDLE	= 0,
	ERDMA_QP_STATE_RTR	= 1,
	ERDMA_QP_STATE_RTS	= 2,
	ERDMA_QP_STATE_CLOSING	= 3,
	ERDMA_QP_STATE_TERMINATE	= 4,
	ERDMA_QP_STATE_ERROR	= 5,
	ERDMA_QP_STATE_MORIBUND	= 6, /* destroy called but still referenced */
	ERDMA_QP_STATE_UNDEF	= 7,
	ERDMA_QP_STATE_COUNT	= 8
};

enum erdma_qp_flags {
	ERDMA_BIND_ENABLED	= (1 << 0),
	ERDMA_WRITE_ENABLED	= (1 << 1),
	ERDMA_READ_ENABLED	= (1 << 2),
	ERDMA_SIGNAL_ALL_WR	= (1 << 3),
	/*
	 * QP currently being destroyed
	 */
	ERDMA_QP_IN_DESTROY	= (1 << 8)
};

enum erdma_qp_attr_mask {
	ERDMA_QP_ATTR_STATE             = (1 << 0),
	ERDMA_QP_ATTR_ACCESS_FLAGS      = (1 << 1),
	ERDMA_QP_ATTR_LLP_HANDLE        = (1 << 2),
	ERDMA_QP_ATTR_ORD               = (1 << 3),
	ERDMA_QP_ATTR_IRD               = (1 << 4),
	ERDMA_QP_ATTR_SQ_SIZE           = (1 << 5),
	ERDMA_QP_ATTR_RQ_SIZE           = (1 << 6),
	ERDMA_QP_ATTR_MPA               = (1 << 7)
};

struct erdma_sk_upcalls {
	void	(*sk_state_change)(struct sock *sk);
	void	(*sk_data_ready)(struct sock *sk, int bytes);
	void	(*sk_write_space)(struct sock *sk);
	void	(*sk_error_report)(struct sock *sk);
};

struct erdma_qp_attrs {
	enum erdma_qp_state     state;
	char                    terminate_buffer[52];
	__u32                   terminate_msg_length;
	__u32                   ddp_rdmap_version; /* 0 or 1 */
	char                    *stream_msg_buf;
	__u32                   stream_msg_buf_length;
	__u32                   rq_hiwat;
	__u32                   sq_size;
	__u32                   rq_size;
	__u32                   orq_size;
	__u32                   irq_size;
	__u32                   sq_max_sges;
	__u32                   sq_max_sges_rdmaw;
	__u32                   rq_max_sges;
	enum erdma_qp_flags     flags;

	struct socket           *llp_stream_handle;
	__u32                   sip;
	__u32                   dip;
	__u16                   sport;
	__u16                   dport;
	__u16                   origin_sport;
	__u32                   remote_qpn;
};

#define ERDMA_QP_TYPE_CLIENT 0
#define ERDMA_QP_TYPE_SERVER 1

struct erdma_queue {
	void        *qbuf;
	dma_addr_t  dma_addr;
	__u16       depth;
	__u32       size;

	u64 *wr_tbl;

	void *backup_db_addr;
	dma_addr_t backup_db_dma_addr;
};

struct erdma_qp {
	struct ib_qp            ibqp;
	struct erdma_objhdr     hdr;
	struct list_head        devq;

	struct erdma_cep        *cep;
	struct rw_semaphore     state_lock;

	struct erdma_pd         *pd;
	struct erdma_cq         *scq;
	struct erdma_cq         *rcq;

	struct erdma_qp_attrs   attrs;

	struct erdma_queue      sendq;
	struct erdma_queue      recvq;

	spinlock_t lock;
	spinlock_t sq_lock;
	__u32 sq_pi;
	__u32 sq_ci;
	void *sq_db;

	bool is_kernel_qp;
	void *cq_db;
	bool without_cm;
	__u8 cc_method;
	u64 reserved;

	spinlock_t rq_lock;
	__u32 rq_pi;
	__u32 rq_ci;
	void *rq_db;

#ifdef ERDMA_ENABLE_DEBUG
	__u8                    *snapshot;
#endif

	__u8                    qp_type;
	__u8                    private_data_len;
};

#define QP_ID(qp)               ((qp)->hdr.id)
#define PD_ID(pd)               ((pd)->hdr.id)
#define CQ_ID(cq)               ((cq)->hdr.id)
#define OBJ_ID(obj)             ((obj)->hdr.id)
#define MR_ID(mr)               ((mr)->mem.hdr.id)

/* QP general functions */
int erdma_modify_qp_internal(struct erdma_qp *qp, struct erdma_qp_attrs *attrs,
		  enum erdma_qp_attr_mask mask);
int erdma_modify_qp_internal_raw(struct erdma_qp *qp, struct erdma_qp_attrs *attrs,
		  enum erdma_qp_attr_mask mask);

void erdma_qp_llp_close(struct erdma_qp *qp);
void erdma_qp_cm_drop(struct erdma_qp *qp, int sched);

struct ib_qp *erdma_get_ibqp(struct ib_device *dev, int id);
void erdma_qp_get_ref(struct ib_qp *qp);
void erdma_qp_put_ref(struct ib_qp *qp);

/* RDMA core event dipatching */
void erdma_qp_event(struct erdma_qp *qp, enum ib_event_type type);
void erdma_cq_event(struct erdma_cq *cq, enum ib_event_type type);
void erdma_port_event(struct erdma_dev *dev, __u8 port, enum ib_event_type type);

extern const struct attribute_group erdma_attr_group;

static inline struct erdma_dev *to_edev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct erdma_dev, ibdev);
}

static inline struct erdma_pd *to_epd(struct ib_pd *pd)
{
	return container_of(pd, struct erdma_pd, ibpd);
}

static inline struct erdma_ucontext *to_ectx(struct ib_ucontext *ibctx)
{
	return container_of(ibctx, struct erdma_ucontext, ib_ucontext);
}

static inline struct erdma_mr *to_emr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct erdma_mr, ibmr);
}

static inline struct erdma_cq *to_ecq(struct ib_cq *ibcq)
{
	return container_of(ibcq, struct erdma_cq, ibcq);
}

static inline struct erdma_qp *to_eqp(struct ib_qp *ibqp)
{
	return container_of(ibqp, struct erdma_qp, ibqp);
}

#endif
