/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * ElasticRDMA driver for Linux
 * Authors: Cheng You <chengyou@linux.alibaba.com>
 *
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

#ifndef _ERDMA_VERBS_H
#define _ERDMA_VERBS_H

#include <linux/errno.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "erdma.h"
#include "erdma_cm.h"


extern int erdma_alloc_ucontext(struct ib_ucontext *ctx, struct ib_udata *data);
extern void erdma_dealloc_ucontext(struct ib_ucontext *ctx);
extern int erdma_query_port(struct ib_device *dev, __u8 port, struct ib_port_attr *attr);
extern int erdma_query_device(struct ib_device *dev, struct ib_device_attr *attr,
			      struct ib_udata *data);
extern int erdma_get_port_immutable(struct ib_device *dev, __u8 port,
				    struct ib_port_immutable *ib_port_immutable);
extern int erdma_create_cq(struct ib_cq *cq,
			   const struct ib_cq_init_attr *attr,
			   struct ib_udata *data);
extern int erdma_query_port(struct ib_device *dev, __u8 port, struct ib_port_attr *attr);
extern int erdma_query_pkey(struct ib_device *dev, __u8 port, __u16 idx, __u16 *pkey);
extern int erdma_query_gid(struct ib_device *dev, __u8 port, int idx, union ib_gid *gid);

extern int erdma_alloc_pd(struct ib_pd *pd, struct ib_udata *data);
extern int erdma_dealloc_pd(struct ib_pd *pd, struct ib_udata *data);

extern struct ib_qp *erdma_create_qp(struct ib_pd *pd, struct ib_qp_init_attr *attr,
				   struct ib_udata *data);
extern int erdma_query_qp(struct ib_qp *qp, struct ib_qp_attr *attr, int mask,
			struct ib_qp_init_attr *init_attr);
extern int erdma_modify_qp(struct ib_qp *qp, struct ib_qp_attr *attr, int mask,
			      struct ib_udata *data);
extern int erdma_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata);

extern int erdma_destroy_cq(struct ib_cq *cq, struct ib_udata *data);
extern int erdma_req_notify_cq(struct ib_cq *cq, enum ib_cq_notify_flags flags);
extern struct ib_mr *erdma_reg_user_mr(struct ib_pd *ibpd, __u64 start, __u64 len,
				__u64 rnic_va, int access, struct ib_udata *udata);
extern struct ib_mr *erdma_get_dma_mr(struct ib_pd *ibpd, int rights);
extern int erdma_dereg_mr(struct ib_mr *mr, struct ib_udata *data);

extern int erdma_mmap(struct ib_ucontext *ctx, struct vm_area_struct *vma);

extern int
erdma_post_send(struct ib_qp *qp,
		const struct ib_send_wr *send_wr,
		const struct ib_send_wr **bad_send_wr);
extern int
erdma_post_recv(struct ib_qp *qp,
		const struct ib_recv_wr *recv_wr,
		const struct ib_recv_wr **bad_recv_wr);
extern int erdma_poll_cq(struct ib_cq *cq, int num_entries, struct ib_wc *wc);

extern int erdma_modify_port(struct ib_device *ibdev, __u8 port, int mask,
			   struct ib_port_modify *props);

extern struct ib_mr *
erdma_ib_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type, u32 max_num_sg);

extern int erdma_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg,
				int sg_nents, unsigned int *sg_offset);
extern struct net_device *erdma_get_netdev(struct ib_device *device, u8 port_num);
extern void erdma_disassociate_ucontext(struct ib_ucontext *ibcontext);

#endif
