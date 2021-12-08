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

#ifndef __ERDMA_COMMAND_H__
#define __ERDMA_COMMAND_H__

#include <linux/kernel.h>
#include <rdma/ib_umem.h>

struct erdma_create_qp_params {
	__u32 pd;
	__u32 qpn;

	__u64 sq_buf_addr;
	__u64 rq_buf_addr;

	__u16 sq_depth;
	__u16 rq_depth;

	__u32 scqn;
	__u32 rcqn;

	__u64 sq_db_dma_addr;
	__u64 rq_db_dma_addr;
};

int erdma_exec_create_qp_cmd(struct erdma_dev *dev,
			     struct erdma_create_qp_params *params);

struct erdma_modify_qp_params {
	__u8   state;
	__u8   ts_enable;

	__u32  qpn;
	__u32  remote_qpn;
	__u32  dip;
	__u32  sip;
	__u16  dport;
	__u16  sport;
	__u32  snd_nxt;
	__u32  rcv_nxt;

	__u32  ts_val;
	__u32  ts_ecr;

	__u8 cc_method;
};

int erdma_exec_modify_qp_cmd(struct erdma_dev *dev,
			     struct erdma_modify_qp_params *params);


struct erdma_dereg_mr_params {
	__u32 l_key;
};

int erdma_exec_dereg_mr_cmd(struct erdma_dev *dev,
			struct erdma_dereg_mr_params *params);

struct erdma_reg_mr_params {
	__u32 stag; /* mpt_idx + key */
	__u8 page_size; /* 0-4K, 1-2M */
	__u8 valid;   /*  */
	__u8 access; /* access right. */
	__u8 rsvd;
	__u32 pd_id;
	__u64 start_va;
	__u32 len;
	struct erdma_mr *mr;
};

int erdma_exec_reg_mr_cmd(struct erdma_dev *dev,
			  struct erdma_reg_mr_params *params);

extern int
erdma_exec_alloc_mr_cmd(struct erdma_dev *dev, struct erdma_reg_mr_params *params);

struct erdma_create_cq_params {
	__u32 cqn;
	__u32 depth;
	__u64 queue_addr;
	__u32 eqn;
	__u32 page_size;
	__u64 *mtt_entry;
	__u32 mtt_cnt;
	__u32 mtt_type;
	__u64 host_db_dma_addr;
	__u32 first_page_offset;
};

int erdma_exec_create_cq_cmd(struct erdma_dev *dev,
			     struct erdma_create_cq_params *params);

struct erdma_destroy_cq_params {
	__u32 cqn;
};

int erdma_exec_destroy_cq_cmd(struct erdma_dev *dev,
			      struct erdma_destroy_cq_params *params);

struct erdma_destroy_qp_params {
	__u32 qpn;
};

int erdma_exec_destroy_qp_cmd(struct erdma_dev *dev,
			      struct erdma_destroy_qp_params *params);

struct erdma_query_device_result {
	__u8 max_send_sge;
	__u8 max_recv_sge;
	__u32 max_recv_wr;
	__u32 max_send_wr;
	__u32 max_qp;
	__u32 max_mr_size;
	__u32 max_mr;
	__u32 max_cqe;
	__u32 max_cq;
	__u32 max_fmr;
	__u32 max_mw;
	__u32 local_dma_key;
	__u8 default_cc;
};

int erdma_exec_query_device_cmd(struct erdma_dev *dev,
				struct erdma_query_device_result *result);

struct erdma_create_eq_params {
	__u16 eqn;
	__u16 vector_idx;
	__u32 depth;
	__u64 queue_addr;
	__u64 db_dma_addr;
};

#define ERDMA_CMD_EQTYPE_AEQ 0
#define ERDMA_CMD_EQTYPE_CEQ 1

int erdma_exec_create_eq_cmd(struct erdma_dev *dev,
			     struct erdma_create_eq_params *params,
			     __u8 eq_type);

struct erdma_destroy_eq_params {
	__u16 eqn;
	__u16 vector_idx;
};

int erdma_exec_destroy_eq_cmd(struct erdma_dev *dev,
			      struct erdma_destroy_eq_params *params,
			      __u8 eq_type);


#endif
