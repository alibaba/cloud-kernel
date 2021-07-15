/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
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

#ifndef __RDMA_WQES_DEFS_H__
#define __RDMA_WQES_DEFS_H__

#define SIZE_OF_TYPE_EQUAL_TO(type, size) \
static inline char size_of_##type##_equal_to_##size(void) \
{ \
	char __dummy1[sizeof(struct type) - size]; \
	char __dummy2[size - sizeof(struct type)]; \
	return __dummy1[-1] + __dummy2[-1]; \
}

enum CMDQ_RDMA_OPCODE {
	CMDQ_OPCODE_QUERY_DEVICE = 0,
	CMDQ_OPCODE_CREATE_QP    = 1,
	CMDQ_OPCODE_DESTROY_QP   = 2,
	CMDQ_OPCODE_MODIFY_QP    = 3,
	CMDQ_OPCODE_CREATE_CQ    = 4,
	CMDQ_OPCODE_DESTROY_CQ   = 5,
	CMDQ_OPCODE_REG_MR       = 8,
	CMDQ_OPCODE_DEREG_MR     = 9
};

enum CMDQ_COMMON_OPCODE {
	CMDQ_OPCODE_CREATE_EQ  = 0,
	CMDQ_OPCODE_DESTROY_EQ = 1
};

enum CMDQ_WQE_SUB_MOD {
	CMDQ_SUBMOD_RDMA    = 0,
	CMDQ_SUBMOD_COMMON  = 1
};

struct erdma_cmdq_wqe_hdr {
	__u32 wqebb_idx:16,  /* wqebb index in the ring buffer. */
	      opcode:8,      /* opcode of this command. */
	      sub_mod:2,     /* opcode belongs to. */
	      dwqe:1,       /* RSVD. */
	      owner:5;       /* owner */

	__u32 rsvd1:20,
	      wqebb_cnt:3,
	      rsvd:9;
};

/* CMDQ wqe definitions. */
struct erdma_cmdq_sq_entry {
	union {
		struct erdma_cmdq_wqe_hdr fields;
		__u32 value[2];
	} hdr;

	union {
		__u8 raw_data[56];
	} req;
};

SIZE_OF_TYPE_EQUAL_TO(erdma_cmdq_sq_entry, 64);


struct erdma_cmdq_cqe_hdr {
	__u32 syndrome:8,
	      qtype:8,
	      opcode:8,
	      rsvd0:7,
	      owner:1;

	__u32 qe_idx:16,
	      rsvd1:16;
};

struct erdma_cmdq_cq_entry {
	union {
		struct erdma_cmdq_cqe_hdr fields;
		__u32 value[2];
	} hdr;

	__u32   qpn:24,
		rsvd0:8;

	__u32   size;
	__u8    rsvd1[16];
};
SIZE_OF_TYPE_EQUAL_TO(erdma_cmdq_cq_entry, 32);

struct erdma_ceq_entry {
	__u32   cqn:20,
		rsvd0:7,
		owner:1;

	__u32   pi:24,
		rsvd1:7,
		from_db:1;

	__u32   rsvd2[2];
};
SIZE_OF_TYPE_EQUAL_TO(erdma_ceq_entry, 16);

struct erdma_aeq_entry {
	__u32   sub_type:8,
		rsvd0:8,
		event_type:8,
		rsvd1:7,
		owner:1;

	__u32   event_data0;
	__u32   event_data1;

	__u32   rsvd2;
};
SIZE_OF_TYPE_EQUAL_TO(erdma_aeq_entry, 16);

struct erdma_cmdq_create_qp_req {
	union {
		struct erdma_cmdq_wqe_hdr fields;
		__u32 value[2];
	} hdr;

	__u32 qpn:20,
	      sq_depth:12;

	__u32 pd:20,
	      rq_depth:12;

	__u32 scqn:20,
	      rsvd0:12;

	__u32 rcqn:20,
	      rsvd1:12;

	__u64 sq_buf_addr;
	__u64 rq_buf_addr;

	__u64 sq_ci_addr;
};

struct erdma_cmdq_destroy_qp_req {
	union {
		struct erdma_cmdq_wqe_hdr fields;
		__u32 value[2];
	} hdr;

	__u32 qpn:20,
	      sq_depth:12;

	__u32 pd:20,
	      rq_depth:12;
};

struct erdma_cmdq_modify_qp_req {
	union {
		struct erdma_cmdq_wqe_hdr fields;
		__u32 value[2];
	} hdr;

	__u32 qpn:20,
	      ts_ok:1,
	      rsvd:3,
	      state:8;

	__u32 remote_qpn;

	__u32 dip;
	__u32 sip;
	__u32 sport:16,
	      dport:16;

	__u32 send_nxt;
	__u32 recv_nxt;

	__u32 ts_val;
	__u32 ts_ecr;
};

struct erdma_cmdq_query_device_resp {
	union {
		struct erdma_cmdq_cqe_hdr fields;
		__u32 value[2];
	} hdr;

	/* DW2 */
	__u8 max_mr_size;
	__u8 max_qp;
	__u8 max_qp_wr;
	__u8 max_sge;

	/* DW3. */
	__u8 max_cq;
	__u8 max_cqe;
	__u8 max_mr;
	__u8 max_pd;

	/* DW4 */
	__u8 max_mw;
	__u8 max_fmr;
	__u16 max_qblk;

	__u32 local_dma_key;
	/* DW5~DW7 */
	__u32 rsvd[2];
};
SIZE_OF_TYPE_EQUAL_TO(erdma_cmdq_query_device_resp, 32);

struct erdma_cmdq_reg_mr_req {
	union {
		struct erdma_cmdq_wqe_hdr fields;
		__u32 value[2];
	} hdr;

	__u32 mpt_idx:20,
	      key:8,
	      page_size:3,
	      valid:1;

	__u32 access_mode:2,
	      access_right:4,
	      type:2,
	      rsvd0:4,
	      pd:20;

	__u64 start_va;

	__u32 size;

	__u32 mtt_cnt:20,
	      mtt_type:2,
	      rsvd1:10;

	__u64 phy_addr[0];
};

struct erdma_cmdq_dereg_mr_req {
	union {
		struct erdma_cmdq_wqe_hdr fields;
		__u32 value[2];
	} hdr;

	__u32 mpt_idx:20,
	      key:8,
	      rsvd0:4;

	__u32 access_mode:2,
	      rsvd1:4,
	      type:2,
	      rsvd2:4,
	      pd:20;
};

#pragma pack(push)
#pragma pack(1)
struct erdma_cmdq_create_cq_req {
	union {
		struct erdma_cmdq_wqe_hdr fields;
		__u32 value[2];
	} hdr;

	__u32 cqn:20,
	      rsvd0:4,
	      cq_depth:8;

	__u64 cq_buf_addr;

	__u32 eqn:10,
	      rsvd2:22;
};
#pragma pack(pop)

struct erdma_cmdq_destroy_cq_req {
	union {
		struct erdma_cmdq_wqe_hdr fields;
		__u32 value[2];
	} hdr;

	__u32 cqn:20,
	      rsvd0:12;
};

struct erdma_cmdq_create_eq_req {
	union {
		struct erdma_cmdq_wqe_hdr fields;
		__u32 value[2];
	} hdr;

	__u64 qbuf_addr;

	__u8  vector_idx;
	__u8  eqn;
	__u8  depth;
	__u8  qtype;
};

struct erdma_cmdq_destroy_eq_req {
	union {
		struct erdma_cmdq_wqe_hdr fields;
		__u32 value[2];
	} hdr;

	__u64 rsvd0;

	__u8  vector_idx;
	__u8  eqn;
	__u8  rsvd1;
	__u8  qtype;
};

#define ERDMA_CMDQ_CQE_STATUS_SUCCESS 0

#endif

