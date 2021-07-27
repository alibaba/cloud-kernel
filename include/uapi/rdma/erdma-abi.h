/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
/*
 * ElasticRDMA driver for Linux
 * Authors: Cheng You <chengyou@linux.alibaba.com>
 * Copyright (c) 2020 Alibaba Group.  All rights reserved.
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

#ifndef _ERDMA_USER_H
#define _ERDMA_USER_H

#include <linux/types.h>

/*
 * user commands/command responses must correlate with the erdma_abi
 * in user land.
 */
/*Common string that is matched to accept the device by the user library*/
#define ERDMA_NODE_DESC_COMMON "Elastic RDMA(iWARP) stack"

#define ERDMA_IBDEV_PREFIX "erdma_"

#define ERDMA_ABI_VERSION       1
#define VERSION_ID_ERDMA        2

#define ERDMA_MAX_SEND_SGE		6
#define ERDMA_MAX_RECV_SGE		1
#define ERDMA_MAX_UOBJ_KEY	0xfffffffe
#define ERDMA_INVAL_UOBJ_KEY	(ERDMA_MAX_UOBJ_KEY + 1)

struct erdma_uresp_create_cq {
	__u32 cq_id;
	__u32 num_cqe;
	__u64 cq_key;
	__u64 dbg_key;

	__u32 rsvd1;
};

struct erdma_uresp_create_qp {
	__u32 qp_id;
	__u32 num_sqe;
	__u32 num_rqe;
	__u32 pad;
	__aligned_u64 sq_key;
	__aligned_u64 rq_key;
	__aligned_u64 dbg_key; /* share memory between kernel and user space. */
};

struct erdma_ureq_reg_mr {
	__u8 stag_key;
	__u8 reserved[3];
	__u32 pad;
};

struct erdma_uresp_reg_mr {
	__u32 stag;
	__u32 pad;
};


#define ERDMA_SDB_PAGE     0
#define ERDMA_SDB_ENTRY    1
#define ERDMA_SDB_SHARED   2


struct erdma_uresp_alloc_ctx {
	__u32 dev_id;
	__u32 pad;
	__u32 sdb_type;
	__u32 sdb_offset;
	__u64 sdb;
	__u64 rdb;
	__u64 cdb;
};

enum erdma_opcode {
	ERDMA_OP_WRITE           = 0,
	ERDMA_OP_READ            = 1,
	ERDMA_OP_SEND            = 2,
	ERDMA_OP_SEND_WITH_IMM   = 3,

	ERDMA_OP_RECEIVE         = 4,
	ERDMA_OP_RECV_IMM        = 5,
	ERDMA_OP_RECV_INV        = 6,

	ERDMA_OP_REQ_ERR         = 7,
	ERDNA_OP_READ_RESPONSE   = 8,
	ERDMA_OP_WRITE_WITH_IMM  = 9,

	ERDMA_OP_RECV_ERR       = 10,

	ERDMA_OP_REG_MR        = 11,
	ERDMA_NUM_OPCODES        = 12,
	ERDMA_OP_INVALID         = ERDMA_NUM_OPCODES + 1
};

/* Keep it same as ibv_sge to allow for memcpy */

struct erdma_sge {
	__aligned_u64 laddr;
	__u32 length;
	__u32 lkey;
};

#define ERDMA_MAX_INLINE	(sizeof(struct erdma_sge) * ERDMA_MAX_SEND_SGE)

enum erdma_wqe_flags {
	ERDMA_WQE_VALID = 1,
	ERDMA_WQE_INLINE = (1 << 1),
	ERDMA_WQE_SIGNALLED = (1 << 2),
	ERDMA_WQE_SOLICITED = (1 << 3),
	ERDMA_WQE_READ_FENCE = (1 << 4),
	ERDMA_WQE_REM_INVAL = (1 << 5),
	ERDMA_WQE_COMPLETED = (1 << 6)
};

#define ERDMA_EQ_WQEBB_SIZE             16
#define ERDMA_SQ_WQEBB_SIZE             32
#define ERDMA_SQ_WQEBB_SIZE_SHIFT       5
#define ERDMA_MAX_SQE_SIZE              128
#define ERDMA_MAX_WQEBB_PER_SQE         4
#define ERDMA_MAX_RQE_SIZE              32


enum erdma_notify_flags {
	ERDMA_NOTIFY_NOT = (0),
	ERDMA_NOTIFY_SOLICITED = (1 << 0),
	ERDMA_NOTIFY_NEXT_COMPLETION = (1 << 1),
	ERDMA_NOTIFY_MISSED_EVENTS = (1 << 2),
	ERDMA_NOTIFY_ALL = ERDMA_NOTIFY_SOLICITED | ERDMA_NOTIFY_NEXT_COMPLETION |
			 ERDMA_NOTIFY_MISSED_EVENTS
};

enum erdma_wc_status {
	ERDMA_WC_SUCCESS = 0,
	ERDMA_WC_GENERAL_ERR = 1,
	ERDMA_WC_RECV_WQE_FORMAT_ERR = 2,
	ERDMA_WC_RECV_STAG_INVALID_ERR = 3,
	ERDMA_WC_RECV_ADDR_VIOLATION_ERR = 4,
	ERDMA_WC_RECV_RIGHT_VIOLATION_ERR = 5,
	ERDMA_WC_RECV_PDID_ERR = 6,
	ERDMA_WC_RECV_WARRPING_ERR = 7,
	ERDMA_WC_SEND_WQE_FORMAT_ERR = 8,
	ERDMA_WC_SEND_WQE_ORD_EXCEED = 9,
	ERDMA_WC_SEND_STAG_INVALID_ERR = 10,
	ERDMA_WC_SEND_ADDR_VIOLATION_ERR = 11,
	ERDMA_WC_SEND_RIGHT_VIOLATION_ERR = 12,
	ERDMA_WC_SEND_PDID_ERR = 13,
	ERDMA_WC_SEND_WARRPING_ERR = 14,
	ERDMA_WC_FLUSH_ERR = 15,
	ERDMA_WC_RETRY_EXC_ERR = 16,
	ERDMA_NUM_WC_STATUS
};

enum erdma_vendor_err {
	ERDMA_WC_VENDOR_NO_ERR = 0,
	ERDMA_WC_VENDOR_INVALID_RQE = 1,
	ERDMA_WC_VENDOR_RQE_INVALID_STAG = 2,
	ERDMA_WC_VENDOR_RQE_ADDR_VIOLATION = 3,
	ERDMA_WC_VENDOR_RQE_ACCESS_RIGHT_ERR = 4,
	ERDMA_WC_VENDOR_RQE_INVALID_PD = 5,
	ERDMA_WC_VENDOR_RQE_WRAP_ERR = 6,
	ERDMA_WC_VENDOR_INVALID_SQE = 0x20,
	ERDMA_WC_VENDOR_ZERO_ORD = 0x21,
	ERDMA_WC_VENDOR_SQE_INVALID_STAG = 0x30,
	ERDMA_WC_VENDOR_SQE_ADDR_VIOLATION = 0x31,
	ERDMA_WC_VENDOR_SQE_ACCESS_ERR = 0x32,
	ERDMA_WC_VENDOR_SQE_INVALID_PD = 0x33,
	ERDMA_WC_VENDOR_SQE_WARP_ERR = 0x34
};


/* CQ doorbell's DW0 */
#define CQDB_FIELD_ARM_OFFSET    31
#define CQDB_FIELD_CMDSN_OFFSET  28
#define CQDB_FIELD_CI_OFFSET     0
/* CQ doobell's DW1 */
#define CQDB_FIELD_EQN_OFFSET    24
#define CQDB_FIELD_CQN_OFFSET    0

#define CQDB_CMD_ARM     1
#define CQDB_CMD_NOARM   0

#define ERDMA_CQE_QTYPE_SQ    0
#define ERDMA_CQE_QTYPE_RQ    1
#define ERDMA_CQE_QTYPE_CMDQ  2

struct erdma_cqe_hdr {
	__u8      owner;
	__u8      opcode;
	__u8      qtype;
	__u8      syndrome;
};

struct erdma_cqe {
	__u8      owner;
	__u8      opcode;
	__u8      qtype;
	__u8      syndrome;

	__u32     qe_idx;
	__u32     qpn;
	__u32     imm_data;
	__u32     size;

	__u32     rsvd[3];
};

#endif
