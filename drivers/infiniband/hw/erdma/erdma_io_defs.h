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

#ifndef __ERDMA_IO_DEFS_H__
#define __ERDMA_IO_DEFS_H__

#include <linux/types.h>

#define ERDMA_SQ_WQEBB_SIZE		32
#define ERDMA_MAX_SQE_SIZE		128

#define ERDMA_CQE_QTYPE_SQ    0
#define ERDMA_CQE_QTYPE_RQ    1
#define ERDMA_CQE_QTYPE_CMDQ  2

/* Send Queue Element */
struct erdma_sqe_common_hdr {
	__u32 wqebb_idx:16,
		  ts_len:4,
		  rsvd0:2,
		  ce:1,
		  se:1,
		  fence:1,
		  is_inline:1,
		  dwqe:1,
		  opcode:5;

	__u32 qpn:20,
		  wqebb_cnt:3,
		  rsvd1:1,
		  sgl_len:8;
};

struct erdma_write_sqe {
	struct erdma_sqe_common_hdr hdr;
	__u32 imm_data;
	__u32 length;

	__u32 sink_stag;
	__u32 sink_to_low;
	__u32 sink_to_high;

	__u32 rsvd;

	struct erdma_sge sgl[0];
};

struct erdma_reg_mr_sqe {
	struct erdma_sqe_common_hdr hdr;
	__u64 addr;
	__u32 length;
	__u32 stag;
	__u64 reserved;
};

struct erdma_send_sqe {
	struct erdma_sqe_common_hdr hdr;
	__u32 imm_data;
	__u32 length;
	struct erdma_sge sgl[0];
};

struct erdma_readreq_sqe {
	struct erdma_sqe_common_hdr hdr;
	__u32 rsvd0;
	__u32 length;

	__u64 sink_to;
	__u32 sink_stag;

	__u32 src_stag; /* make aligned. */
	__u64 src_to;
};


/* Receive Queue Element */
struct erdma_rqe {
	__u32 qe_idx:16,
		  rsvd0:15,
		  dwqe:1;

	__u32 qpn:24,
		  rsvd1:8;

	__u32 rsvd2;
	__u32 rsvd3;

	__u64 to;

	__u32 length;
	__u32 stag;
};

#endif
