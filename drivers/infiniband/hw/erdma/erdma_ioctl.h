/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
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

#ifndef __EADM_IOCTL_H__
#define __EADM_IOCTL_H__

#include <linux/ioctl.h>
#include <linux/kernel.h>

#define EADM_DUMP_CMD        0x0
#define EADM_TEST_CMD        0x1
#define EADM_CTRL_CMD        0x2
#define EADM_STAT_CMD        0x3
#define EADM_INFO_CMD        0x4

#define ERDMA_DUMP_OPCODE_CQE 0
#define ERDMA_DUMP_OPCODE_SQE 1
#define ERDMA_DUMP_OPCODE_RQE 2
#define ERDMA_DUMP_OPCODE_EQE 3

#define ERDMA_TEST_CMDQ       0
#define ERDMA_TEST_SQ_DUMMY   1
#define ERDMA_TEST_CI         2

#define ERDMA_CTRL_GET_CMDSQ_CI    0
#define ERDMA_CTRL_SET_CMDSQ_CI    1
#define ERDMA_CTRL_GET_CMDSQ_PI    2
#define ERDMA_CTRL_SET_CMDSQ_PI    3
#define ERDMA_CTRL_GET_CMDCQ_CI    4
#define ERDMA_CTRL_SET_CMDCQ_CI    5
#define ERDMA_CTRL_GET_CMDCQ_OWNER 6
#define ERDMA_CTRL_SET_CMDCQ_OWNER 7

#define ERDMA_STAT_OPCODE_QP   0
#define ERDMA_STAT_OPCODE_CQ   1
#define ERDMA_STAT_OPCODE_DEV  2

#define ERDMA_INFO_OPCODE_DEV 0
#define ERDMA_INFO_OPCODE_QP  1

struct erdma_dev_info {
	__u32 devid;
	__u64 node_guid;
};

struct erdma_qp_info {
	__u32 qpn;
	__u32 qp_state;

	__u32 sip;
	__u32 dip;
	__u16 sport;
	__u16 dport;

	__u16 qtype; /* Client or Server. */
	__u16 origin_sport;
	__u16 sq_depth;
	__u16 rq_depth;

	__u32 remote_qpn;
};

struct erdma_ioctl_inbuf {
	__u32 opcode;
	__u32 qn;
	__u32 idx;
	__u32 data;
};

struct erdma_ioctl_outbuf {
	__u32 status;
	__u32 length;
	char data[256];
};

struct erdma_ioctl_msg {
	struct erdma_ioctl_inbuf in;
	struct erdma_ioctl_outbuf out;
};

#define ERDMA_IOC_MAGIC  'k'

#define ERDMA_DUMP           _IOWR(ERDMA_IOC_MAGIC, EADM_DUMP_CMD, struct erdma_ioctl_msg)
#define ERDMA_TEST           _IOWR(ERDMA_IOC_MAGIC, EADM_TEST_CMD, struct erdma_ioctl_msg)
#define ERDMA_CTRL           _IOWR(ERDMA_IOC_MAGIC, EADM_CTRL_CMD, struct erdma_ioctl_msg)
#define ERDMA_STAT           _IOWR(ERDMA_IOC_MAGIC, EADM_STAT_CMD, struct erdma_ioctl_msg)
#define ERDMA_INFO           _IOWR(ERDMA_IOC_MAGIC, EADM_INFO_CMD, struct erdma_ioctl_msg)

#define ERDMA_IOC_MAXNR 5

#ifdef __KERNEL__
long chardev_ioctl(struct file *filp,
		   unsigned int cmd, unsigned long arg);
long do_ioctl(void *edev, unsigned int cmd, unsigned long arg);
#else

#endif
int exec_ioctl_cmd(int cmd, struct erdma_ioctl_msg *msg);

#endif
