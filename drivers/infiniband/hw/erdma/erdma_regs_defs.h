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

#ifndef __ERDMA_REGS_DEFS_H__
#define __ERMDA_REGS_DEFS_H__

#include "erdma_hw.h"

/* erdma PCIe BAR0 regs definition. */
#define ERDMA_REGS_VERSION_REG      0x0

#define ERDMA_REGS_DEV_CTRL_REG             0x10
#define ERDMA_REGS_DEV_ST_REG               0x14
#define ERDMA_REGS_NETDEV_MAC_L_REG         0x18
#define ERDMA_REGS_NETDEV_MAC_H_REG         0x1C

#define ERDMA_REGS_CMDQ_SQ_ADDR_L_REG       0x20
#define ERDMA_REGS_CMDQ_SQ_ADDR_H_REG       0x24
#define ERDMA_REGS_CMDQ_CQ_ADDR_L_REG       0x28
#define ERDMA_REGS_CMDQ_CQ_ADDR_H_REG       0x2C

#define ERDMA_REGS_CMDQ_DEPTH_REG           0x30

#define ERDMA_REGS_CMDQ_EQ_DEPTH_REG        0x34
#define ERDMA_REGS_CMDQ_EQ_ADDR_L_REG       0x38
#define ERDMA_REGS_CMDQ_EQ_ADDR_H_REG       0x3C

#define ERDMA_REGS_AEQ_ADDR_L_REG           0x40
#define ERDMA_REGS_AEQ_ADDR_H_REG           0x44
#define ERDMA_REGS_AEQ_DEPTH_REG            0x48

#define ERDMA_REGS_GRP_NUM_REG              0x4c

#define ERDMA_REGS_AEQ_DB_REG               0x50
#define ERDMA_QBLK_NUM_REG                  0x58

#define ERDMA_CMDQ_SQ_DB_HOST_ADDR		0x60
#define ERDMA_CMDQ_CQ_DB_HOST_ADDR		0x68
#define ERDMA_CMDQ_EQ_DB_HOST_ADDR		0x70
#define ERDMA_AEQ_DB_HOST_ADDR			0x78

#define ERDMA_REGS_RES_CNT_REG              0x5c

#define ERDMA_REGS_CEQ_DB_BASE_REG          0x100

/* dev ctrl reg details. */
#define ERDMA_REG_DEV_CTRL_RESET_MASK       0x00000001 /* start reset device. bit[0] */
#define ERDMA_REG_DEV_CTRL_INIT_MASK        0x00000002
/* reset type, now we only support normal reset, bit[3:1] */

/* dev status reg details. */
/* when start reset, the value should be set to 0 if reset not done. */
#define ERDMA_REG_DEV_ST_RESET_DONE_MASK    0x00000001U
#define ERDMA_REG_DEV_ST_INIT_DONE_MASK     0x00000002U /*  */
#define ERDMA_REG_DEV_ST_SUSPEND_MASK       0x00000004U

/* erdma PCIe BAR0 regs definition. */
#define ERDMA_DBS_CMDQ_DB_BASE      0x0

/* erdma PCIe DirectWQE bar definition. */
/* in 20201130 version, DWQE and normal doorbell is all in BAR1. */

#define ERDMA_BAR_TRUNK_SIZE             1024
#define ERDMA_SQDB_SIZE                  (ERDMA_SQEBB_SIZE * 4)
#define ERDMA_RQDB_SIZE                  ERDMA_RQEBB_SIZE
#define ERDMA_CQDB_SIZE                  8

/* direct wqe doorbell base is offset = 4K */
#define ERDMA_BAR_DB_SPACE_BASE            4096

/* max wqe size is 128Byte. 1130 version only support 64Byte and 128Byte WQEs. */

#define ERDMA_512K_BAR
#ifdef ERDMA_512K_BAR
#define ERDMA_BAR_CMDQ_SQDB_OFFSET 0x200
#define ERDMA_BAR_CMDQ_CQDB_OFFSET 0x300

#define ERDMA_BAR_SQDB_SPACE_OFFSET (ERDMA_BAR_DB_SPACE_BASE)
#define ERDMA_BAR_RQDB_SPACE_OFFSET (384 * 1024)
#define ERDMA_BAR_CQDB_SPACE_OFFSET (ERDMA_BAR_RQDB_SPACE_OFFSET + 96 * 1024)

#else
#define ERDMA_BAR_CMDQ_SQDB_OFFSET ERDMA_BAR_DB_SPACE_BASE
#define ERDMA_BAR_CMDQ_CQDB_OFFSET (ERDMA_BAR_DB_SPACE_BASE + ERDMA_BAR_CQDB_SPACE_OFFSET)

#define ERDMA_BAR_SQDB_SPACE_OFFSET (ERDMA_BAR_DB_SPACE_BASE)
#define ERDMA_BAR_RQDB_SPACE_OFFSET (ERDMA_SQDB_SIZE * ERDMA_BAR_TRUNK_SIZE)
#define ERDMA_BAR_CQDB_SPACE_OFFSET (ERDMA_BAR_TRUNK_SIZE * (ERDMA_SQDB_SIZE + ERDMA_RQDB_SIZE))

#endif

/*  */
#define ERDMA_RQDB_SIZE                  ERDMA_RQEBB_SIZE

#endif
