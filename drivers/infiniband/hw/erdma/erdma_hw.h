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

#ifndef __ERDMA_IO_H__
#define __ERDMA_IO_H__

#include <linux/kernel.h>
#include <linux/types.h>
#include "erdma.h"

/* PCIe Configuration Space definition. */
#define ERDMA_VENDOR_ID 0x1ded
#define ERDMA_DEVICE_ID 0x107f

#define ERDMA_SRIOV_PF_ID 0x5007

#define ERDMA_FUNC_BAR   0
#define ERDMA_MISX_BAR   2

#define ERDMA_BAR_MASK (BIT(ERDMA_FUNC_BAR) | BIT(ERDMA_MISX_BAR))

/* MSI-X related. */
#define ERDMA_NUM_MSIX_VEC      32
#define ERDMA_MSIX_VECTOR_CMDQ  0

/* Db page allocation. */
#define ERDMA_SDB_NPAGE            64
#define ERDMA_SQB_NENTRY           496

#define ERDMA_SDB_NENTRY_PER_PAGE  16
#define ERDMA_SDB_ENTRY_SIZE       256

/* total npages: 384KB / PAGE_SIZE = 96, the last page used for shared db */
#define ERDMA_SDB_SHARED_PAGE      95

/* iWarp Capbility. */
#define ERDMA_MAX_QP                (128 * 1024)
#define ERDMA_MAX_QP_WR             (1024 * 16)
#define ERDMA_MAX_ORD               128             /* not used now. */
#define ERDMA_MAX_IRD               128             /* not used now. */
#define ERDMA_MAX_SGE_RD            1	            /* iwarp limitation. we could relax */
#define ERDMA_MAX_CQ                (1024 * 256)
#define ERDMA_MAX_CQE               (ERDMA_MAX_QP_WR * 100)
#define ERDMA_MAX_MR                (ERDMA_MAX_QP * 10)
#define ERDMA_MAX_MR_SIZE           (2U * 1024 * 1024 * 1024) /* 2GBytes */
#define ERDMA_MAX_PD                ERDMA_MAX_QP
#define ERDMA_MAX_MW                0               /* to be set if MW's are supported */
#define ERDMA_MAX_FMR               0
#define ERDMA_MAX_SRQ               0               /* not support srq. */
#define ERDMA_MAX_SRQ_WR            0               /* not support srq. */
#define ERDMA_MAX_SRQ_SGE           0               /* not support srq. */
#define ERDMA_MAX_CONTEXT           ERDMA_MAX_PD

#define ERDMA_SQEBB_SIZE            32
#define ERDMA_RQEBB_SIZE            32
#define ERDMA_CQEBB_SIZE            32

#define ERDMA_SQE_64B_WQEBB_CNT     1

/* CMDQ related. */
/* one cmdq wqe is 256Byte, POC support 64Byte * 1024, so the cmdq depth is 256. */
#define ERDMA_CMDQ_DEPTH            256
#define ERDMA_DEFAULT_EQ_DEPTH      256

#endif
