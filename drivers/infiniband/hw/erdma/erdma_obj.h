/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Software iWARP device driver for Linux
 *
 * Copyright (c) 2020-2021 Alibaba Group.
 * Copyright (c) 2008-2016, IBM Corporation
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *   Redistribution and use in source and binary forms, with or
 *   without modification, are permitted provided that the following
 *   conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of IBM nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
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

#ifndef _ERDMA_OBJ_H
#define _ERDMA_OBJ_H

#include <linux/idr.h>
#include <linux/rwsem.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/semaphore.h>

#include <rdma/ib_verbs.h>

#include "erdma.h"
#include "erdma_debug.h"

static inline void erdma_cq_get(struct erdma_cq *cq)
{
	kref_get(&cq->hdr.ref);
	dprint(DBG_OBJ, "(CQ%d): New refcount: %d\n",
		OBJ_ID(cq), kref_read(&cq->hdr.ref));
}
static inline void erdma_qp_get(struct erdma_qp *qp)
{
	kref_get(&qp->hdr.ref);
	dprint(DBG_OBJ, "(QP%d): New refcount: %d\n",
		OBJ_ID(qp), kref_read(&qp->hdr.ref));
}
static inline void erdma_pd_get(struct erdma_pd *pd)
{
	kref_get(&pd->hdr.ref);
	dprint(DBG_OBJ, "(PD%d): New refcount: %d\n",
		OBJ_ID(pd), kref_read(&pd->hdr.ref));
}
static inline void erdma_mem_get(struct erdma_mem *mem)
{
	kref_get(&mem->hdr.ref);
	dprint(DBG_OBJ|DBG_MM, "(MEM%d): New refcount: %d\n",
		OBJ_ID(mem), kref_read(&mem->hdr.ref));
}

extern void erdma_remove_obj(spinlock_t *lock, struct idr *idr,
				struct erdma_objhdr *hdr);

extern void erdma_objhdr_init(struct erdma_objhdr *dev);
extern void erdma_idr_init(struct erdma_dev *dev);
extern void erdma_idr_release(struct erdma_dev *dev);

extern struct erdma_cq *erdma_cq_id2obj(struct erdma_dev *dev, int cqn, int ref);
extern struct erdma_qp *erdma_qp_id2obj(struct erdma_dev *dev, int qpn);
extern struct erdma_mem *erdma_mem_id2obj(struct erdma_dev *dev, int mpt_idx);

extern int erdma_qp_add(struct erdma_dev *dev, struct erdma_qp *qp);
extern int erdma_cq_add(struct erdma_dev *dev, struct erdma_cq *cq);
extern int erdma_pd_add(struct erdma_dev *dev, struct erdma_pd *pd);
extern int erdma_mem_add(struct erdma_dev *dev, struct erdma_mem *mem);

extern void erdma_cq_put(struct erdma_cq *cq);
extern void erdma_qp_put(struct erdma_qp *qp);
extern void erdma_pd_put(struct erdma_pd *pd);
extern void erdma_mem_put(struct erdma_mem *mem);

#endif
