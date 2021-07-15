// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Software iWARP device driver for Linux
 *
 * Copyright (c) 2020-2021 Alibaba Group.
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

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/pci.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>

#include "erdma.h"
#include "erdma_ae.h"
#include "erdma_cm.h"
#include "erdma_hw.h"
#include "erdma_obj.h"
#include "erdma_regs_defs.h"

void erdma_qp_event(struct erdma_qp *qp, enum ib_event_type etype)
{
	struct ib_event event;
	struct ib_qp	*ibqp = &qp->ibqp;

	event.event = etype;
	event.device = ibqp->device;
	event.element.qp = ibqp;

	if (ibqp->event_handler)
		(*ibqp->event_handler)(&event, ibqp->qp_context);
}

static int erdma_poll_aeq_event(struct erdma_eq *aeq, void *out)
{
	struct erdma_aeq_entry   *aeqe;
	__u16                    queue_size_mask = aeq->depth - 1;
	__u32                    val;

	aeqe = (struct erdma_aeq_entry *)aeq->qbuf + (aeq->ci & queue_size_mask);

	/* Go over all the completions */
	val = READ_ONCE(*(__u32 *)aeqe);
	if (((val & 0x80000000) >> 31) == aeq->owner) {
		aeq->ci++;

		if ((aeq->ci & queue_size_mask) == 0)
			aeq->owner = !aeq->owner;

		atomic64_add(1, &aeq->event_num);
		if (out)
			memcpy(out, aeqe, sizeof(struct erdma_aeq_entry));

		return 1;
	}

	return 0;
}

void erdma_aeq_event_handler(struct erdma_dev *edev)
{
	struct erdma_aeq_entry aeqe;
	__u32                  cqn, qpn;
	struct erdma_qp        *qp;
	struct erdma_cq        *cq;

	while (erdma_poll_aeq_event(&edev->aeq.eq, &aeqe)) {
		if (aeqe.event_type == ERDMA_AE_CQ_ERR) {
			cqn = aeqe.event_data0;
			cq = erdma_cq_id2obj(edev, cqn, 0);
			if (!cq)
				continue;
		} else {
			qpn = aeqe.event_data0;
			qp = erdma_qp_id2obj(edev, qpn);
			if (!qp)
				continue;

			erdma_qp_put(qp);
		}
	}

	notify_eq(&edev->aeq.eq);
}

int erdma_aeq_init(struct erdma_dev *dev)
{
	struct erdma_eq *eq      = &dev->aeq.eq;
	__u32           buf_size = ERDMA_DEFAULT_EQ_DEPTH * sizeof(struct erdma_ceq_entry);

	eq->qbuf = dma_alloc_coherent(&dev->pdev->dev, buf_size, &eq->dma_addr, GFP_KERNEL);
	if (!eq->qbuf)
		return -ENOMEM;

	memset(eq->qbuf, 0, buf_size);

	spin_lock_init(&eq->lock);
	atomic64_set(&eq->event_num, 0);
	atomic64_set(&eq->notify_num, 0);

	eq->depth = ERDMA_DEFAULT_EQ_DEPTH;
	eq->db_addr = (__u64 __iomem *)(dev->func_bar + ERDMA_REGS_AEQ_DB_REG);
	eq->ci = 0;

	eq->owner = 1;
	dev->aeq.dev = dev;

	dev->aeq.ready = 1;

	erdma_reg_write32(dev, ERDMA_REGS_AEQ_ADDR_H_REG, (eq->dma_addr >> 32) & 0xFFFFFFFF);
	erdma_reg_write32(dev, ERDMA_REGS_AEQ_ADDR_L_REG, eq->dma_addr & 0xFFFFFFFF);
	erdma_reg_write32(dev, ERDMA_REGS_AEQ_DEPTH_REG, eq->depth);

	return 0;
}

void erdma_aeq_destroy(struct erdma_dev *dev)
{
	struct erdma_eq *eq       = &dev->aeq.eq;
	__u32           buf_size  = ERDMA_DEFAULT_EQ_DEPTH * sizeof(struct erdma_ceq_entry);

	dev->aeq.ready = 0;

	dma_free_coherent(&dev->pdev->dev, buf_size, eq->qbuf, eq->dma_addr);
}
