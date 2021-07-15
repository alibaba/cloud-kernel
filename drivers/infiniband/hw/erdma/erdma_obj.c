// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ElasticRDMA driver for Linux
 *
 * Authors: Cheng You <chengyou@linux.alibaba.com>
 *
 * Copyright (c) 2020-2021 Alibaba Group.
 * Copyright (c) 2008-2016, IBM Corporation
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
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <linux/pci.h>

#include <rdma/ib_umem.h>

#include "erdma.h"
#include "erdma_hw.h"
#include "erdma_debug.h"
#include "erdma_obj.h"
#include "erdma_cm.h"

static int qn_fast_reuse = 1;
module_param(qn_fast_reuse, int, 0644);
MODULE_PARM_DESC(qn_fast_reuse, "Fast reuse CQN/EQN enable.");


void erdma_idr_init(struct erdma_dev *edev)
{
	spin_lock_init(&edev->idr_lock);

	idr_init(&edev->qp_idr);
	idr_init(&edev->cq_idr);
	idr_init(&edev->pd_idr);
	idr_init(&edev->mem_idr);
}

void erdma_idr_release(struct erdma_dev *edev)
{
	idr_destroy(&edev->qp_idr);
	idr_destroy(&edev->cq_idr);
	idr_destroy(&edev->pd_idr);
	idr_destroy(&edev->mem_idr);
}

void erdma_objhdr_init(struct erdma_objhdr *hdr)
{
	kref_init(&hdr->ref);
}


static inline struct erdma_objhdr *erdma_get_obj(struct idr *idr, int id, int get_ref)
{
	struct erdma_objhdr *obj;

	obj = idr_find(idr, id);
	if (obj && get_ref)
		kref_get(&obj->ref);

	return obj;
}

static inline int erdma_add_obj(spinlock_t *lock, struct idr *idr,
				struct erdma_objhdr *obj, int prefer_id, int max_id)
{
	unsigned long flags;
	int id, try_next = 0;

	if (prefer_id >= max_id) {
		prefer_id = 1;
		dprint(DBG_OBJ, "ID alloc goto next round %u to 1.\n", prefer_id);
	}

try_twice:
	dprint(DBG_OBJ, "alloc idr between 0x%x and 0x%x.\n", prefer_id, max_id);

	spin_lock_irqsave(lock, flags);
	id = idr_alloc(idr, obj, prefer_id, max_id, GFP_KERNEL);
	spin_unlock_irqrestore(lock, flags);

	if (id >= 0) {
		erdma_objhdr_init(obj);
		obj->id = id;
		dprint(DBG_OBJ, "(OBJ%d): IDR New Object\n", id);
	} else {
		dprint(DBG_OBJ|DBG_ON, "(OBJ??): IDR New Object failed!\n");
		if (!try_next && prefer_id != 1) {
			prefer_id = 1;
			try_next = 1;
			goto try_twice;
		}
	}

	return id >= 0 ? 0 : id;
}

void erdma_remove_obj(spinlock_t *lock, struct idr *idr,
		      struct erdma_objhdr *hdr)
{
	unsigned long flags;

	dprint(DBG_OBJ, "(OBJ%d): IDR Remove Object\n", hdr->id);

	spin_lock_irqsave(lock, flags);
	idr_remove(idr, hdr->id);
	spin_unlock_irqrestore(lock, flags);
}

int erdma_pd_add(struct erdma_dev *edev, struct erdma_pd *pd)
{
	int rv = erdma_add_obj(&edev->idr_lock, &edev->pd_idr, &pd->hdr, 1, ERDMA_MAX_PD);

	if (!rv) {
		dprint(DBG_OBJ, "(PD%d): New Object\n", pd->hdr.id);
		pd->hdr.edev = edev;
	}

	return rv;
}

int erdma_qp_add(struct erdma_dev *edev, struct erdma_qp *qp)
{
	int rv;

	rv = erdma_add_obj(&edev->idr_lock, &edev->qp_idr, &qp->hdr,
		qn_fast_reuse ? 1 : edev->next_alloc_qpn, edev->attrs.max_qp);
	if (!rv) {
		dprint(DBG_OBJ, "(QP%d): New Object\n", QP_ID(qp));
		qp->hdr.edev = edev;
		edev->next_alloc_qpn = QP_ID(qp) + 1;
	}
	return rv;
}

static void erdma_free_pd(struct kref *ref)
{
	struct erdma_pd	*pd =
		container_of(container_of(ref, struct erdma_objhdr, ref),
			     struct erdma_pd, hdr);

	dprint(DBG_OBJ, "(PD%d): Free Object\n", pd->hdr.id);

	atomic_dec(&pd->hdr.edev->num_pd);
}

void erdma_pd_put(struct erdma_pd *pd)
{
	kref_put(&pd->hdr.ref, erdma_free_pd);
}


static void erdma_free_qp(struct kref *ref)
{
	struct erdma_qp	*qp =
		container_of(container_of(ref, struct erdma_objhdr, ref),
			     struct erdma_qp, hdr);
	struct erdma_dev	*edev = qp->hdr.edev;
	unsigned long flags;

	dprint(DBG_OBJ|DBG_CM, "(QP%d): Free Object\n", QP_ID(qp));

	if (qp->cep)
		erdma_cep_put(qp->cep);

	erdma_remove_obj(&edev->idr_lock, &edev->qp_idr, &qp->hdr);

	spin_lock_irqsave(&edev->idr_lock, flags);
	list_del(&qp->devq);
	spin_unlock_irqrestore(&edev->idr_lock, flags);

#ifdef ERDMA_ENABLE_DEBUG
	if (qp->snapshot)
		free_pages_exact(qp->snapshot, 4096);
#endif
	atomic_dec(&edev->num_qp);
	kfree(qp);
}

void erdma_qp_put(struct erdma_qp *qp)
{
	dprint(DBG_OBJ, "(QP%d): Old refcount: %d\n",
		QP_ID(qp), kref_read(&qp->hdr.ref));
	kref_put(&qp->hdr.ref, erdma_free_qp);
}

struct erdma_qp *erdma_qp_id2obj(struct erdma_dev *edev, int id)
{
	struct erdma_objhdr *obj = erdma_get_obj(&edev->qp_idr, id, 1);

	if (obj)
		return container_of(obj, struct erdma_qp, hdr);

	return NULL;
}


int erdma_cq_add(struct erdma_dev *edev, struct erdma_cq *cq)
{
	int rv;

	rv = erdma_add_obj(&edev->idr_lock, &edev->cq_idr, &cq->hdr,
		qn_fast_reuse ? 1 : edev->next_alloc_cqn, edev->attrs.max_cq);
	if (!rv) {
		dprint(DBG_OBJ, "(CQ%d): New Object\n", cq->hdr.id);
		cq->hdr.edev = edev;
		edev->next_alloc_cqn = CQ_ID(cq) + 1;
	}

	return rv;
}

static void erdma_free_cq(struct kref *ref)
{
	struct erdma_cq *cq =
		(container_of(container_of(ref, struct erdma_objhdr, ref),
			      struct erdma_cq, hdr));

	dprint(DBG_OBJ, "(CQN%d): Free Object\n", cq->hdr.id);

	atomic_dec(&cq->hdr.edev->num_cq);
	if (cq->queue)
		dma_free_coherent(&cq->hdr.edev->pdev->dev,
			cq->depth * sizeof(struct erdma_cqe), cq->queue, cq->qbuf_dma_addr);
#ifdef ERDMA_ENABLE_DEBUG
	if (cq->snapshot)
		free_pages_exact(cq->snapshot, 4096);
#endif
}

void erdma_cq_put(struct erdma_cq *cq)
{
	dprint(DBG_OBJ, "(CQ%d): Old refcount: %d\n",
		OBJ_ID(cq), kref_read(&cq->hdr.ref));
	kref_put(&cq->hdr.ref, erdma_free_cq);
}

/* ref: increase the ref or not. */
struct erdma_cq *erdma_cq_id2obj(struct erdma_dev *edev, int id, int ref)
{
	struct erdma_objhdr *obj = erdma_get_obj(&edev->cq_idr, id, ref);

	if (obj)
		return container_of(obj, struct erdma_cq, hdr);

	return NULL;
}

/*
 * Stag lookup is based on its index part only (24 bits).
 * The code avoids special Stag of zero and tries to randomize
 * STag values between 1 and ERDMA_STAG_MAX.
 */
int erdma_mem_add(struct erdma_dev *edev, struct erdma_mem *m)
{
	unsigned long flags;
	int id;

	spin_lock_irqsave(&edev->idr_lock, flags);
	/* avoid zero stag. */
	id = idr_alloc(&edev->mem_idr, m, 1, edev->attrs.max_mr, GFP_KERNEL);
	spin_unlock_irqrestore(&edev->idr_lock, flags);

	if (id == -ENOSPC || id > ERDMA_STAG_MAX) {
		dprint(DBG_OBJ|DBG_MM|DBG_ON,
			"(MPT): New Object failed, max_mr = %d, id = %d.\n",
			edev->attrs.max_mr, id);
		return -ENOSPC;
	}

	erdma_objhdr_init(&m->hdr);
	m->hdr.id = id;
	m->hdr.edev = edev;

	return 0;
}

static void erdma_free_mem(struct kref *ref)
{
	struct erdma_mem *m;
	struct erdma_mw *mw;
	struct erdma_mr *mr;

	m = container_of(container_of(ref, struct erdma_objhdr, ref),
			 struct erdma_mem, hdr);

	dprint(DBG_MM|DBG_OBJ, "(MEM%d): Free Object\n", OBJ_ID(m));

	atomic_dec(&m->hdr.edev->num_mem);

	if (ERDMA_MEM_IS_MW(m)) {
		/* Now we not support memory window. */
		dprint(DBG_MM, "not support memory window.\n");
		mw = container_of(m, struct erdma_mw, mem);
	} else {
		mr = container_of(m, struct erdma_mr, mem);
		dprint(DBG_MM|DBG_OBJ, "(MEM%d): Release UMem\n", OBJ_ID(m));
		if (mr->umem)
			ib_umem_release(mr->umem);
	}
}


void erdma_mem_put(struct erdma_mem *m)
{
	dprint(DBG_MM|DBG_OBJ, "(MEM%d): Old refcount: %d\n",
		OBJ_ID(m), kref_read(&m->hdr.ref));
	kref_put(&m->hdr.ref, erdma_free_mem);
}
