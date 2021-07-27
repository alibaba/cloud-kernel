// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * ElasticRDMA driver for Linux
 * Authors: Cheng You <chengyou@linux.alibaba.com>
 *			Kai Shen <KaiShen@linux.alibaba.com>
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

#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/uverbs_ioctl.h>

#include "erdma.h"
#include "erdma_debug.h"
#include "erdma_verbs.h"
#include "erdma_hw.h"
#include "erdma_regs_defs.h"
#include "erdma_obj.h"
#include "erdma_common.h"
#include "erdma_command.h"
#include "erdma_cm.h"
#include "erdma_io_defs.h"

enum {
	ERDMA_MMAP_DMA_PAGE = 0, /* dma queue buffer. */
	ERDMA_MMAP_IO_WC,        /* cacheble */
	ERDMA_MMAP_IO_NC,        /* no cache */
	ERDMA_MMAP_DBG_PAGE
};

static __u32
erdma_insert_uobj(struct erdma_ucontext *uctx, void *vaddr, __u32 size, __u32 mmap_type)
{
	struct erdma_uobj   *uobj;
	__u32               key    = ERDMA_INVAL_UOBJ_KEY;

	uobj = kzalloc(sizeof(*uobj), GFP_KERNEL);
	if (!uobj)
		goto out;

	size = PAGE_ALIGN(size);
	uobj->size = size;
	uobj->type = mmap_type;
	uobj->addr = vaddr;

	spin_lock(&uctx->uobj_lock);

	if (list_empty(&uctx->uobj_list))
		uctx->uobj_key = 0;

	key = uctx->uobj_key;

	uobj->key = uctx->uobj_key;
	uctx->uobj_key += size; /* advance for next object */

	if (key > ERDMA_MAX_UOBJ_KEY) {
		uctx->uobj_key -= size;
		spin_unlock(&uctx->uobj_lock);
		key = ERDMA_INVAL_UOBJ_KEY;
		kfree(uobj);
		return key;
	}

	list_add_tail(&uobj->list, &uctx->uobj_list);

	spin_unlock(&uctx->uobj_lock);
out:
	return key;
}

static struct erdma_uobj *erdma_remove_uobj(struct erdma_ucontext *uctx,
					    __u32 key, __u32 size)
{
	struct list_head *pos, *nxt;

	spin_lock(&uctx->uobj_lock);

	list_for_each_safe(pos, nxt, &uctx->uobj_list) {
		struct erdma_uobj *uobj = list_entry(pos, struct erdma_uobj, list);

		if (uobj->key == key && uobj->size == size) {
			list_del(&uobj->list);
			spin_unlock(&uctx->uobj_lock);
			return uobj;
		}
	}
	spin_unlock(&uctx->uobj_lock);

	return NULL;
}


int erdma_modify_port(struct ib_device *ibdev, __u8 port, int mask,
		      struct ib_port_modify *props)
{
	return -EOPNOTSUPP;
}

static void erdma_update_dev_attr(struct erdma_dev *dev,
				  struct erdma_query_device_result *result)
{
	dev->attrs.max_send_sge = result->max_send_sge;
	dev->attrs.max_send_wr = result->max_send_wr;
	dev->attrs.max_recv_wr = result->max_recv_wr;
	dev->attrs.max_qp = result->max_qp;
	dev->attrs.max_mr_size = result->max_mr_size;
	dev->attrs.max_mr = result->max_mr;
	dev->attrs.max_cqe = result->max_cqe;
	dev->attrs.max_cq = result->max_cq;
	dev->attrs.max_mw = result->max_mw;
	dev->attrs.local_dma_key = result->local_dma_key;
}

int erdma_query_device(struct ib_device *ibdev, struct ib_device_attr *attr,
		       struct ib_udata *unused)
{
	struct erdma_dev *dev = to_edev(ibdev);
	struct erdma_query_device_result result;
	int err;

	memset(attr, 0, sizeof(*attr));

	err = erdma_exec_query_device_cmd(dev, &result);
	if (err)
		return -EINVAL;

	erdma_update_dev_attr(dev, &result);

	attr->max_mr_size = dev->attrs.max_mr_size; /* per process */
	attr->vendor_id = dev->attrs.vendor_id;
	attr->vendor_part_id = 0;
	attr->max_qp = dev->attrs.max_qp;
	attr->max_qp_wr = dev->attrs.max_send_wr > dev->attrs.max_recv_wr
					? dev->attrs.max_recv_wr : dev->attrs.max_send_wr;

	/*
	 * RDMA Read parameters:
	 * Max. ORD (Outbound Read queue Depth), a.k.a. max_initiator_depth
	 * Max. IRD (Inbound Read queue Depth), a.k.a. max_responder_resources
	 */
	attr->max_qp_rd_atom = dev->attrs.max_ord;
	attr->max_qp_init_rd_atom = dev->attrs.max_ird;
	attr->max_res_rd_atom = dev->attrs.max_qp * dev->attrs.max_ird;
	attr->device_cap_flags = dev->attrs.cap_flags | IB_DEVICE_LOCAL_DMA_LKEY;
	ibdev->local_dma_lkey = dev->attrs.local_dma_key;
	attr->max_send_sge = dev->attrs.max_send_sge;
	attr->max_recv_sge = dev->attrs.max_recv_sge;
	attr->max_sge_rd = dev->attrs.max_sge_rd;
	attr->max_cq = dev->attrs.max_cq;
	attr->max_cqe = dev->attrs.max_cqe;
	attr->max_mr = dev->attrs.max_mr;
	attr->max_pd = dev->attrs.max_pd;
	attr->max_mw = dev->attrs.max_mw;
	attr->max_srq = dev->attrs.max_srq;
	attr->max_srq_wr = dev->attrs.max_srq_wr;
	attr->max_srq_sge = dev->attrs.max_srq_sge;

	memcpy(&attr->sys_image_guid, dev->netdev->dev_addr, 6);

	return 0;
}

int erdma_query_pkey(struct ib_device *ibdev, __u8 port, __u16 idx, __u16 *pkey)
{
	/* Report the default pkey */
	*pkey = 0xffff;
	return 0;
}


int erdma_query_gid(struct ib_device *ibdev, __u8 port, int idx,
		    union ib_gid *gid)
{
	struct erdma_dev *edev = to_edev(ibdev);

	/* subnet_prefix == interface_id == 0; */
	memset(gid, 0, sizeof(*gid));
	memcpy(&gid->raw[0], edev->netdev->dev_addr, 6);

	ddump("gid", &gid->raw[0], 16);

	return 0;
}

int erdma_query_port(struct ib_device *ibdev, __u8 port,
		     struct ib_port_attr *attr)
{
	struct erdma_dev *dev = to_edev(ibdev);

	memset(attr, 0, sizeof(*attr));

	attr->state = dev->state;
	attr->max_mtu = IB_MTU_1024;
	attr->active_mtu = attr->max_mtu;
	attr->gid_tbl_len = 1;
	attr->port_cap_flags = IB_PORT_CM_SUP;	/* ?? */
	attr->port_cap_flags |= IB_PORT_DEVICE_MGMT_SUP;
	attr->max_msg_sz = -1;
	attr->pkey_tbl_len = 1;
	attr->active_width = 2;
	attr->active_speed = 2;
	attr->phys_state = dev->state == IB_PORT_ACTIVE ? 5 : 3;
	/*
	 * All zero
	 *
	 * attr->lid = 0;
	 * attr->bad_pkey_cntr = 0;
	 * attr->qkey_viol_cntr = 0;
	 * attr->sm_lid = 0;
	 * attr->lmc = 0;
	 * attr->max_vl_num = 0;
	 * attr->sm_sl = 0;
	 * attr->subnet_timeout = 0;
	 * attr->init_type_repy = 0;
	 */
	return 0;
}

int erdma_get_port_immutable(struct ib_device *ibdev, __u8 port,
			     struct ib_port_immutable *port_immutable)
{
	struct ib_port_attr attr;
	int                 rv    = erdma_query_port(ibdev, port, &attr);

	if (rv)
		return rv;

	port_immutable->pkey_tbl_len = attr.pkey_tbl_len;
	port_immutable->gid_tbl_len = attr.gid_tbl_len;
	port_immutable->core_cap_flags = RDMA_CORE_PORT_IWARP;

	return 0;
}

static inline void notify_cq(struct erdma_cq *cq)
{
	__u32 db[2];

	db[0] = (CQDB_CMD_ARM << CQDB_FIELD_ARM_OFFSET) |
		(cq->ci & 0xFFFFFF);

	db[1] = (cq->assoc_eqn << CQDB_FIELD_EQN_OFFSET) | cq->hdr.id;

	*(__u64 *)cq->db = *(__u64 *)db;
}

/*
 * erdma_req_notify_cq()
 *
 * Request notification for new CQE's added to that CQ.
 * Defined flags:
 * o erdma_cq_NOTIFY_SOLICITED lets erdma trigger a notification
 *   event if a WQE with notification flag set enters the CQ
 * o erdma_cq_NOTIFY_NEXT_COMP lets erdma trigger a notification
 *   event if a WQE enters the CQ.
 * o IB_CQ_REPORT_MISSED_EVENTS: return value will provide the
 *   number of not reaped CQE's regardless of its notification
 *   type and current or new CQ notification settings.
 *
 * @ibcq:	OFA CQ contained in erdma CQ.
 * @flags:	Requested notification flags.
 */
int erdma_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
	struct erdma_cq *cq = to_ecq(ibcq);

	notify_cq(cq);
	/* TBD: support interrupt mode. */
	return 0;
}

int erdma_alloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct erdma_pd     *pd   = to_epd(ibpd);
	struct erdma_dev    *dev  = to_edev(ibpd->device);
	int                 rv;

	if (atomic_inc_return(&dev->num_pd) > ERDMA_MAX_PD) {
		dprint(DBG_ON, ": Out of PD's\n");
		return -ENOMEM;
	}

	rv = erdma_pd_add(dev, pd);
	if (rv) {
		dprint(DBG_ON, ": erdma_pd_add\n");
		rv = -ENOMEM;
		goto err_out;
	}

	return 0;

err_out:
	atomic_dec(&dev->num_pd);

	return rv;
}

int erdma_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct erdma_pd    *pd   = to_epd(ibpd);
	struct erdma_dev   *edev = to_edev(ibpd->device);

	erdma_remove_obj(&edev->idr_lock, &edev->pd_idr, &pd->hdr);
	erdma_pd_put(pd);

	return 0;
}

struct ib_ah *
erdma_create_ah(struct ib_pd *pd, struct rdma_ah_attr *attr, struct ib_udata *udata)
{
	return ERR_PTR(-EOPNOTSUPP);
}

int erdma_destroy_ah(struct ib_ah *ah)
{
	return -EOPNOTSUPP;
}


static inline int
erdma_qp_validate_cap(struct erdma_dev *dev, struct ib_qp_init_attr *attrs)
{
	if ((attrs->cap.max_send_wr > dev->attrs.max_send_wr) ||
	    (attrs->cap.max_recv_wr > dev->attrs.max_recv_wr) ||
	    (attrs->cap.max_send_sge > dev->attrs.max_send_sge)  ||
	    (attrs->cap.max_recv_sge > dev->attrs.max_recv_sge)) {
		dprint(DBG_ON, "send_wr:%u(%u),recv_wr:%u(%u),send_sge:%u(%u),recv_sge:%u(%u)\n",
			attrs->cap.max_send_wr, dev->attrs.max_send_wr,
			attrs->cap.max_recv_wr, dev->attrs.max_recv_wr,
			attrs->cap.max_send_sge, dev->attrs.max_send_sge,
			attrs->cap.max_recv_sge, dev->attrs.max_recv_sge);
		return -EINVAL;
	}

	if (attrs->cap.max_inline_data > ERDMA_MAX_INLINE) {
		dprint(DBG_ON, ": Max Inline Send %d > %d!\n",
			attrs->cap.max_inline_data, (int)ERDMA_MAX_INLINE);
		return -EINVAL;
	}

	/*
	 * NOTE: we allow for zero element SQ and RQ WQE's SGL's
	 * but not for a QP unable to hold any WQE (SQ + RQ)
	 */
	if (attrs->cap.max_send_wr + attrs->cap.max_recv_wr == 0)
		return -EINVAL;

	return 0;
}

#define IB_QP_IWARP_WITHOUT_CM (1 << 26)
static inline int
erdma_qp_validate_attr(struct erdma_dev *dev, struct ib_qp_init_attr *attrs)
{
	if (attrs->qp_type != IB_QPT_RC) {
		dprint(DBG_ON, ": Only RC QP's supported\n");
		return -EINVAL;
	}

	if (attrs->srq) {
		dprint(DBG_ON, ": Not support SRQ.\n");
		return -EOPNOTSUPP;
	}

	if (attrs->create_flags && attrs->create_flags != IB_QP_IWARP_WITHOUT_CM) {
		dprint(DBG_ON, "Unsupported create_flags\n");
		return -EOPNOTSUPP;
	}

	return 0;
}

static void
init_kernel_qp(struct erdma_dev *dev, struct erdma_qp *qp, struct ib_qp_init_attr *attrs)
{
	struct iw_ext_conn_param *param = (struct iw_ext_conn_param *)(attrs->qp_context);

	qp->is_kernel_qp = true;
	qp->sq_pi = 0;
	qp->sq_ci = 0;
	qp->rq_pi = 0;
	qp->rq_ci = 0;
	qp->sq_db = dev->func_bar + ERDMA_BAR_SQDB_SPACE_OFFSET +
		((ERDMA_SDB_NPAGE + ERDMA_SQB_NENTRY / ERDMA_SDB_NENTRY_PER_PAGE) << PAGE_SHIFT);
	qp->rq_db = dev->func_bar + ERDMA_BAR_SQDB_SPACE_OFFSET + ERDMA_BAR_RQDB_SPACE_OFFSET;
	qp->cq_db = dev->func_bar + ERDMA_BAR_SQDB_SPACE_OFFSET + ERDMA_BAR_CQDB_SPACE_OFFSET;

	if (param != NULL) {
		qp->without_cm = true;
		qp->attrs.state = ERDMA_QP_STATE_IDLE;
		qp->attrs.dip = ntohl(param->sk_addr.daddr_v4);
		qp->attrs.sip = ntohl(param->sk_addr.saddr_v4);
		qp->attrs.dport = ntohs(param->sk_addr.dport);
		qp->attrs.sport = param->sk_addr.sport;
	}
}

/*
 * erdma_create_qp()
 *
 * Create QP of requested size on given device.
 *
 * @ibpd:	OFA PD contained in erdma PD
 * @attrs:	Initial QP attributes.
 * @udata:	used to provide QP ID, SQ and RQ size back to user.
 */

struct ib_qp *erdma_create_qp(struct ib_pd *ibpd,
			    struct ib_qp_init_attr *attrs,
			    struct ib_udata *udata)
{
	struct erdma_qp               *qp      = NULL;
	struct erdma_pd               *pd      = to_epd(ibpd);
	struct ib_device              *ibdev   = ibpd->device;
	struct erdma_dev              *edev    = to_edev(ibdev);
	struct erdma_cq               *scq     = NULL, *rcq = NULL;
	struct erdma_ucontext         *ctx;
	struct erdma_uresp_create_qp  uresp;
	struct erdma_create_qp_params params;
	unsigned long                 flags;
	int                           rv       = 0;
	bool user_access = (udata != NULL) ? true : false;

	dprint(DBG_OBJ|DBG_CM, ": new QP on device %s\n",
		ibdev->name);

	if (user_access && !ibpd->uobject) {
		ibdev_dbg(&edev->ibdev, "udata or uobject is NULL.\n");
		rv = -EOPNOTSUPP;
		goto out;
	}

	rv = erdma_qp_validate_cap(edev, attrs);
	if (rv)
		goto out;

	rv = erdma_qp_validate_attr(edev, attrs);
	if (rv)
		goto out;

	if (atomic_inc_return(&edev->num_qp) > ERDMA_MAX_QP) {
		dprint(DBG_ON, ": Out of QP's\n");
		rv = -ENOMEM;
		goto err_out;
	}

	scq = erdma_cq_id2obj(edev, ((struct erdma_cq *)attrs->send_cq)->hdr.id, 1);
	rcq = erdma_cq_id2obj(edev, ((struct erdma_cq *)attrs->recv_cq)->hdr.id, 1);

	if (!scq || !rcq) {
		dprint(DBG_OBJ, ": Fail: SCQ: 0x%p, RCQ: 0x%p\n",
			scq, rcq);
		rv = -EINVAL;
		goto err_out;
	}

	qp = kzalloc(sizeof(*qp), GFP_KERNEL);
	if (!qp) {
		dprint(DBG_ON, ": kzalloc failed.\n");
		rv = -ENOMEM;
		goto err_out;
	}

#ifdef ERDMA_ENABLE_DEBUG
	qp->snapshot = alloc_pages_exact(4096, GFP_KERNEL | __GFP_ZERO);
	if (!qp->snapshot)
		goto err_out;

	if (scq)
		((struct erdma_usr_qp_info *)qp->snapshot)->scq = CQ_ID(scq);
	if (rcq)
		((struct erdma_usr_qp_info *)qp->snapshot)->rcq = CQ_ID(rcq);
#endif

	init_rwsem(&qp->state_lock);

	rv = erdma_qp_add(edev, qp);
	if (rv)
		goto err_out;

	qp->sendq.depth = roundup_pow_of_two(attrs->cap.max_send_wr * ERDMA_MAX_WQEBB_PER_SQE);
	qp->sendq.size = (__u32)qp->sendq.depth * ERDMA_SQ_WQEBB_SIZE;
	qp->sendq.wr_tbl = vmalloc(qp->sendq.depth * sizeof(u64));

	qp->recvq.depth = roundup_pow_of_two(attrs->cap.max_recv_wr);
	qp->recvq.size = (__u32)qp->recvq.depth * ERDMA_MAX_RQE_SIZE;
	qp->recvq.wr_tbl = vmalloc(qp->recvq.depth * sizeof(u64));

	dprint(DBG_QP, "max_send_wr:%u, max_recv_wr:%u.\n",
		attrs->cap.max_send_wr, attrs->cap.max_recv_wr);

	qp->sendq.qbuf = dma_alloc_coherent(&edev->pdev->dev,
		qp->sendq.size,
		&qp->sendq.dma_addr,
		GFP_KERNEL);
	if (qp->sendq.qbuf == NULL) {
		pr_warn("(QP%d): send queue size %d alloc failed\n",
			QP_ID(qp), qp->sendq.depth);
		rv = -ENOMEM;
		goto err_out_idr;
	}

	qp->pd = pd;
	qp->scq = scq;

	if (qp->recvq.depth) {
		qp->recvq.qbuf = dma_alloc_coherent(&edev->pdev->dev,
			qp->recvq.size, &qp->recvq.dma_addr, GFP_KERNEL);

		if (qp->recvq.qbuf == NULL) {
			pr_warn("QP(%d): recv queue size %d alloc failed\n",
				QP_ID(qp), qp->recvq.depth);
			rv = -ENOMEM;
			goto err_out_idr;
		}

		qp->attrs.rq_size = qp->recvq.depth;
		qp->rcq = rcq;
	}

	qp->attrs.sq_size = qp->sendq.depth;
	qp->attrs.sq_max_sges = attrs->cap.max_send_sge;
	/*
	 * ofed has no max_send_sge_rdmawrite
	 */
	qp->attrs.sq_max_sges_rdmaw = attrs->cap.max_send_sge;
	qp->attrs.rq_max_sges = attrs->cap.max_recv_sge;

	qp->attrs.state = ERDMA_QP_STATE_IDLE;

	dprint(DBG_QP,
		"(QP%u),sq-va:%p,sq-dma:%llx,sq-depth:%u,rq-va:%p,rq-dma:%llx,rq-depth:%u.\n",
		QP_ID(qp), qp->sendq.qbuf, qp->sendq.dma_addr, qp->sendq.depth,
		qp->recvq.qbuf, qp->recvq.dma_addr, qp->recvq.depth);

	params.pd = PD_ID(pd);
	params.qpn = QP_ID(qp);
	params.rcqn = CQ_ID(rcq);
	params.rq_buf_addr = qp->recvq.dma_addr;
	params.rq_depth = qp->recvq.depth;
	params.scqn = CQ_ID(scq);
	params.sq_buf_addr = qp->sendq.dma_addr;
	params.sq_depth = qp->sendq.depth;
	rv = erdma_exec_create_qp_cmd(edev, &params);
	if (rv)
		goto err_out_idr;

	if (user_access) {
		ctx = to_ectx(ibpd->uobject->context);
		memset(&uresp, 0, sizeof(uresp));

		uresp.rq_key = ERDMA_INVAL_UOBJ_KEY;
		uresp.num_sqe = qp->sendq.depth;
		uresp.num_rqe = qp->recvq.depth;
		uresp.qp_id = QP_ID(qp);

		uresp.sq_key = erdma_insert_uobj(ctx, (void *)virt_to_phys(qp->sendq.qbuf),
				qp->sendq.size, ERDMA_MMAP_DMA_PAGE);
		if (uresp.sq_key == ERDMA_MAX_UOBJ_KEY)
			pr_warn("Preparing mmap SQ failed\n");

		if (qp->recvq.qbuf) {
			uresp.rq_key = erdma_insert_uobj(ctx, (void *)virt_to_phys(qp->recvq.qbuf),
				qp->recvq.size, ERDMA_MMAP_DMA_PAGE);
			if (uresp.rq_key == ERDMA_MAX_UOBJ_KEY)
				pr_warn("Preparing mmap RQ failed\n");
		}

#ifdef ERDMA_ENABLE_DEBUG
		uresp.dbg_key = erdma_insert_uobj(ctx, (void *)virt_to_phys(qp->snapshot),
			4096, ERDMA_MMAP_DBG_PAGE);
		if (uresp.dbg_key == ERDMA_MAX_UOBJ_KEY)
			pr_warn("Preparing mmap failed.\n");
#endif

		dprint(DBG_QP, "uresp size is %lu.\n", sizeof(uresp));

		rv = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (rv)
			goto err_out_idr;
	} else {
		init_kernel_qp(edev, qp, attrs);
	}

	qp->ibqp.qp_num = QP_ID(qp);

	erdma_pd_get(pd);

	INIT_LIST_HEAD(&qp->devq);
	spin_lock_irqsave(&edev->idr_lock, flags);
	list_add_tail(&qp->devq, &edev->qp_list);
	spin_unlock_irqrestore(&edev->idr_lock, flags);
	spin_lock_init(&qp->lock);

	return &qp->ibqp;

err_out_idr:
	vfree(qp->sendq.wr_tbl);
	vfree(qp->recvq.wr_tbl);
	erdma_remove_obj(&edev->idr_lock, &edev->qp_idr, &qp->hdr);
err_out:
	if (scq)
		erdma_cq_put(scq);
	if (rcq)
		erdma_cq_put(rcq);

	if (qp) {
		if (qp->sendq.qbuf) {
			dma_free_coherent(&edev->pdev->dev, qp->sendq.size,
				qp->sendq.qbuf, qp->sendq.dma_addr);
			qp->sendq.qbuf = NULL;
		}
		if (qp->recvq.qbuf) {
			dma_free_coherent(&edev->pdev->dev, qp->recvq.size,
				qp->recvq.qbuf, qp->recvq.dma_addr);
			qp->recvq.qbuf = NULL;
		}
#ifdef ERDMA_ENABLE_DEBUG
		if (qp->snapshot)
			free_pages_exact(qp->snapshot, 4096);
#endif
		kfree(qp);
	}
	atomic_dec(&edev->num_qp);

out:
	return ERR_PTR(rv);
}

static struct erdma_mr *
erdma_alloc_mr(struct ib_pd *ibpd, struct erdma_dev *edev, struct ib_umem *umem,
				       __u64 start, __u64 len, int rights)
{
	struct erdma_mr *mr = kzalloc(sizeof(*mr), GFP_KERNEL);

	if (!mr)
		return NULL;

	mr->mem.stag_state = STAG_INVALID;

	if (erdma_mem_add(edev, &mr->mem) < 0) {
		dprint(DBG_ON, ": erdma_mem_add\n");
		kfree(mr);
		return NULL;
	}
	dprint(DBG_OBJ|DBG_MM, "(MPT%d): New Object, UMEM %p\n",
		mr->mem.hdr.id, umem);

	mr->ibmr.lkey = mr->ibmr.rkey = mr->mem.hdr.id << 8;
	mr->ibmr.pd = ibpd;

	mr->mem.va  = start;
	mr->mem.len = len;
	mr->mem.assoc_mr  = NULL;
	mr->mem.perms = SR_MEM_LREAD | /* not selectable in OFA */
			(rights & IB_ACCESS_REMOTE_READ  ? SR_MEM_RREAD  : 0) |
			(rights & IB_ACCESS_LOCAL_WRITE  ? SR_MEM_LWRITE : 0) |
			(rights & IB_ACCESS_REMOTE_WRITE ? SR_MEM_RWRITE : 0);

	mr->umem = umem;

	return mr;
}

/*
 * erdma_get_dma_mr()
 *
 * Create a (empty) DMA memory region, where no umem is attached.
 * All DMA addresses are created via erdma_dma_mapping_ops - which
 * will return just kernel virtual addresses, since erdma runs on top
 * of TCP kernel sockets.
 */
struct ib_mr *erdma_get_dma_mr(struct ib_pd *ibpd, int rights)
{
	/* Fix Me: */
	struct erdma_mr         *mr;
	struct erdma_pd         *pd   = to_epd(ibpd);
	struct erdma_dev        *edev = pd->hdr.edev;
	int rv;

	if (atomic_inc_return(&edev->num_mem) > ERDMA_MAX_MR) {
		dprint(DBG_ON, ": Out of MRs: %d\n",
			atomic_read(&edev->num_mem));
		rv = -ENOMEM;
		goto err_out;
	}

	mr = erdma_alloc_mr(ibpd, edev, NULL, 0, ULONG_MAX, rights);
	if (!mr) {
		rv = -ENOMEM;
		goto err_out;
	}
	mr->mem.stag_state = STAG_VALID;

	mr->ibmr.lkey = edev->attrs.local_dma_key;
	mr->ibmr.rkey = edev->attrs.local_dma_key; /* XXX ??? */

	mr->pd = pd;
	erdma_pd_get(pd);

	return &mr->ibmr;

err_out:
	atomic_dec(&edev->num_mem);

	return ERR_PTR(rv);
}

struct ib_umem *erdma_map_pages(struct ib_device *device, struct page *page,
								unsigned long npages, int access)
{
	struct ib_umem *umem;
	struct scatterlist *sg, *sg_list_start;
	int i, ret;
	unsigned long dma_attrs = 0;

	if (!page)
		return ERR_PTR(-EINVAL);

	if (access & IB_ACCESS_RELAXED_ORDERING)
		dma_attrs |= DMA_ATTR_WEAK_ORDERING;

	umem = kzalloc(sizeof(*umem), GFP_KERNEL);
	if (!umem)
		return ERR_PTR(-ENOMEM);

	ret = sg_alloc_table(&umem->sg_head, npages, GFP_KERNEL);
	if (ret)
		goto umem_kfree;

	sg_list_start = umem->sg_head.sgl;

	for_each_sg(sg_list_start, sg, npages, i) {
		sg_set_page(sg, &page[i], PAGE_SIZE, 0);
	}

	umem->nmap = ib_dma_map_sg_attrs(device,
					umem->sg_head.sgl,
					npages,
					DMA_BIDIRECTIONAL,
					dma_attrs);

	if (!umem->nmap) {
		ret = -ENOMEM;
		goto free_sg;
	}

	return umem;

free_sg:
	sg_free_table(&umem->sg_head);
umem_kfree:
	kfree(umem);
	return ERR_PTR(ret);
}

int
prealloc_mtt(struct erdma_dev *dev, struct erdma_mr *mr, u32 max_num_sg)
{
	mr->total_mtt_size = max_num_sg * 8;
	mr->mtt_size = 0;
	mr->mtt_nents = 0;

	if (mr->total_mtt_size > 4 * 1024 * 1024) {
		ibdev_err(&dev->ibdev, "(MPT%u): mtt to large:%u",
			MR_ID(mr), mr->total_mtt_size);
		mr->total_mtt_size = 0;
		return -EINVAL;
	}

	mr->mtt_va_addr = dma_alloc_coherent(&dev->pdev->dev, mr->total_mtt_size,
				&mr->mtt_dma_addr, GFP_KERNEL);
	if (!mr->mtt_va_addr) {
		mr->total_mtt_size = 0;
		return -ENOMEM;
	}
	return 0;
}

struct ib_mr *
erdma_ib_alloc_mr(struct ib_pd *ibpd, enum ib_mr_type mr_type, u32 max_num_sg)
{
	struct erdma_mr *mr;
	struct erdma_pd *pd;
	struct erdma_dev *edev;
	int ret;

	if (!ibpd)
		return ERR_PTR(-EINVAL);

	pd = to_epd(ibpd);
	edev = pd->hdr.edev;

	if (atomic_inc_return(&edev->num_mem) > edev->attrs.max_mr) {
		dev_err(&edev->pdev->dev, "ERROR: Out of MRs: %d, max %d\n",
			atomic_read(&edev->num_mem), edev->attrs.max_mr);
		ret = -ENOMEM;
		goto out;
	}

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		ret = -ENOMEM;
		goto out;
	}

	mr->mem.stag_state = STAG_INVALID;
	ret = erdma_mem_add(edev, &mr->mem);
	if (ret < 0) {
		dprint(DBG_ON, ": erdma_mem_add\n");
		goto out_free;
	}
	dprint(DBG_OBJ|DBG_MM, "(MPT%d): New Object", mr->mem.hdr.id);

	mr->ibmr.lkey = mr->ibmr.rkey = mr->mem.hdr.id << 8;

	ret = prealloc_mtt(edev, mr, max_num_sg);
	if (ret) {
		dprint(DBG_ON, ":prealloc mtt\n");
		goto out_free;
	}

	return &mr->ibmr;

out_free:
	kfree(mr);
out:
	atomic_dec(&edev->num_mem);
	return ERR_PTR(ret);
}

static int
erdma_set_mr(struct erdma_mr *mr, struct ib_umem *umem, __u64 start, __u64 len, int rights)
{
	mr->mem.va  = start;
	mr->mem.len = len;
	mr->mem.assoc_mr  = NULL;
	mr->mem.perms = SR_MEM_LREAD | /* not selectable in OFA */
			(rights & IB_ACCESS_REMOTE_READ  ? SR_MEM_RREAD  : 0) |
			(rights & IB_ACCESS_LOCAL_WRITE  ? SR_MEM_LWRITE : 0) |
			(rights & IB_ACCESS_REMOTE_WRITE ? SR_MEM_RWRITE : 0);

	mr->umem = umem;
	/* remove this */
	return 0;
}

int erdma_reg_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg, int sg_nents,
					unsigned int *sg_offset, int valid)
{
	struct erdma_pd *pd;
	struct erdma_dev *edev;
	struct erdma_reg_mr_params params;
	struct erdma_mr *mr;
	int ret;
	int access =
		IB_ACCESS_REMOTE_READ | IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE;
	__u64 virt_addr = 0;
	__u64 len = 0;

	dprint(DBG_ON, "reg invalid mr");

	if (!ibmr || ibmr->pd == NULL)
		return -EINVAL;

	mr = to_emr(ibmr);
	pd = to_epd(mr->ibmr.pd);
	edev = pd->hdr.edev;

	virt_addr = mr->ibmr.iova;
	len = mr->ibmr.length;

	ret = erdma_set_mr(mr, NULL, virt_addr, len, access);
	if (ret)
		return ret;

	mr->mem.stag_state = STAG_VALID;

	params.access = mr->mem.perms;
	params.page_size = 0; /* 4K */
	params.valid = valid;
	params.stag = mr->ibmr.lkey;
	params.mr = mr;
	params.pd_id = OBJ_ID(pd);
	params.start_va = virt_addr;
	params.len = len;

	ret = erdma_exec_reg_mr_cmd_no_umem(edev, &params, sg, sg_nents, sg_offset);
	mr->pd = pd;
	erdma_pd_get(pd);

	return ret;
}

int erdma_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg, int sg_nents,
					unsigned int *sg_offset)
{
	return erdma_reg_mr_sg(ibmr, sg, sg_nents, sg_offset, STAG_INVALID);
}

/*
 * erdma_reg_user_mr()
 *
 * Register Memory Region.
 *
 * @ibpd:	OFA PD contained in erdma PD.
 * @start:	starting address of MR (virtual address)
 * @len:	len of MR
 * @rnic_va:	not used by erdma
 * @rights:	MR access rights
 * @udata:	user buffer to communicate STag and Key.
 */
struct ib_mr *erdma_reg_user_mr(struct ib_pd *ibpd, __u64 start, __u64 len,
				__u64 rnic_va, int access, struct ib_udata *udata)
{
	struct erdma_mr                 *mr     = NULL;
	struct erdma_pd                 *pd     = to_epd(ibpd);
	struct ib_umem                  *umem   = NULL;
	struct erdma_ureq_reg_mr        ureq;
	struct erdma_uresp_reg_mr       uresp;
	struct erdma_dev                *edev   = pd->hdr.edev;
	struct erdma_reg_mr_params      params;
	int                             rv;

	dprint(DBG_MM|DBG_OBJ, "(MPT?): start:0x%llx,va:0x%llx,len:%llu,ctx:%p\n",
		(unsigned long long)start,
		(unsigned long long)rnic_va,
		(unsigned long long)len,
		ibpd->uobject->context);

	if (atomic_inc_return(&edev->num_mem) > edev->attrs.max_mr) {
		dev_err(&edev->pdev->dev, "ERROR: Out of MRs: %d, max %d\n",
			atomic_read(&edev->num_mem), edev->attrs.max_mr);
		rv = -ENOMEM;
		goto err_out;
	}

	if (!len || len > edev->attrs.max_mr_size) {
		dev_err(&edev->pdev->dev, "ERROR: Out of mr size: %llu, max %llu\n",
			len, edev->attrs.max_mr_size);
		rv = -EINVAL;
		goto err_out;
	}

	umem = ib_umem_get(ibpd->device, start, len, access);
	if (IS_ERR(umem)) {
		dev_err(&edev->pdev->dev,
			"ib_umem_get:%ld\n", PTR_ERR(umem));
		rv = PTR_ERR(umem);
		umem = NULL;
		goto err_out;
	}

	mr = erdma_alloc_mr(ibpd, edev, umem, start, len, access);
	if (!mr) {
		rv = -ENOMEM;
		goto err_out;
	}

	if (udata) {
		rv = ib_copy_from_udata(&ureq, udata, sizeof(ureq));
		if (rv)
			goto err_out_mr;

		mr->ibmr.lkey |= ureq.stag_key;
		mr->ibmr.rkey |= ureq.stag_key; /* XXX ??? */
		uresp.stag = mr->ibmr.lkey;

		rv = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (rv)
			goto err_out_mr;
	}

	mr->mem.stag_state = STAG_VALID;
	mr->mtt_va_addr = 0;

	params.access = mr->mem.perms;
	params.page_size = 0; /* 4K */
	params.valid = STAG_VALID;
	params.stag = mr->ibmr.lkey;
	params.mr = mr;
	params.pd_id = OBJ_ID(pd);
	params.start_va = rnic_va;
	params.len = len;

	rv = erdma_exec_reg_mr_cmd(edev, &params);
	if (rv)
		goto err_out_mr;

	mr->pd = pd;
	erdma_pd_get(pd);
	return &mr->ibmr;

err_out_mr:
	erdma_remove_obj(&edev->idr_lock, &edev->mem_idr, &mr->mem.hdr);

	if (mr->mtt_va_addr) {
		dma_free_coherent(&edev->pdev->dev, mr->mtt_size,
			mr->mtt_va_addr, mr->mtt_dma_addr);
	}
	kfree(mr);

err_out:
	if (umem)
		ib_umem_release(umem);

	atomic_dec(&edev->num_mem);

	return ERR_PTR(rv);
}

/*
 * erdma_dereg_mr()
 *
 * Release Memory Region.
 *
 * @ibmr:     OFA MR contained in erdma MR.
 */
int erdma_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata)
{
	struct erdma_mr              *mr;
	struct erdma_dev             *edev = to_edev(ibmr->device);
	struct erdma_dereg_mr_params params;
	int                          rv;

	mr = to_emr(ibmr);

	dprint(DBG_OBJ|DBG_MM, "(MPT%d): Release UMem %p, #ref's: %d\n",
		mr->mem.hdr.id, mr->umem,
		kref_read(&mr->mem.hdr.ref));
	params.l_key = ibmr->lkey;
	rv = erdma_exec_dereg_mr_cmd(edev, &params);
	if (rv) {
		ibdev_err(&edev->ibdev, "(MPT%d):dereg mr failed, lkey = %d.\n",
			mr->mem.hdr.id, ibmr->lkey);
		return rv;
	}

	mr->mem.stag_state = STAG_INVALID;

	erdma_pd_put(mr->pd);
	erdma_remove_obj(&edev->idr_lock, &edev->mem_idr, &mr->mem.hdr);
	erdma_mem_put(&mr->mem);

	if (mr->mtt_va_addr)
		dma_free_coherent(&edev->pdev->dev, mr->mtt_size,
			mr->mtt_va_addr, mr->mtt_dma_addr);

	kfree(mr);
	return 0;
}

int erdma_destroy_cq(struct ib_cq *ibcq, struct ib_udata *udata)
{
	struct erdma_cq                *cq      = to_ecq(ibcq);
	struct ib_device               *ibdev   = ibcq->device;
	struct erdma_dev               *edev    = to_edev(ibdev);
	struct erdma_destroy_cq_params params;
	int                            err;

	params.cqn = OBJ_ID(cq);
	dprint(DBG_CQ, "destroy cq(%d)\n", OBJ_ID(cq));

	err = erdma_exec_destroy_cq_cmd(edev, &params);
	if (err)
		return err;

	/* TBD. free cq buffer. make sure that no cqe generate after. */
	erdma_remove_obj(&edev->idr_lock, &edev->cq_idr, &cq->hdr);
	erdma_cq_put(cq);

	return 0;
}

int erdma_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata)
{
	struct erdma_qp                *qp       = to_eqp(ibqp);
	struct erdma_dev               *edev     = to_edev(ibqp->device);
	struct erdma_qp_attrs          qp_attrs;
	struct erdma_destroy_qp_params params;
	int err;

	dprint(DBG_CM, "(QP%d): ERDMA QP state=%d, cep=0x%p\n",
		QP_ID(qp), qp->attrs.state, qp->cep);

	/*
	 * Mark QP as in process of destruction to prevent from eventual async
	 * callbacks to OFA core
	 */
	qp->attrs.flags |= ERDMA_QP_IN_DESTROY;

	down_write(&qp->state_lock);

	qp_attrs.state = ERDMA_QP_STATE_CLOSING;
	(void)erdma_modify_qp_internal(qp, &qp_attrs, ERDMA_QP_ATTR_STATE);

	params.qpn = QP_ID(qp);
	err = erdma_exec_destroy_qp_cmd(edev, &params);
	if (err) {
		up_write(&qp->state_lock);
		return err;
	}

	if (qp->sendq.qbuf) {
		dma_free_coherent(&edev->pdev->dev, qp->sendq.size,
				qp->sendq.qbuf, qp->sendq.dma_addr);
		qp->sendq.qbuf = NULL;
	}
	if (qp->recvq.qbuf) {
		dma_free_coherent(&edev->pdev->dev, qp->recvq.size,
				qp->recvq.qbuf, qp->recvq.dma_addr);
		qp->recvq.qbuf = NULL;
	}

	if (qp->cep) {
		erdma_cep_put(qp->cep);
		qp->cep = NULL;
	}

	up_write(&qp->state_lock);

	vfree(qp->sendq.wr_tbl);
	vfree(qp->recvq.wr_tbl);
	/* Drop references */
	erdma_cq_put(qp->scq);
	erdma_cq_put(qp->rcq);
	erdma_pd_put(qp->pd);

	qp->scq = qp->rcq = NULL;

	erdma_qp_put(qp);

	return 0;
}

void erdma_qp_get_ref(struct ib_qp *ibqp)
{
	struct erdma_qp	*qp = to_eqp(ibqp);

	dprint(DBG_OBJ|DBG_CM, "(QP%d): Get Reference\n", QP_ID(qp));
	erdma_qp_get(qp);
}

void erdma_qp_put_ref(struct ib_qp *ibqp)
{
	struct erdma_qp	*qp = to_eqp(ibqp);

	dprint(DBG_OBJ|DBG_CM, "(QP%d): Put Reference\n", QP_ID(qp));
	erdma_qp_put(qp);
}

int erdma_mmap(struct ib_ucontext *ctx, struct vm_area_struct *vma)
{
	struct erdma_ucontext *uctx  = to_ectx(ctx);
	struct erdma_uobj     *uobj;
	__u32                 key    = vma->vm_pgoff << PAGE_SHIFT;
	int                   size   = vma->vm_end - vma->vm_start;
	int                   err    = -EINVAL;
	__u64                 pfn;

	/*
	 * Must be page aligned
	 */
	if (vma->vm_start & (PAGE_SIZE - 1)) {
		pr_warn("WARN: map not page aligned\n");
		goto out;
	}

	uobj = erdma_remove_uobj(uctx, key, size);
	if (!uobj) {
		pr_warn("WARN: mmap lookup failed: %u, %d\n", key, size);
		goto out;
	}

	pfn = (__u64)uobj->addr >> PAGE_SHIFT;

	dprint(DBG_MM, "Map-type:%u,key:%u,map 0x%llx to user-space:0x%lx,len:%u.\n",
		uobj->type, key, (__u64)uobj->addr, vma->vm_start, size);

	switch (uobj->type) {
	case ERDMA_MMAP_IO_NC:
		/* map doorbell. */
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		err = io_remap_pfn_range(vma, vma->vm_start, pfn,
			PAGE_SIZE, vma->vm_page_prot);
		break;
	case ERDMA_MMAP_IO_WC:
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
		err = io_remap_pfn_range(vma, vma->vm_start, pfn,
			PAGE_SIZE, vma->vm_page_prot);
		break;
	case ERDMA_MMAP_DMA_PAGE:
		dprint(DBG_CTRL, "vm_start:%lx, vm_end:%lx.\n", vma->vm_start, vma->vm_end);
		/*
		 * Map WQ or CQ contig dma memory...
		 */
		err = remap_pfn_range(vma, vma->vm_start,
			pfn, size, vma->vm_page_prot);
		break;
	case ERDMA_MMAP_DBG_PAGE:
		err = remap_pfn_range(vma, vma->vm_start,
			pfn, size, vma->vm_page_prot);
		break;
	default:
		pr_err("mmap failed, uobj type = %d\n", uobj->type);
		err = -EINVAL;
		break;
	}

	kfree(uobj);
out:
	return err;
}

static void __erdma_alloc_sdb(struct erdma_dev *dev, struct erdma_ucontext *ctx)
{
	__u32 bitmap_idx;

	/* Try to alloc independent SDB page. */
	spin_lock(&dev->db_bitmap_lock);
	bitmap_idx = find_first_zero_bit(dev->sdb_page, ERDMA_SDB_NPAGE);
	if (bitmap_idx != ERDMA_SDB_NPAGE) {
		set_bit(bitmap_idx, dev->sdb_page);
		spin_unlock(&dev->db_bitmap_lock);

		ctx->sdb_type = ERDMA_SDB_PAGE;
		ctx->sdb_idx = bitmap_idx;
		ctx->sdb_page_idx = bitmap_idx;
		ctx->sdb = dev->func_bar_addr +
			ERDMA_BAR_SQDB_SPACE_OFFSET + (bitmap_idx << PAGE_SHIFT);
		ctx->sdb_page_off = 0;

		return;
	}

	bitmap_idx = find_first_zero_bit(dev->sdb_entry, ERDMA_SQB_NENTRY);
	if (bitmap_idx != ERDMA_SQB_NENTRY) {
		set_bit(bitmap_idx, dev->sdb_entry);
		spin_unlock(&dev->db_bitmap_lock);

		ctx->sdb_type = ERDMA_SDB_ENTRY;
		ctx->sdb_idx = bitmap_idx;
		ctx->sdb_page_idx = ERDMA_SDB_NPAGE + bitmap_idx / ERDMA_SDB_NENTRY_PER_PAGE;
		ctx->sdb_page_off = bitmap_idx % ERDMA_SDB_NENTRY_PER_PAGE;

		ctx->sdb = dev->func_bar_addr +
			ERDMA_BAR_SQDB_SPACE_OFFSET + (ctx->sdb_page_idx << PAGE_SHIFT);

		return;
	}

	spin_unlock(&dev->db_bitmap_lock);

	ctx->sdb_type = ERDMA_SDB_SHARED;
	ctx->sdb_idx = 0;
	ctx->sdb_page_idx = ERDMA_SDB_SHARED_PAGE;
	ctx->sdb_page_off = 0;

	ctx->sdb = dev->func_bar_addr +
		ERDMA_BAR_SQDB_SPACE_OFFSET + (ctx->sdb_page_idx << PAGE_SHIFT);
}

int erdma_alloc_ucontext(struct ib_ucontext *ibctx,
			 struct ib_udata *udata)
{
	struct erdma_ucontext        *ctx  = to_ectx(ibctx);
	struct erdma_dev             *edev = to_edev(ibctx->device);
	int                          rv;
	struct erdma_uresp_alloc_ctx uresp = {};

	dprint(DBG_CM, "(device=%s)\n", edev->ibdev.name);

	if (atomic_inc_return(&edev->num_ctx) > ERDMA_MAX_CONTEXT) {
		dprint(DBG_ON, ": Out of CONTEXT's\n");
		rv = -ENOMEM;
		goto err_out;
	}

	spin_lock_init(&ctx->uobj_lock);
	INIT_LIST_HEAD(&ctx->uobj_list);
	ctx->uobj_key = 0;
	ctx->edev = edev;

	__erdma_alloc_sdb(edev, ctx);
	dprint(DBG_CM, "sdb_type:%u,sdb_idx:%u,sdb_page_idx:%u,sdb_page_off:%u,sdb:%llx\n",
		ctx->sdb_type, ctx->sdb_idx, ctx->sdb_page_idx, ctx->sdb_page_off, ctx->sdb);

	ctx->rdb = edev->func_bar_addr + ERDMA_BAR_SQDB_SPACE_OFFSET + ERDMA_BAR_RQDB_SPACE_OFFSET;
	ctx->cdb = edev->func_bar_addr + ERDMA_BAR_SQDB_SPACE_OFFSET + ERDMA_BAR_CQDB_SPACE_OFFSET;

	if (udata->outlen < sizeof(uresp)) {
		rv = -EINVAL;
		goto err_out;
	}

	uresp.sdb = erdma_insert_uobj(ctx, (void *)ctx->sdb, PAGE_SIZE, ERDMA_MMAP_IO_NC);
	if (uresp.sdb == ERDMA_MAX_UOBJ_KEY) {
		rv = -EINVAL;
		goto err_out;
	}

	uresp.rdb = erdma_insert_uobj(ctx, (void *)ctx->rdb, PAGE_SIZE, ERDMA_MMAP_IO_NC);
	if (uresp.rdb == ERDMA_MAX_UOBJ_KEY) {
		rv = -EINVAL;
		goto err_out;
	}

	uresp.cdb = erdma_insert_uobj(ctx, (void *)ctx->cdb, PAGE_SIZE, ERDMA_MMAP_IO_NC);
	if (uresp.cdb == ERDMA_MAX_UOBJ_KEY) {
		rv = -EINVAL;
		goto err_out;
	}

	uresp.dev_id = edev->attrs.vendor_part_id;
	uresp.sdb_type = ctx->sdb_type;
	uresp.sdb_offset = ctx->sdb_page_off;

	rv = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
	if (rv)
		goto err_out;

	return 0;

err_out:

	atomic_dec(&edev->num_ctx);
	return rv;
}


void erdma_dealloc_ucontext(struct ib_ucontext *ibctx)
{
	struct erdma_ucontext *ctx = to_ectx(ibctx);
	struct erdma_dev      *dev = ctx->edev;

	spin_lock(&dev->db_bitmap_lock);
	if (ctx->sdb_type == ERDMA_SDB_PAGE)
		clear_bit(ctx->sdb_idx, dev->sdb_page);
	else if (ctx->sdb_type == ERDMA_SDB_ENTRY)
		clear_bit(ctx->sdb_idx, dev->sdb_entry);

	spin_unlock(&dev->db_bitmap_lock);

	atomic_dec(&ctx->edev->num_ctx);
}

static int ib_qp_state_to_erdma_qp_state[IB_QPS_ERR+1] = {
	[IB_QPS_RESET]	= ERDMA_QP_STATE_IDLE,
	[IB_QPS_INIT]	= ERDMA_QP_STATE_IDLE,
	[IB_QPS_RTR]	= ERDMA_QP_STATE_RTR,
	[IB_QPS_RTS]	= ERDMA_QP_STATE_RTS,
	[IB_QPS_SQD]	= ERDMA_QP_STATE_CLOSING,
	[IB_QPS_SQE]	= ERDMA_QP_STATE_TERMINATE,
	[IB_QPS_ERR]	= ERDMA_QP_STATE_ERROR
};


int erdma_modify_qp_raw(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		    int attr_mask, struct ib_udata *udata)
{
	struct erdma_qp *qp = to_eqp(ibqp);
	struct erdma_qp_attrs new_attrs;
	enum erdma_qp_attr_mask erdma_attr_mask = 0;
	int ret;

	if (!attr_mask) {
		dprint(DBG_CM, "(QP%d): attr_mask==0 ignored\n", QP_ID(qp));
		return -EINVAL;
	}
	memset(&new_attrs, 0, sizeof(new_attrs));

	if (attr_mask & IB_QP_ACCESS_FLAGS) {
		erdma_attr_mask |= ERDMA_QP_ATTR_ACCESS_FLAGS;
		if (attr->qp_access_flags & IB_ACCESS_REMOTE_READ)
			new_attrs.flags |= ERDMA_READ_ENABLED;
		if (attr->qp_access_flags & IB_ACCESS_REMOTE_WRITE)
			new_attrs.flags |= ERDMA_WRITE_ENABLED;
		if (attr->qp_access_flags & IB_ACCESS_MW_BIND)
			new_attrs.flags |= ERDMA_BIND_ENABLED;
	}

	if (attr_mask & IB_QP_STATE) {
		dprint(DBG_CM, "(QP%d): Desired IB QP state: %s\n",
			   QP_ID(qp), ib_qp_state_to_string[attr->qp_state]);
		if (attr->qp_state == IB_QPS_INIT)
			return 0;

		new_attrs.state = ib_qp_state_to_erdma_qp_state[attr->qp_state];

		if (qp->is_kernel_qp && new_attrs.state == ERDMA_QP_STATE_RTR)
			new_attrs.state = ERDMA_QP_STATE_RTS;
		if (new_attrs.state == ERDMA_QP_STATE_UNDEF)
			return -EINVAL;
		erdma_attr_mask |= ERDMA_QP_ATTR_STATE;
	}

	down_write(&qp->state_lock);
	ret = erdma_modify_qp_internal_raw(qp, &new_attrs, erdma_attr_mask);
	up_write(&qp->state_lock);
	if (ret)
		return ret;

	qp->attrs.state = new_attrs.state;
	qp->attrs.llp_stream_handle = new_attrs.llp_stream_handle;

	return 0;
}

int erdma_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		    int attr_mask, struct ib_udata *udata)
{
	struct erdma_qp_attrs   new_attrs;
	enum erdma_qp_attr_mask erdma_attr_mask = 0;
	struct erdma_qp         *qp             = to_eqp(ibqp);
	int                     rv              = 0;

	if (qp->without_cm)
		return erdma_modify_qp_raw(ibqp, attr, attr_mask, udata);

	if (!attr_mask) {
		dprint(DBG_CM, "(QP%d): attr_mask==0 ignored\n", QP_ID(qp));
		goto out;
	}

	erdma_dprint_qp_attr_mask(attr_mask);

	memset(&new_attrs, 0, sizeof(new_attrs));

	if (attr_mask & IB_QP_ACCESS_FLAGS) {

		erdma_attr_mask |= ERDMA_QP_ATTR_ACCESS_FLAGS;

		if (attr->qp_access_flags & IB_ACCESS_REMOTE_READ)
			new_attrs.flags |= ERDMA_READ_ENABLED;
		if (attr->qp_access_flags & IB_ACCESS_REMOTE_WRITE)
			new_attrs.flags |= ERDMA_WRITE_ENABLED;
		if (attr->qp_access_flags & IB_ACCESS_MW_BIND)
			new_attrs.flags |= ERDMA_BIND_ENABLED;
	}

	if (attr_mask & IB_QP_STATE) {
		dprint(DBG_CM, "(QP%d): Desired IB QP state: %s\n",
			   QP_ID(qp), ib_qp_state_to_string[attr->qp_state]);

		new_attrs.state = ib_qp_state_to_erdma_qp_state[attr->qp_state];

		if (new_attrs.state == ERDMA_QP_STATE_UNDEF)
			return -EINVAL;

		erdma_attr_mask |= ERDMA_QP_ATTR_STATE;
	}

	down_write(&qp->state_lock);

	rv = erdma_modify_qp_internal(qp, &new_attrs, erdma_attr_mask);

	up_write(&qp->state_lock);

out:
	dprint(DBG_CM, "(QP%d): Exit with %d\n", QP_ID(qp), rv);
	return rv;
}

/*
 * Approximate translation of real MTU for IB.
 */
static inline enum ib_mtu erdma_mtu_net2ib(unsigned short mtu)
{
	if (mtu >= 4096)
		return IB_MTU_4096;
	if (mtu >= 2048)
		return IB_MTU_2048;
	if (mtu >= 1024)
		return IB_MTU_1024;
	if (mtu >= 512)
		return IB_MTU_512;
	if (mtu >= 256)
		return IB_MTU_256;
	return IB_MTU_4096;
}

/*
 * Minimum erdma_query_qp() verb interface.
 *
 * @qp_attr_mask is not used but all available information is provided
 */
int erdma_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr,
		 int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr)
{
	struct erdma_qp *qp;
	struct erdma_dev *edev;

	if (ibqp && qp_attr && qp_init_attr) {
		qp = to_eqp(ibqp);
		edev = to_edev(ibqp->device);
	} else
		return -EINVAL;

	qp_attr->cap.max_inline_data = ERDMA_MAX_INLINE;
	qp_init_attr->cap.max_inline_data = ERDMA_MAX_INLINE;

	qp_attr->cap.max_send_wr = qp->attrs.sq_size;
	qp_attr->cap.max_recv_wr = qp->attrs.rq_size;
	qp_attr->cap.max_send_sge = qp->attrs.sq_max_sges;
	qp_attr->cap.max_recv_sge = qp->attrs.rq_max_sges;

	qp_attr->path_mtu = erdma_mtu_net2ib(edev->netdev->mtu);
	qp_attr->max_rd_atomic = qp->attrs.irq_size;
	qp_attr->max_dest_rd_atomic = qp->attrs.orq_size;

	qp_attr->qp_access_flags = IB_ACCESS_LOCAL_WRITE |
			IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ;

	qp_init_attr->cap = qp_attr->cap;

	return 0;
}



/*
 * erdma_create_cq()
 *
 * Create CQ of requested size on given device.
 *
 * @ibdev:	OFA device contained in erdma device
 * @size:	maximum number of CQE's allowed.
 * @ib_context: user context.
 * @udata:	used to provide CQ ID back to user.
 */
int erdma_create_cq(struct ib_cq *ibcq,
		    const struct ib_cq_init_attr *attr,
		    struct ib_udata *udata)
{
	struct erdma_cq                *cq     = to_ecq(ibcq);
	struct erdma_dev               *edev   = to_edev(ibcq->device);
	struct erdma_uresp_create_cq   uresp;
	int                            rv;
	unsigned int                   size    = attr->cqe;
	struct erdma_ucontext          *ctx    =
		rdma_udata_to_drv_context(udata, struct erdma_ucontext, ib_ucontext);
	struct erdma_create_cq_params  params;
	bool user_access = (udata != NULL) ? true : false;

	if (size > edev->attrs.max_cqe) {
		dev_warn(&edev->pdev->dev,
			"WARN: exceed cqe(%d) > capbility(%d)\n",
			size, edev->attrs.max_cqe);
		rv = -EINVAL;
		goto err_out;
	}

	if (atomic_inc_return(&edev->num_cq) > edev->attrs.max_cq) {
		dev_err(&edev->pdev->dev,
			"ERROR: total cq number exceed (max cq %d)\n",
			edev->attrs.max_cq);
		rv = -ENOMEM;
		goto err_out_dec;
	}

#ifdef ERDMA_ENABLE_DEBUG
	cq->snapshot = alloc_pages_exact(4096, GFP_KERNEL | __GFP_ZERO);
	if (!cq->snapshot) {
		rv = -ENOMEM;
		goto err_out_free;
	}
#endif

	size = roundup_pow_of_two(size);
	cq->ibcq.cqe = size;
	cq->depth = size;
	cq->assoc_eqn = attr->comp_vector + 1;

	cq->owner = 1;

	cq->queue = dma_alloc_coherent(&edev->pdev->dev,
		size * sizeof(struct erdma_cqe), &cq->qbuf_dma_addr, GFP_KERNEL);
	if (cq->queue == NULL) {
		rv = -ENOMEM;
		pr_err("ERROR: Cannot malloc queue buffer.\n");
		goto err_out_free;
	}

	rv = erdma_cq_add(edev, cq);
	if (rv)
		goto err_out_free;

	dprint(DBG_CQ, "CQN(%u) va:%p,pa:%llx,dma_addr:%llx,depth:%u\n",
		CQ_ID(cq), cq->queue, virt_to_phys(cq->queue),
		cq->qbuf_dma_addr, cq->depth);

	params.cqn = cq->hdr.id;
	params.depth = cq->depth;
	params.eqn = cq->assoc_eqn;
	params.queue_addr = cq->qbuf_dma_addr;
	rv = erdma_exec_create_cq_cmd(edev, &params);
	if (rv)
		goto err_out_idr;

	spin_lock_init(&cq->lock);

	if (user_access) {
		//memset(&uresp, 0, sizeof(uresp));

		uresp.cq_key = erdma_insert_uobj(ctx, (void *)virt_to_phys(cq->queue),
			size * sizeof(struct erdma_cqe), ERDMA_MMAP_DMA_PAGE);
		if (uresp.cq_key >= ERDMA_MAX_UOBJ_KEY)
			pr_warn("Preparing mmap CQ failed\n");

#ifdef ERDMA_ENABLE_DEBUG
		uresp.dbg_key = erdma_insert_uobj(ctx, (void *)virt_to_phys(cq->snapshot),
			4096, ERDMA_MMAP_DBG_PAGE);
		if (uresp.dbg_key >= ERDMA_MAX_UOBJ_KEY)
			pr_warn("Preparing dbg page failed\n");
#endif

		uresp.cq_id = OBJ_ID(cq);
		uresp.num_cqe = size;

		rv = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (rv)
			goto err_out_idr;
	} else {
		cq->db = edev->func_bar + ERDMA_BAR_SQDB_SPACE_OFFSET + ERDMA_BAR_CQDB_SPACE_OFFSET;
	}

	return 0;

err_out_idr:
	erdma_remove_obj(&edev->idr_lock, &edev->cq_idr, &cq->hdr);

err_out_free:
	dprint(DBG_OBJ, ": CQ creation failed %d", rv);
#ifdef ERDMA_ENABLE_DEBUG
	if (cq->snapshot)
		free_pages_exact(cq->snapshot, 4096);
#endif
	if (cq && cq->queue)
		dma_free_coherent(&edev->pdev->dev,
			size * sizeof(struct erdma_cqe), cq->queue, cq->qbuf_dma_addr);

err_out_dec:
	atomic_dec(&edev->num_cq);
err_out:
	return rv;
}

static inline u32 map_send_flags(int ib_flags)
{
	u32 flags = ERDMA_WQE_VALID;

	if (ib_flags & IB_SEND_SIGNALED)
		flags |= ERDMA_WQE_SIGNALLED;
	if (ib_flags & IB_SEND_SOLICITED)
		flags |= ERDMA_WQE_SOLICITED;
	if (ib_flags & IB_SEND_INLINE)
		flags |= ERDMA_WQE_INLINE;
	if (ib_flags & IB_SEND_FENCE)
		flags |= ERDMA_WQE_READ_FENCE;

	return flags;
}

static inline void
erdma_fill_sqe_hdr(struct ib_qp *ibqp, const struct ib_send_wr *send_wr,
					struct erdma_sqe_common_hdr *wqe_hdr, unsigned int sq_pi)
{
	struct erdma_qp *qp = (struct erdma_qp *)ibqp;
	u32 flags = map_send_flags(send_wr->send_flags);

	switch (send_wr->opcode) {
	case IB_WR_RDMA_WRITE:
		wqe_hdr->opcode = ERDMA_OP_WRITE;
		break;
	case IB_WR_RDMA_WRITE_WITH_IMM:
		wqe_hdr->opcode = ERDMA_OP_WRITE_WITH_IMM;
		break;
	case IB_WR_SEND:
		wqe_hdr->opcode = ERDMA_OP_SEND;
		break;
	case IB_WR_SEND_WITH_IMM:
		wqe_hdr->opcode = ERDMA_OP_SEND_WITH_IMM;
		break;
	case IB_WR_REG_MR:
		wqe_hdr->opcode = ERDMA_OP_REG_MR;
	default:
		break;
	}

	wqe_hdr->sgl_len = send_wr->num_sge;
	wqe_hdr->ce = flags & ERDMA_WQE_SIGNALLED ? 1 : 0;
	wqe_hdr->se = flags & ERDMA_WQE_SOLICITED ? 1 : 0;
	wqe_hdr->fence = flags & ERDMA_WQE_READ_FENCE ? 1 : 0;
	/* force no-inline currently */
	wqe_hdr->is_inline = 0;
	wqe_hdr->dwqe = 0;
	wqe_hdr->qpn = QP_ID(qp);
	wqe_hdr->wqebb_idx = sq_pi;
}

static inline int
sgl_fill_buf(void *dest, struct ib_sge *sg_list, int num_sge, int max_size)
{
	int size = 0;
	int i;

	for (i = 0; i < num_sge; i++) {
		size += sg_list[i].length;
		if (size > max_size)
			return -1;

		memcpy(dest, (void *)sg_list[i].addr, sg_list[i].length);
		dest += sg_list[i].length;
	}
	return size;
}

int erdma_wr_write(struct ib_qp *ibqp,
		const struct ib_send_wr *send_wr,
		const struct ib_send_wr **bad_send_wr)
{
	struct erdma_qp *qp = (struct erdma_qp *)ibqp;
	struct erdma_write_sqe *sqe;
	struct erdma_sqe_common_hdr *wqe_hdr;
	struct ib_rdma_wr *rdma_wr = container_of(send_wr, struct ib_rdma_wr, wr);
	unsigned int sq_pi;
	u32 wqe_size;
	int ret;
	u32 idx = qp->sq_pi & (qp->sendq.depth - 1);

	sq_pi = qp->sq_pi;
	sqe = (struct erdma_write_sqe *)(qp->sendq.qbuf + idx * ERDMA_SQ_WQEBB_SIZE);
	wqe_hdr = &sqe->hdr;
	*(__u64 *)sqe = 0;

	erdma_fill_sqe_hdr(ibqp, send_wr, wqe_hdr, sq_pi);
	sqe->imm_data = send_wr->ex.imm_data;
	sqe->sink_stag = rdma_wr->rkey;
	sqe->sink_to_low = *(__u32 *)(&rdma_wr->remote_addr);
	sqe->sink_to_high = *((__u32 *)(&rdma_wr->remote_addr) + 1);
	sqe->length = 0;

	wqe_size = sizeof(struct erdma_write_sqe);

	if (wqe_hdr->is_inline) {
		ret = sgl_fill_buf((void *)sqe->sgl, send_wr->sg_list,
					send_wr->num_sge, ERDMA_MAX_INLINE);
		if (ret < 0)
			return -EINVAL;
		wqe_size += ret;
		sqe->length = ret;
	} else {
		int i = 0;

		if (send_wr->num_sge > ERDMA_MAX_SEND_SGE)
			return -EINVAL;

		sqe->length = 0;
		for (i = 0; i < send_wr->num_sge; i++)
			sqe->length += send_wr->sg_list[i].length;

		if (idx == qp->sendq.depth - 1)
			memcpy((void *)qp->sendq.qbuf, send_wr->sg_list,
					send_wr->num_sge * sizeof(struct ib_sge));
		else
			memcpy((void *)sqe->sgl, send_wr->sg_list,
					send_wr->num_sge * sizeof(struct ib_sge));
		wqe_size += wqe_hdr->sgl_len * 16;
	}

	wqe_hdr->wqebb_cnt = (wqe_size + (ERDMA_SQ_WQEBB_SIZE - 1)) / ERDMA_SQ_WQEBB_SIZE - 1;
	wqe_hdr->wqebb_idx = sq_pi + wqe_hdr->wqebb_cnt + 1;

	qp->sq_pi = wqe_hdr->wqebb_idx;
	qp->sendq.wr_tbl[sq_pi & (qp->sendq.depth - 1)] = send_wr->wr_id;

	/* qbuf should be ready when kcik the db */
	mb();
	*(__u64 *)qp->sq_db = *(__u64 *)wqe_hdr;

	return 0;
}

int erdma_wr_send(struct ib_qp *ibqp,
		const struct ib_send_wr *send_wr,
		const struct ib_send_wr **bad_send_wr)
{
	struct erdma_qp *qp = (struct erdma_qp *)ibqp;
	struct erdma_send_sqe *sqe;
	struct erdma_sqe_common_hdr *wqe_hdr;
	unsigned int sq_pi;
	u32 wqe_size;
	int ret;
	u32 idx = qp->sq_pi & (qp->sendq.depth - 1);

	sq_pi = qp->sq_pi;
	sqe = (struct erdma_send_sqe *)(qp->sendq.qbuf + idx * ERDMA_SQ_WQEBB_SIZE);
	wqe_hdr = &sqe->hdr;
	*(__u64 *)sqe = 0;

	erdma_fill_sqe_hdr(ibqp, send_wr, wqe_hdr, sq_pi);
	sqe->imm_data = send_wr->ex.imm_data;
	wqe_size = sizeof(struct erdma_send_sqe);

	if (wqe_hdr->is_inline) {
		ret = sgl_fill_buf((void *)sqe->sgl, send_wr->sg_list,
					send_wr->num_sge, ERDMA_MAX_INLINE);
		if (ret < 0)
			return -EINVAL;
		wqe_size += ret;
		sqe->length = ret;
	} else {
		int i = 0;

		if (send_wr->num_sge > ERDMA_MAX_SEND_SGE)
			return -EINVAL;

		sqe->length = 0;
		for (i = 0; i < send_wr->num_sge; i++)
			sqe->length += send_wr->sg_list[i].length;

		memcpy((void *)sqe->sgl, send_wr->sg_list,
				send_wr->num_sge * sizeof(struct ib_sge));
		wqe_size += wqe_hdr->sgl_len * 16;
	}

	wqe_hdr->wqebb_cnt = (wqe_size + (ERDMA_SQ_WQEBB_SIZE - 1)) / ERDMA_SQ_WQEBB_SIZE - 1;
	wqe_hdr->wqebb_idx = sq_pi + wqe_hdr->wqebb_cnt + 1;

	qp->sq_pi = wqe_hdr->wqebb_idx;
	qp->sendq.wr_tbl[sq_pi & (qp->sendq.depth - 1)] = send_wr->wr_id;

	/* qbuf should be ready when kcik the db */
	mb();
	*(__u64 *)qp->sq_db = *(__u64 *)wqe_hdr;

	return 0;
}

static int
erdma_validate_mr(struct ib_qp *ibqp,
				const struct ib_send_wr *send_wr,
				const struct ib_send_wr **bad_send_wr)
{
	struct erdma_qp *qp = (struct erdma_qp *)ibqp;
	struct erdma_mr *mr = to_emr(reg_wr(send_wr)->mr);
	struct erdma_reg_mr_sqe *sqe;
	struct erdma_sqe_common_hdr *wqe_hdr;
	unsigned int sq_pi;
	u32 wqe_size;
	u32 idx = qp->sq_pi & (qp->sendq.depth - 1);

	dprint(DBG_ON, "validate mr");

	sq_pi = qp->sq_pi;
	sqe = (struct erdma_reg_mr_sqe *)(qp->sendq.qbuf + idx * ERDMA_SQ_WQEBB_SIZE);
	wqe_hdr = &sqe->hdr;
	*(__u64 *)sqe = 0;

	erdma_fill_sqe_hdr(ibqp, send_wr, wqe_hdr, sq_pi);
	wqe_size = sizeof(struct erdma_reg_mr_sqe);

	sqe->addr = mr->ibmr.iova;
	sqe->length = mr->ibmr.length;
	sqe->stag = mr->ibmr.lkey;

	wqe_hdr->wqebb_cnt = (wqe_size + (ERDMA_SQ_WQEBB_SIZE - 1)) / ERDMA_SQ_WQEBB_SIZE - 1;
	wqe_hdr->wqebb_idx = sq_pi + wqe_hdr->wqebb_cnt + 1;

	qp->sq_pi = wqe_hdr->wqebb_idx;
	qp->sendq.wr_tbl[sq_pi & (qp->sendq.depth - 1)] = send_wr->wr_id;

	/* qbuf should be ready when kcik the db */
	mb();
	*(__u64 *)qp->sq_db = *(__u64 *)wqe_hdr;

	return 0;
}

int
erdma_post_send(struct ib_qp *qp,
				const struct ib_send_wr *send_wr,
				const struct ib_send_wr **bad_send_wr)
{
	struct erdma_qp *eqp = to_eqp(qp);
	int ret = 0;
	const struct ib_send_wr *wr = send_wr;
	unsigned long flags;

	if (!qp || !send_wr)
		return -EINVAL;

	spin_lock_irqsave(&eqp->lock, flags);  /* loop */
	while (wr) {
		switch (send_wr->opcode) {
		case IB_WR_RDMA_WRITE:
		case IB_WR_RDMA_WRITE_WITH_IMM:
			ret = erdma_wr_write(qp, wr, bad_send_wr);
			if (ret)
				dprint(DBG_ON, "erdma_wr_write failed %d", ret);
			break;
		case IB_WR_SEND:
		case IB_WR_SEND_WITH_IMM:
			ret = erdma_wr_send(qp, wr, bad_send_wr);
			if (ret)
				dprint(DBG_ON, "erdma_wr_send failed %d", ret);
			break;
		case IB_WR_RDMA_READ:
		case IB_WR_ATOMIC_CMP_AND_SWP:
		case IB_WR_ATOMIC_FETCH_AND_ADD:
		case IB_WR_LSO:
		case IB_WR_SEND_WITH_INV:
		case IB_WR_RDMA_READ_WITH_INV:
		case IB_WR_LOCAL_INV:
		case IB_WR_REG_MR:
			ret = erdma_validate_mr(qp, wr, bad_send_wr);
			break;
		case IB_WR_MASKED_ATOMIC_CMP_AND_SWP:
		case IB_WR_MASKED_ATOMIC_FETCH_AND_ADD:
			ret = -EOPNOTSUPP;
			break;
		default:
			ret =  -EINVAL;
		}
		if (ret)
			break;
		wr = wr->next;
	}

	spin_unlock_irqrestore(&eqp->lock, flags);
	return ret;
}

int erdma_post_recv_one(struct ib_qp *ibqp, const struct ib_recv_wr *recv_wr,
		const struct ib_recv_wr **bad_recv_wr)
{
	struct erdma_qp *qp = to_eqp(ibqp);
	struct erdma_rqe *rqe;
	unsigned int rq_pi;
	u16 idx;

	rq_pi = qp->rq_pi;
	idx = rq_pi & (qp->recvq.depth - 1);
	rqe = (struct erdma_rqe *)qp->recvq.qbuf + idx;

	rqe->qe_idx = rq_pi + 1;
	rqe->dwqe = 1;
	rqe->qpn = QP_ID(qp);

	if (recv_wr->num_sge == 0) {
		rqe->length = 0;
	} else if (recv_wr->num_sge == 1) {
		rqe->stag = recv_wr->sg_list[0].lkey;
		rqe->to = recv_wr->sg_list[0].addr;
		rqe->length = recv_wr->sg_list[0].length;
	} else {
		pr_info("erdma post recv not support more than 1 sge");
		return -EINVAL;
	}

	/* qbuf should be ready when kcik the db */
	mb();

	rqe_kickoff(rqe, qp->rq_db);

	qp->recvq.wr_tbl[idx] = recv_wr->wr_id;
	qp->rq_pi = rq_pi + 1;

	return 0;
}

int
erdma_post_recv(struct ib_qp *qp,
				const struct ib_recv_wr *recv_wr,
				const struct ib_recv_wr **bad_recv_wr)
{
	struct erdma_qp *eqp = to_eqp(qp);
	int ret = 0;
	const struct ib_recv_wr *wr = recv_wr;
	unsigned long flags;

	if (!qp || !recv_wr)
		return -EINVAL;

	spin_lock_irqsave(&eqp->lock, flags);
	while (wr) {
		ret = erdma_post_recv_one(qp, wr, bad_recv_wr);
		if (ret)
			dprint(DBG_ON, "erdma_wr_send failed %d\n", ret);
		wr = wr->next;
	}
	spin_unlock_irqrestore(&eqp->lock, flags);
	return ret;
}

static const struct {
	enum erdma_opcode erdma;
	enum ib_wc_opcode base;
} map_cqe_opcode[ERDMA_NUM_OPCODES] = {
	{ ERDMA_OP_WRITE, IB_WC_RDMA_WRITE },
	{ ERDMA_OP_READ, IB_WC_RDMA_READ },
	{ ERDMA_OP_SEND, IB_WC_SEND },
	{ ERDMA_OP_SEND_WITH_IMM, IB_WC_SEND },
	{ ERDMA_OP_RECEIVE, IB_WC_RECV },
	{ ERDMA_OP_RECV_IMM, IB_WC_RECV_RDMA_WITH_IMM },
	{ ERDMA_OP_RECV_INV, IB_WC_LOCAL_INV}, /* confirm afterwards */
	{ ERDMA_OP_REQ_ERR, IB_WC_RECV }, /* remove afterwards */
	{ ERDNA_OP_READ_RESPONSE, IB_WC_RECV }, /* can not appear */
	{ ERDMA_OP_WRITE_WITH_IMM, IB_WC_RDMA_WRITE },
	{ ERDMA_OP_RECV_ERR, IB_WC_RECV_RDMA_WITH_IMM }, /* can not appear */
	{ ERDMA_OP_REG_MR, IB_WC_REG_MR },
};

static const struct {
	enum erdma_wc_status erdma;
	enum ib_wc_status base;
	enum erdma_vendor_err vendor;
} map_cqe_status[ERDMA_NUM_WC_STATUS] = {
	{ ERDMA_WC_SUCCESS, IB_WC_SUCCESS, ERDMA_WC_VENDOR_NO_ERR },
	{ ERDMA_WC_GENERAL_ERR, IB_WC_GENERAL_ERR, ERDMA_WC_VENDOR_NO_ERR },
	{ ERDMA_WC_RECV_WQE_FORMAT_ERR, IB_WC_GENERAL_ERR, ERDMA_WC_VENDOR_INVALID_RQE },
	{ ERDMA_WC_RECV_STAG_INVALID_ERR, IB_WC_REM_ACCESS_ERR,
			ERDMA_WC_VENDOR_RQE_INVALID_STAG },
	{ ERDMA_WC_RECV_ADDR_VIOLATION_ERR, IB_WC_REM_ACCESS_ERR,
			ERDMA_WC_VENDOR_RQE_ADDR_VIOLATION },
	{ ERDMA_WC_RECV_RIGHT_VIOLATION_ERR, IB_WC_REM_ACCESS_ERR,
			ERDMA_WC_VENDOR_RQE_ACCESS_RIGHT_ERR },
	{ ERDMA_WC_RECV_PDID_ERR, IB_WC_REM_ACCESS_ERR, ERDMA_WC_VENDOR_RQE_INVALID_PD },
	{ ERDMA_WC_RECV_WARRPING_ERR, IB_WC_REM_ACCESS_ERR, ERDMA_WC_VENDOR_RQE_WRAP_ERR },
	{ ERDMA_WC_SEND_WQE_FORMAT_ERR, IB_WC_LOC_QP_OP_ERR, ERDMA_WC_VENDOR_INVALID_SQE },
	{ ERDMA_WC_SEND_WQE_ORD_EXCEED, IB_WC_GENERAL_ERR, ERDMA_WC_VENDOR_ZERO_ORD },
	{ ERDMA_WC_SEND_STAG_INVALID_ERR, IB_WC_LOC_ACCESS_ERR,
			ERDMA_WC_VENDOR_SQE_INVALID_STAG },
	{ ERDMA_WC_SEND_ADDR_VIOLATION_ERR, IB_WC_LOC_ACCESS_ERR,
			ERDMA_WC_VENDOR_SQE_ADDR_VIOLATION },
	{ ERDMA_WC_SEND_RIGHT_VIOLATION_ERR, IB_WC_LOC_ACCESS_ERR,
			ERDMA_WC_VENDOR_SQE_ACCESS_ERR },
	{ ERDMA_WC_SEND_PDID_ERR, IB_WC_LOC_ACCESS_ERR, ERDMA_WC_VENDOR_SQE_INVALID_PD },
	{ ERDMA_WC_SEND_WARRPING_ERR, IB_WC_LOC_ACCESS_ERR, ERDMA_WC_VENDOR_SQE_WARP_ERR },
	{ ERDMA_WC_FLUSH_ERR, IB_WC_WR_FLUSH_ERR, ERDMA_WC_VENDOR_NO_ERR },
	{ ERDMA_WC_RETRY_EXC_ERR, IB_WC_RETRY_EXC_ERR, ERDMA_WC_VENDOR_NO_ERR },
};

static int
erdma_poll_one_cqe(struct erdma_cq *cq, struct erdma_cqe *cqe, struct ib_wc *wc)
{
	struct erdma_dev *edev = cq->hdr.edev;
	struct erdma_qp *qp;
	struct erdma_cqe_hdr cqe_hdr;
	u64 *id_table;
	u32 qpn = htonl(cqe->qpn);
	u16 wqe_idx = htonl(cqe->qe_idx);
	u16 depth;

	*(u32 *)&cqe_hdr = *(u32 *)cqe;

	qp = erdma_qp_id2obj(edev, qpn);

	if (cqe_hdr.qtype == ERDMA_CQE_QTYPE_SQ) {
		id_table = qp->sendq.wr_tbl;
		depth = qp->sendq.depth;
		/* todo keep order*/
		/*ci update*/
	} else {
		id_table = qp->recvq.wr_tbl;
		depth = qp->recvq.depth;
	}
	wc->wr_id = id_table[wqe_idx & (depth - 1)];
	wc->byte_len = htonl(cqe->size);

	wc->wc_flags = 0;

	wc->opcode = map_cqe_opcode[cqe_hdr.opcode].base;
	if (wc->opcode == IB_WC_RECV_RDMA_WITH_IMM) {
		wc->ex.imm_data = cpu_to_be32(cqe->imm_data);
		wc->wc_flags |= IB_WC_WITH_IMM;
	}

	if (cqe_hdr.syndrome >= ERDMA_NUM_WC_STATUS)
		cqe_hdr.syndrome = ERDMA_WC_GENERAL_ERR;

	wc->status = map_cqe_status[cqe_hdr.syndrome].base;
	wc->vendor_err = map_cqe_status[cqe_hdr.syndrome].vendor;
	wc->qp = &qp->ibqp;

	return 0;
}

int erdma_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	struct erdma_cq *cq;
	struct erdma_cqe *cqe;
	u32 owner;
	u32 ci;
	int i, ret;
	int new = 0;

	if (!ibcq || !wc)
		return -EINVAL;

	cq = to_ecq(ibcq);
	owner = cq->owner;
	ci = cq->ci;

	for (i = 0; i < num_entries; i++) {
		cqe = &cq->queue[ci & (cq->depth - 1)];

		if (((cqe->owner & 0x80) >> 7) != owner)
			break;
		/* cqbuf should be ready when we poll*/
		mb();
		ret = erdma_poll_one_cqe(cq, cqe, wc);
		if (ret) {
			dprint(DBG_ON, "poll one cqe error");
		} else {
			wc++;
			new++;
		}

		ci++;
		if ((ci & (cq->depth - 1)) == 0)
			owner = !owner;
	}
	cq->owner = owner;
	cq->ci = ci;

	return new;
}


struct net_device *erdma_get_netdev(struct ib_device *device, u8 port_num)
{
	struct erdma_dev *edev = to_edev(device);

	return edev->netdev;
}

void erdma_disassociate_ucontext(struct ib_ucontext *ibcontext)
{
}
