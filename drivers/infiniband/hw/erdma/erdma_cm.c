// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
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

#include <linux/errno.h>
#include <linux/inetdevice.h>
#include <linux/net.h>
#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <net/sock.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_verbs.h>

#include "erdma.h"
#include "erdma_cm.h"
#include "erdma_obj.h"

static bool mpa_crc_strict = 1;
module_param(mpa_crc_strict, bool, 0644);
static bool mpa_crc_required;
module_param(mpa_crc_required, bool, 0644);

MODULE_PARM_DESC(mpa_crc_required, "MPA CRC required");
MODULE_PARM_DESC(mpa_crc_strict, "MPA CRC off enforced");

static void erdma_cm_llp_state_change(struct sock *sk);
static void erdma_cm_llp_data_ready(struct sock *sk);
static void erdma_cm_llp_write_space(struct sock *sk);
static void erdma_cm_llp_error_report(struct sock *sk);

static void erdma_sk_assign_cm_upcalls(struct sock *sk)
{
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_state_change = erdma_cm_llp_state_change;
	sk->sk_data_ready   = erdma_cm_llp_data_ready;
	sk->sk_write_space  = erdma_cm_llp_write_space;
	sk->sk_error_report = erdma_cm_llp_error_report;
	write_unlock_bh(&sk->sk_callback_lock);
}

static void erdma_sk_save_upcalls(struct sock *sk)
{
	struct erdma_cep *cep = sk_to_cep(sk);

	WARN_ON(!cep);

	write_lock_bh(&sk->sk_callback_lock);
	cep->sk_state_change = sk->sk_state_change;
	cep->sk_data_ready   = sk->sk_data_ready;
	cep->sk_write_space  = sk->sk_write_space;
	cep->sk_error_report = sk->sk_error_report;
	write_unlock_bh(&sk->sk_callback_lock);
}

static void erdma_sk_restore_upcalls(struct sock *sk, struct erdma_cep *cep)
{
	sk->sk_state_change	= cep->sk_state_change;
	sk->sk_data_ready	= cep->sk_data_ready;
	sk->sk_write_space	= cep->sk_write_space;
	sk->sk_error_report	= cep->sk_error_report;
	sk->sk_user_data	= NULL;
}

static void erdma_socket_disassoc(struct socket *s)
{
	struct sock	*sk = s->sk;
	struct erdma_cep	*cep;

	if (sk) {
		write_lock_bh(&sk->sk_callback_lock);
		cep = sk_to_cep(sk);
		if (cep) {
			erdma_sk_restore_upcalls(sk, cep);
			erdma_cep_put(cep);
		} else
			pr_warn("cannot restore sk callbacks: no ep\n");
		write_unlock_bh(&sk->sk_callback_lock);
	} else
		pr_warn("cannot restore sk callbacks: no sk\n");
}


static inline int kernel_peername(struct socket *s, struct sockaddr_in *addr)
{
	return s->ops->getname(s, (struct sockaddr *)addr, 1);
}

static inline int kernel_localname(struct socket *s, struct sockaddr_in *addr)
{
	return s->ops->getname(s, (struct sockaddr *)addr, 0);
}

static void erdma_cep_socket_assoc(struct erdma_cep *cep, struct socket *s)
{
	cep->llp.sock = s;
	erdma_cep_get(cep);
	s->sk->sk_user_data = cep;

	erdma_sk_save_upcalls(s->sk);
	erdma_sk_assign_cm_upcalls(s->sk);
}


static struct erdma_cep *erdma_cep_alloc(struct erdma_dev  *edev)
{
	struct erdma_cep *cep = kzalloc(sizeof(*cep), GFP_KERNEL);

	if (cep) {
		unsigned long flags;

		INIT_LIST_HEAD(&cep->listenq);
		INIT_LIST_HEAD(&cep->devq);
		INIT_LIST_HEAD(&cep->work_freelist);

		kref_init(&cep->ref);
		cep->state = ERDMA_EPSTATE_IDLE;
		init_waitqueue_head(&cep->waitq);
		spin_lock_init(&cep->lock);
		cep->edev = edev;

		spin_lock_irqsave(&edev->idr_lock, flags);
		list_add_tail(&cep->devq, &edev->cep_list);
		spin_unlock_irqrestore(&edev->idr_lock, flags);
		atomic_inc(&edev->num_cep);

		dprint(DBG_OBJ|DBG_CM, "(CEP 0x%p): New Object\n", cep);
	}
	return cep;
}

static void erdma_cm_free_work(struct erdma_cep *cep)
{
	struct list_head	*w, *tmp;
	struct erdma_cm_work	*work;

	list_for_each_safe(w, tmp, &cep->work_freelist) {
		work = list_entry(w, struct erdma_cm_work, list);
		list_del(&work->list);
		kfree(work);
	}
}

static void erdma_cancel_mpatimer(struct erdma_cep *cep)
{
	spin_lock_bh(&cep->lock);
	if (cep->mpa_timer) {
		if (cancel_delayed_work(&cep->mpa_timer->work)) {
			erdma_cep_put(cep);
			kfree(cep->mpa_timer); /* not needed again */
		}
		cep->mpa_timer = NULL;
	}
	spin_unlock_bh(&cep->lock);
}

static void erdma_put_work(struct erdma_cm_work *work)
{
	INIT_LIST_HEAD(&work->list);
	spin_lock_bh(&work->cep->lock);
	list_add(&work->list, &work->cep->work_freelist);
	spin_unlock_bh(&work->cep->lock);
}

static void erdma_cep_set_inuse(struct erdma_cep *cep)
{
	unsigned long flags;
	int rv;
retry:
	dprint(DBG_CM, " (CEP 0x%p): use %d\n",
		cep, cep->in_use);

	spin_lock_irqsave(&cep->lock, flags);

	if (cep->in_use) {
		spin_unlock_irqrestore(&cep->lock, flags);
		rv = wait_event_interruptible(cep->waitq, !cep->in_use);
		if (signal_pending(current))
			flush_signals(current);
		goto retry;
	} else {
		cep->in_use = 1;
		spin_unlock_irqrestore(&cep->lock, flags);
	}
}

static void erdma_cep_set_free(struct erdma_cep *cep)
{
	unsigned long flags;

	dprint(DBG_CM, " (CEP 0x%p): use %d\n",
		cep, cep->in_use);

	spin_lock_irqsave(&cep->lock, flags);
	cep->in_use = 0;
	spin_unlock_irqrestore(&cep->lock, flags);

	wake_up(&cep->waitq);
}


static void __erdma_cep_dealloc(struct kref *ref)
{
	struct erdma_cep *cep = container_of(ref, struct erdma_cep, ref);
	struct erdma_dev *edev = cep->edev;
	unsigned long flags;

	dprint(DBG_OBJ|DBG_CM, "(CEP 0x%p): Free Object\n", cep);

	WARN_ON(cep->listen_cep);

	/* kfree(NULL) is save */
	if (cep->private_storage != NULL)
		kfree(cep->private_storage);
	if (cep->private_storage != NULL)
		kfree(cep->mpa.pdata);
	spin_lock_bh(&cep->lock);
	if (!list_empty(&cep->work_freelist))
		erdma_cm_free_work(cep);
	spin_unlock_bh(&cep->lock);

	spin_lock_irqsave(&edev->idr_lock, flags);
	list_del(&cep->devq);
	spin_unlock_irqrestore(&edev->idr_lock, flags);
	atomic_dec(&edev->num_cep);
	kfree(cep);
}

static struct erdma_cm_work *erdma_get_work(struct erdma_cep *cep)
{
	struct erdma_cm_work    *work = NULL;
	unsigned long           flags;

	spin_lock_irqsave(&cep->lock, flags);
	if (!list_empty(&cep->work_freelist)) {
		work = list_entry(cep->work_freelist.next, struct erdma_cm_work,
				  list);
		list_del_init(&work->list);
	}
	spin_unlock_irqrestore(&cep->lock, flags);
	return work;
}

static int erdma_cm_alloc_work(struct erdma_cep *cep, int num)
{
	struct erdma_cm_work        *work;

	if (!list_empty(&cep->work_freelist)) {
		pr_err("ERROR: Not init work_freelist.\n");
		return -ENOMEM;
	}

	while (num--) {
		work = kmalloc(sizeof(*work), GFP_KERNEL);
		if (!work) {
			if (!(list_empty(&cep->work_freelist)))
				erdma_cm_free_work(cep);
			dprint(DBG_ON, " Failed\n");
			return -ENOMEM;
		}
		work->cep = cep;
		INIT_LIST_HEAD(&work->list);
		list_add(&work->list, &cep->work_freelist);
	}
	return 0;
}

/*
 * erdma_cm_upcall()
 *
 * Upcall to IWCM to inform about async connection events
 */
static int erdma_cm_upcall(struct erdma_cep *cep, enum iw_cm_event_type reason,
			 int status)
{
	struct iw_cm_event	event;
	struct iw_cm_id		*cm_id;

	memset(&event, 0, sizeof(event));
	event.status = status;
	event.event = reason;

	if (reason == IW_CM_EVENT_CONNECT_REQUEST ||
	    reason == IW_CM_EVENT_CONNECT_REPLY) {
		__u16 pd_len = be16_to_cpu(cep->mpa.hdr.params.pd_len);

		if (pd_len) {
			/*
			 * hand over MPA private data
			 */
			event.private_data_len = pd_len;
			event.private_data = cep->mpa.pdata;
			if (cep->mpa.pdata == NULL && pd_len) {
				event.private_data_len = 0;
				if (status != 0) {
					pr_err("unexcept situation.!\n");
					pr_err("sip:%x,dip:%x,sport:%x,dport:%x\n",
						cep->llp.raddr.sin_addr.s_addr,
						cep->llp.laddr.sin_addr.s_addr,
						cep->llp.raddr.sin_port,
						cep->llp.laddr.sin_port);
				}
			}
		}

		to_sockaddr_in(event.local_addr) = cep->llp.laddr;
		to_sockaddr_in(event.remote_addr) = cep->llp.raddr;
	}
	if (reason == IW_CM_EVENT_CONNECT_REQUEST) {
		event.ird = cep->edev->attrs.max_ird;
		event.ord = cep->edev->attrs.max_ord;
		event.provider_data = cep;
		cm_id = cep->listen_cep->cm_id;
	} else
		cm_id = cep->cm_id;

	dprint(DBG_CM, " (QP%d): cep=0x%p, id=0x%p, dev(id)=%s, reason=%d, status=%d\n",
		cep->qp ? QP_ID(cep->qp) : -1, cep, cm_id,
		cm_id->device->name, reason, status);

	if (!cep->is_connecting && reason == IW_CM_EVENT_CONNECT_REPLY) {
		dprint(DBG_CM, "unexpected CONNECT_REPLY event");
		return 0;
	}
	cep->is_connecting = false;

	return cm_id->event_handler(cm_id, &event);
}
/*
 * erdma_qp_cm_drop()
 *
 * Drops established LLP connection if present and not already
 * scheduled for dropping. Called from user context, SQ workqueue
 * or receive IRQ. Caller signals if socket can be immediately
 * closed (basically, if not in IRQ).
 */
void erdma_qp_cm_drop(struct erdma_qp *qp, int schedule)
{
	struct erdma_cep *cep = qp->cep;

	if (!qp->cep)
		return;

	if (schedule)
		erdma_cm_queue_work(cep, ERDMA_CM_WORK_CLOSE_LLP);
	else {
		erdma_cep_set_inuse(cep);

		if (cep->state == ERDMA_EPSTATE_CLOSED) {
			dprint(DBG_CM, "(): cep=0x%p, already closed\n", cep);
			goto out;
		}

		/*
		 * Immediately close socket
		 */
		dprint(DBG_CM,
			"(): immediate close, cep=0x%p, state=%d, id=0x%p, sock=0x%p, QP%d\n",
			cep, cep->state,
			cep->cm_id, cep->llp.sock,
			cep->qp ? QP_ID(cep->qp) : -1);

		if (cep->cm_id) {
			switch (cep->state) {

			case ERDMA_EPSTATE_AWAIT_MPAREP:
				erdma_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY,
					      -EINVAL);
				break;

			case ERDMA_EPSTATE_RDMA_MODE:
				erdma_cm_upcall(cep, IW_CM_EVENT_CLOSE, 0);

				break;

			case ERDMA_EPSTATE_IDLE:
			case ERDMA_EPSTATE_LISTENING:
			case ERDMA_EPSTATE_CONNECTING:
			case ERDMA_EPSTATE_AWAIT_MPAREQ:
			case ERDMA_EPSTATE_RECVD_MPAREQ:
			case ERDMA_EPSTATE_CLOSED:
			default:

				break;
			}
			cep->cm_id->rem_ref(cep->cm_id);
			cep->cm_id = NULL;
			erdma_cep_put(cep);
		}
		cep->state = ERDMA_EPSTATE_CLOSED;

		if (cep->llp.sock) {
			erdma_socket_disassoc(cep->llp.sock);
			sock_release(cep->llp.sock);
			cep->llp.sock = NULL;
		}
		if (cep->qp) {
			WARN_ON(qp != cep->qp);
			cep->qp = NULL;
			erdma_qp_put(qp);
		}
out:
		erdma_cep_set_free(cep);
	}
}


void erdma_cep_put(struct erdma_cep *cep)
{
	dprint(DBG_OBJ, "(CEP 0x%p): New refcount: %d\n",
		cep, kref_read(&cep->ref) - 1);

	WARN_ON(kref_read(&cep->ref) < 1);
	kref_put(&cep->ref, __erdma_cep_dealloc);
}

void erdma_cep_get(struct erdma_cep *cep)
{
	kref_get(&cep->ref);
	dprint(DBG_OBJ, "(CEP 0x%p): New refcount: %d\n",
		cep, kref_read(&cep->ref));
}

static inline int ksock_recv(struct socket *sock, char *buf, size_t size,
			     int flags)
{
	struct kvec iov = {buf, size};
	struct msghdr msg = {.msg_name = NULL, .msg_flags = flags};

	return kernel_recvmsg(sock, &msg, &iov, 1, size, flags);
}

/*
 * Expects params->pd_len in host byte order
 */
static int erdma_send_mpareqrep(struct erdma_cep *cep, const void *pdata,
			      __u8 pd_len)
{
	struct socket	*s = cep->llp.sock;
	struct mpa_rr	*rr = &cep->mpa.hdr;
	struct kvec	iov[2];
	struct msghdr	msg;
	int		rv;

	memset(&msg, 0, sizeof(msg));

	rr->params.pd_len = cpu_to_be16(pd_len);

	iov[0].iov_base = rr;
	iov[0].iov_len = sizeof(*rr);

	if (pd_len) {
		iov[1].iov_base = (char *)pdata;
		iov[1].iov_len = pd_len;

		rv =  kernel_sendmsg(s, &msg, iov, 2, pd_len + sizeof(*rr));
	} else
		rv =  kernel_sendmsg(s, &msg, iov, 1, sizeof(*rr));

	return rv < 0 ? rv : 0;
}

/*
 * Receive MPA Request/Reply header.
 *
 * Returns 0 if complete MPA Request/Reply haeder including
 * eventual private data was received. Returns -EAGAIN if
 * header was partially received or negative error code otherwise.
 *
 * Context: May be called in process context only
 */
static int erdma_recv_mpa_rr(struct erdma_cep *cep)
{
	struct mpa_rr	*hdr = &cep->mpa.hdr;
	struct socket	*s = cep->llp.sock;
	__u16		pd_len;
	int		rcvd, to_rcv;

	if (cep->mpa.bytes_rcvd < sizeof(struct mpa_rr)) {

		rcvd = ksock_recv(s, (char *)hdr + cep->mpa.bytes_rcvd,
				  sizeof(struct mpa_rr) -
				  cep->mpa.bytes_rcvd, MSG_DONTWAIT);
		/* we use DONTWAIT mode, so EAGAIN may appear. */
		if (rcvd == -EAGAIN)
			return -EAGAIN;

		if (rcvd <= 0)
			return -ECONNABORTED;

		cep->mpa.bytes_rcvd += rcvd;

		if (cep->mpa.bytes_rcvd < sizeof(struct mpa_rr))
			return -EAGAIN;

		if (be16_to_cpu(hdr->params.pd_len) > MPA_MAX_PRIVDATA)
			return -EPROTO;
	}
	pd_len = be16_to_cpu(hdr->params.pd_len);

	/*
	 * At least the MPA Request/Reply header (frame not including
	 * private data) has been received.
	 * Receive (or continue receiving) any private data.
	 */
	to_rcv = pd_len - (cep->mpa.bytes_rcvd - sizeof(struct mpa_rr));

	if (!to_rcv) {
		/*
		 * We must have hdr->params.pd_len == 0 and thus received a
		 * complete MPA Request/Reply frame.
		 * Check against peer protocol violation.
		 */
		__u32 word;

		rcvd = ksock_recv(s, (char *)&word, sizeof(word), MSG_DONTWAIT);
		if (rcvd == -EAGAIN)
			return 0;

		if (rcvd == 0) {
			dprint(DBG_CM, " peer EOF\n");
			return -EPIPE;
		}
		if (rcvd < 0) {
			dprint(DBG_CM, " ERROR: %d:\n", rcvd);
			return rcvd;
		}
		dprint(DBG_CM, " peer sent extra data: %d\n", rcvd);
		return -EPROTO;
	}

	/*
	 * At this point, we must have hdr->params.pd_len != 0.
	 * A private data buffer gets allocated if hdr->params.pd_len != 0.
	 */
	if (!cep->mpa.pdata) {
		cep->mpa.pdata = kmalloc(pd_len + 4, GFP_KERNEL);
		if (!cep->mpa.pdata)
			return -ENOMEM;
	}
	rcvd = ksock_recv(s, cep->mpa.pdata + cep->mpa.bytes_rcvd
			  - sizeof(struct mpa_rr), to_rcv + 4, MSG_DONTWAIT);

	if (rcvd < 0)
		return rcvd;

	if (rcvd > to_rcv)
		return -EPROTO;

	cep->mpa.bytes_rcvd += rcvd;

	if (to_rcv == rcvd) {
		dprint(DBG_CM, " %d bytes private_data received\n", pd_len);

		return 0;
	}
	return -EAGAIN;
}


/*
 * erdma_proc_mpareq()
 *
 * Read MPA Request from socket and signal new connection to IWCM
 * if success. Caller must hold lock on corresponding listening CEP.
 */
static int erdma_proc_mpareq(struct erdma_cep *cep)
{
	struct mpa_rr      *req;
	int                rv;

	rv = erdma_recv_mpa_rr(cep);
	if (rv)
		goto out;

	req = &cep->mpa.hdr;

	if (__mpa_rr_revision(req->params.bits) > MPA_REVISION_1) {
		/* allow for 0 and 1 only */
		rv = -EPROTO;
		goto out;
	}

	if (memcmp(req->key, MPA_KEY_REQ, 12)) {
		rv = -EPROTO;
		goto out;
	}

	cep->mpa.remote_qpn = *(__u32 *)&req->key[12];
	dprint(DBG_CM, "get remote qpn %d.\n", cep->mpa.remote_qpn);
	/*
	 * Prepare for sending MPA reply
	 */
	memcpy(req->key, MPA_KEY_REP, 12);

	if (req->params.bits & MPA_RR_FLAG_MARKERS ||
	    (req->params.bits & MPA_RR_FLAG_CRC &&
	    !mpa_crc_required && mpa_crc_strict)) {
		/*
		 * MPA Markers: currently not supported. Marker TX to be added.
		 *
		 * CRC:
		 *    RFC 5044, page 27: CRC MUST be used if peer requests it.
		 *    erdma specific: 'mpa_crc_strict' parameter to reject
		 *    connection with CRC if local CRC off enforced by
		 *    'mpa_crc_strict' module parameter.
		 */
		dprint(DBG_CM|DBG_ON, " Reject: CRC %d:%d:%d, M %d:%d\n",
			req->params.bits & MPA_RR_FLAG_CRC ? 1 : 0,
			mpa_crc_required, mpa_crc_strict,
			req->params.bits & MPA_RR_FLAG_MARKERS ? 1 : 0, 0);

		req->params.bits &= ~MPA_RR_FLAG_MARKERS;
		req->params.bits |= MPA_RR_FLAG_REJECT; /* reject */

		if (!mpa_crc_required && mpa_crc_strict)
			req->params.bits &= ~MPA_RR_FLAG_CRC;

		kfree(cep->mpa.pdata);
		cep->mpa.pdata = NULL;

		(void)erdma_send_mpareqrep(cep, NULL, 0);
		rv = -EOPNOTSUPP;
		goto out;
	}
	/*
	 * Enable CRC if requested by module initialization
	 */
	if (!(req->params.bits & MPA_RR_FLAG_CRC) && mpa_crc_required)
		req->params.bits |= MPA_RR_FLAG_CRC;

	cep->state = ERDMA_EPSTATE_RECVD_MPAREQ;

	/* Keep reference until IWCM accepts/rejects */
	erdma_cep_get(cep);
	rv = erdma_cm_upcall(cep, IW_CM_EVENT_CONNECT_REQUEST, 0);
	if (rv)
		erdma_cep_put(cep);
out:
	return rv;
}

static int erdma_proc_mpareply(struct erdma_cep *cep)
{
	struct erdma_qp_attrs	qp_attrs;
	struct erdma_qp		*qp = cep->qp;
	struct mpa_rr		*rep;
	int			rv;

	rv = erdma_recv_mpa_rr(cep);
	if (rv != -EAGAIN)
		erdma_cancel_mpatimer(cep);
	if (rv)
		goto out_err;

	rep = &cep->mpa.hdr;

	if (__mpa_rr_revision(rep->params.bits) > MPA_REVISION_1) {
		/* allow for 0 and 1 only */
		rv = -EPROTO;
		goto out_err;
	}
	if (memcmp(rep->key, MPA_KEY_REP, 12)) {
		rv = -EPROTO;
		goto out_err;
	}

	cep->mpa.remote_qpn = *(__u32 *)&rep->key[12];
	dprint(DBG_CM, "get remote qpn %d.\n", cep->mpa.remote_qpn);

	if (rep->params.bits & MPA_RR_FLAG_REJECT) {
		dprint(DBG_CM, "(cep=0x%p): Got MPA reject\n", cep);
		(void)erdma_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY,
				    -ECONNRESET);

		rv = -ECONNRESET;
		goto out;
	}
	if ((rep->params.bits & MPA_RR_FLAG_MARKERS)
		|| (mpa_crc_required && !(rep->params.bits & MPA_RR_FLAG_CRC))
		|| (mpa_crc_strict && !mpa_crc_required
			&& (rep->params.bits & MPA_RR_FLAG_CRC))) {

		dprint(DBG_CM|DBG_ON, " Reply unsupp: CRC %d:%d:%d, M %d:%d\n",
			rep->params.bits & MPA_RR_FLAG_CRC ? 1 : 0,
			mpa_crc_required, mpa_crc_strict,
			rep->params.bits & MPA_RR_FLAG_MARKERS ? 1 : 0, 0);

		(void)erdma_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY,
				    -ECONNREFUSED);
		rv = -EINVAL;
		goto out;
	}
	memset(&qp_attrs, 0, sizeof(qp_attrs));
	qp_attrs.irq_size = cep->ird;
	qp_attrs.orq_size = cep->ord;
	qp_attrs.llp_stream_handle = cep->llp.sock;
	qp_attrs.state = ERDMA_QP_STATE_RTS;

	/* Move socket RX/TX under QP control */
	down_write(&qp->state_lock);
	if (qp->attrs.state > ERDMA_QP_STATE_RTS) {
		rv = -EINVAL;
		up_write(&qp->state_lock);
		goto out_err;
	}

	qp->qp_type = ERDMA_QP_TYPE_CLIENT;
	qp->cc_method = __mpa_rr_cc(rep->params.bits) == qp->hdr.edev->cc_method ?
			qp->hdr.edev->cc_method : COMPROMISE_CC;
	dprint(DBG_CM, "CC method: %d default CC: %d peer CC: %d\n",
		qp->cc_method, qp->hdr.edev->cc_method, __mpa_rr_cc(cep->mpa.hdr.params.bits));
	rv = erdma_modify_qp_internal(qp, &qp_attrs, ERDMA_QP_ATTR_STATE|
					       ERDMA_QP_ATTR_LLP_HANDLE|
					       ERDMA_QP_ATTR_ORD|
					       ERDMA_QP_ATTR_IRD|
					       ERDMA_QP_ATTR_MPA);

	up_write(&qp->state_lock);

	if (!rv) {
		rv = erdma_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY, 0);
		if (!rv) {
			cep->state = ERDMA_EPSTATE_RDMA_MODE;
			atomic_inc_return(&cep->edev->num_success_connect);
		}
		goto out;
	}

out_err:
	(void)erdma_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY, -EINVAL);
out:
	if (rv)
		atomic_inc_return(&cep->edev->num_failed_connect);
	return rv;
}

/*
 * erdma_accept_newconn - accept an incoming pending connection
 *
 */
static void erdma_accept_newconn(struct erdma_cep *cep)
{
	struct socket    *s       = cep->llp.sock;
	struct socket    *new_s   = NULL;
	struct erdma_cep *new_cep = NULL;
	int              rv       = 0; /* debug only. should disappear */

	if (cep->state != ERDMA_EPSTATE_LISTENING)
		goto error;

	new_cep = erdma_cep_alloc(cep->edev);
	if (!new_cep)
		goto error;

	if (erdma_cm_alloc_work(new_cep, 6) != 0)
		goto error;

	/*
	 * Copy saved socket callbacks from listening CEP
	 * and assign new socket with new CEP
	 */
	new_cep->sk_state_change = cep->sk_state_change;
	new_cep->sk_data_ready   = cep->sk_data_ready;
	new_cep->sk_write_space  = cep->sk_write_space;
	new_cep->sk_error_report = cep->sk_error_report;

	rv = kernel_accept(s, &new_s, O_NONBLOCK);
	if (rv != 0) {
		dprint(DBG_CM|DBG_ON, "(cep=0x%p): ERROR: kernel_accept(): rv=%d\n", cep, rv);
		goto error;
	}

	new_cep->llp.sock = new_s;
	new_s->sk->sk_user_data = new_cep;
	erdma_cep_get(new_cep);

	dprint(DBG_CM,
		"(cep=0x%p, s=0x%p, new_s=0x%p): New LLP connection accepted\n", cep, s, new_s);

	tcp_sock_set_nodelay(new_s->sk);

	rv = kernel_peername(new_s, &new_cep->llp.raddr);
	if (rv < 0) {
		dprint(DBG_CM|DBG_ON, "(cep=0x%p): ERROR: kernel_peername(): rv=%d\n", cep, rv);
		goto error;
	}

	rv = kernel_localname(new_s, &new_cep->llp.laddr);
	if (rv < 0) { /* Kernel 4.9 return 0 if success, Kernel 4.19 return size if success. */
		dprint(DBG_CM|DBG_ON, "(cep=0x%p): ERROR: kernel_localname(): rv=%d\n", cep, rv);
		goto error;
	}

	new_cep->state = ERDMA_EPSTATE_AWAIT_MPAREQ;

	rv = erdma_cm_queue_work(new_cep, ERDMA_CM_WORK_MPATIMEOUT);
	if (rv)
		goto error;
	/*
	 * See erdma_proc_mpareq() etc. for the use of new_cep->listen_cep.
	 */
	new_cep->listen_cep = cep;
	erdma_cep_get(cep);

	if (atomic_read(&new_s->sk->sk_rmem_alloc)) {
		/*
		 * MPA REQ already queued
		 */
		dprint(DBG_CM, "(cep=0x%p): Immediate MPA req.\n", cep);

		erdma_cep_set_inuse(new_cep);
		rv = erdma_proc_mpareq(new_cep);
		erdma_cep_set_free(new_cep);

		if (rv != -EAGAIN) {
			erdma_cep_put(cep);
			new_cep->listen_cep = NULL;
			if (rv)
				goto error;
		}
	}


	return;

error:
	if (new_cep) {
		new_cep->state = ERDMA_EPSTATE_CLOSED;
		erdma_cancel_mpatimer(new_cep);

		erdma_cep_put(new_cep);
		new_cep->llp.sock = NULL;
	}

	if (new_s) {
		erdma_socket_disassoc(new_s);
		sock_release(new_s);
	}
	dprint(DBG_CM|DBG_ON, "(cep=0x%p): ERROR: rv=%d\n", cep, rv);
}

static int erdma_newconn_connected(struct erdma_cep *cep)
{
	struct socket    *s       = cep->llp.sock;
	int              rv;
	int              qpn;

	rv = kernel_peername(s, &cep->llp.raddr);
	if (rv < 0)
		goto error;

	rv = kernel_localname(s, &cep->llp.laddr);
	if (rv < 0)
		goto error;

	/*
	 * Set MPA Request bits: CRC if required, no MPA Markers,
	 * MPA Rev. 1, Key 'Request'.
	 */
	cep->mpa.hdr.params.bits = 0;
	__mpa_rr_set_revision(&cep->mpa.hdr.params.bits, MPA_REVISION_1);
	__mpa_rr_set_cc(&cep->mpa.hdr.params.bits, cep->edev->cc_method);

	if (mpa_crc_required)
		cep->mpa.hdr.params.bits |= MPA_RR_FLAG_CRC;

	qpn = QP_ID(cep->qp);
	memcpy(cep->mpa.hdr.key, MPA_KEY_REQ, 12);
	memcpy(&cep->mpa.hdr.key[12], &qpn, 4);

	dprint(DBG_CM, "Sending MPA Req time:%u.\n", jiffies_to_msecs(jiffies));
	rv = erdma_send_mpareqrep(cep, cep->private_storage, cep->pd_len);

	/*
	 * Reset private data.
	 */
	cep->mpa.hdr.params.pd_len = 0;

	if (rv >= 0) {
		cep->state = ERDMA_EPSTATE_AWAIT_MPAREP;
		rv = erdma_cm_queue_work(cep, ERDMA_CM_WORK_MPATIMEOUT);
		if (!rv) {
			dprint(DBG_CM, "(id=0x%p, cep=0x%p QP%d): Exit\n",
				cep->cm_id, cep, qpn);
			return 0;
		}
		return rv;
	}

	dprint(DBG_CM, "%s: {}\n", __func__);

error:
	return rv;
}

static void erdma_cm_work_handler(struct work_struct *w)
{
	struct erdma_cm_work *work;
	struct erdma_cep     *cep;
	int                  release_cep = 0, rv = 0;

	work = container_of(w, struct erdma_cm_work, work.work);
	cep = work->cep;

	dprint(DBG_CM, " (QP%d): WORK type: %d, CEP: 0x%p, state: %d\n",
		cep->qp ? QP_ID(cep->qp) : -1, work->type, cep, cep->state);

	erdma_cep_set_inuse(cep);

	switch (work->type) {
	case ERDMA_CM_WORK_CONNECTED:
		erdma_cancel_mpatimer(cep);

		rv = erdma_newconn_connected(cep);
		if (rv) {
			erdma_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY,
					-EIO);
			release_cep = 1;
			atomic_inc_return(&cep->edev->num_failed_connect);
		}

		break;
	case ERDMA_CM_WORK_CONNECTTIMEOUT:
		if (cep->state == ERDMA_EPSTATE_CONNECTING) {
			cep->mpa_timer = NULL;
			erdma_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY,
					-ETIMEDOUT);
			release_cep = 1;
			atomic_inc_return(&cep->edev->num_failed_connect);
		}

		break;
	case ERDMA_CM_WORK_ACCEPT:

		erdma_accept_newconn(cep);
		break;

	case ERDMA_CM_WORK_READ_MPAHDR:
		dprint(DBG_CM, "process data time :%u.\n", jiffies_to_msecs(jiffies));
		switch (cep->state) {

		case ERDMA_EPSTATE_AWAIT_MPAREQ:

			if (cep->listen_cep) {
				erdma_cep_set_inuse(cep->listen_cep);

				if (cep->listen_cep->state ==
				    ERDMA_EPSTATE_LISTENING)
					rv = erdma_proc_mpareq(cep);
				else
					rv = -EFAULT;

				erdma_cep_set_free(cep->listen_cep);

				if (rv != -EAGAIN) {
					erdma_cep_put(cep->listen_cep);
					cep->listen_cep = NULL;
					if (rv)
						erdma_cep_put(cep);
				}
			}
			break;

		case ERDMA_EPSTATE_AWAIT_MPAREP:

			rv = erdma_proc_mpareply(cep);
			break;

		default:
			/*
			 * CEP already moved out of MPA handshake.
			 * any connection management already done.
			 * silently ignore the mpa packet.
			 */
			dprint(DBG_CM, "(): CEP not in MPA handshake state: %d\n", cep->state);
			if (cep->state == ERDMA_EPSTATE_RDMA_MODE) {
				cep->llp.sock->sk->sk_data_ready(
					cep->llp.sock->sk);
				pr_info("cep already in RDMA mode");
			}
		}
		if (rv && rv != -EAGAIN)
			release_cep = 1;

		break;

	case ERDMA_CM_WORK_CLOSE_LLP:
		/*
		 * QP scheduled LLP close
		 */
		dprint(DBG_CM, "(): ERDMA_CM_WORK_CLOSE_LLP, cep->state=%d\n",
			cep->state);

		if (cep->cm_id)
			erdma_cm_upcall(cep, IW_CM_EVENT_CLOSE, 0);

		release_cep = 1;

		break;

	case ERDMA_CM_WORK_PEER_CLOSE:

		dprint(DBG_CM, "(): ERDMA_CM_WORK_PEER_CLOSE, cep->state=%d\n", cep->state);

		if (cep->cm_id) {
			switch (cep->state) {
			case ERDMA_EPSTATE_CONNECTING:
			case ERDMA_EPSTATE_AWAIT_MPAREP:
				/*
				 * MPA reply not received, but connection drop
				 */
				erdma_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY,
					      -ECONNRESET);
				atomic_inc_return(&cep->edev->num_failed_connect);
				break;

			case ERDMA_EPSTATE_RDMA_MODE:
				/*
				 * NOTE: IW_CM_EVENT_DISCONNECT is given just
				 *       to transition IWCM into CLOSING.
				 *       FIXME: is that needed?
				 */
				erdma_cm_upcall(cep, IW_CM_EVENT_DISCONNECT, 0);
				erdma_cm_upcall(cep, IW_CM_EVENT_CLOSE, 0);

				break;

			default:

				break;
				/*
				 * for these states there is no connection
				 * known to the IWCM.
				 */
			}
		} else {
			switch (cep->state) {

			case ERDMA_EPSTATE_RECVD_MPAREQ:
				/*
				 * Wait for the CM to call its accept/reject
				 */
				dprint(DBG_CM, "(): STATE_RECVD_MPAREQ: wait for CM:\n");
				break;
			case ERDMA_EPSTATE_AWAIT_MPAREQ:
				/*
				 * Socket close before MPA request received.
				 */
				dprint(DBG_CM,
					"(): STATE_AWAIT_MPAREQ: unlink from Listener\n");
				if (cep->listen_cep) {
					erdma_cep_put(cep->listen_cep);
					cep->listen_cep = NULL;
				}

				break;

			default:
				break;
			}
		}
		release_cep = 1;

		break;

	case ERDMA_CM_WORK_MPATIMEOUT:
		cep->mpa_timer = NULL;

		if (cep->state == ERDMA_EPSTATE_AWAIT_MPAREP) {
			/*
			 * MPA request timed out:
			 * Hide any partially received private data and signal
			 * timeout
			 */
			cep->mpa.hdr.params.pd_len = 0;

			if (cep->cm_id) {
				erdma_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY,
					      -ETIMEDOUT);
			}
			release_cep = 1;
			atomic_inc_return(&cep->edev->num_failed_connect);

		} else if (cep->state == ERDMA_EPSTATE_AWAIT_MPAREQ) {
			/*
			 * No MPA request received after peer TCP stream setup.
			 */
			if (cep->listen_cep) {
				erdma_cep_put(cep->listen_cep);
				cep->listen_cep = NULL;
			}

			erdma_cep_put(cep);
			release_cep = 1;
		}
		break;

	default:
		pr_err("ERROR: work task type:%u.\n", work->type);
		break;
	}

	if (release_cep) {

		dprint(DBG_CM, " (CEP 0x%p): Release: mpa_timer=%s, sock=0x%p, QP%d, id=0x%p\n",
			cep, cep->mpa_timer ? "y" : "n", cep->llp.sock,
			cep->qp ? QP_ID(cep->qp) : -1, cep->cm_id);

		erdma_cancel_mpatimer(cep);

		cep->state = ERDMA_EPSTATE_CLOSED;

		if (cep->qp) {
			struct erdma_qp *qp = cep->qp;
			/*
			 * Serialize a potential race with application
			 * closing the QP and calling erdma_qp_cm_drop()
			 */
			erdma_qp_get(qp);
			erdma_cep_set_free(cep);

			erdma_qp_llp_close(qp);
			erdma_qp_put(qp);

			erdma_cep_set_inuse(cep);
			cep->qp = NULL;
			erdma_qp_put(qp);
		}
		if (cep->llp.sock) {
			erdma_socket_disassoc(cep->llp.sock);
			sock_release(cep->llp.sock);
			cep->llp.sock = NULL;
		}

		if (cep->cm_id) {
			cep->cm_id->rem_ref(cep->cm_id);
			cep->cm_id = NULL;
			/* Notice: the Listen cep also can receive an ERDMA_CM_WORK_PEER_CLOSE
			 * message When we call the erdma_listena_address, we do not get the
			 * cep when add cm_id's refcnt. So, If the cep is Listen Cep, we do
			 * not put the refcnt.
			 */
			if (cep->state != ERDMA_EPSTATE_LISTENING)
				erdma_cep_put(cep);
		}
	}

	erdma_cep_set_free(cep);

	dprint(DBG_CM, " (Exit): WORK type: %d, CEP: 0x%p\n", work->type, cep);
	erdma_put_work(work);
	erdma_cep_put(cep);
}

static struct workqueue_struct *erdma_cm_wq;

int erdma_cm_queue_work(struct erdma_cep *cep, enum erdma_work_type type)
{
	struct erdma_cm_work *work = erdma_get_work(cep);
	unsigned long delay = 0;

	if (!work) {
		dprint(DBG_ON, " Failed\n");
		return -ENOMEM;
	}
	work->type = type;
	work->cep = cep;

	erdma_cep_get(cep);

	INIT_DELAYED_WORK(&work->work, erdma_cm_work_handler);

	if (type == ERDMA_CM_WORK_MPATIMEOUT) {
		cep->mpa_timer = work;

		if (cep->state == ERDMA_EPSTATE_AWAIT_MPAREP)
			delay = MPAREQ_TIMEOUT;
		else
			delay = MPAREP_TIMEOUT;
	} else if (type == ERDMA_CM_WORK_CONNECTTIMEOUT) {
		cep->mpa_timer = work;

		delay = CONNECT_TIMEOUT;
	}

	dprint(DBG_CM, " (QP%d): WORK type: %d, CEP: 0x%p, work 0x%p, timeout %lu\n",
		cep->qp ? QP_ID(cep->qp) : -1, type, cep, work, delay);

	queue_delayed_work(erdma_cm_wq, &work->work, delay);

	return 0;
}

static void erdma_cm_llp_data_ready(struct sock *sk)
{
	struct erdma_cep              *cep;

	read_lock(&sk->sk_callback_lock);

	cep = sk_to_cep(sk);
	if (!cep)
		goto out;

	dprint(DBG_CM, "(): cep 0x%p, state: %d\n", cep, cep->state);

	switch (cep->state) {

	case ERDMA_EPSTATE_RDMA_MODE:
	case ERDMA_EPSTATE_LISTENING:

		break;

	case ERDMA_EPSTATE_AWAIT_MPAREQ:
	case ERDMA_EPSTATE_AWAIT_MPAREP:
		erdma_cm_queue_work(cep, ERDMA_CM_WORK_READ_MPAHDR);
		break;

	default:
		dprint(DBG_CM, "(): Unexpected DATA, state %d\n", cep->state);
		break;
	}
out:
	read_unlock(&sk->sk_callback_lock);
}

static void erdma_cm_llp_write_space(struct sock *sk)
{
	struct erdma_cep	*cep = sk_to_cep(sk);

	if (cep)
		dprint(DBG_CM, "(): cep: 0x%p, state: %d\n", cep, cep->state);
}

static void erdma_cm_llp_error_report(struct sock *sk)
{
	struct erdma_cep	*cep = sk_to_cep(sk);

	dprint(DBG_CM, "(): error: %d, state: %d\n", sk->sk_err, sk->sk_state);

	if (cep) {
		cep->sk_error = sk->sk_err;
		dprint(DBG_CM, "(): cep->state: %d\n", cep->state);
		cep->sk_error_report(sk);
	}
}

static void erdma_cm_llp_state_change(struct sock *sk)
{
	struct erdma_cep *cep;
	struct socket *s;
	void (*orig_state_change)(struct sock *sk);

	read_lock(&sk->sk_callback_lock);

	cep = sk_to_cep(sk);
	if (!cep) {
		read_unlock(&sk->sk_callback_lock);
		return;
	}
	orig_state_change = cep->sk_state_change;

	s = sk->sk_socket;

	dprint(DBG_CM, "(): cep: 0x%p, state: %d, tcp_state: %d\n", cep, cep->state, sk->sk_state);

	switch (sk->sk_state) {

	case TCP_ESTABLISHED:
		if (cep->state == ERDMA_EPSTATE_CONNECTING) {
			erdma_cm_queue_work(cep, ERDMA_CM_WORK_CONNECTED);
		} else {
			/*
			 * handle accepting socket as special case where only
			 * new connection is possible
			 */
			erdma_cm_queue_work(cep, ERDMA_CM_WORK_ACCEPT);
		}

		break;

	case TCP_CLOSE:
	case TCP_CLOSE_WAIT:
		if (cep->state != ERDMA_EPSTATE_LISTENING)
			erdma_cm_queue_work(cep, ERDMA_CM_WORK_PEER_CLOSE);
		else
			dprint(DBG_CM, "listen cep should not process peer close message.\n");
		break;

	default:
		dprint(DBG_CM, "Unexpected sock state %d\n", sk->sk_state);
	}
	read_unlock(&sk->sk_callback_lock);
	orig_state_change(sk);
}


static int kernel_bindconnect(struct socket *s,
			      struct sockaddr *laddr, int laddrlen,
			      struct sockaddr *raddr, int raddrlen, int flags)
{
	int err;
	struct sock *sk = s->sk;

	/*
	 * Make address available again asap.
	 */
	sock_set_reuseaddr(s->sk);

	err = s->ops->bind(s, laddr, laddrlen);
	if (err < 0) {
		pr_info("try port (%u) failed\n", ((struct sockaddr_in *)laddr)->sin_port);
		/* Try to alloc port, not use RDMA port. */
		((struct sockaddr_in *)laddr)->sin_port = 0;
		err = s->ops->bind(s, laddr, laddrlen);
		if (err < 0)
			goto done;
		pr_info("alloc source port %u.\n", inet_sk(sk)->inet_num);
	}

	err = s->ops->connect(s, raddr, raddrlen, flags);
	if (err < 0)
		goto done;

	err = s->ops->getname(s, laddr, 0);
done:
	return err;
}


int erdma_connect(struct iw_cm_id *id, struct iw_cm_conn_param *params)
{
	struct erdma_dev  *edev  = to_edev(id->device);
	struct erdma_qp   *qp;
	struct erdma_cep  *cep   = NULL;
	struct socket     *s     = NULL;
	struct sockaddr   *laddr, *raddr;

	__u16             pd_len = params->private_data_len;
	int               rv;

	atomic_inc_return(&edev->num_total_connect);

	if (pd_len > MPA_MAX_PRIVDATA) {
		atomic_inc_return(&edev->num_failed_connect);
		return -EINVAL;
	}

	qp = erdma_qp_id2obj(edev, params->qpn);
	if (!qp) {
		atomic_inc_return(&edev->num_failed_connect);
		return -ENOENT;
	}

	dprint(DBG_CM, "(id=0x%p, QP%d): dev(id)=%s, netdev=%s\n",
		id, QP_ID(qp), edev->ibdev.name, edev->netdev->name);
	dprint(DBG_CM, "(id=0x%p, QP%d): laddr=(0x%x,%d,mport %d), raddr=(0x%x,%d,mport %d)\n",
		id, QP_ID(qp),
		ntohl(to_sockaddr_in(id->local_addr).sin_addr.s_addr),
		ntohs(to_sockaddr_in(id->local_addr).sin_port),
		ntohs(to_sockaddr_in(id->m_local_addr).sin_port),
		ntohl(to_sockaddr_in(id->remote_addr).sin_addr.s_addr),
		ntohs(to_sockaddr_in(id->remote_addr).sin_port),
		ntohs(to_sockaddr_in(id->m_remote_addr).sin_port));

	laddr = (struct sockaddr *)&id->m_local_addr;
	raddr = (struct sockaddr *)&id->m_remote_addr;

	qp->attrs.sip = ntohl(to_sockaddr_in(id->local_addr).sin_addr.s_addr);
	qp->attrs.origin_sport = ntohs(to_sockaddr_in(id->local_addr).sin_port);
	qp->attrs.dip = ntohl(to_sockaddr_in(id->remote_addr).sin_addr.s_addr);
	qp->attrs.dport = ntohs(to_sockaddr_in(id->m_remote_addr).sin_port);

	/* Attention: we do not use the allocated source port, because it is allocated by RDMA-CM,
	 * and is not registered to IP/TCP stack. So the port may be used by TCP, and then,
	 * we will fail with bind API.
	 * And we do not use iwpmd, so we allocate an new port with port 0 in bind API.
	 */

	rv = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &s);
	if (rv < 0)
		goto error_put_qp;

	cep = erdma_cep_alloc(edev);
	if (!cep) {
		rv = -ENOMEM;
		goto error_release_sock;
	}

	erdma_cep_set_inuse(cep);

	/* Associate QP with CEP */
	erdma_cep_get(cep);
	qp->cep = cep;
	/* erdma_qp_get(qp) already done by QP lookup */
	cep->qp = qp;

	/* Associate cm_id with CEP */
	id->add_ref(id);
	cep->cm_id = id;

	rv = erdma_cm_alloc_work(cep, 6);
	if (rv != 0) {
		rv = -ENOMEM;
		goto error_release_cep;
	}

	cep->ird = params->ird;
	cep->ord = params->ord;
	cep->state = ERDMA_EPSTATE_CONNECTING;
	cep->is_connecting = true;

	dprint(DBG_CM, " (id=0x%p, QP%d): pd_len = %u\n",
		id, QP_ID(qp), pd_len);

	/*
	 * Associate CEP with socket
	 */
	erdma_cep_socket_assoc(cep, s);


	cep->pd_len = pd_len;
	cep->private_storage = kmalloc(pd_len, GFP_KERNEL);
	if (!cep->private_storage) {
		rv = -ENOMEM;
		goto error_disasssoc;
	}

	memcpy(cep->private_storage, params->private_data, params->private_data_len);

	/*
	 * NOTE: For simplification, connect() is called in blocking
	 * mode. Might be reconsidered for async connection setup at
	 * TCP level.
	 */
	rv = kernel_bindconnect(s, laddr, sizeof(*laddr), raddr,
				sizeof(*raddr), O_NONBLOCK);
	if (rv != -EINPROGRESS && rv != 0) {
		dprint(DBG_CM, "(id=0x%p, QP%d): kernel_bindconnect: rv=%d\n",
			id, QP_ID(qp), rv);
		goto error_disasssoc;
	} else if (rv == 0) {
		rv = erdma_cm_queue_work(cep, ERDMA_CM_WORK_CONNECTED);
	} else {
		rv = erdma_cm_queue_work(cep, ERDMA_CM_WORK_CONNECTTIMEOUT);
		if (rv)
			goto error_disasssoc;
	}

	erdma_cep_set_free(cep);
	return 0;

error_disasssoc:
	dprint(DBG_CM, " Failed: %d\n", rv);
	kfree(cep->private_storage);
	if (cep->private_storage) {
		cep->private_storage = NULL;
		cep->pd_len = 0;
	}

	erdma_socket_disassoc(s);

error_release_cep:
	/* disassoc with cm_id */
	cep->cm_id = NULL;
	id->rem_ref(id);

	/* disassoc with qp */
	qp->cep = NULL;
	erdma_cep_put(cep);

	cep->state = ERDMA_EPSTATE_CLOSED;

	erdma_cep_set_free(cep);

	/* release the cep. */
	erdma_cep_put(cep);

error_release_sock:
	if (s)
		sock_release(s);
error_put_qp:
	erdma_qp_put(qp);
	atomic_inc_return(&edev->num_failed_connect);

	return rv;
}

/*
 * erdma_accept - Let SoftiWARP accept an RDMA connection request
 *
 * @id:		New connection management id to be used for accepted
 *		connection request
 * @params:	Connection parameters provided by ULP for accepting connection
 *
 * Transition QP to RTS state, associate new CM id @id with accepted CEP
 * and get prepared for TCP input by installing socket callbacks.
 * Then send MPA Reply and generate the "connection established" event.
 * Socket callbacks must be installed before sending MPA Reply, because
 * the latter may cause a first RDMA message to arrive from the RDMA Initiator
 * side very quickly, at which time the socket callbacks must be ready.
 */
int erdma_accept(struct iw_cm_id *id, struct iw_cm_conn_param *params)
{
	struct erdma_dev		*edev = to_edev(id->device);
	struct erdma_cep		*cep = (struct erdma_cep *)id->provider_data;
	struct erdma_qp		*qp;
	struct erdma_qp_attrs	qp_attrs;
	int rv;


	atomic_inc_return(&edev->num_total_accept);

	erdma_cep_set_inuse(cep);
	erdma_cep_put(cep);

	/* Free lingering inbound private data */
	if (cep->mpa.hdr.params.pd_len) {
		cep->mpa.hdr.params.pd_len = 0;
		kfree(cep->mpa.pdata);
		cep->mpa.pdata = NULL;
	}
	erdma_cancel_mpatimer(cep);

	if (cep->state != ERDMA_EPSTATE_RECVD_MPAREQ) {
		if (cep->state == ERDMA_EPSTATE_CLOSED) {

			dprint(DBG_CM, "(id=0x%p): Out of State\n", id);

			erdma_cep_set_free(cep);
			erdma_cep_put(cep);

			atomic_inc_return(&edev->num_failed_accept);
			return -ECONNRESET;
		}
		atomic_inc_return(&edev->num_failed_accept);
		return -EBADFD;
	}

	qp = erdma_qp_id2obj(edev, params->qpn);
	if (!qp) {
		atomic_inc_return(&edev->num_failed_accept);
		return -ENOENT;
	}

	down_write(&qp->state_lock);
	if (qp->attrs.state > ERDMA_QP_STATE_RTS) {
		rv = -EINVAL;
		up_write(&qp->state_lock);
		goto error;
	}

	dprint(DBG_CM, "(id=0x%p, cep:0x%p, QP%d): dev(id)=%s\n",
		id, cep, QP_ID(qp), edev->ibdev.name);

	if (params->ord > edev->attrs.max_ord ||
	    params->ird > edev->attrs.max_ord) {
		dprint(DBG_CM|DBG_ON, "(id=0x%p, QP%d): ORD: %d (max: %d), IRD: %d (max: %d)\n",
			id, QP_ID(qp),
			params->ord, qp->attrs.orq_size,
			params->ird, qp->attrs.irq_size);
		rv = -EINVAL;
		up_write(&qp->state_lock);
		goto error;
	}
	if (params->private_data_len > MPA_MAX_PRIVDATA) {
		dprint(DBG_CM|DBG_ON, "(id=0x%p, QP%d): Private data too long: %d (max: %d)\n",
			id, QP_ID(qp),
			params->private_data_len, MPA_MAX_PRIVDATA);
		rv = -EINVAL;
		up_write(&qp->state_lock);
		goto error;
	}

	cep->cm_id = id;
	id->add_ref(id);

	memset(&qp_attrs, 0, sizeof(qp_attrs));
	qp_attrs.orq_size = params->ord;
	qp_attrs.irq_size = params->ird;
	qp_attrs.llp_stream_handle = cep->llp.sock;

	qp_attrs.state = ERDMA_QP_STATE_RTS;

	qp->attrs.sip = ntohl(cep->llp.laddr.sin_addr.s_addr);
	qp->attrs.origin_sport = ntohs(cep->llp.laddr.sin_port);
	qp->attrs.dip = ntohl(cep->llp.raddr.sin_addr.s_addr);
	qp->attrs.dport = ntohs(cep->llp.raddr.sin_port);
	qp->attrs.sport = ntohs(cep->llp.laddr.sin_port);

	dprint(DBG_CM, "(id=0x%p, QP%d): Moving to RTS\n", id, QP_ID(qp));

	/* Associate QP with CEP */
	erdma_cep_get(cep);
	qp->cep = cep;

	/* erdma_qp_get(qp) already done by QP lookup */
	cep->qp = qp;

	cep->state = ERDMA_EPSTATE_RDMA_MODE;

	qp->qp_type = ERDMA_QP_TYPE_SERVER;
	qp->private_data_len = params->private_data_len;
	qp->cc_method =
		__mpa_rr_cc(cep->mpa.hdr.params.bits) == qp->hdr.edev->cc_method ?
		qp->hdr.edev->cc_method : COMPROMISE_CC;
	dprint(DBG_CM, "CC method: %d default CC: %d peer CC: %d\n",
		qp->cc_method, qp->hdr.edev->cc_method, __mpa_rr_cc(cep->mpa.hdr.params.bits));
	/* Move socket RX/TX under QP control */
	rv = erdma_modify_qp_internal(qp, &qp_attrs, ERDMA_QP_ATTR_STATE|
					  ERDMA_QP_ATTR_LLP_HANDLE|
					  ERDMA_QP_ATTR_ORD|
					  ERDMA_QP_ATTR_IRD|
					  ERDMA_QP_ATTR_MPA);
	up_write(&qp->state_lock);

	if (rv)
		goto error;

	__mpa_rr_set_cc(&cep->mpa.hdr.params.bits, qp->hdr.edev->cc_method);
	memcpy(&cep->mpa.hdr.key[12], (__u32 *)&QP_ID(qp), 4);
	rv = erdma_send_mpareqrep(cep, params->private_data,
				params->private_data_len);

	if (!rv) {
		rv = erdma_cm_upcall(cep, IW_CM_EVENT_ESTABLISHED, 0);
		if (rv)
			goto error;

		erdma_cep_set_free(cep);

		dprint(DBG_CM, "(id=0x%p, QP%d): Exit\n", id, QP_ID(qp));
		atomic_inc_return(&edev->num_success_accept);
		return 0;
	}

error:
	erdma_socket_disassoc(cep->llp.sock);
	sock_release(cep->llp.sock);
	cep->llp.sock = NULL;

	cep->state = ERDMA_EPSTATE_CLOSED;

	if (cep->cm_id) {
		cep->cm_id->rem_ref(id);
		cep->cm_id = NULL;
	}
	if (qp->cep) {
		erdma_cep_put(cep);
		qp->cep = NULL;
	}
	cep->qp = NULL;
	erdma_qp_put(qp);

	erdma_cep_set_free(cep);
	erdma_cep_put(cep);

	atomic_inc_return(&edev->num_failed_accept);

	return rv;
}

/*
 * erdma_reject()
 *
 * Local connection reject case. Send private data back to peer,
 * close connection and dereference connection id.
 */
int erdma_reject(struct iw_cm_id *id, const void *pdata, __u8 plen)
{
	struct erdma_cep	*cep = (struct erdma_cep *)id->provider_data;
	struct erdma_dev  *edev  = to_edev(id->device);

	erdma_cep_set_inuse(cep);
	erdma_cep_put(cep);

	erdma_cancel_mpatimer(cep);

	if (cep->state != ERDMA_EPSTATE_RECVD_MPAREQ) {
		if (cep->state == ERDMA_EPSTATE_CLOSED) {

			dprint(DBG_CM, "(id=0x%p): Out of State\n", id);

			erdma_cep_set_free(cep);
			erdma_cep_put(cep); /* should be last reference */

			return -ECONNRESET;
		}
		return -EBADFD;
	}

	dprint(DBG_CM, "(id=0x%p): cep->state=%d\n", id, cep->state);
	dprint(DBG_CM, " Reject: %d: %x\n", plen, plen ? *(char *)pdata : 0);

	if (__mpa_rr_revision(cep->mpa.hdr.params.bits) == MPA_REVISION_1) {
		cep->mpa.hdr.params.bits |= MPA_RR_FLAG_REJECT; /* reject */
		(void)erdma_send_mpareqrep(cep, pdata, plen);
	}
	erdma_socket_disassoc(cep->llp.sock);
	sock_release(cep->llp.sock);
	cep->llp.sock = NULL;

	cep->state = ERDMA_EPSTATE_CLOSED;

	erdma_cep_set_free(cep);
	erdma_cep_put(cep);
	atomic_inc_return(&edev->num_reject);

	return 0;
}

int erdma_create_listen(struct iw_cm_id *id, int backlog)
{
	struct socket          *s;
	struct erdma_cep       *cep        = NULL;
	int                    rv          = 0;
	struct erdma_dev       *edev       = to_edev(id->device);
	int                    addr_family = id->local_addr.ss_family;

	atomic_inc_return(&edev->num_total_listen);

	if (addr_family != AF_INET) {
		atomic_inc_return(&edev->num_failed_listen);
		return -EAFNOSUPPORT;
	}

	rv = sock_create(addr_family, SOCK_STREAM, IPPROTO_TCP, &s);
	if (rv < 0) {
		dprint(DBG_CM|DBG_ON, "(id=0x%p): ERROR: sock_create(): rv=%d\n", id, rv);
		atomic_inc_return(&edev->num_failed_listen);
		return rv;
	}

	/*
	 * Allow binding local port when still in TIME_WAIT from last close.
	 */
	sock_set_reuseaddr(s->sk);

	if (addr_family == AF_INET) {
		struct sockaddr_in *laddr = &to_sockaddr_in(id->local_addr);
		__u8               *l_ip, *r_ip;

		l_ip = (__u8 *) &to_sockaddr_in(id->local_addr).sin_addr.s_addr;
		r_ip = (__u8 *) &to_sockaddr_in(id->remote_addr).sin_addr.s_addr;
		dprint(DBG_CM, "(id=0x%p): ", id);
		dprint(DBG_CM, "laddr(id)  : ipv4=%d.%d.%d.%d, port=%d, mport=%d; ",
			l_ip[0], l_ip[1], l_ip[2], l_ip[3],
			ntohs(to_sockaddr_in(id->local_addr).sin_port),
			ntohs(to_sockaddr_in(id->m_local_addr).sin_port));
		dprint(DBG_CM, "raddr(id)  : ipv4=%d.%d.%d.%d, port=%d, mport=%d\n",
			r_ip[0], r_ip[1], r_ip[2], r_ip[3],
			ntohs(to_sockaddr_in(id->remote_addr).sin_port),
			ntohs(to_sockaddr_in(id->m_remote_addr).sin_port));

		/* For wildcard addr, limit binding to current device only */
		if (ipv4_is_zeronet(laddr->sin_addr.s_addr))
			s->sk->sk_bound_dev_if = edev->netdev->ifindex;

		rv = s->ops->bind(s, (struct sockaddr *)laddr, sizeof(struct sockaddr_in));
	} else {
		rv = -EAFNOSUPPORT;
		goto error;
	}

	if (rv != 0) {
		dprint(DBG_CM|DBG_ON, "(id=0x%p): ERROR: bind(): rv=%d\n",
			id, rv);
		goto error;
	}

	cep = erdma_cep_alloc(edev);
	if (!cep) {
		rv = -ENOMEM;
		goto error;
	}
	erdma_cep_socket_assoc(cep, s);

	rv = erdma_cm_alloc_work(cep, backlog);
	if (rv != 0) {
		dprint(DBG_CM|DBG_ON, "(id=0x%p): ERROR: erdma_cm_alloc_work(backlog=%d): rv=%d\n",
			id, backlog, rv);
		goto error;
	}

	rv = s->ops->listen(s, backlog);
	if (rv != 0) {
		dprint(DBG_CM|DBG_ON, "(id=0x%p): ERROR: listen() rv=%d\n",
			id, rv);
		goto error;
	}

	memcpy(&cep->llp.laddr, &id->local_addr, sizeof(cep->llp.laddr));
	memcpy(&cep->llp.raddr, &id->remote_addr, sizeof(cep->llp.raddr));

	cep->cm_id = id;
	id->add_ref(id);

	/*
	 * In case of a wildcard rdma_listen on a multi-homed device,
	 * a listener's IWCM id is associated with more than one listening CEP.
	 *
	 * We currently use id->provider_data in three different ways:
	 *
	 * o For a listener's IWCM id, id->provider_data points to
	 *   the list_head of the list of listening CEPs.
	 *   Uses: erdma_create_listen(), erdma_destroy_listen()
	 *
	 * o For a passive-side IWCM id, id->provider_data points to
	 *   the CEP itself. This is a consequence of
	 *   - erdma_cm_upcall() setting event.provider_data = cep and
	 *   - the IWCM's cm_conn_req_handler() setting provider_data of the
	 *     new passive-side IWCM id equal to event.provider_data
	 *   Uses: erdma_accept(), erdma_reject()
	 *
	 * o For an active-side IWCM id, id->provider_data is not used at all.
	 *
	 */
	if (!id->provider_data) {
		id->provider_data = kmalloc(sizeof(struct list_head), GFP_KERNEL);
		if (!id->provider_data) {
			rv = -ENOMEM;
			goto error;
		}
		INIT_LIST_HEAD((struct list_head *)id->provider_data);
	}

	dprint(DBG_CM, "(id=0x%p): dev(id)=%s, netdev=%s, id->provider_data=0x%p, cep=0x%p\n",
		id, id->device->name,
		to_edev(id->device)->netdev->name,
		id->provider_data, cep);

	list_add_tail(&cep->listenq, (struct list_head *)id->provider_data);
	cep->state = ERDMA_EPSTATE_LISTENING;

	atomic_inc_return(&edev->num_success_listen);

	return 0;

error:
	dprint(DBG_CM, " Failed: %d\n", rv);

	if (cep) {
		erdma_cep_set_inuse(cep);

		if (cep->cm_id) {
			cep->cm_id->rem_ref(cep->cm_id);
			cep->cm_id = NULL;
		}
		cep->llp.sock = NULL;
		erdma_socket_disassoc(s);
		cep->state = ERDMA_EPSTATE_CLOSED;

		erdma_cep_set_free(cep);
		erdma_cep_put(cep);
	}
	sock_release(s);

	atomic_inc_return(&edev->num_failed_listen);

	return rv;
}

static void erdma_drop_listeners(struct iw_cm_id *id)
{
	struct list_head	*p, *tmp;
	/*
	 * In case of a wildcard rdma_listen on a multi-homed device,
	 * a listener's IWCM id is associated with more than one listening CEP.
	 */
	list_for_each_safe(p, tmp, (struct list_head *)id->provider_data) {
		struct erdma_cep *cep = list_entry(p, struct erdma_cep, listenq);

		list_del(p);
		dprint(DBG_CM, "(id=0x%p): drop CEP 0x%p, state %d\n",
			id, cep, cep->state);
		erdma_cep_set_inuse(cep);

		if (cep->cm_id) {
			cep->cm_id->rem_ref(cep->cm_id);
			cep->cm_id = NULL;
		}
		if (cep->llp.sock) {
			erdma_socket_disassoc(cep->llp.sock);
			sock_release(cep->llp.sock);
			cep->llp.sock = NULL;
		}
		cep->state = ERDMA_EPSTATE_CLOSED;
		erdma_cep_set_free(cep);
		erdma_cep_put(cep);
	}
}

int erdma_destroy_listen(struct iw_cm_id *id)
{

	struct erdma_dev  *edev  = to_edev(id->device);


	dprint(DBG_CM, "(id=0x%p): dev(id)=%s, netdev=%s\n",
		id, id->device->name,
		to_edev(id->device)->netdev->name);

	if (!id->provider_data) {
		dprint(DBG_CM, "(id=0x%p): Listener id: no CEP(s)\n", id);
		return 0;
	}
	erdma_drop_listeners(id);
	kfree(id->provider_data);
	id->provider_data = NULL;

	atomic_inc_return(&edev->num_destroy_listen);
	return 0;
}

int erdma_cm_init(void)
{
	/*
	 * create_single_workqueue for strict ordering
	 */
	erdma_cm_wq = create_singlethread_workqueue("erdma_cm_wq");
	if (!erdma_cm_wq)
		return -ENOMEM;

	return 0;
}

void erdma_cm_exit(void)
{
	if (erdma_cm_wq) {
		flush_workqueue(erdma_cm_wq);
		destroy_workqueue(erdma_cm_wq);
	}
}
