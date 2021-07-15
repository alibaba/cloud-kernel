// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
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

#include <asm/barrier.h>

#include <linux/errno.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/net.h>
#include <linux/pci.h>
#include <linux/scatterlist.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/tcp.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "erdma.h"
#include "erdma_command.h"
#include "erdma_obj.h"
#include "erdma_cm.h"

static char erdma_qp_state_to_string[ERDMA_QP_STATE_COUNT][sizeof "TERMINATE"] = {
	[ERDMA_QP_STATE_IDLE]           = "IDLE",
	[ERDMA_QP_STATE_RTR]            = "RTR",
	[ERDMA_QP_STATE_RTS]            = "RTS",
	[ERDMA_QP_STATE_CLOSING]        = "CLOSING",
	[ERDMA_QP_STATE_TERMINATE]      = "TERMINATE",
	[ERDMA_QP_STATE_ERROR]          = "ERR",
	[ERDMA_QP_STATE_MORIBUND]       = "MORIBUND",
	[ERDMA_QP_STATE_UNDEF]          = "UNDEF"
};

struct ib_qp *erdma_get_ibqp(struct ib_device *ibdev, int id)
{
	struct erdma_qp *qp =  erdma_qp_id2obj(to_edev(ibdev), id);

	dprint(DBG_OBJ, ": dev_name: %s, OFA QPID: %d, QP: %p\n",
		ibdev->name, id, qp);
	if (qp) {
		/*
		 * erdma_qp_id2obj() increments object reference count
		 */
		erdma_qp_put(qp);
		dprint(DBG_OBJ, " QPID: %d\n", QP_ID(qp));
		return &qp->ibqp;
	}
	return (struct ib_qp *)NULL;
}

static int erdma_modify_qp_state_to_rts(struct erdma_qp *qp,
					struct erdma_qp_attrs *attrs,
					enum erdma_qp_attr_mask mask)
{
	int                           rv;
	struct erdma_dev              *dev = qp->hdr.edev;
	struct erdma_modify_qp_params params = {};
	struct tcp_sock               *tp;

	if (!(mask & ERDMA_QP_ATTR_LLP_HANDLE)) {
		dprint(DBG_ON, "(QP%d): socket?\n", QP_ID(qp));
		rv = -EINVAL;
		goto out;
	}
	if (!(mask & ERDMA_QP_ATTR_MPA)) {
		dprint(DBG_ON, "(QP%d): MPA?\n", QP_ID(qp));
		rv = -EINVAL;
		goto out;
	}

	dprint(DBG_CM, "(QP%d): Enter RTS: peer 0x%08x, local 0x%08x\n",
		QP_ID(qp),
		qp->cep->llp.raddr.sin_addr.s_addr,
		qp->cep->llp.laddr.sin_addr.s_addr);

	/*
	 * move socket rx and tx under qp's control
	 */

	qp->attrs.state = ERDMA_QP_STATE_RTS;
	qp->attrs.remote_qpn = qp->cep->mpa.remote_qpn;
	qp->attrs.llp_stream_handle = attrs->llp_stream_handle;
	/*
	 * set initial mss
	 */
	tp = tcp_sk(attrs->llp_stream_handle->sk);

	params.state = ERDMA_QP_STATE_RTS;
	params.qpn = QP_ID(qp);
	params.remote_qpn = qp->cep->mpa.remote_qpn;
	params.rcv_nxt = tp->rcv_nxt;
	if (qp->qp_type == ERDMA_QP_TYPE_SERVER)
		params.snd_nxt = tp->snd_nxt + 20 + qp->private_data_len; /* MPA reply length. */
	else
		params.snd_nxt = tp->snd_nxt;

	dprint(DBG_CM, "qp_type:%u, snd_nxt:%u, rcv_nxt:%u.\n",
		qp->qp_type, params.snd_nxt, params.rcv_nxt);

	params.dip = qp->cep->llp.raddr.sin_addr.s_addr;
	params.sip = qp->cep->llp.laddr.sin_addr.s_addr;

	params.dport = qp->cep->llp.raddr.sin_port;
	params.sport = qp->cep->llp.laddr.sin_port;

	params.ts_enable = tp->rx_opt.tstamp_ok;
	params.ts_ecr = tp->rx_opt.ts_recent;
	params.ts_val = tcp_time_stamp(tp) + tp->tsoffset;
	dprint(DBG_CM, "dport:%u, sport:%u.\n", params.dport, params.sport);

	rv = erdma_exec_modify_qp_cmd(dev, &params);
	if (rv)
		dev_err(&dev->pdev->dev, "ERROR: code = %d, exec modify QP command with error.\n",
			rv);

out:
	return rv;
}

static int erdma_modify_qp_state_to_stop(struct erdma_qp *qp,
					 struct erdma_qp_attrs *attrs,
					 enum erdma_qp_attr_mask mask)
{
	int                           rv;
	struct erdma_dev              *dev = qp->hdr.edev;
	struct erdma_modify_qp_params params = {0};

	qp->attrs.state = attrs->state;

	params.state = attrs->state;
	params.qpn = QP_ID(qp);

	rv = erdma_exec_modify_qp_cmd(dev, &params);
	if (rv)
		dev_err(&dev->pdev->dev, "ERROR: code = %d, exec modify QP command with error.\n",
			rv);

	return rv;
}

int erdma_modify_qp_internal_raw(struct erdma_qp *qp, struct erdma_qp_attrs *attrs,
			     enum erdma_qp_attr_mask mask)
{
	struct erdma_dev *dev = qp->hdr.edev;
	struct erdma_modify_qp_params params = {};
	int ret;

	pr_info("modify qp raw");

	if (!mask)
		return 0;

	if (mask != ERDMA_QP_ATTR_STATE) {
		if (mask & ERDMA_QP_ATTR_ACCESS_FLAGS) {
			if (attrs->flags & ERDMA_BIND_ENABLED)
				qp->attrs.flags |= ERDMA_BIND_ENABLED;
			else
				qp->attrs.flags &= ~ERDMA_BIND_ENABLED;

			if (attrs->flags & ERDMA_WRITE_ENABLED)
				qp->attrs.flags |= ERDMA_WRITE_ENABLED;
			else
				qp->attrs.flags &= ~ERDMA_WRITE_ENABLED;

			if (attrs->flags & ERDMA_READ_ENABLED)
				qp->attrs.flags |= ERDMA_READ_ENABLED;
			else
				qp->attrs.flags &= ~ERDMA_READ_ENABLED;

		}
	}
	if (!(mask & ERDMA_QP_ATTR_STATE))
		return 0;

	dprint(DBG_CM, "(QP%d): ERDMA QP state: %s => %s\n", QP_ID(qp),
		erdma_qp_state_to_string[qp->attrs.state],
		erdma_qp_state_to_string[attrs->state]);

	params.state = attrs->state;
	params.qpn = QP_ID(qp);
	params.remote_qpn = qp->attrs.remote_qpn;
	params.rcv_nxt = 0;

	if (qp->qp_type == ERDMA_QP_TYPE_SERVER)
		params.snd_nxt = 0 + 20 + qp->private_data_len; /* MPA reply length. */
	else
		params.snd_nxt = 0;

	dprint(DBG_CM, "qp_type:%u, snd_nxt:%u, rcv_nxt:%u.\n",
		qp->qp_type, params.snd_nxt, params.rcv_nxt);

	params.dip = htonl(qp->attrs.dip);
	params.sip = htonl(qp->attrs.sip);

	params.dport = htons(qp->attrs.dport);
	params.sport = htons(qp->attrs.sport);

	params.ts_enable = 0;
	params.ts_ecr = 0;
	params.ts_val = 0;

	dprint(DBG_CM, "dport:%u, sport:%u.\n", params.dport, params.sport);

	ret = erdma_exec_modify_qp_cmd(dev, &params);
	if (ret)
		dev_err(&dev->pdev->dev, "ERROR: code = %d, exec modify QP command with error.\n",
			ret);

	return ret;
}
/*
 * caller holds qp->state_lock
 */
int erdma_modify_qp_internal(struct erdma_qp *qp, struct erdma_qp_attrs *attrs,
			     enum erdma_qp_attr_mask mask)
{
	int      drop_conn = 0, rv = 0;

	if (!mask)
		return 0;

	if (mask != ERDMA_QP_ATTR_STATE) {
		/*
		 * changes of qp attributes (maybe state, too)
		 */
		if (mask & ERDMA_QP_ATTR_ACCESS_FLAGS) {

			if (attrs->flags & ERDMA_BIND_ENABLED)
				qp->attrs.flags |= ERDMA_BIND_ENABLED;
			else
				qp->attrs.flags &= ~ERDMA_BIND_ENABLED;

			if (attrs->flags & ERDMA_WRITE_ENABLED)
				qp->attrs.flags |= ERDMA_WRITE_ENABLED;
			else
				qp->attrs.flags &= ~ERDMA_WRITE_ENABLED;

			if (attrs->flags & ERDMA_READ_ENABLED)
				qp->attrs.flags |= ERDMA_READ_ENABLED;
			else
				qp->attrs.flags &= ~ERDMA_READ_ENABLED;

		}
	}
	if (!(mask & ERDMA_QP_ATTR_STATE))
		return 0;

	dprint(DBG_CM, "(QP%d): ERDMA QP state: %s => %s\n", QP_ID(qp),
		erdma_qp_state_to_string[qp->attrs.state],
		erdma_qp_state_to_string[attrs->state]);

	switch (qp->attrs.state) {

	case ERDMA_QP_STATE_IDLE:
	case ERDMA_QP_STATE_RTR:
		switch (attrs->state) {
		case ERDMA_QP_STATE_RTS:
			rv = erdma_modify_qp_state_to_rts(qp, attrs, mask);
			break;
		case ERDMA_QP_STATE_ERROR:
			qp->attrs.state = ERDMA_QP_STATE_ERROR;
			if (qp->cep) {
				erdma_cep_put(qp->cep);
				qp->cep = NULL;
			}
			rv = erdma_modify_qp_state_to_stop(qp, attrs, mask);
			break;

		case ERDMA_QP_STATE_RTR:
			/* ignore */
			break;

		default:
			dprint(DBG_CM,
				" QP state transition undefined: %s => %s\n",
				erdma_qp_state_to_string[qp->attrs.state],
				erdma_qp_state_to_string[attrs->state]);
			break;
		}
		break;

	case ERDMA_QP_STATE_RTS:

		switch (attrs->state) {

		case ERDMA_QP_STATE_CLOSING:
			/*
			 * Verbs: move to IDLE if SQ and ORQ are empty.
			 * Move to ERROR otherwise. But first of all we must
			 * close the connection. So we keep CLOSING or ERROR
			 * as a transient state, schedule connection drop work
			 * and wait for the socket state change upcall to
			 * come back closed.
			 */

			rv = erdma_modify_qp_state_to_stop(qp, attrs, mask);

			drop_conn = 1;
			break;

		case ERDMA_QP_STATE_TERMINATE:
			qp->attrs.state = ERDMA_QP_STATE_TERMINATE;
			rv = erdma_modify_qp_state_to_stop(qp, attrs, mask);
			drop_conn = 1;

			break;

		case ERDMA_QP_STATE_ERROR:
			/*
			 * This is an emergency close.
			 *
			 * Any in progress transmit operation will get
			 * cancelled.
			 * This will likely result in a protocol failure,
			 * if a TX operation is in transit. The caller
			 * could unconditional wait to give the current
			 * operation a chance to complete.
			 * Esp., how to handle the non-empty IRQ case?
			 * The peer was asking for data transfer at a valid
			 * point in time.
			 */
			rv = erdma_modify_qp_state_to_stop(qp, attrs, mask);
			qp->attrs.state = ERDMA_QP_STATE_ERROR;
			drop_conn = 1;

			break;

		default:
			dprint(DBG_ON,
				" QP state transition undefined: %s => %s\n",
				erdma_qp_state_to_string[qp->attrs.state],
				erdma_qp_state_to_string[attrs->state]);
			break;
		}
		break;

	case ERDMA_QP_STATE_TERMINATE:

		switch (attrs->state) {

		case ERDMA_QP_STATE_ERROR:
			qp->attrs.state = ERDMA_QP_STATE_ERROR;
			break;
		default:
			dprint(DBG_ON,
				" QP state transition undefined: %s => %s\n",
				erdma_qp_state_to_string[qp->attrs.state],
				erdma_qp_state_to_string[attrs->state]);
		}
		break;

	case ERDMA_QP_STATE_CLOSING:

		switch (attrs->state) {

		case ERDMA_QP_STATE_IDLE:
			qp->attrs.state = ERDMA_QP_STATE_IDLE;

			break;

		case ERDMA_QP_STATE_CLOSING:
			/*
			 * The LLP may already moved the QP to closing
			 * due to graceful peer close init
			 */
			break;

		case ERDMA_QP_STATE_ERROR:
			/*
			 * QP was moved to CLOSING by LLP event
			 * not yet seen by user.
			 */
			rv = erdma_modify_qp_state_to_stop(qp, attrs, mask);
			qp->attrs.state = ERDMA_QP_STATE_ERROR;

			break;

		default:
			dprint(DBG_CM,
				" QP state transition undefined: %s => %s\n",
				erdma_qp_state_to_string[qp->attrs.state],
				erdma_qp_state_to_string[attrs->state]);
			return -ECONNABORTED;
		}
		break;

	default:
		dprint(DBG_CM, " NOP: State: %d\n", qp->attrs.state);
		break;
	}

	if (drop_conn)
		erdma_qp_cm_drop(qp, 0);

	return rv;
}

void erdma_qp_llp_close(struct erdma_qp *qp)
{
	struct erdma_qp_attrs          qp_attrs;

	dprint(DBG_CM, "(QP%d): Enter: ERDMA QP state = %s, cep=0x%p\n",
		QP_ID(qp), erdma_qp_state_to_string[qp->attrs.state],
		qp->cep);

	down_write(&qp->state_lock);

	dprint(DBG_CM, "(QP%d): state locked\n", QP_ID(qp));

	qp->attrs.llp_stream_handle = NULL;

	switch (qp->attrs.state) {

	case ERDMA_QP_STATE_RTS:
	case ERDMA_QP_STATE_RTR:
	case ERDMA_QP_STATE_IDLE:
	case ERDMA_QP_STATE_TERMINATE:
		qp_attrs.state = ERDMA_QP_STATE_CLOSING;
		(void)erdma_modify_qp_internal(qp, &qp_attrs, ERDMA_QP_ATTR_STATE);

		break;
	/*
	 * ERDMA_QP_STATE_CLOSING:
	 */
	case ERDMA_QP_STATE_CLOSING:
		qp->attrs.state = ERDMA_QP_STATE_IDLE;
		break;
	default:
		dprint(DBG_CM, " No state transition needed: %d\n",
			qp->attrs.state);
		break;
	}
	/*
	 * dereference closing CEP
	 */
	if (qp->cep) {
		erdma_cep_put(qp->cep);
		qp->cep = NULL;
	}

	up_write(&qp->state_lock);
	dprint(DBG_CM, "(QP%d): Exit: ERDMA QP state = %s, cep=0x%p\n",
		QP_ID(qp), erdma_qp_state_to_string[qp->attrs.state],
		qp->cep);
}
