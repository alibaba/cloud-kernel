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

#include "erdma.h"
#include "erdma_ioctl.h"
#include "erdma_obj.h"

int erdma_ioctl_ctrl_cmd(struct erdma_dev *edev, struct erdma_ioctl_msg *msg)
{
	switch (msg->in.opcode) {
	case ERDMA_CTRL_GET_CMDSQ_CI:
		msg->out.length = 2;
		*(__u16 *)msg->out.data = edev->cmdq.sq.ci;
		break;
	case ERDMA_CTRL_SET_CMDSQ_CI:
		pr_info("set cmdq-sq ci to 0x%x.\n", msg->in.data);
		edev->cmdq.sq.ci = msg->in.data;
		msg->out.length = 0;
		break;
	case ERDMA_CTRL_GET_CMDSQ_PI:
		msg->out.length = 2;
		*(__u16 *)msg->out.data = edev->cmdq.sq.pi;
		break;
	case ERDMA_CTRL_SET_CMDSQ_PI:
		pr_info("set cmdq-sq pi to 0x%x.\n", msg->in.data);
		edev->cmdq.sq.pi = msg->in.data;
		msg->out.length = 0;
		break;
	case ERDMA_CTRL_GET_CMDCQ_CI:
		msg->out.length = 2;
		*(__u16 *)msg->out.data = edev->cmdq.cq.ci;
		break;
	case ERDMA_CTRL_SET_CMDCQ_CI:
		pr_info("set cmdq-cq ci to 0x%x.\n", msg->in.data);
		edev->cmdq.cq.ci = msg->in.data;
		msg->out.length = 0;
		break;
	case ERDMA_CTRL_GET_CMDCQ_OWNER:
		msg->out.length = 2;
		*(__u16 *)msg->out.data = edev->cmdq.cq.owner;
		break;
	case ERDMA_CTRL_SET_CMDCQ_OWNER:
		pr_info("set cmdq-cq owner to 0x%x.\n", msg->in.data);
		edev->cmdq.cq.owner = msg->in.data;
		msg->out.length = 0;
		break;
	default:
		pr_err("unknown dump opcode %d.\n", msg->in.opcode);
		return -1;
	}
	return 0;
}

int erdma_ioctl_dump_cmd(struct erdma_dev *edev, struct erdma_ioctl_msg *msg)
{
	struct erdma_cq *ecq;
	struct erdma_qp *eqp;
	__u8 *cqe;
	__u8 *sqe;
	__u8 *rqe;
	__u8 *eqe;
	__u16 idx = msg->in.idx;
	__u16 qn = msg->in.qn;

	switch (msg->in.opcode) {
	case ERDMA_DUMP_OPCODE_CQE:
		if (qn == 0) {
			cqe = (__u8 *)(edev->cmdq.cq.qbuf + (idx & (edev->cmdq.depth - 1)));
		} else {
			ecq = erdma_cq_id2obj(edev, qn, 0);
			if (!ecq) {
				pr_err("Can not find CQ(%d).\n", qn);
				return -1;
			}

			cqe = (__u8 *)(ecq->queue + (idx & (ecq->depth - 1)));
		}

		ddump("cqe", cqe, sizeof(struct erdma_cqe));
		memcpy(msg->out.data, cqe, sizeof(struct erdma_cqe));
		msg->out.length = sizeof(struct erdma_cqe);

		break;
	case ERDMA_DUMP_OPCODE_SQE:
		if (qn == 0) {
			idx &= (edev->cmdq.depth - 1);
			sqe = (__u8 *)((void *)edev->cmdq.sq.qbuf + idx * ERDMA_SQ_WQEBB_SIZE);
		} else {
			eqp = erdma_qp_id2obj(edev, qn);
			if (!eqp) {
				pr_err("Can not find QP(%d).\n", qn);
				return -1;
			}
			erdma_qp_put(eqp);

			idx &= (eqp->sendq.depth - 1);
			sqe = (__u8 *)(eqp->sendq.qbuf + ERDMA_SQ_WQEBB_SIZE * idx);
		}

		ddump("sqe", sqe, ERDMA_SQ_WQEBB_SIZE);
		memcpy(msg->out.data, sqe, ERDMA_SQ_WQEBB_SIZE);
		msg->out.length = ERDMA_SQ_WQEBB_SIZE;

		break;
	case ERDMA_DUMP_OPCODE_RQE:
		if (qn == 0)
			return -1;

		eqp = erdma_qp_id2obj(edev, qn);
		if (!eqp) {
			pr_err("Can not find QP(%d).\n", qn);
			return -1;
		}
		erdma_qp_put(eqp);
		idx &= (eqp->recvq.depth - 1);
		rqe = (__u8 *)(eqp->recvq.qbuf + ERDMA_MAX_RQE_SIZE * idx);

		ddump("rqe", rqe, ERDMA_MAX_RQE_SIZE);
		memcpy(msg->out.data, rqe, ERDMA_MAX_RQE_SIZE);
		msg->out.length = ERDMA_MAX_RQE_SIZE;

		break;
	case ERDMA_DUMP_OPCODE_EQE:
		if (msg->in.qn == 0) {
			idx &= (edev->cmdq.eq.depth - 1);
			eqe = (__u8 *)(edev->cmdq.eq.qbuf + ERDMA_EQ_WQEBB_SIZE * idx);

			ddump("eqe", eqe, ERDMA_EQ_WQEBB_SIZE);
			memcpy(msg->out.data, eqe, ERDMA_EQ_WQEBB_SIZE);
			msg->out.length = ERDMA_EQ_WQEBB_SIZE;
		} else if (msg->in.qn >= 1 && msg->in.qn < edev->irq_num) {
			if (edev->ceqs[msg->in.qn - 1].ready == 0)
				return -1;

			idx &= (edev->ceqs[msg->in.qn - 1].eq.depth - 1);
			eqe = (__u8 *)(edev->ceqs[msg->in.qn - 1].eq.qbuf +
						ERDMA_EQ_WQEBB_SIZE * idx);
			ddump("eqe", eqe, ERDMA_EQ_WQEBB_SIZE);
			memcpy(msg->out.data, eqe, ERDMA_EQ_WQEBB_SIZE);
			msg->out.length = ERDMA_EQ_WQEBB_SIZE;
		} else
			return -1;

		break;
	default:
		pr_err("unknown dump opcode %d.\n", msg->in.opcode);
		return -1;
	}
	return 0;
}


int erdma_ioctl_stat_cmd(struct erdma_dev *edev, struct erdma_ioctl_msg *msg)
{
#ifdef ERDMA_ENABLE_DEBUG
	struct erdma_cq *cq;
	struct erdma_qp *eqp;
	__u16 qn = msg->in.qn;
	__u64 *stats_data;

	switch (msg->in.opcode) {
	case ERDMA_STAT_OPCODE_QP:
		if (qn == 0)
			return -1;
		eqp = erdma_qp_id2obj(edev, qn);
		if (!eqp) {
			pr_err("Can not find QP(%d).\n", qn);
			return -1;
		}
		erdma_qp_put(eqp);

		memcpy(msg->out.data, eqp->snapshot, 256);
		msg->out.length = 256;

		break;
	case ERDMA_STAT_OPCODE_CQ:
		if (qn == 0)
			return -1;
		cq = erdma_cq_id2obj(edev, qn, 0);
		if (!cq) {
			pr_err("Can not find CQ(%d).\n", qn);
			return -1;
		}

		memcpy(msg->out.data, cq->snapshot, 256);
		msg->out.length = 256;

		break;
	case ERDMA_STAT_OPCODE_DEV:
		stats_data = (__u64 *)msg->out.data;
		stats_data[0] = erdma_reg_read64(edev, 0x80);
		stats_data[1] = erdma_reg_read64(edev, 0x88);
		stats_data[2] = erdma_reg_read64(edev, 0x90);
		stats_data[3] = erdma_reg_read64(edev, 0x98);
		stats_data[4] = erdma_reg_read64(edev, 0xa0);
		stats_data[5] = erdma_reg_read64(edev, 0xa8);

		stats_data[6] = erdma_reg_read64(edev, 0xc0);
		stats_data[7] = erdma_reg_read64(edev, 0xc8);
		stats_data[8] = erdma_reg_read64(edev, 0xd0);
		stats_data[9] = erdma_reg_read64(edev, 0xd8);
		stats_data[10] = erdma_reg_read64(edev, 0xe0);

		msg->out.length = 256;
		break;
	default:
		pr_err("unknown stat opcode %d.\n", msg->in.opcode);
		return -1;
	}

	return 0;
#else
	return -1;
#endif
}

int erdma_ioctl_info_cmd(struct erdma_dev *edev, struct erdma_ioctl_msg *msg)
{
	struct erdma_dev_info *dev_info = (struct erdma_dev_info *)&msg->out.data;
	struct erdma_qp_info  *qp_info  = (struct erdma_qp_info *)&msg->out.data;
	__u32 qpn;
	struct erdma_qp *qp;

	switch (msg->in.opcode) {
	case ERDMA_INFO_OPCODE_DEV:
		dev_info->devid = edev->dev_id;
		memset(&dev_info->node_guid, 0, 8);

		if (edev->netdev)
			memcpy(&dev_info->node_guid, edev->netdev->dev_addr, 6);

		msg->out.length = 256;
		break;
	case ERDMA_INFO_OPCODE_QP:
		qpn = msg->in.qn;
		if (qpn == 0)
			return -1;
		qp = erdma_qp_id2obj(edev, qpn);
		if (!qp)
			return -ENOENT;

		qp_info->qpn = QP_ID(qp);
		qp_info->qp_state = qp->attrs.state;
		qp_info->sip = qp->attrs.sip;
		qp_info->dip = qp->attrs.dip;
		qp_info->dport = qp->attrs.dport;
		qp_info->sport = qp->attrs.sport;
		qp_info->origin_sport = qp->attrs.origin_sport;
		qp_info->sq_depth = qp->sendq.depth;
		qp_info->rq_depth = qp->recvq.depth;
		qp_info->remote_qpn = qp->attrs.remote_qpn;
		qp_info->qtype = qp->qp_type;

		erdma_qp_put(qp);

		break;
	default:
		break;
	}

	return 0;
}

long do_ioctl(void *pedev, unsigned int cmd, unsigned long arg)
{
	struct erdma_dev *edev = (struct erdma_dev *)pedev;
	struct erdma_ioctl_msg msg;
	struct erdma_cq *ecq;
	int err = 0;

	err = copy_from_user(&msg, (const void *)arg, sizeof(struct erdma_ioctl_msg));
	if (err)
		return -EINVAL;

	if (_IOC_TYPE(cmd) != ERDMA_IOC_MAGIC)
		return -EINVAL;
	if (_IOC_NR(cmd) > ERDMA_IOC_MAXNR)
		return -EINVAL;

	switch (cmd) {
	case ERDMA_DUMP:
		err = erdma_ioctl_dump_cmd(edev, &msg);
		if (err)
			return err;
		msg.out.status = 0x0;
		if (copy_to_user((void *)arg, (const void *)&msg, sizeof(struct erdma_ioctl_msg))) {
			pr_err("copy data to user space failed.\n");
			return -EINVAL;
		}
		break;
	case ERDMA_CTRL:
		err = erdma_ioctl_ctrl_cmd(edev, &msg);
		if (err)
			return err;
		msg.out.status = 0x0;
		if (copy_to_user((void *)arg, (const void *)&msg, sizeof(struct erdma_ioctl_msg))) {
			pr_err("copy data to user space failed.\n");
			return -EINVAL;
		}
		break;
	case ERDMA_STAT:
		err = erdma_ioctl_stat_cmd(edev, &msg);
		if (err)
			return err;
		msg.out.status = 0x0;
		if (copy_to_user((void *)arg, (const void *)&msg, sizeof(struct erdma_ioctl_msg))) {
			pr_err("copy data to user space failed.\n");
			return -EINVAL;
		}
		break;
	case ERDMA_INFO:
		err = erdma_ioctl_info_cmd(edev, &msg);
		if (err)
			return err;
		msg.out.status = 0;
		if (copy_to_user((void *)arg, (const void *)&msg, sizeof(struct erdma_ioctl_msg))) {
			pr_err("copy data to user space failed.\n");
			return -EINVAL;
		}
		break;
	case 0x10:
		ecq = erdma_cq_id2obj(edev, msg.in.qn, 0);
		if (ecq == NULL) {
			pr_err("can not find cqn(%d).\n", msg.in.qn);
			return -EINVAL;
		}

		ecq->queue[0].qe_idx = 0;
		ecq->queue[0].owner = 0x80;
		ecq->queue[0].qpn = 1;
		ecq->queue[0].qtype = 0;
		ecq->queue[0].syndrome = 0;

		if (ecq->ibcq.comp_handler) {
			pr_info("wait up cqn (%d)\n", msg.in.qn);
			ecq->ibcq.comp_handler(&ecq->ibcq, ecq->ibcq.cq_context);
		}

		break;
	default:
		return -EINVAL;
	}
	return err;
}

long chardev_ioctl(struct file *filp,
		   unsigned int cmd, unsigned long arg)
{
	struct erdma_dev *edev = filp->private_data;

	return do_ioctl(edev, cmd, arg);
}


