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

#include <linux/kernel.h>
#include <linux/pci.h>

#include <rdma/ib_umem.h>

#include "erdma.h"
#include "erdma_debug.h"
#include "erdma_command.h"
#include "erdma_common.h"
#include "erdma_hw.h"
#include "erdma_wqes_defs.h"

#define ERDMA_CMDQ_BUILD_REQ_HDR(req_hdr, mod, op, wqe_size) \
do { \
	(req_hdr)->hdr.fields.sub_mod = mod;\
	(req_hdr)->hdr.fields.opcode = op;\
	(req_hdr)->hdr.fields.dwqe = 1;\
	(req_hdr)->hdr.fields.wqebb_cnt = wqe_size;\
} while (0)

int erdma_exec_query_device_cmd(struct erdma_dev *dev,
				struct erdma_query_device_result *result)
{
	int                                  rv;
	struct erdma_cmdq_sq_entry           base_req = {0};
	struct erdma_cmdq_query_device_resp  resp;

	ERDMA_CMDQ_BUILD_REQ_HDR(&base_req, CMDQ_SUBMOD_RDMA,
			CMDQ_OPCODE_QUERY_DEVICE, ERDMA_SQE_64B_WQEBB_CNT);
	rv = erdma_command_exec(&dev->cmdq, &base_req,
		sizeof(struct erdma_cmdq_sq_entry), (struct erdma_cmdq_cq_entry *)&resp);

	if (rv || resp.hdr.fields.syndrome != 0) {
		dev_err(&dev->pdev->dev,
			"ERROR: code = %d, exec query device command failed.\n",
			resp.hdr.fields.syndrome);
		return -EINVAL;
	}

	result->max_cq = 1 << resp.max_cq;
	result->max_cqe = 1 << resp.max_cqe;
	result->max_fmr = 1 << resp.max_fmr;
	result->max_mr = 1 << resp.max_mr;
	result->max_mr_size = 1 << resp.max_mr_size;
	result->max_mw = 1 << resp.max_mw;
	result->max_qp = 1 << resp.max_qp;
	result->max_recv_wr = 1 << resp.max_qp_wr;
	result->max_send_wr = (1 << 15) / 4;

	result->max_send_sge = resp.max_sge;
	result->max_recv_sge = 1;
	result->local_dma_key = resp.local_dma_key;
	result->default_cc = resp.default_cc;

	if (resp.max_qblk != 0) {
		result->max_qp = 1024 * resp.max_qblk;
		result->max_mr = 2 * result->max_qp;
		result->max_cq =  2  * result->max_qp;
	}
	dprint(DBG_CMDQ, "default_cc: %d\n", resp.default_cc);
	dprint(DBG_CMDQ, "device cap: max_cq:0x%x, max_cqe:0x%x\n",
				result->max_cq, result->max_cqe);
	dprint(DBG_CMDQ, "device cap: max_mr:0x%x, max_mr_size:0x%x\n",
				result->max_mr, result->max_mr_size);
	dprint(DBG_CMDQ,
		"device cap: max_qp:0x%x, max_recv_wr:0x%x, max_send_sge:0x%x, max_recv_sge:0x%x\n",
		result->max_qp, result->max_recv_wr, result->max_send_sge, result->max_recv_sge);

	return 0;
}

int erdma_exec_create_qp_cmd(struct erdma_dev *dev,
			     struct erdma_create_qp_params *params)
{
	struct erdma_cmdq_sq_entry base_req = {0};
	struct erdma_cmdq_create_qp_req *req = (struct erdma_cmdq_create_qp_req *)&base_req;
	struct erdma_cmdq_cq_entry resp;
	int rv;

	ERDMA_CMDQ_BUILD_REQ_HDR(&base_req, CMDQ_SUBMOD_RDMA,
			CMDQ_OPCODE_CREATE_QP, ERDMA_SQE_64B_WQEBB_CNT);

	if ((params->sq_depth & (params->sq_depth - 1)) != 0 ||
	    (params->rq_depth & (params->rq_depth - 1)) != 0) {
		dev_err(&dev->pdev->dev, "ERROR: sq/rq depth is not power of 2.\n");
		return -EINVAL;
	}

	req->pd = params->pd;
	req->qpn = params->qpn;
	req->rcqn = params->rcqn;
	req->scqn = params->scqn;
	req->rq_buf_addr = params->rq_buf_addr;

	req->rq_depth = ffs(params->rq_depth) - 1;
	req->sq_buf_addr = params->sq_buf_addr;

	req->sq_depth = ffs(params->sq_depth) - 1;
	req->sq_db_dma_addr = params->sq_db_dma_addr;
	req->rq_db_dma_addr = params->rq_db_dma_addr;
	rv = erdma_command_exec(&dev->cmdq, &base_req,
		sizeof(struct erdma_cmdq_sq_entry), &resp);

	if (rv)
		return rv;

	if (rv || resp.hdr.fields.syndrome != 0) {
		dev_err(&dev->pdev->dev, "ERROR: CQE has error %d.\n",
			resp.hdr.fields.syndrome);
		return -EIO;
	}

	return 0;
}

int erdma_exec_modify_qp_cmd(struct erdma_dev *dev,
			     struct erdma_modify_qp_params *params)
{
	struct erdma_cmdq_sq_entry base_req = {0};
	struct erdma_cmdq_modify_qp_req *req = (struct erdma_cmdq_modify_qp_req *)&base_req;
	struct erdma_cmdq_cq_entry resp;
	int rv;

	ERDMA_CMDQ_BUILD_REQ_HDR(&base_req, CMDQ_SUBMOD_RDMA,
			CMDQ_OPCODE_MODIFY_QP, ERDMA_SQE_64B_WQEBB_CNT);

	req->state = params->state;
	req->qpn = params->qpn;
	req->remote_qpn = params->remote_qpn;

	req->dip = params->dip;
	req->sip = params->sip;
	req->dport = params->dport;
	req->sport = params->sport;

	req->send_nxt = params->snd_nxt;
	req->recv_nxt = params->rcv_nxt;

	req->cc_method = params->cc_method;
	req->ts_ecr = params->ts_ecr;
	req->ts_val = params->ts_val;

	rv = erdma_command_exec(&dev->cmdq, &base_req,
		sizeof(struct erdma_cmdq_sq_entry), &resp);

	if (rv || resp.hdr.fields.syndrome != 0) {
		dev_err(&dev->pdev->dev, "ERROR: CQE has error %d.\n",
			resp.hdr.fields.syndrome);
		return -EIO;
	}

	return 0;
}

int erdma_exec_dereg_mr_cmd(struct erdma_dev *dev,
			    struct erdma_dereg_mr_params *params)
{
	int err;
	struct erdma_cmdq_sq_entry base_req = {0};
	struct erdma_cmdq_dereg_mr_req *req = (struct erdma_cmdq_dereg_mr_req *)&base_req;
	struct erdma_cmdq_cq_entry resp;

	ERDMA_CMDQ_BUILD_REQ_HDR(&base_req, CMDQ_SUBMOD_RDMA,
			CMDQ_OPCODE_DEREG_MR, ERDMA_SQE_64B_WQEBB_CNT);
	req->mpt_idx = params->l_key >> 8;
	req->key = (params->l_key & 0xFF);

	err = erdma_command_exec(&dev->cmdq, &base_req,
		sizeof(struct erdma_cmdq_sq_entry), (struct erdma_cmdq_cq_entry *)&resp);

	if (err || resp.hdr.fields.syndrome != 0) {
		dev_err(&dev->pdev->dev,
			"ERROR: code = %d, exec command failed.\n", resp.hdr.fields.syndrome);
		return -EIO;
	}

	return 0;
}

int erdma_exec_reg_mr_cmd(struct erdma_dev *dev,
			  struct erdma_reg_mr_params *params)
{
	struct erdma_mr *mr = params->mr;
	struct ib_umem *umem = mr->umem;
	struct erdma_cmdq_sq_entry base_req = {0};
	struct erdma_cmdq_reg_mr_req *regmr_req = (struct erdma_cmdq_reg_mr_req *)&base_req;
	struct erdma_cmdq_cq_entry resp;
	__u64 *phy_addr;
	int rv;
	int mtt_cnt = 0;
	int total_mtt_cnt;
	struct ib_block_iter biter;
	__u32                        page_size;

	ERDMA_CMDQ_BUILD_REQ_HDR(&base_req, CMDQ_SUBMOD_RDMA, CMDQ_OPCODE_REG_MR,
			ERDMA_SQE_64B_WQEBB_CNT);

	regmr_req->valid = params->valid;
	regmr_req->key = params->stag & 0xFF;
	regmr_req->mpt_idx = params->stag >> 8;
	regmr_req->pd = params->pd_id;
	regmr_req->type = 0;
	regmr_req->access_right = params->access;
	regmr_req->access_mode = 0;

	regmr_req->start_va = params->start_va;
	regmr_req->size = params->len;

	page_size = ib_umem_find_best_pgsz(umem, (SZ_2G - SZ_4K), params->start_va);
	total_mtt_cnt = ib_umem_num_dma_blocks(umem, page_size);

	dprint(DBG_MM, "(MPT%u): total_sgl_cnt %d.\n",
		MR_ID(mr), total_mtt_cnt);

	if (total_mtt_cnt <= 4) {
		phy_addr = regmr_req->phy_addr;
		rdma_umem_for_each_dma_block(umem, &biter, page_size) {
			*phy_addr = rdma_block_iter_dma_address(&biter);
			phy_addr++;
			mtt_cnt++;
		}

		regmr_req->mtt_type = 0;
		regmr_req->mtt_cnt = mtt_cnt;
	} else {
		mr->mtt_size = total_mtt_cnt * 8;

		if (mr->mtt_size > 4 * 1024 * 1024) {
			ibdev_err(&dev->ibdev, "(MPT%u): mtt to large:%u",
				MR_ID(mr), mr->mtt_size);
			return -EINVAL;
		}

		mr->mtt_va_addr = dma_alloc_coherent(&dev->pdev->dev, mr->mtt_size,
				&mr->mtt_dma_addr, GFP_KERNEL);
		if (!mr->mtt_va_addr)
			return -ENOMEM;
		mr->total_mtt_size = mr->mtt_size;

		phy_addr = mr->mtt_va_addr;
		rdma_umem_for_each_dma_block(umem, &biter, page_size) {
			*phy_addr = rdma_block_iter_dma_address(&biter);
			phy_addr++;
			mtt_cnt++;
		}

		regmr_req->mtt_type = 1;
		regmr_req->mtt_cnt = mtt_cnt;
		phy_addr = regmr_req->phy_addr;
		*phy_addr = mr->mtt_dma_addr;
	}

	regmr_req->log_page_size = ilog2(page_size);

	rv = erdma_command_exec(&dev->cmdq, &base_req,
		sizeof(struct erdma_cmdq_sq_entry), &resp);

	return rv;
}

int erdma_exec_alloc_mr_cmd(struct erdma_dev *dev, struct erdma_reg_mr_params *params)
{
	struct erdma_mr              *mr          = params->mr;
	struct erdma_cmdq_sq_entry   base_req     = {0};
	struct erdma_cmdq_reg_mr_req *regmr_req   = (struct erdma_cmdq_reg_mr_req *)&base_req;
	struct erdma_cmdq_cq_entry   resp;
	__u64                        *phy_addr;
	int                          rv;
	int num;

	ERDMA_CMDQ_BUILD_REQ_HDR(&base_req, CMDQ_SUBMOD_RDMA,
			CMDQ_OPCODE_REG_MR, ERDMA_SQE_64B_WQEBB_CNT);

	regmr_req->valid = params->valid;
	regmr_req->key = params->stag & 0xFF;
	regmr_req->mpt_idx = params->stag >> 8;
	regmr_req->pd = params->pd_id;
	regmr_req->type = 0;
	regmr_req->access_right = params->access;
	regmr_req->access_mode = 0;

	regmr_req->start_va = params->start_va;
	regmr_req->size = params->len;
	mr->ibmr.page_size = SZ_4K;
	regmr_req->log_page_size = ilog2(mr->ibmr.page_size);
	if (mr->ibmr.page_size != SZ_4K)
		pr_warn("erdma: mr page size is not 4K");

	regmr_req->mtt_type = 1;
	regmr_req->mtt_cnt = mr->prealloc_mtt_nents;

	phy_addr = regmr_req->phy_addr;
	*phy_addr = mr->mtt_dma_addr;

	rv = erdma_command_exec(&dev->cmdq, &base_req,
		sizeof(struct erdma_cmdq_sq_entry), &resp);
	if (rv)
		return rv;

	return num;
}

int erdma_exec_create_cq_cmd(struct erdma_dev *dev,
			     struct erdma_create_cq_params *params)
{
	int                                 i, err;
	struct erdma_cmdq_sq_entry          base_req = {0};
	struct erdma_cmdq_create_cq_req     *req     = (struct erdma_cmdq_create_cq_req *)&base_req;
	struct erdma_cmdq_cq_entry          resp;

	ERDMA_CMDQ_BUILD_REQ_HDR(&base_req, CMDQ_SUBMOD_RDMA,
			CMDQ_OPCODE_CREATE_CQ, ERDMA_SQE_64B_WQEBB_CNT);
	req->cqn = params->cqn;

	if ((params->depth & (params->depth - 1)) != 0) {
		dev_err(&dev->pdev->dev, "ERROR: cq depth is not power of 2.\n");
		return -EINVAL;
	}

	req->cq_depth = ffs(params->depth) - 1;
	req->eqn = params->eqn;
	req->cq_buf_addr0 = params->mtt_entry[0];
	req->page_size = ffs(params->page_size) - 13;
	req->mtt_cnt = params->mtt_cnt;
	req->type = params->mtt_type;
	req->cq_host_db_addr_l = *(__u32 *)(&params->host_db_dma_addr);
	req->cq_host_db_addr_h = *((__u32 *)(&params->host_db_dma_addr) + 1);
	req->first_page_offset = params->first_page_offset;

	dprint(DBG_CTRL, "page_size:%u,mtt_cnt:%u,type:%u", req->page_size,
			req->mtt_cnt, req->type);
	dprint(DBG_CTRL, "addr0:%llx\n", req->cq_buf_addr0);

	if (req->type == 0) {
		for (i = 1; i < req->mtt_cnt; i++) {
			req->cq_buf_addr1[i - 1] = params->mtt_entry[i];
			dprint(DBG_CTRL, "addr1[%d]:%llx\n", i - 1, req->cq_buf_addr1[i - 1]);
		}
	}

	err = erdma_command_exec(&dev->cmdq, &base_req,
		sizeof(struct erdma_cmdq_sq_entry), (struct erdma_cmdq_cq_entry *)&resp);

	if (err || resp.hdr.fields.syndrome != 0) {
		dev_err(&dev->pdev->dev,
			"ERROR: code = %d, exec command failed.\n", resp.hdr.fields.syndrome);
		return -EIO;
	}

	return 0;
}

int erdma_exec_destroy_cq_cmd(struct erdma_dev *dev,
			      struct erdma_destroy_cq_params *params)
{
	int err;
	struct erdma_cmdq_sq_entry base_req = {0};
	struct erdma_cmdq_destroy_cq_req *req = (struct erdma_cmdq_destroy_cq_req *)&base_req;
	struct erdma_cmdq_cq_entry resp;

	ERDMA_CMDQ_BUILD_REQ_HDR(&base_req, CMDQ_SUBMOD_RDMA,
			CMDQ_OPCODE_DESTROY_CQ, ERDMA_SQE_64B_WQEBB_CNT);
	req->cqn = params->cqn;

	err = erdma_command_exec(&dev->cmdq, &base_req,
		sizeof(struct erdma_cmdq_sq_entry), (struct erdma_cmdq_cq_entry *)&resp);

	if (err || resp.hdr.fields.syndrome != 0) {
		dev_err(&dev->pdev->dev,
			"ERROR: code = %d, exec command failed.\n", resp.hdr.fields.syndrome);
		return -EIO;
	}

	return 0;
}

int erdma_exec_destroy_qp_cmd(struct erdma_dev *dev,
			      struct erdma_destroy_qp_params *params)
{
	int err;
	struct erdma_cmdq_sq_entry base_req = {0};
	struct erdma_cmdq_destroy_qp_req *req =
			(struct erdma_cmdq_destroy_qp_req *)&base_req;
	struct erdma_cmdq_cq_entry resp;

	ERDMA_CMDQ_BUILD_REQ_HDR(&base_req, CMDQ_SUBMOD_RDMA,
			CMDQ_OPCODE_DESTROY_QP, ERDMA_SQE_64B_WQEBB_CNT);
	req->qpn = params->qpn;

	err = erdma_command_exec(&dev->cmdq, &base_req,
		sizeof(struct erdma_cmdq_sq_entry), (struct erdma_cmdq_cq_entry *)&resp);

	if (err || resp.hdr.fields.syndrome != 0) {
		dev_err(&dev->pdev->dev,
			"ERROR: code = %d, exec command failed.\n", resp.hdr.fields.syndrome);
		return -EIO;
	}

	return 0;
}

int erdma_exec_create_eq_cmd(struct erdma_dev *dev,
			     struct erdma_create_eq_params *params,
			     __u8 eq_type)
{
	int err;
	struct erdma_cmdq_sq_entry base_req = {0};
	struct erdma_cmdq_create_eq_req *req = (struct erdma_cmdq_create_eq_req *)&base_req;
	struct erdma_cmdq_cq_entry resp;

	ERDMA_CMDQ_BUILD_REQ_HDR(&base_req, CMDQ_SUBMOD_COMMON,
			CMDQ_OPCODE_CREATE_EQ, ERDMA_SQE_64B_WQEBB_CNT);
	req->eqn = params->eqn;
	req->depth = ffs(params->depth) - 1;
	req->qbuf_addr = params->queue_addr;
	req->qtype = eq_type;
	req->vector_idx = params->vector_idx;
	req->db_dma_addr_l = *(__u32 *)(&params->db_dma_addr);
	req->db_dma_addr_h = *((__u32 *)(&params->db_dma_addr) + 1);

	err = erdma_command_exec(&dev->cmdq, &base_req,
		sizeof(struct erdma_cmdq_sq_entry), (struct erdma_cmdq_cq_entry *)&resp);

	if (err || resp.hdr.fields.syndrome != 0) {
		dev_err(&dev->pdev->dev,
			"ERROR: code = %d, exec command failed.\n", resp.hdr.fields.syndrome);
		return -EIO;
	}

	return 0;
}

int erdma_exec_destroy_eq_cmd(struct erdma_dev *dev,
			      struct erdma_destroy_eq_params *params,
			      __u8 eq_type)
{
	int err;
	struct erdma_cmdq_sq_entry base_req = {0};
	struct erdma_cmdq_destroy_eq_req *req = (struct erdma_cmdq_destroy_eq_req *)&base_req;
	struct erdma_cmdq_cq_entry resp;

	ERDMA_CMDQ_BUILD_REQ_HDR(&base_req, CMDQ_SUBMOD_COMMON,
			CMDQ_OPCODE_DESTROY_EQ, ERDMA_SQE_64B_WQEBB_CNT);
	req->eqn = params->eqn;
	req->qtype = eq_type;
	req->vector_idx = params->vector_idx;

	err = erdma_command_exec(&dev->cmdq, &base_req,
		sizeof(struct erdma_cmdq_sq_entry), (struct erdma_cmdq_cq_entry *)&resp);

	if (err || resp.hdr.fields.syndrome != 0) {
		dev_err(&dev->pdev->dev,
			"ERROR: code = %d, exec command failed.\n", resp.hdr.fields.syndrome);
		return -EIO;
	}

	return 0;
}
