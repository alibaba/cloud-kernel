// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
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

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/pci.h>

#include "erdma.h"
#include "erdma_common.h"
#include "erdma_debug.h"
#include "erdma_hw.h"
#include "erdma_obj.h"
#include "erdma_regs_defs.h"

#include <asm/fpu/api.h>

static bool cmdq_polling_mode;
module_param(cmdq_polling_mode, bool, 0644);
MODULE_PARM_DESC(cmdq_polling_mode, "Use polling mode completion event, else interrupt mode.");

static DEFINE_STATIC_KEY_FALSE(has_avx2);

__u32 erdma_reg_read32(struct erdma_dev *dev, __u32 reg)
{
	return readl(dev->func_bar + reg);
}

__u64 erdma_reg_read64(struct erdma_dev *dev, __u32 reg)
{
	return readq(dev->func_bar + reg);
}

void erdma_reg_write32(struct erdma_dev *dev, __u32 reg, __u32 value)
{
	dprint(DBG_CTRL, "write [%p] with value [%u(0x%x)].\n",
		dev->func_bar + reg, value, value);
	writel(value, dev->func_bar + reg);
}

void erdma_reg_write64(struct erdma_dev *dev, __u32 reg, __u64 value)
{
	dprint(DBG_CTRL, "write [%p] with value [%llu(0x%llx)].\n",
		dev->func_bar + reg, value, value);
	writeq(value, dev->func_bar + reg);
}

void avx_check(void)
{
	if (static_cpu_has(X86_FEATURE_AVX2))
		static_branch_enable(&has_avx2);
}

void avx256_kickoff(unsigned char *src, unsigned char *dst)
{
	kernel_fpu_begin();

	asm volatile("vmovdqa %0, %%ymm0\n\t"
				:
				: "m" (src[0]));

	asm volatile("vmovdqa %%ymm0, %0\n\t"
				:
				: "m" (dst[0]));

	kernel_fpu_end();
}

void rqe_kickoff(struct erdma_rqe *rqe, void *rq_db)
{
	if (static_branch_likely(&has_avx2))
		avx256_kickoff((unsigned char *)rqe, (unsigned char *)rq_db);
	else {
		/* fallback */
		rqe->dwqe = 0;
		/* rarely here buf should be ready*/
		mb();
		*(__u64 *)rq_db = *(__u64 *)rqe;
	}
}

/* ID to be used with erdma_get_comp_ctx */
static __u16 erdma_alloc_ctx_id(struct erdma_cmd_queue *cmdq)
{
	__u16 ctx_id;

	spin_lock(&cmdq->comp_ctx_lock);
	ctx_id = cmdq->comp_ctx_pool[cmdq->comp_ctx_pool_next];
	cmdq->comp_ctx_pool_next++;
	spin_unlock(&cmdq->comp_ctx_lock);

	return ctx_id;
}

static void erdma_dealloc_ctx_id(struct erdma_cmd_queue *cmdq,
				   __u16 ctx_id)
{
	WARN_ON(cmdq->comp_ctx_pool_next < 1 || cmdq->comp_ctx_pool_next > cmdq->max_outstandings);

	spin_lock(&cmdq->comp_ctx_lock);
	cmdq->comp_ctx_pool_next--;
	cmdq->comp_ctx_pool[cmdq->comp_ctx_pool_next] = ctx_id;
	spin_unlock(&cmdq->comp_ctx_lock);
}

static struct erdma_comp_ctx *erdma_get_comp_ctx(struct erdma_cmd_queue *cmdq,
						 __u16 ctx_id, bool capture)
{
	if (cmdq->comp_ctx[ctx_id].occupied && capture) {
		ibdev_err_ratelimited(
			cmdq->erdma_dev,
			"Completion context %#x is occupied\n", ctx_id);
		return NULL;
	}

	if (capture) {
		cmdq->comp_ctx[ctx_id].occupied = 1;
		ibdev_dbg(cmdq->erdma_dev,
			  "Take completion ctxt for ctx_id %#x\n", ctx_id);
	}

	return &cmdq->comp_ctx[ctx_id];
}


static inline void erdma_put_comp_ctx(struct erdma_cmd_queue *cmdq,
				      struct erdma_comp_ctx *comp_ctx)
{
	ibdev_dbg(cmdq->erdma_dev, "Put completion ctx_id %#x\n", comp_ctx->ctx_id);

	WARN_ON(comp_ctx->occupied != 1);

	comp_ctx->occupied = 0;
	erdma_dealloc_ctx_id(cmdq, comp_ctx->ctx_id);
}

static void erdma_cmdq_stats_init(struct erdma_dev *dev)
{
	atomic64_t *s = (atomic64_t *)&dev->cmdq.stats;
	int i;

	for (i = 0; i < sizeof(dev->cmdq.stats) / sizeof(*s); i++, s++)
		atomic64_set(s, 0);
}

static int erdma_cmdq_comp_ctx_init(struct erdma_dev *dev, struct erdma_cmd_queue *cmdq)
{
	size_t size = cmdq->max_outstandings * sizeof(struct erdma_comp_ctx);
	struct erdma_comp_ctx *comp_ctx;
	int i;

	cmdq->comp_ctx = devm_kzalloc(&dev->pdev->dev, size, GFP_KERNEL);
	if (!cmdq->comp_ctx)
		return -ENOMEM;
	cmdq->comp_ctx_pool = devm_kzalloc(&dev->pdev->dev,
			sizeof(*cmdq->comp_ctx_pool) * cmdq->max_outstandings, GFP_KERNEL);
	if (!cmdq->comp_ctx_pool) {
		devm_kfree(&dev->pdev->dev, cmdq->comp_ctx);
		return -ENOMEM;
	}

	cmdq->ctx_mapping_tbl = devm_kzalloc(&dev->pdev->dev,
			sizeof(*cmdq->ctx_mapping_tbl) * cmdq->depth, GFP_KERNEL);
	if (!cmdq->ctx_mapping_tbl) {
		devm_kfree(&dev->pdev->dev, cmdq->comp_ctx);
		devm_kfree(&dev->pdev->dev, cmdq->comp_ctx_pool);
		return -ENOMEM;
	}

	for (i = 0; i < cmdq->depth; i++)
		cmdq->ctx_mapping_tbl[i] = 0xFF;

	for (i = 0; i < cmdq->max_outstandings; i++) {
		comp_ctx = erdma_get_comp_ctx(cmdq, i, 0);
		comp_ctx->ctx_id = i;
		init_completion(&comp_ctx->wait_event);
		cmdq->comp_ctx_pool[i] = i;
	}

	spin_lock_init(&cmdq->comp_ctx_lock);
	cmdq->comp_ctx_pool_next = 0;

	return 0;
}

static void erdma_cmdq_set_polling_mode(struct erdma_dev *dev, bool poll_en)
{
	if (poll_en)
		set_bit(ERDMA_CMDQ_STATE_POLLING_BIT, &dev->cmdq.state);
	else
		clear_bit(ERDMA_CMDQ_STATE_POLLING_BIT, &dev->cmdq.state);
}


static int erdma_cmdq_sq_init(struct erdma_dev *dev)
{
	struct erdma_cmd_queue *cmdq = &dev->cmdq;
	struct erdma_cmdq_sq *sq = &cmdq->sq;
	__u32 buf_size = cmdq->depth * sizeof(struct erdma_cmdq_sq_entry);

	sq->qbuf = dma_alloc_coherent(&dev->pdev->dev, buf_size, &sq->dma_addr, GFP_KERNEL);
	if (!sq->qbuf)
		return -ENOMEM;

	sq->backup_db_addr = dma_alloc_coherent(&dev->pdev->dev, 8,
			&sq->backup_db_dma_addr, GFP_KERNEL);
	if (!sq->backup_db_addr)
		return -ENOMEM;
	memset(sq->backup_db_addr, 0, 8);

	spin_lock_init(&sq->lock);

	sq->ci = 0;
	sq->pi = 0;

	sq->db_addr = (__u64 __iomem *)(dev->func_bar + ERDMA_BAR_CMDQ_SQDB_OFFSET);

	erdma_reg_write32(dev, ERDMA_REGS_CMDQ_SQ_ADDR_H_REG, (sq->dma_addr >> 32) & 0xFFFFFFFF);
	erdma_reg_write32(dev, ERDMA_REGS_CMDQ_SQ_ADDR_L_REG, sq->dma_addr & 0xFFFFFFFF);
	erdma_reg_write32(dev, ERDMA_REGS_CMDQ_DEPTH_REG, ERDMA_CMDQ_DEPTH);
	erdma_reg_write64(dev, ERDMA_CMDQ_SQ_DB_HOST_ADDR, sq->backup_db_dma_addr);

	return 0;
}

static int erdma_cmdq_cq_init(struct erdma_dev *dev)
{
	struct erdma_cmd_queue *cmdq = &dev->cmdq;
	struct erdma_cmdq_cq   *cq   = &cmdq->cq;
	__u32 buf_size               = cmdq->depth * sizeof(struct erdma_cmdq_cq_entry);

	cq->qbuf = dma_alloc_coherent(&dev->pdev->dev, buf_size,
			&cq->dma_addr, GFP_KERNEL);
	if (!cq->qbuf)
		return -ENOMEM;

	cq->backup_db_addr = dma_alloc_coherent(&dev->pdev->dev, 8,
			&cq->backup_db_dma_addr, GFP_KERNEL);
	if (!cq->backup_db_addr)
		return -ENOMEM;

	memset(cq->qbuf, 0, buf_size);
	memset(cq->backup_db_addr, 0, 8);

	spin_lock_init(&cq->lock);

	cq->db_addr = (__u64 __iomem *)(dev->func_bar + ERDMA_BAR_CMDQ_CQDB_OFFSET);
	cq->ci = 0;
	/* First  */
	cq->owner = 1;

	erdma_reg_write32(dev, ERDMA_REGS_CMDQ_CQ_ADDR_H_REG, (cq->dma_addr >> 32) & 0xFFFFFFFF);
	erdma_reg_write32(dev, ERDMA_REGS_CMDQ_CQ_ADDR_L_REG, cq->dma_addr & 0xFFFFFFFF);
	erdma_reg_write64(dev, ERDMA_CMDQ_CQ_DB_HOST_ADDR, cq->backup_db_dma_addr);

	return 0;
}

static int erdma_cmdq_eq_init(struct erdma_dev *dev)
{
	struct erdma_cmd_queue *cmdq = &dev->cmdq;
	struct erdma_eq   *eq        = &cmdq->eq;
	__u32 buf_size               = cmdq->depth * sizeof(struct erdma_ceq_entry);

	eq->qbuf = dma_alloc_coherent(&dev->pdev->dev, buf_size,
			&eq->dma_addr, GFP_KERNEL);
	if (!eq->qbuf)
		return -ENOMEM;

	eq->backup_db_addr = dma_alloc_coherent(&dev->pdev->dev,
			8, &eq->backup_db_dma_addr, GFP_KERNEL);
	if (!eq->backup_db_addr)
		return -ENOMEM;

	memset(eq->qbuf, 0, buf_size);
	memset(eq->backup_db_addr, 0, 8);

	spin_lock_init(&eq->lock);
	atomic64_set(&eq->event_num, 0);

	eq->depth = cmdq->depth;
	eq->db_addr = (__u64 __iomem *)(dev->func_bar + ERDMA_REGS_CEQ_DB_BASE_REG);
	eq->ci = 0;
	eq->owner = 1;

	erdma_reg_write32(dev, ERDMA_REGS_CMDQ_EQ_ADDR_H_REG, (eq->dma_addr >> 32) & 0xFFFFFFFF);
	erdma_reg_write32(dev, ERDMA_REGS_CMDQ_EQ_ADDR_L_REG, eq->dma_addr & 0xFFFFFFFF);
	erdma_reg_write32(dev, ERDMA_REGS_CMDQ_EQ_DEPTH_REG, cmdq->depth);
	erdma_reg_write64(dev, ERDMA_CMDQ_EQ_DB_HOST_ADDR, eq->backup_db_dma_addr);

	return 0;
}

int erdma_cmdq_init(struct erdma_dev *dev)
{
	int                    err, i;
	struct erdma_cmd_queue *cmdq = &dev->cmdq;
	__u32                  status, ctrl;

	cmdq->depth = ERDMA_CMDQ_DEPTH;
	cmdq->erdma_dev = dev;

	set_bit(ERDMA_CMDQ_STATE_POLLING_BIT, &cmdq->state);
	cmdq->max_outstandings = cmdq->depth / 2;

	sema_init(&cmdq->avail_cmds, cmdq->max_outstandings);
	erdma_cmdq_stats_init(dev);
	err = erdma_cmdq_comp_ctx_init(dev, cmdq);
	if (err)
		return err;

	err = erdma_cmdq_sq_init(dev);
	if (err)
		return err;

	err = erdma_cmdq_cq_init(dev);
	if (err)
		goto err_destroy_sq;

	err = erdma_cmdq_eq_init(dev);
	if (err)
		goto err_destroy_cq;

	ctrl = FIELD_PREP(ERDMA_REG_DEV_CTRL_INIT_MASK, 1);
	erdma_reg_write32(dev, ERDMA_REGS_DEV_CTRL_REG, ctrl);

	for (i = 0; i < ERDMA_WAIT_DEV_DONE_CNT; i++) {
		status = erdma_reg_read32_filed(dev, ERDMA_REGS_DEV_ST_REG,
			ERDMA_REG_DEV_ST_INIT_DONE_MASK);
		if (status)
			break;

		msleep(ERDMA_REG_ACCESS_WAIT_MS);
	}

	if (i == ERDMA_WAIT_DEV_DONE_CNT) {
		dev_err(&dev->pdev->dev, "wait init done failed.\n");
		err = -ETIMEDOUT;
		goto err_destroy_eq;
	}

	cmdq->poll_interval = ERDMA_CMDQ_POLL_INTERVAL_MS;
	cmdq->completion_timeout = ERDMA_CMDQ_TIMEOUT_MS;
	set_bit(ERDMA_CMDQ_STATE_RUNNING_BIT, &cmdq->state);

	return 0;

err_destroy_eq:
	dma_free_coherent(&dev->pdev->dev, cmdq->depth * sizeof(cmdq->eq.qbuf),
		cmdq->eq.qbuf, cmdq->eq.dma_addr);

err_destroy_cq:
	dma_free_coherent(&dev->pdev->dev, cmdq->depth * sizeof(cmdq->cq.qbuf),
		cmdq->cq.qbuf, cmdq->cq.dma_addr);

err_destroy_sq:
	dma_free_coherent(&dev->pdev->dev, cmdq->depth * sizeof(cmdq->sq.qbuf),
		cmdq->sq.qbuf, cmdq->sq.dma_addr);

	return err;
}

void erdma_finish_cmdq_init(struct erdma_dev *dev)
{
	if (cmdq_polling_mode)
		erdma_cmdq_set_polling_mode(dev, true);
	else
		erdma_cmdq_set_polling_mode(dev, false);

	if (!cmdq_polling_mode)
		arm_cmdq_cq(&dev->cmdq);
}

void erdma_cmdq_destroy(struct erdma_dev *dev)
{
	struct erdma_cmd_queue *cmdq = &dev->cmdq;
	__u32                  size;

	dprint(DBG_INIT, "destroy cmdq resources started.\n");

	clear_bit(ERDMA_CMDQ_STATE_RUNNING_BIT, &cmdq->state);

	size = cmdq->depth * sizeof(struct erdma_ceq_entry);
	dprint(DBG_INIT, "free cmdq-eq, va:%p, pa:%llx, size:0x%x\n",
		cmdq->eq.qbuf, cmdq->eq.dma_addr, size);
	dma_free_coherent(&dev->pdev->dev, size, cmdq->eq.qbuf, cmdq->eq.dma_addr);

	size = cmdq->depth * sizeof(struct erdma_cmdq_sq_entry);
	dprint(DBG_INIT, "free cmdq-sq, va:%p, pa:%llx, size:0x%x\n",
		cmdq->sq.qbuf, cmdq->sq.dma_addr, size);
	dma_free_coherent(&dev->pdev->dev, size, cmdq->sq.qbuf, cmdq->sq.dma_addr);

	size = cmdq->depth * sizeof(struct erdma_cmdq_cq_entry);
	dprint(DBG_INIT, "free cmdq-cq, va:%p, pa:%llx, size:0x%x\n",
		cmdq->cq.qbuf, cmdq->cq.dma_addr, size);
	dma_free_coherent(&dev->pdev->dev, size, cmdq->cq.qbuf, cmdq->cq.dma_addr);

	dma_free_coherent(&dev->pdev->dev, 8, cmdq->sq.backup_db_addr, cmdq->sq.backup_db_dma_addr);
	dma_free_coherent(&dev->pdev->dev, 8, cmdq->cq.backup_db_addr, cmdq->cq.backup_db_dma_addr);
	dma_free_coherent(&dev->pdev->dev, 8, cmdq->eq.backup_db_addr, cmdq->eq.backup_db_dma_addr);

	dprint(DBG_INIT, "destroy cmdq resources finished.\n");
}

static struct erdma_comp_ctx *__erdma_submit_command_request(struct erdma_cmd_queue *cmdq,
						       struct erdma_cmdq_sq_entry *req,
						       size_t cmd_size_in_bytes,
						       struct erdma_cmdq_cq_entry *comp)
{
	struct erdma_cmdq_sq_entry *sqe;
	struct erdma_comp_ctx *comp_ctx;
	__u16 queue_size_mask;
	__u16 pi, cmd_id;

	queue_size_mask = cmdq->depth - 1;
	pi = cmdq->sq.pi & queue_size_mask;

	cmd_id = erdma_alloc_ctx_id(cmdq);
	comp_ctx = erdma_get_comp_ctx(cmdq, cmd_id, true);
	if (!comp_ctx)
		return ERR_PTR(-EINVAL);

	comp_ctx->sq_idx = pi;
	comp_ctx->status = ERDMA_CMD_SUBMITTED;
	comp_ctx->comp_size = sizeof(struct erdma_cmdq_cq_entry);
	comp_ctx->cqe = comp;
	comp_ctx->cmd_opcode = req->hdr.fields.opcode;

	reinit_completion(&comp_ctx->wait_event);

	sqe = (struct erdma_cmdq_sq_entry *)(((__u8 *)cmdq->sq.qbuf + (pi << 5)));
	memset(sqe, 0, sizeof(*sqe));
	memcpy(sqe, req, cmd_size_in_bytes);

	/* For new, each cmdq-sqe is 64Byte. */
	cmdq->ctx_mapping_tbl[pi] = cmd_id;
	cmdq->sq.pi += 2;
	atomic64_inc(&cmdq->stats.submitted_cmd);
	sqe->hdr.fields.wqebb_idx = cmdq->sq.pi;

	sqe->hdr.fields.dwqe = 0;
	ddump("cmd-sq db", (__u8 *)sqe, 8);

	native_store_db(sqe, cmdq->sq.backup_db_addr);
	/* data should be ready when tlp get down*/
	mb();
	kick_cmdq_db(sqe, cmdq->sq.db_addr);

	return comp_ctx;
}

static struct erdma_comp_ctx *erdma_submit_cmdq_req(struct erdma_cmd_queue *cmdq,
						    struct erdma_cmdq_sq_entry *cmd,
						    size_t cmd_size_in_bytes,
						    struct erdma_cmdq_cq_entry *comp)
{
	struct erdma_comp_ctx *comp_ctx;

	spin_lock(&cmdq->sq.lock);
	if (!test_bit(ERDMA_CMDQ_STATE_RUNNING_BIT, &cmdq->state)) {
		spin_unlock(&cmdq->sq.lock);
		ibdev_err_ratelimited(cmdq->erdma_dev, "Admin queue is closed\n");
		return ERR_PTR(-ENODEV);
	}

	comp_ctx = __erdma_submit_command_request(cmdq, cmd, cmd_size_in_bytes, comp);
	spin_unlock(&cmdq->sq.lock);

	if (IS_ERR(comp_ctx))
		clear_bit(ERDMA_CMDQ_STATE_RUNNING_BIT, &cmdq->state);

	return comp_ctx;
}

static void memcpy_htonl(__u32 *dst, __u32 *src, __u32 len)
{
	__u32 i = 0;

	while (i < len) {
		dst[i] = ERDMA_HTONL(src[i]);
		i++;
	}
}

static void erdma_handle_single_cmdq_completion(struct erdma_cmd_queue *cmdq,
						struct erdma_cmdq_cq_entry *cqe)
{
	struct erdma_comp_ctx       *comp_ctx;
	struct erdma_cmdq_cq_entry  tmp_hdr;
	__u16                       ctx_id;

	tmp_hdr.hdr.value[0] = ERDMA_HTONL(cqe->hdr.value[0]);
	tmp_hdr.hdr.value[1] = ERDMA_HTONL(cqe->hdr.value[1]);

	ctx_id = cmdq->ctx_mapping_tbl[tmp_hdr.hdr.fields.qe_idx & (cmdq->depth - 1)];

	comp_ctx = erdma_get_comp_ctx(cmdq, ctx_id, false);
	if (!comp_ctx) {
		ibdev_err(cmdq->erdma_dev,
			  "comp_ctx is NULL. Changing the admin queue running state\n");
		clear_bit(ERDMA_CMDQ_STATE_RUNNING_BIT, &cmdq->state);
		return;
	}

	WARN_ON(comp_ctx->occupied != 1);

	comp_ctx->status = ERDMA_CMD_COMPLETED;
	comp_ctx->comp_status = tmp_hdr.hdr.fields.syndrome;

	if (comp_ctx->cqe)
		memcpy_htonl((__u32 *)comp_ctx->cqe, (u32 *)cqe,
				sizeof(struct erdma_cmdq_cq_entry) >> 2);

	ddump("get cmdq cqe", cqe, sizeof(struct erdma_cmdq_cq_entry));

	if (!test_bit(ERDMA_CMDQ_STATE_POLLING_BIT, &cmdq->state))
		complete(&comp_ctx->wait_event);
}

static void erdma_handle_cmdq_completion(struct erdma_cmd_queue *cmdq)
{
	struct erdma_cmdq_cq_entry *cqe;
	__u16 queue_size_mask;
	__u16 comp_num = 0;
	__u8 owner;
	__u16 ci;

	queue_size_mask = cmdq->depth - 1;

	ci = cmdq->cq.ci & queue_size_mask;
	owner = cmdq->cq.owner;

	cqe = &cmdq->cq.qbuf[ci];

	/* Go over all the completions */
	while (((READ_ONCE(cqe->hdr.value[0]) & 0x80) >> 7) == owner) {
		/*
		 * Do not read the rest of the completion entry before the
		 * owner bit was validated
		 */
		dma_rmb();
		erdma_handle_single_cmdq_completion(cmdq, cqe);

		ci++;
		comp_num++;
		if (ci == cmdq->depth) {
			ci = 0;
			owner = !owner;
		}

		cqe = &cmdq->cq.qbuf[ci];
	}

	cmdq->cq.ci += comp_num;
	cmdq->cq.owner = owner;
	cmdq->sq.ci += comp_num * 2; /* per CMDQ-SQ has 2 WQEBBs */
	atomic64_add(comp_num, &cmdq->stats.completed_cmd);
	if (comp_num && !test_bit(ERDMA_CMDQ_STATE_POLLING_BIT, &cmdq->state))
		arm_cmdq_cq(cmdq);
}

static int erdma_comp_status_to_errno(__u8 comp_status)
{
	switch (comp_status) {
	case ERDMA_CMDQ_CQE_STATUS_SUCCESS:
		return 0;
	default:
		return -EIO;
	}
}

static int erdma_poll_ceq_event(struct erdma_eq *ceq)
{
	struct erdma_ceq_entry      *ceqe;
	__u16                      queue_size_mask = ceq->depth - 1;
	__u32                      val;

	ceqe = (struct erdma_ceq_entry *)ceq->qbuf + (ceq->ci & queue_size_mask);

	/* Get the current completion. */
	val = READ_ONCE(*(__u32 *)ceqe);
	dma_rmb();
	if (((val & 0x80000000) >> 31) == ceq->owner) {
		ceq->ci++;

		if ((ceq->ci & queue_size_mask) == 0)
			ceq->owner = !ceq->owner;

		atomic64_add(1, &ceq->event_num);

		return val & 0xFFFFF;
	}

	return -1;
}

#define MAX_POLL_CHUNK_SIZE 16

/**
 * erdma_ceq_completion_handler - cmdq interrupt handler
 * @edev: erdma device.
 *
 * This method goes over the admin completion queue and wakes up
 * all the pending threads that wait on the commands wait event.
 *
 * @note: Should be called after MSI-X interrupt.
 */
void erdma_ceq_completion_handler(struct erdma_eq_cb *ceq_cb)
{
	int              cqn;
	struct erdma_cq  *cq;
	struct erdma_dev *edev = ceq_cb->dev;
	__u32            max_poll_cnt = 0;

	if (!ceq_cb->ready)
		return;

	while ((cqn = erdma_poll_ceq_event(&ceq_cb->eq)) != -1) {
		max_poll_cnt++;
		if (cqn == 0)
			continue;
		/* TBD: Need to clear all cq entries, to make sure that no future cq's report. */
		cq = erdma_cq_id2obj(edev, cqn, 0);
		if (!cq)
			continue;

		if (cq->ibcq.comp_handler)
			cq->ibcq.comp_handler(&cq->ibcq, cq->ibcq.cq_context);

		if (max_poll_cnt >= MAX_POLL_CHUNK_SIZE)
			break;
	}

	if (max_poll_cnt > ceq_cb->eq.max_poll_cnt)
		ceq_cb->eq.max_poll_cnt = max_poll_cnt;

	notify_eq(&ceq_cb->eq);
}

/**
 * erdma_cmdq_completion_handler - cmdq interrupt handler
 * @edev: erdma device.
 *
 * This method goes over the admin completion queue and wakes up
 * all the pending threads that wait on the commands wait event.
 *
 * @note: Should be called after MSI-X interrupt.
 */
void erdma_cmdq_completion_handler(struct erdma_dev *edev)
{
	unsigned long flags;
	int           cqn, got_event = 0;

	if (test_bit(ERDMA_CMDQ_STATE_POLLING_BIT, &edev->cmdq.state) ||
	    !test_bit(ERDMA_CMDQ_STATE_RUNNING_BIT, &edev->cmdq.state))
		return;

	while ((cqn = erdma_poll_ceq_event(&edev->cmdq.eq)) != -1)
		got_event++;

	if (got_event) {
		spin_lock_irqsave(&edev->cmdq.cq.lock, flags);
		erdma_handle_cmdq_completion(&edev->cmdq);
		spin_unlock_irqrestore(&edev->cmdq.cq.lock, flags);
	}

	notify_eq(&edev->cmdq.eq);
}

static int erdma_wait_and_process_cmdq_resp_polling(struct erdma_comp_ctx *comp_ctx,
						    struct erdma_cmd_queue *cmdq)
{
	unsigned long timeout;
	unsigned long flags;
	int err;

	dprint(DBG_CTRL, "polling cmd-cq.\n");
	timeout = jiffies + msecs_to_jiffies(cmdq->completion_timeout);

	while (1) {
		spin_lock_irqsave(&cmdq->cq.lock, flags);
		erdma_handle_cmdq_completion(cmdq);
		spin_unlock_irqrestore(&cmdq->cq.lock, flags);

		if (comp_ctx->status != ERDMA_CMD_SUBMITTED)
			break;

		if (time_is_before_jiffies(timeout)) {
			ibdev_err_ratelimited(
				cmdq->erdma_dev,
				"Wait for completion (polling) timeout\n");
			/* ERDMA didn't have any completion */
			atomic64_inc(&cmdq->stats.no_completion);

			clear_bit(ERDMA_CMDQ_STATE_RUNNING_BIT, &cmdq->state);
			err = -ETIME;
			goto out;
		}

		msleep(cmdq->poll_interval);
	}

	err = erdma_comp_status_to_errno(comp_ctx->comp_status);
out:
	erdma_put_comp_ctx(cmdq, comp_ctx);
	return err;
}

static int erdma_wait_and_process_cmdq_resp_interrupts(struct erdma_comp_ctx *comp_ctx,
						       struct erdma_cmd_queue *cmdq)
{
	unsigned long flags = 0;
	int err, stop = 0;

	wait_for_completion_timeout(&comp_ctx->wait_event,
		msecs_to_jiffies(cmdq->completion_timeout));

	/* In case the command wasn't completed find out the root cause.
	 * There might be 2 kinds of errors
	 * 1) No completion (timeout reached)
	 * 2) There is completion but the device didn't get any msi-x interrupt.
	 */
	if (unlikely(comp_ctx->status == ERDMA_CMD_SUBMITTED)) {
		spin_lock_irqsave(&cmdq->cq.lock, flags);
		erdma_handle_cmdq_completion(cmdq);
		if (comp_ctx->status == ERDMA_CMD_SUBMITTED) {
			comp_ctx->cqe = NULL; /* avoid too late interrupt for this work. */
			comp_ctx->status = ERDMA_CMD_ABORTED;
		}
		spin_unlock_irqrestore(&cmdq->cq.lock, flags);

		if (comp_ctx->status == ERDMA_CMD_COMPLETED) {
			pr_err("The erdma device sent a completion but the driver didn't receive a MSI-X interrupt.\n");
		} else {
			atomic64_inc(&cmdq->stats.no_completion);
			clear_bit(ERDMA_CMDQ_STATE_RUNNING_BIT, &cmdq->state);
			stop = 1;
			pr_err("The erdma device didn't send a completion for the cmdq.\n");
		}
	}

	err = erdma_comp_status_to_errno(comp_ctx->comp_status);
	if (!stop)
		erdma_put_comp_ctx(cmdq, comp_ctx);

	return err;
}

/*
 * There are two types to wait for completion.
 * Polling mode - wait until the completion is available.
 * Async mode - wait on wait queue until the completion is ready
 * (or the timeout expired).
 * It is expected that the IRQ called erdma_handle_cmdq_completion
 * to mark the completions.
 */
static int erdma_wait_and_process_cmdq_resp(struct erdma_comp_ctx *comp_ctx,
					    struct erdma_cmd_queue *cmdq)
{
	if (test_bit(ERDMA_CMDQ_STATE_POLLING_BIT, &cmdq->state))
		return erdma_wait_and_process_cmdq_resp_polling(comp_ctx, cmdq);

	return erdma_wait_and_process_cmdq_resp_interrupts(comp_ctx, cmdq);
}

/**
 * erdma_command_exec - Execute admin command
 * @cmdq: command queue.
 * @req: the admin command to execute.
 * @req_size: the command size.
 * @resp: command completion return entry.
 * Submit an admin command and then wait until the device will return a
 * completion.
 * The completion will be copied into comp.
 *
 * @return - 0 on success, negative value on failure.
 */
int erdma_command_exec(struct erdma_cmd_queue *cmdq,
		       struct erdma_cmdq_sq_entry *req,
		       size_t req_size,
		       struct erdma_cmdq_cq_entry *resp)
{
	struct erdma_comp_ctx *comp_ctx;
	int err;

	might_sleep();

	/* In case of queue FULL */
	down(&cmdq->avail_cmds);

	comp_ctx = erdma_submit_cmdq_req(cmdq, req, req_size, resp);
	if (IS_ERR(comp_ctx)) {
		ibdev_err_ratelimited(
			cmdq->erdma_dev,
			"Failed to submit command (opcode %u) err %ld\n",
			req->hdr.fields.opcode, PTR_ERR(comp_ctx));

		up(&cmdq->avail_cmds);
		atomic64_inc(&cmdq->stats.cmd_err);
		return PTR_ERR(comp_ctx);
	}

	err = erdma_wait_and_process_cmdq_resp(comp_ctx, cmdq);
	if (err) {
		ibdev_err_ratelimited(
			cmdq->erdma_dev,
			"Failed to process command (opcode %u) comp_status %d err %d\n",
			req->hdr.fields.opcode, comp_ctx->comp_status,
			err);
		atomic64_inc(&cmdq->stats.cmd_err);
	}

	up(&cmdq->avail_cmds);

	return err;
}

