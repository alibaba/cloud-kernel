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

#ifndef __ERDMA_COMMON_H__
#define __ERDMA_COMMON_H__

#include <linux/bitfield.h>
#include <linux/cdev.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/semaphore.h>
#include <linux/types.h>

#include <rdma/ib_verbs.h>

#include "erdma.h"
#include "erdma_hw.h"
#include "erdma_wqes_defs.h"
#include "erdma_io_defs.h"

enum erdma_cmd_status {
	ERDMA_CMD_SUBMITTED,
	ERDMA_CMD_COMPLETED,
	ERDMA_CMD_ABORTED
};

#define COMPROMISE_CC ERDMA_CC_CUBIC
enum erdma_cc_method {
	ERDMA_CC_NEWRENO = 0,
	ERDMA_CC_CUBIC,
	ERDMA_CC_HPCC_RTT,
	ERDMA_CC_HPCC_ECN,
	ERDMA_CC_HPCC_INT,
	ERDMA_CC_METHODS_NUM
};

struct erdma_comp_ctx {
	struct completion wait_event;
	struct erdma_cmdq_cq_entry *cqe;
	__u32 comp_size;
	enum erdma_cmd_status status;

	__u8 comp_status;
	__u8 cmd_opcode;
	__u8 occupied;
	__u8 ctx_id;

	__u16 sq_idx;
};

struct erdma_cmdq_sq {
	struct erdma_cmdq_sq_entry *qbuf;

	dma_addr_t dma_addr;

	spinlock_t lock;

	__u64 __iomem *db_addr;

	__u16 ci;
	__u16 pi;

	void *backup_db_addr;
	dma_addr_t backup_db_dma_addr;
};

struct erdma_cmdq_cq {
	struct erdma_cmdq_cq_entry *qbuf;

	dma_addr_t dma_addr;

	__u64 __iomem *db_addr;
	spinlock_t lock;

	__u32 ci; /* we only care about the ci of the cmdq, cqe is available when owner changes. */
	__u16 owner;

	void *backup_db_addr;
	dma_addr_t backup_db_dma_addr;
};

struct erdma_eq {
	__u8 *qbuf;

	__u32 depth;
	dma_addr_t dma_addr;
	__u64 __iomem *db_addr;

	spinlock_t lock;

	__u16 ci; /* we only care about the ci of the cmdq, cqe is available when owner changes. */
	__u16 owner;

	atomic64_t event_num;
	atomic64_t notify_num;
	__u32    max_poll_cnt;

	void *backup_db_addr;
	dma_addr_t backup_db_dma_addr;
};

struct erdma_cmdq_stats {
	atomic64_t submitted_cmd;
	atomic64_t completed_cmd;
	atomic64_t cmd_err;
	atomic64_t no_completion;
	atomic64_t cq_armed_num;
};

enum {
	ERDMA_CMDQ_STATE_RUNNING_BIT = 0,
	ERDMA_CMDQ_STATE_POLLING_BIT = 1,
};

#define ERDMA_CMDQ_POLL_INTERVAL_MS 10  /* 100ms */
#define ERDMA_CMDQ_TIMEOUT_MS       15000

#define ERDMA_REG_ACCESS_WAIT_MS    10

#define ERDMA_WAIT_DEV_DONE_CNT     1000

/* CMDQ structure. */
struct erdma_cmd_queue {
	void *erdma_dev;

	struct erdma_comp_ctx *comp_ctx;

	__u16 poll_interval;
	__u16 depth;

	__u32 completion_timeout;

	struct erdma_cmdq_sq sq;
	struct erdma_cmdq_cq cq;
	struct erdma_eq eq;

	unsigned long state;

	struct semaphore avail_cmds;
	__u16            max_outstandings;
	spinlock_t       comp_ctx_lock; /* Protects completion context pool */
	__u32            *comp_ctx_pool;
	__u16            comp_ctx_pool_next;
	__u16            *ctx_mapping_tbl;

	struct erdma_cmdq_stats stats;

	__u16 msix_vector_idx;
};

#define ERDMA_IRQNAME_SIZE 40
struct erdma_irq {
	irq_handler_t handler;
	void *data;
	int cpu;
	__u32 vector;
	cpumask_t affinity_hint_mask;
	char name[ERDMA_IRQNAME_SIZE];
};

struct erdma_stats {
	atomic64_t create_qp_cnt;
	atomic64_t destroy_qp_cnt;
	atomic64_t alloc_pd_err;
};

struct erdma_devattr {
	unsigned int device;
	unsigned int version;

	/* close match to ib_device_attr where appropriate */
	__u32                      vendor_id;
	__u32                      vendor_part_id;
	__u32                      sw_version;
	__u32                      max_qp;
	__u32                      max_send_wr;
	__u32                      max_recv_wr;
	__u32                      max_ord; /* max. outbound read queue depth */
	__u32                      max_ird; /* max. inbound read queue depth */

	enum ib_device_cap_flags   cap_flags;
	__u32                      max_send_sge;
	__u32                      max_recv_sge;
	__u32                      max_sge_rd;
	__u32                      max_cq;
	__u32                      max_cqe;
	__u64                      max_mr_size;
	__u32                      max_mr;
	__u32                      max_pd;
	__u32                      max_mw;
	__u32                      max_srq;
	__u32                      max_srq_wr;
	__u32                      max_srq_sge;
	__u32                      local_dma_key;
	/* end ib_device_attr */
};

struct erdma_eq_cb {
	__u8                  ready;
	__u8                  rsvd[3];
	struct erdma_dev      *dev;
	struct erdma_irq      irq;
	struct erdma_eq       eq;
	struct tasklet_struct tasklet;
};

struct erdma_dev {
	struct ib_device ibdev;
	struct net_device *netdev;
	struct pci_dev *pdev;

	__u8 dev_id;  /* we support max 32 devices. */

	struct device *chrdev;
	struct cdev cdev;

	struct notifier_block netdev_nb;
	unsigned char peer_addr[MAX_ADDR_LEN];

	/* physical port state (only one port per device) */
	enum ib_port_state state;

	__u8 __iomem *func_bar;

	resource_size_t func_bar_addr;
	resource_size_t func_bar_len;

	__u32 dma_width;

	struct erdma_irq cmd_irq;
	struct erdma_cmd_queue cmdq;

	__u16 irq_num;
	__u16 rsvd;

	struct erdma_eq_cb aeq;
	struct erdma_eq_cb ceqs[31];

	struct erdma_stats stats;
	struct erdma_devattr attrs;

	spinlock_t idr_lock;
	spinlock_t netdev_nb_lock;

	struct idr pd_idr;
	struct idr qp_idr;
	struct idr cq_idr;
	struct idr mem_idr;

	__u32 next_alloc_qpn;
	__u32 next_alloc_cqn;
	__u32 next_alloc_mrn;
	__u32 next_alloc_pdn;

	spinlock_t db_bitmap_lock;
	/* sdb_page + sdb_entry = 64 * 4096 + 496 * 2 * 128 = 380K */
	/* We provide 64 uContexts that each has one SQ doorbell Page. */
	DECLARE_BITMAP(sdb_page, ERDMA_SDB_NPAGE);
	/* We provide 496 uContexts that each has one SQ normal Db, and one directWQE db */
	DECLARE_BITMAP(sdb_entry, ERDMA_SQB_NENTRY);
	/* The last db page only used for normal doorbell */

	atomic_t num_pd;
	atomic_t num_qp;
	atomic_t num_cq;
	atomic_t num_cep;
	atomic_t num_mem;
	atomic_t num_ctx;
	atomic_t num_total_connect;
	atomic_t num_success_connect;
	atomic_t num_failed_connect;
	atomic_t num_total_accept;
	atomic_t num_success_accept;
	atomic_t num_failed_accept;
	atomic_t num_reject;
	atomic_t num_total_listen;
	atomic_t num_success_listen;
	atomic_t num_failed_listen;
	atomic_t num_destroy_listen;

	struct list_head qp_list;
	struct list_head cep_list;

	__u32 is_registered;
	struct dentry *debugfs;

	int numa_node;
	int cc_method;
	int grp_num;
	int disable_dwqe;
	int dwqe_pages;
	int dwqe_entries;

};

__u32 erdma_reg_read32(struct erdma_dev *dev, __u32 reg);
__u64 erdma_reg_read64(struct erdma_dev *dev, __u32 reg);
void erdma_reg_write32(struct erdma_dev *dev, __u32 reg, __u32 value);
void erdma_reg_write64(struct erdma_dev *dev, __u32 reg, __u64 value);

static inline __u32 erdma_reg_read32_filed(struct erdma_dev *dev, __u32 reg, __u32 filed_mask)
{
	__u32 val = erdma_reg_read32(dev, reg);

	return FIELD_GET(filed_mask, val);
}

static inline void native_store_db(void *db, void *db_addr)
{
	*(__u64 *)db_addr = *(__u64 *)db;
}

static inline void kick_cmdq_db(void *db, void *cmdq_db_addr)
{
	*(__u64 *)cmdq_db_addr = *(__u64 *)db;
}

static inline void arm_cmdq_cq(struct erdma_cmd_queue *cmdq)
{
	__u32 db[2];

	db[0] = (CQDB_CMD_ARM << CQDB_FIELD_ARM_OFFSET) |
		(cmdq->cq.ci & 0xFFFFFF);

	db[1] = 0;

	*(__u64 *)cmdq->cq.backup_db_addr = *(__u64 *)db;
	/* data should be ready when tlp get down*/
	mb();
	*(__u64 *)cmdq->cq.db_addr = *(__u64 *)db;

	atomic64_inc(&cmdq->stats.cq_armed_num);
}

static inline void notify_eq(struct erdma_eq *eq)
{
	__u32 db[2];

	db[0] = CQDB_CMD_ARM << CQDB_FIELD_ARM_OFFSET |
		eq->ci;
	db[1] = 0;

	*(__u64 *)eq->backup_db_addr = *(__u64 *)db;
	/* data should be ready when tlp get down*/
	mb();
	*(__u64 *)eq->db_addr = *(__u64 *)db;

	atomic64_inc(&eq->notify_num);
}

int erdma_cmdq_init(struct erdma_dev *dev);
void erdma_finish_cmdq_init(struct erdma_dev *dev);
void erdma_cmdq_destroy(struct erdma_dev *dev);

int erdma_command_exec(struct erdma_cmd_queue *cmdq,
		     struct erdma_cmdq_sq_entry *req,
		     size_t req_size,
		     struct erdma_cmdq_cq_entry *resp);

void erdma_cmdq_completion_handler(struct erdma_dev *edev);
void erdma_ceq_completion_handler(struct erdma_eq_cb *ceq_cb);

int erdma_aeq_init(struct erdma_dev *dev);
void erdma_aeq_destroy(struct erdma_dev *dev);

void avx256_kickoff(unsigned char *src, unsigned char *dst);
extern void rqe_kickoff(struct erdma_rqe *rqe, void *rq_db);
extern void avx_check(void);
#endif
