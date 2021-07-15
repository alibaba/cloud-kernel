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

#include <linux/errno.h>
#include <linux/types.h>
#include <net/tcp.h>
#include <linux/list.h>
#include <linux/debugfs.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "erdma.h"
#include "erdma_cm.h"
#include "erdma_obj.h"
#include "erdma_ioctl.h"

__u32 dprint_mask;
module_param(dprint_mask, uint, 0644);
MODULE_PARM_DESC(dprint_mask, "debug information print level");

#define FDENTRY(f) (f->f_path.dentry)

char ib_qp_state_to_string[IB_QPS_ERR+1][sizeof "RESET"] = {
	[IB_QPS_RESET]	= "RESET",
	[IB_QPS_INIT]	= "INIT",
	[IB_QPS_RTR]	= "RTR",
	[IB_QPS_RTS]	= "RTS",
	[IB_QPS_SQD]	= "SQD",
	[IB_QPS_SQE]	= "SQE",
	[IB_QPS_ERR]	= "ERR"
};

void erdma_print_qp_attr_mask(enum ib_qp_attr_mask attr_mask, char *msg)
{
	if (DBG_CM & dprint_mask) {
		pr_info("-------- %s -------\n", msg);
		if (IB_QP_STATE & attr_mask)
			pr_info("IB_QP_STATE\n");
		if (IB_QP_CUR_STATE & attr_mask)
			pr_info("IB_QP_CUR_STATE\n");
		if (IB_QP_EN_SQD_ASYNC_NOTIFY & attr_mask)
			pr_info("IB_QP_EN_SQD_ASYNC_NOTIFY\n");
		if (IB_QP_ACCESS_FLAGS & attr_mask)
			pr_info("IB_QP_ACCESS_FLAGS\n");
		if (IB_QP_PKEY_INDEX & attr_mask)
			pr_info("IB_QP_PKEY_INDEX\n");
		if (IB_QP_PORT & attr_mask)
			pr_info("IB_QP_PORT\n");
		if (IB_QP_QKEY & attr_mask)
			pr_info("IB_QP_QKEY\n");
		if (IB_QP_AV & attr_mask)
			pr_info("IB_QP_AV\n");
		if (IB_QP_PATH_MTU & attr_mask)
			pr_info("IB_QP_PATH_MTU\n");
		if (IB_QP_TIMEOUT & attr_mask)
			pr_info("IB_QP_TIMEOUT\n");
		if (IB_QP_RETRY_CNT & attr_mask)
			pr_info("IB_QP_RETRY_CNT\n");
		if (IB_QP_RNR_RETRY & attr_mask)
			pr_info("IB_QP_RNR_RETRY\n");
		if (IB_QP_RQ_PSN & attr_mask)
			pr_info("IB_QP_RQ_PSN\n");
		if (IB_QP_MAX_QP_RD_ATOMIC & attr_mask)
			pr_info("IB_QP_MAX_QP_RD_ATOMIC\n");
		if (IB_QP_ALT_PATH & attr_mask)
			pr_info("IB_QP_ALT_PATH\n");
		if (IB_QP_MIN_RNR_TIMER & attr_mask)
			pr_info("IB_QP_MIN_RNR_TIMER\n");
		if (IB_QP_SQ_PSN & attr_mask)
			pr_info("IB_QP_SQ_PSN\n");
		if (IB_QP_MAX_DEST_RD_ATOMIC & attr_mask)
			pr_info("IB_QP_MAX_DEST_RD_ATOMIC\n");
		if (IB_QP_PATH_MIG_STATE & attr_mask)
			pr_info("IB_QP_PATH_MIG_STATE\n");
		if (IB_QP_CAP & attr_mask)
			pr_info("IB_QP_CAP\n");
		if (IB_QP_DEST_QPN & attr_mask)
			pr_info("IB_QP_DEST_QPN\n");
		pr_info("-------- %s -(end)-\n", msg);
	}
}

static ssize_t erdma_show_qps(struct file *f, char __user *buf, size_t space,
			      loff_t *ppos)
{

	struct erdma_dev	*edev = FDENTRY(f)->d_inode->i_private;
	struct list_head *pos, *tmp;
	char *kbuf = NULL;
	int len = 0, n, num_qp;

	if (*ppos)
		goto out;

	kbuf = kmalloc(space, GFP_KERNEL);
	if (!kbuf)
		goto out;

	num_qp = atomic_read(&edev->num_qp);
	if (!num_qp)
		goto out;

	len = snprintf(kbuf, space, "%s: %d QPs\n", edev->ibdev.name, num_qp);
	if (len > space) {
		len = space;
		goto out;
	}
	space -= len;
	n = snprintf(kbuf + len, space,
		     "%-7s%-6s%-6s%-5s%-5s%-5s%-5s%-20s%-20s\n",
		     "QP-ID", "State", "Ref's", "SQ", "RQ", "IRQ", "ORQ",
		     "Sock", "CEP");

	if (n > space) {
		len += space;
		goto out;
	}
	len += n;
	space -= n;

	list_for_each_safe(pos, tmp, &edev->qp_list) {
		struct erdma_qp *qp = list_entry(pos, struct erdma_qp, devq);

		n = snprintf(kbuf + len, space,
			"%-7d%-6d%-6d%-5d%-5d%-5d%-5d0x%-17p 0x%-18p\n",
			QP_ID(qp),
			qp->attrs.state,
			kref_read(&qp->hdr.ref),
			qp->attrs.sq_size,
			qp->attrs.rq_size,
			qp->attrs.irq_size,
			qp->attrs.orq_size,
			qp->attrs.llp_stream_handle,
			qp->cep);
		if (n < space) {
			len += n;
			space -= n;
		} else {
			len += space;
			break;
		}
	}
out:
	if (len)
		len = simple_read_from_buffer(buf, len, ppos, kbuf, len);

	kfree(kbuf);

	return len;

};

static ssize_t erdma_show_ceps(struct file *f, char __user *buf, size_t space,
			     loff_t *ppos)
{

	struct erdma_dev          *edev = FDENTRY(f)->d_inode->i_private;
	struct list_head          *pos, *tmp;
	char                      *kbuf = NULL;
	int                       len = 0, n, num_cep;

	if (*ppos)
		goto out;

	kbuf = kmalloc(space, GFP_KERNEL);
	if (!kbuf)
		goto out;

	num_cep = atomic_read(&edev->num_cep);
	if (!num_cep)
		goto out;

	len = snprintf(kbuf, space, "%s: %d CEPs\n", edev->ibdev.name,
		       num_cep);
	if (len > space) {
		len = space;
		goto out;
	}
	space -= len;

	n = snprintf(kbuf + len, space,
		     "%-20s%-6s%-6s%-7s%-3s%-3s%-4s%-21s%-9s\n",
		     "CEP", "State", "Ref's", "QP-ID", "LQ", "LC", "U", "Sock",
		     "CM-ID");

	if (n > space) {
		len += space;
		goto out;
	}
	len += n;
	space -= n;

	list_for_each_safe(pos, tmp, &edev->cep_list) {
		struct erdma_cep *cep = list_entry(pos, struct erdma_cep, devq);

		n = snprintf(kbuf + len, space,
			"0x%-18p%-6d%-6d%-7d%-3s%-3s%-4d0x%-18p 0x%-16p\n",
			cep, cep->state,
			kref_read(&cep->ref),
			cep->qp ? QP_ID(cep->qp) : -1,
			list_empty(&cep->listenq) ? "n" : "y",
			cep->listen_cep ? "y" : "n",
			cep->in_use,
			cep->llp.sock,
			cep->cm_id);
		if (n < space) {
			len += n;
			space -= n;
		} else {
			len += space;
			break;
		}
	}
out:
	if (len)
		len = simple_read_from_buffer(buf, len, ppos, kbuf, len);

	kfree(kbuf);

	return len;

};

static ssize_t erdma_show_stats(struct file *f, char __user *buf, size_t space,
			      loff_t *ppos)
{

	struct erdma_dev	*edev = FDENTRY(f)->d_inode->i_private;
	char *kbuf = NULL;
	int len = 0;

	if (*ppos)
		goto out;

	kbuf = kmalloc(space, GFP_KERNEL);
	if (!kbuf)
		goto out;

	len =  snprintf(kbuf, space, "Allocated ERDMA Objects:\n"
		"Device %s (%s):\t"
		"%s: %d, %s %d, %s: %d, %s: %d, %s: %d, %s: %d\n",
		edev->ibdev.name,
		edev->netdev->flags & IFF_UP ? "IFF_UP" : "IFF_DOWN",
		"CXs", atomic_read(&edev->num_ctx),
		"PDs", atomic_read(&edev->num_pd),
		"QPs", atomic_read(&edev->num_qp),
		"CQs", atomic_read(&edev->num_cq),
		"MRs", atomic_read(&edev->num_mem),
		"CEPs", atomic_read(&edev->num_cep));
	if (len > space)
		len = space;
out:
	if (len)
		len = simple_read_from_buffer(buf, len, ppos, kbuf, len);

	kfree(kbuf);
	return len;

}

static ssize_t erdma_show_cmdq(struct file *f, char __user *buf, size_t space,
			      loff_t *ppos)
{

	struct erdma_dev        *edev = FDENTRY(f)->d_inode->i_private;
	char                    *kbuf = NULL;
	int                     len = 0, n;

	if (*ppos)
		goto out;

	kbuf = kmalloc(space, GFP_KERNEL);
	if (!kbuf)
		goto out;

	len =  snprintf(kbuf, space,
		"CMDQ Summary:\n"
		"submitted:%llu, completed:%llu, error:%llu, not completed: %llu.\n"
		"ceq notify:%llu,,notify:%llu aeq event:%llu,,notify:%llu cq armed:%llu\n",
		atomic64_read(&edev->cmdq.stats.submitted_cmd),
		atomic64_read(&edev->cmdq.stats.completed_cmd),
		atomic64_read(&edev->cmdq.stats.cmd_err),
		atomic64_read(&edev->cmdq.stats.no_completion),
		atomic64_read(&edev->cmdq.eq.event_num),
		atomic64_read(&edev->cmdq.eq.notify_num),
		atomic64_read(&edev->aeq.eq.event_num),
		atomic64_read(&edev->aeq.eq.notify_num),
		atomic64_read(&edev->cmdq.stats.cq_armed_num));
	if (len > space) {
		len = space;
		goto out;
	}

	space -= len;
	n = snprintf(kbuf + len, space,
		"SQ-buf  va:%p, pa:%p, depth:%u, ci:0x%x, pi:0x%x, db_addr:%p\n",
		edev->cmdq.sq.qbuf, (void *)edev->cmdq.sq.dma_addr, edev->cmdq.depth,
				edev->cmdq.sq.ci, edev->cmdq.sq.pi, edev->cmdq.sq.db_addr);
	len += n;
	space -= n;
	n = snprintf(kbuf + len, space,
		"CQ-buf  va:%p, pa:%p, depth:%u, ci:0x%x, db_addr:%p\n",
		edev->cmdq.cq.qbuf, (void *)edev->cmdq.cq.dma_addr, edev->cmdq.depth,
				edev->cmdq.cq.ci, edev->cmdq.cq.db_addr);
	len += n;
	space -= n;
	n = snprintf(kbuf + len, space,
		"EQ-buf  va:%p, pa:%p, depth:%u, ci:0x%x, db_addr:%p\n",
		edev->cmdq.eq.qbuf, (void *)edev->cmdq.eq.dma_addr, edev->cmdq.eq.depth,
				edev->cmdq.eq.ci, edev->cmdq.eq.db_addr);
	len += n;
	space -= n;
	n = snprintf(kbuf + len, space,
		"AEQ-buf va:%p, pa:%p, depth:%u, ci:0x%x, db_addr:%p\n",
		edev->aeq.eq.qbuf, (void *)edev->aeq.eq.dma_addr, edev->aeq.eq.depth,
				edev->aeq.eq.ci, edev->aeq.eq.db_addr);
	len += n;
	space -= n;
	n = snprintf(kbuf + len, space,
		"q-flags:0x%lx, completion_timeout:%ums.\n",
		edev->cmdq.state, edev->cmdq.completion_timeout);

	len += n;
	space -= n;

out:
	if (len)
		len = simple_read_from_buffer(buf, len, ppos, kbuf, len);

	kfree(kbuf);
	return len;

}

static ssize_t erdma_show_ceq(struct file *f, char __user *buf, size_t space,
			      loff_t *ppos)
{

	struct erdma_dev        *edev = FDENTRY(f)->d_inode->i_private;
	char                    *kbuf = NULL;
	int                     len = 0, n, i;
	struct erdma_eq_cb      *eq_cb;

	if (*ppos)
		goto out;

	kbuf = kmalloc(space, GFP_KERNEL);
	if (!kbuf)
		goto out;

	len =  snprintf(kbuf, space, "CEQs Summary:\n");
	if (len > space) {
		len = space;
		goto out;
	}

	space -= len;

	for (i = 0; i < 31; i++) {
		eq_cb = &edev->ceqs[i];
		n = snprintf(kbuf + len, space,
			"%d ready:%u,event_num:%llu,notify_num:%llu,va:%p,pa:%p,depth:%u,ci:0x%x,db:%p,max:%u\n",
			i, eq_cb->ready,
			atomic64_read(&eq_cb->eq.event_num),
			atomic64_read(&eq_cb->eq.notify_num),
			eq_cb->eq.qbuf, (void *)eq_cb->eq.dma_addr,
			eq_cb->eq.depth, eq_cb->eq.ci, eq_cb->eq.db_addr, eq_cb->eq.max_poll_cnt);
		if (n < space) {
			len += n;
			space -= n;
		} else {
			len += space;
			break;
		}
	}

out:
	if (len)
		len = simple_read_from_buffer(buf, len, ppos, kbuf, len);

	kfree(kbuf);
	return len;

}

static ssize_t erdma_show_print(struct file *f, char __user *buf, size_t space,
			      loff_t *ppos)
{
	char *kbuf = NULL;
	int len = 0;

	if (*ppos)
		goto out;

	kbuf = kmalloc(space, GFP_KERNEL);
	if (!kbuf)
		goto out;

	len =  snprintf(kbuf, space, "0x%8x\n", dprint_mask);
	if (len > space)
		len = space;
out:
	if (len)
		len = simple_read_from_buffer(buf, len, ppos, kbuf, len);

	kfree(kbuf);
	return len;

}

static ssize_t erdma_set_print(struct file *f, const char __user *buf, size_t count, loff_t *ppos)
{
	int bytes_not_copied;
	__u32 new_print_mask;
	int ret;

	char cmd_buf[64];

	if (*ppos != 0)
		return 0;

	if (count >= sizeof(cmd_buf))
		return -ENOSPC;

	bytes_not_copied = copy_from_user(cmd_buf, buf, count);
	if (bytes_not_copied < 0)
		return bytes_not_copied;
	if (bytes_not_copied > 0)
		count -= bytes_not_copied;

	cmd_buf[count] = '\0';
	*ppos = 0;

	ret = kstrtoul(cmd_buf, 0, (long *)&new_print_mask);
	if (ret)
		return -EINVAL;

	dprint_mask = new_print_mask;

	return count;
}

static const struct file_operations erdma_qp_debug_fops = {
	.owner	= THIS_MODULE,
	.read	= erdma_show_qps
};

static const struct file_operations erdma_cep_debug_fops = {
	.owner	= THIS_MODULE,
	.read	= erdma_show_ceps
};

static const struct file_operations erdma_stats_debug_fops = {
	.owner	= THIS_MODULE,
	.read	= erdma_show_stats
};

static const struct file_operations erdma_cmdq_debug_fops = {
	.owner	= THIS_MODULE,
	.read	= erdma_show_cmdq
};

static const struct file_operations erdma_ceq_debug_fops = {
	.owner	= THIS_MODULE,
	.read	= erdma_show_ceq
};

static const struct file_operations erdma_print_fops = {
	.owner	= THIS_MODULE,
	.read	= erdma_show_print,
	.write = erdma_set_print,

};

static int eadm_open(struct inode *inode, struct file *file)
{
	return nonseekable_open(inode, file);
}

static int eadm_close(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t eadm_read(struct file *file, char __user *buf,
			    size_t size, loff_t *ppos)
{
	return 0;
}


long eadm_ioctl(struct file *filp,
		   unsigned int cmd, unsigned long arg)
{
	struct erdma_dev *edev = FDENTRY(filp)->d_inode->i_private;

	return do_ioctl(edev, cmd, arg);
}

static const struct file_operations erdma_eadm_fops = {
	.owner = THIS_MODULE,
	.open = eadm_open,
	.release = eadm_close,
	.read = eadm_read,
	.unlocked_ioctl = eadm_ioctl
};


static struct dentry *erdma_debugfs;


void erdma_debugfs_add_device(struct erdma_dev *edev)
{
	struct dentry	*entry;

	if (!erdma_debugfs)
		return;

	edev->debugfs = debugfs_create_dir(edev->ibdev.name, erdma_debugfs);
	if (edev->debugfs) {
		entry = debugfs_create_file("qp", 0400, edev->debugfs,
					    (void *)edev, &erdma_qp_debug_fops);
		if (!entry)
			dprint(DBG_DM, ": could not create 'qp' entry\n");

		entry = debugfs_create_file("cep", 0400, edev->debugfs,
					    (void *)edev, &erdma_cep_debug_fops);
		if (!entry)
			dprint(DBG_DM, ": could not create 'cep' entry\n");

		entry = debugfs_create_file("stats", 0400, edev->debugfs,
					    (void *)edev,
					    &erdma_stats_debug_fops);
		if (!entry)
			dprint(DBG_DM, ": could not create 'stats' entry\n");

		entry = debugfs_create_file("cmdq", 0400, edev->debugfs,
					    (void *)edev,
					    &erdma_cmdq_debug_fops);
		if (!entry)
			dprint(DBG_DM, ": could not create 'cmdq' entry\n");

		entry = debugfs_create_file("ceq", 0400, edev->debugfs,
					    (void *)edev,
					    &erdma_ceq_debug_fops);
		if (!entry)
			dprint(DBG_DM, ": could not create 'ceq' entry\n");

		entry = debugfs_create_file("print", 0400, edev->debugfs,
					    (void *)edev,
					    &erdma_print_fops);
		if (!entry)
			dprint(DBG_DM, ": could not create 'print' entry\n");

		entry = debugfs_create_file("eadm", 0400, edev->debugfs,
					    (void *)edev,
					    &erdma_eadm_fops);
		if (!entry)
			dprint(DBG_DM, ": could not create 'eadm' entry\n");

	}

}

void erdma_debugfs_del_device(struct erdma_dev *edev)
{
	debugfs_remove_recursive(edev->debugfs);
	edev->debugfs = NULL;
}

void erdma_debug_init(void)
{
	erdma_debugfs = debugfs_create_dir("erdma", NULL);

	if (!erdma_debugfs || erdma_debugfs == ERR_PTR(-ENODEV)) {
		dprint(DBG_DM, ": could not init debugfs\n");
		erdma_debugfs = NULL;
	}
}

void erdma_dbg_exit(void)
{
	debugfs_remove_recursive(erdma_debugfs);
	erdma_debugfs = NULL;
}
