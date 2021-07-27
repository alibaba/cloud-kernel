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

#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/rtnetlink.h>

#include <net/net_namespace.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "erdma.h"
#include "erdma_ae.h"
#include "erdma_cm.h"
#include "erdma_command.h"
#include "erdma_common.h"
#include "erdma_hw.h"
#include "erdma_ioctl.h"
#include "erdma_obj.h"
#include "erdma_regs_defs.h"
#include "erdma_verbs.h"

#define DESC __stringify(ElasticRDMA(iWarp) Driver)

MODULE_AUTHOR("Alibaba");
MODULE_DESCRIPTION(DESC);
MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.0");

#define DRV_VER_MAJOR 0
#define DRV_VER_MINOR 0
#define DRV_VER_BUILD 1
#define DRV_VER \
	__stringify(DRV_VER_MAJOR) "." __stringify(DRV_VER_MINOR) "." __stringify(DRV_VER_BUILD)

static int qpn_start = 1;
module_param(qpn_start, int, 0644);
MODULE_PARM_DESC(qpn_start, "Specify the QPN where the driver alloc to use.");

static int cqn_start = 1;
module_param(cqn_start, int, 0644);
MODULE_PARM_DESC(cqn_start, "Specify the CQN where the driver alloc to use.");

static int max_vectors = 4;
module_param(max_vectors, int, 0644);
MODULE_PARM_DESC(max_vectors, "Specify the max vectors used, should whithin [1, 32].");

DECLARE_BITMAP(erdma_devid, ERDMA_MAX_DEVICES);

static unsigned int erdma_chrdev_major;
static struct class *erdma_chrdev_class;

static void erdma_device_register(struct erdma_dev *edev)
{
	struct ib_device     *ibdev = &edev->ibdev;
	struct net_device    *netdev  = edev->netdev;
	int                  rv;

	memset(ibdev->name, 0, IB_DEVICE_NAME_MAX);
	rv = snprintf(ibdev->name, IB_DEVICE_NAME_MAX, "%s%.2x%.2x%.2x",
		ERDMA_IBDEV_PREFIX,
		*((__u8 *)edev->netdev->dev_addr + 3),
		*((__u8 *)edev->netdev->dev_addr + 4),
		*((__u8 *)edev->netdev->dev_addr + 5));
	if (rv < 0) {
		pr_err("ERROR: copy ibdev name failed.\n");
		return;
	}

	memset(&ibdev->node_guid, 0, sizeof(ibdev->node_guid));
	memcpy(&ibdev->node_guid, netdev->dev_addr, 6);

	ibdev->phys_port_cnt = 1;
	rv = ib_device_set_netdev(ibdev, edev->netdev, 1);
	if (rv)
		return;

	rv = ib_register_device(ibdev, ibdev->name, &edev->pdev->dev);
	if (rv) {
		pr_err("ERROR: ib_register_device(%s) failed: rv = %d\n",
			ibdev->name, rv);
		return;
	}

	erdma_debugfs_add_device(edev);

	dprint(DBG_DM, " Registered '%s' for interface '%s',HWaddr=%02x.%02x.%02x.%02x.%02x.%02x\n",
			ibdev->name, edev->netdev->name,
			*(__u8 *)edev->netdev->dev_addr,
			*((__u8 *)edev->netdev->dev_addr + 1),
			*((__u8 *)edev->netdev->dev_addr + 2),
			*((__u8 *)edev->netdev->dev_addr + 3),
			*((__u8 *)edev->netdev->dev_addr + 4),
			*((__u8 *)edev->netdev->dev_addr + 5));

	edev->is_registered = 1;
}

static void erdma_device_deregister(struct erdma_dev *edev)
{
	int i;

	erdma_debugfs_del_device(edev);

	if (edev->is_registered) {
		dprint(DBG_DM, ": deregister %s at %s\n", edev->ibdev.name,
		       edev->netdev->name);

		ib_unregister_device(&edev->ibdev);
	}
	WARN_ON(atomic_read(&edev->num_ctx));
	WARN_ON(atomic_read(&edev->num_qp));
	WARN_ON(atomic_read(&edev->num_cq));
	WARN_ON(atomic_read(&edev->num_mem));
	WARN_ON(atomic_read(&edev->num_pd));
	WARN_ON(atomic_read(&edev->num_cep));
	i = 0;

	while (!list_empty(&edev->cep_list)) {
		struct erdma_cep *cep = list_entry(edev->cep_list.next,
						   struct erdma_cep, devq);
		list_del(&cep->devq);
		dprint(DBG_ON, ": Free CEP (0x%p), state: %d\n",
			cep, cep->state);
		kfree(cep);
		i++;
	}
	if (i)
		pr_warn("erdma device deregister: free'd %d CEPs\n", i);
}

static int erdma_netdev_matched_edev(struct net_device *netdev, struct erdma_dev *edev)
{
	dprint(DBG_DM, "mac addr : %x %x %x %x %x %x\n",
		netdev->perm_addr[0], netdev->perm_addr[1],
		netdev->perm_addr[2], netdev->perm_addr[3],
		netdev->perm_addr[4], netdev->perm_addr[5]);

	if (netdev->perm_addr[0] == edev->peer_addr[0] &&
	    netdev->perm_addr[1] == edev->peer_addr[1] &&
	    netdev->perm_addr[2] == edev->peer_addr[2] &&
	    netdev->perm_addr[3] == edev->peer_addr[3] &&
	    netdev->perm_addr[4] == edev->peer_addr[4] &&
	    netdev->perm_addr[5] == edev->peer_addr[5])
		return 1;

	return 0;
}

static int erdma_netdev_event(struct notifier_block *nb, unsigned long event,
			      void *arg)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(arg);
	struct in_device *in_dev;
	struct erdma_dev *edev = container_of(nb, struct erdma_dev, netdev_nb);

	dprint(DBG_DM, " netdev:%s,ns:%p: Event %lu to erdma_dev %p\n",
				netdev->name, dev_net(netdev), event, edev);
	if (edev->netdev != NULL && edev->netdev != netdev)
		goto done;

	if (!spin_trylock(&edev->netdev_nb_lock))
		/* The module is being removed */
		goto done;

	switch (event) {
	case NETDEV_UP:
		if (!edev)
			break;

		if (edev->is_registered) {
			edev->state = IB_PORT_ACTIVE;
			break;
		}

		in_dev = in_dev_get(netdev);
		if (!in_dev) {
			dprint(DBG_DM, ": %s: no in_dev\n", netdev->name);
			edev->state = IB_PORT_INIT;
			break;
		}

		if (in_dev->ifa_list) {
			edev->state = IB_PORT_ACTIVE;
		} else {
			dprint(DBG_DM, ": %s: no ifa\n", netdev->name);
			edev->state = IB_PORT_INIT;
		}
		in_dev_put(in_dev);
		break;
	case NETDEV_DOWN:
		if (edev && edev->is_registered) {
			edev->state = IB_PORT_DOWN;
			break;
		}
		break;
	case NETDEV_REGISTER:
		if (!edev->is_registered) {
			if (erdma_netdev_matched_edev(netdev, edev)) {
				edev->netdev = netdev;
				edev->state = IB_PORT_INIT;
				dprint(DBG_DM, ": new erdma lowlevel device for %s\n",
				       netdev->name);
				erdma_device_register(edev);
			}
		}
		break;
	case NETDEV_UNREGISTER:
		break;
	/*
	 * Todo: Below netdev events are currently not handled.
	 */
	case NETDEV_CHANGEADDR:
	case NETDEV_CHANGEMTU:
	case NETDEV_GOING_DOWN:
	case NETDEV_CHANGE:
	default:
		break;
	}

	spin_unlock(&edev->netdev_nb_lock);
done:
	return NOTIFY_OK;
}

void erdma_intr_ceq_task(unsigned long data)
{
	erdma_ceq_completion_handler((struct erdma_eq_cb *)data);
}

static irqreturn_t erdma_intr_ceq_handler(int irq, void *data)
{
	struct erdma_eq_cb *ceq_cb = data;

	tasklet_schedule(&ceq_cb->tasklet);

	return IRQ_HANDLED;
}

static irqreturn_t erdma_intr_cmdq_handler(int irq, void *data)
{
	struct erdma_dev *dev = data;

	erdma_cmdq_completion_handler(dev);
	erdma_aeq_event_handler(dev);

	return IRQ_HANDLED;
}

static int erdma_enable_msix(struct erdma_dev *dev)
{
	int msix_vecs, irq_num;
	/* reserve the max msi-x vectors we might need. */

	msix_vecs = max_vectors;
	if (msix_vecs < 1 || msix_vecs > ERDMA_NUM_MSIX_VEC)
		return -EINVAL;

	dprint(DBG_DM, "Trying to enable MSI-X, vectors %d\n", msix_vecs);

	irq_num = pci_alloc_irq_vectors(dev->pdev, 1, msix_vecs, PCI_IRQ_MSIX);

	if (irq_num <= 0) {
		dev_err(&dev->pdev->dev, "request irq vectors failed(%d), expected(%d).\n",
			irq_num, msix_vecs);
		return -ENOSPC;
	}

	dev_info(&dev->pdev->dev, "hardware return %d irqs.\n", irq_num);
	dev->irq_num = irq_num;

	return 0;
}

static void erdma_disable_msix(struct erdma_dev *dev)
{
	pci_free_irq_vectors(dev->pdev);
}

static int erdma_set_mgmt_irq(struct erdma_dev *dev)
{
	__u32 cpu;
	int err;
	struct erdma_irq *irq = &dev->cmd_irq;

	snprintf(dev->cmd_irq.name, ERDMA_IRQNAME_SIZE, "erdma-mgmt@pci:%s", pci_name(dev->pdev));
	irq->handler = erdma_intr_cmdq_handler;
	irq->data = dev;
	irq->vector = pci_irq_vector(dev->pdev, ERDMA_MSIX_VECTOR_CMDQ);

	cpu = cpumask_first(cpumask_of_node(dev->numa_node));

	irq->cpu = cpu;
	cpumask_set_cpu(cpu, &dev->cmd_irq.affinity_hint_mask);
	dev_info(&dev->pdev->dev, "setup irq:%p vector:%d name:%s\n",
		 irq,
		 irq->vector,
		 irq->name);

	err = request_irq(irq->vector, irq->handler, 0, irq->name, irq->data);
	if (err) {
		dev_err(&dev->pdev->dev, "failed to request_irq(%d)\n", err);
		return err;
	}

	irq_set_affinity_hint(irq->vector, &irq->affinity_hint_mask);

	return 0;
}

static void erdma_free_mgmt_irq(struct erdma_dev *dev)
{
	struct erdma_irq *irq;

	irq = &dev->cmd_irq;
	irq_set_affinity_hint(irq->vector, NULL);
	free_irq(irq->vector, irq->data);
}

/* do device flr. */
static int erdma_device_init(struct erdma_dev *dev, struct pci_dev *pdev)
{
	int err;

	erdma_reg_write32(dev, ERDMA_REGS_AEQ_ADDR_H_REG, dev->func_bar_addr >> 32);
	erdma_reg_write32(dev, ERDMA_REGS_AEQ_ADDR_L_REG, dev->func_bar_addr & 0xFFFFFFFF);

	/* force dma width to 64. */
	dev->dma_width = 64;

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(dev->dma_width));
	if (err) {
		dev_err(&pdev->dev, "pci_set_dma_mask failed(%d)\n", err);
		return err;
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(dev->dma_width));
	if (err) {
		dev_err(&pdev->dev, "pci_set_consistent_dma_mask failed(%d)\n", err);
		return err;
	}

	return err;
}

static void erdma_device_uninit(struct erdma_dev *dev)
{
	__u32 ctrl;

	ctrl = FIELD_PREP(ERDMA_REG_DEV_CTRL_RESET_MASK, 1);
	erdma_reg_write32(dev, ERDMA_REGS_DEV_CTRL_REG, ctrl);
}

static int erdma_set_ceq_irq(struct erdma_dev *dev, __u16 eqn)
{
	__u32 cpu;
	int err;
	struct erdma_irq *irq = &dev->ceqs[eqn - 1].irq;

	snprintf(irq->name, ERDMA_IRQNAME_SIZE, "erdma-ceq%u@pci:%s", eqn - 1, pci_name(dev->pdev));
	irq->handler = erdma_intr_ceq_handler;
	irq->data = &dev->ceqs[eqn - 1];
	irq->vector = pci_irq_vector(dev->pdev, eqn);

	tasklet_init(&dev->ceqs[eqn - 1].tasklet, erdma_intr_ceq_task,
			(unsigned long)&dev->ceqs[eqn - 1]);

	cpu = cpumask_local_spread(eqn, dev->numa_node);
	irq->cpu = cpu;
	cpumask_set_cpu(cpu, &irq->affinity_hint_mask);
	dev_info(&dev->pdev->dev, "setup irq:%p vector:%d name:%s\n",
		 irq,
		 irq->vector,
		 irq->name);

	err = request_irq(irq->vector, irq->handler, 0, irq->name, irq->data);
	if (err) {
		dev_err(&dev->pdev->dev, "failed to request_irq(%d)\n", err);
		return err;
	}

	irq_set_affinity_hint(irq->vector, &irq->affinity_hint_mask);

	return 0;
}

static void erdma_free_ceq_irq(struct erdma_dev *dev, __u16 eqn)
{
	struct erdma_irq *irq = &dev->ceqs[eqn - 1].irq;

	irq_set_affinity_hint(irq->vector, NULL);
	free_irq(irq->vector, irq->data);
}

static int erdma_ceq_init_one(struct erdma_dev *dev, __u16 eqn)
{
	struct erdma_eq *eq = &dev->ceqs[eqn - 1].eq;
	__u32 buf_size = ERDMA_DEFAULT_EQ_DEPTH * sizeof(struct erdma_ceq_entry);
	int rv;
	struct erdma_create_eq_params params;

	eq->qbuf = dma_alloc_coherent(&dev->pdev->dev, buf_size, &eq->dma_addr, GFP_KERNEL);
	if (!eq->qbuf)
		return -ENOMEM;

	memset(eq->qbuf, 0, buf_size);

	spin_lock_init(&eq->lock);
	atomic64_set(&eq->event_num, 0);
	atomic64_set(&eq->notify_num, 0);
	eq->max_poll_cnt = 0;

	eq->depth = ERDMA_DEFAULT_EQ_DEPTH;
	eq->db_addr = (__u64 __iomem *)(dev->func_bar + ERDMA_REGS_CEQ_DB_BASE_REG + eqn * 8);
	eq->ci = 0;
	/* First  */
	eq->owner = 1;
	dev->ceqs[eqn - 1].dev = dev;

	/* CEQ indexed from 1, 0 rsvd for CMDQ-EQ. */
	params.eqn = eqn;
	/* Vector index is the same sa EQN. */
	params.vector_idx = eqn;
	params.depth = ERDMA_DEFAULT_EQ_DEPTH;
	params.queue_addr = eq->dma_addr;
	dprint(DBG_DM, "CEQ(%u), va:%p,pa:%llx,size:0x%x,depth:%u, db_addr:%p\n",
		eqn - 1, eq->qbuf, eq->dma_addr, buf_size, eq->depth, eq->db_addr);

	rv = erdma_exec_create_eq_cmd(dev, &params, 1);
	if (rv) {
		dev->ceqs[eqn - 1].ready = 0;
		return rv;
	}

	dev->ceqs[eqn - 1].ready = 1;

	return rv;
}

static void erdma_ceq_uninit_one(struct erdma_dev *dev, __u16 eqn)
{
	struct erdma_eq *eq = &dev->ceqs[eqn - 1].eq;
	__u32 buf_size = ERDMA_DEFAULT_EQ_DEPTH * sizeof(struct erdma_ceq_entry);
	int rv;
	struct erdma_destroy_eq_params params;

	dev->ceqs[eqn - 1].ready = 0;
	params.eqn = eqn;
	params.vector_idx = eqn;

	rv = erdma_exec_destroy_eq_cmd(dev, &params, 1);
	if (rv)
		pr_warn("destroy ceq(%u) failed.\n", eqn - 1);

	dma_free_coherent(&dev->pdev->dev, buf_size, eq->qbuf, eq->dma_addr);
}

static int erdma_ceqs_init(struct erdma_dev *dev)
{
	__u32 i, j;
	int err = 0;

	for (i = 1; i < dev->irq_num; i++) {
		err = erdma_ceq_init_one(dev, i);
		if (err)
			goto out_err;

		err = erdma_set_ceq_irq(dev, i);
		if (err) {
			erdma_ceq_uninit_one(dev, i);
			goto out_err;
		}
	}

	return 0;

out_err:
	for (j = 1; j < i; j++) {
		erdma_free_ceq_irq(dev, j);
		erdma_ceq_uninit_one(dev, j);
	}

	return err;
}

static void erdma_ceqs_uninit(struct erdma_dev *dev)
{
	__u32 i;

	for (i = 1; i < dev->irq_num; i++) {
		erdma_free_ceq_irq(dev, i);
		erdma_ceq_uninit_one(dev, i);
	}
}

static const struct pci_device_id erdma_pci_tbl[] = {
	{PCI_DEVICE(ERDMA_VENDOR_ID, ERDMA_DEVICE_ID)},
	{PCI_DEVICE(ERDMA_VENDOR_ID, ERDMA_SRIOV_PF_ID)},
	{}
};

static int erdma_probe_dev(struct pci_dev *pdev)
{
	int              err;
	struct erdma_dev *edev;
	__u32            version;
	__u32            dev_id;
	int              bars;
	struct ib_device *ibdev;

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "pci_enable_device failed(%d)\n", err);
		return err;
	}

	pci_set_master(pdev);

	edev = ib_alloc_device(erdma_dev, ibdev);
	if (!edev) {
		dev_err(&pdev->dev, "ib_alloc_device failed\n");
		err = -ENOMEM;
		goto err_disable_device;
	}

	ibdev = &edev->ibdev;

	pci_set_drvdata(pdev, edev);
	edev->pdev = pdev;
	edev->numa_node = pdev->dev.numa_node;

	bars = pci_select_bars(pdev, IORESOURCE_MEM);
	err = pci_request_selected_regions(pdev, bars, DRV_MODULE_NAME);
	if (bars != ERDMA_BAR_MASK || err) {
		dev_err(&pdev->dev,
			"pci_request_selected_regions failed(bars:%d, err:%d)\n", bars, err);
		err = err == 0 ? -EINVAL : err;
		goto err_ib_device_release;
	}

	edev->func_bar_addr = pci_resource_start(pdev, ERDMA_FUNC_BAR);
	edev->func_bar_len = pci_resource_len(pdev, ERDMA_FUNC_BAR);

	edev->func_bar = devm_ioremap(&pdev->dev, edev->func_bar_addr, edev->func_bar_len);
	if (!edev->func_bar) {
		dev_err(&pdev->dev, "devm_ioremap failed.\n");
		err = -EFAULT;
		goto err_release_bars;
	}

	version = erdma_reg_read32(edev, ERDMA_REGS_VERSION_REG);
	if (version == 0) {
		/* we knows that it is a non-functional function. */
		err = -ENODEV;
		goto err_iounmap_func_bar;
	}

	err = erdma_device_init(edev, pdev);
	if (err) {
		dev_err(&pdev->dev, "erdma_device_init failed.\n");
		goto err_iounmap_func_bar;
	}

	err = erdma_enable_msix(edev);
	if (err) {
		dev_err(&pdev->dev, "erdma_enable_msi failed.\n");
		goto err_iounmap_func_bar;
	}

	dev_id = find_first_zero_bit(erdma_devid, ERDMA_MAX_DEVICES);
	if (dev_id == ERDMA_MAX_DEVICES) {
		err = -ENOSPC;
		goto err_disable_msix;
	}

	set_bit(dev_id, erdma_devid);
	edev->dev_id = dev_id;

	err = erdma_set_mgmt_irq(edev);
	if (err) {
		dev_err(&pdev->dev, "erdma_set_mgmt_irq failed.\n");
		goto err_clear_devid;
	}


	err = erdma_aeq_init(edev);
	if (err)
		goto err_free_mgmt_irq;

	err = erdma_cmdq_init(edev);
	if (err)
		goto err_uninit_aeq;

	err = erdma_ceqs_init(edev);
	if (err)
		goto err_uninit_cmdq;

	erdma_finish_cmdq_init(edev);

	return 0;

err_uninit_cmdq:
	erdma_device_uninit(edev);
	erdma_cmdq_destroy(edev);

err_uninit_aeq:
	erdma_aeq_destroy(edev);

err_free_mgmt_irq:
	erdma_free_mgmt_irq(edev);

err_clear_devid:
	clear_bit(edev->dev_id, erdma_devid);

err_disable_msix:
	erdma_disable_msix(edev);

err_iounmap_func_bar:
	devm_iounmap(&pdev->dev, edev->func_bar);

err_release_bars:
	pci_release_selected_regions(pdev, bars);

err_ib_device_release:
	ib_dealloc_device(&edev->ibdev);

err_disable_device:
	pci_disable_device(pdev);

	return err;
}

static void erdma_remove_dev(struct pci_dev *pdev)
{
	struct erdma_dev *dev = pci_get_drvdata(pdev);

	erdma_ceqs_uninit(dev);

	erdma_device_uninit(dev);

	erdma_cmdq_destroy(dev);
	erdma_aeq_destroy(dev);
	erdma_free_mgmt_irq(dev);
	clear_bit(dev->dev_id, erdma_devid);
	erdma_disable_msix(dev);

	devm_iounmap(&pdev->dev, dev->func_bar);
	pci_release_selected_regions(pdev, ERDMA_BAR_MASK);

	ib_dealloc_device(&dev->ibdev);

	pci_disable_device(pdev);

}

static char *erdma_chrdev_devnode(struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = 0666;
	return kasprintf(GFP_KERNEL, "%s", dev_name(dev));
}

static int chardev_open(struct inode *inode, struct file *file)
{
	struct erdma_dev *dev;

	dev = container_of(inode->i_cdev, struct erdma_dev, cdev);
	file->private_data = dev;

	return nonseekable_open(inode, file);
}

static ssize_t chardev_read(struct file *file, char __user *buf,
			    size_t size, loff_t *ppos)
{
	return 0;
}

static int chardev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct erdma_dev      *edev = filp->private_data;
	__u32                 key   = vma->vm_pgoff;
	int                   size  = vma->vm_end - vma->vm_start;
	int                   err   = -EINVAL;
	__u64                 pfn;

	/*
	 * Must be page aligned
	 */
	if (vma->vm_start & (PAGE_SIZE - 1)) {
		pr_warn("WARN: map not page aligned\n");
		goto out;
	}

	pr_info("key = %u, size = %d, vaddr = %lx\n", key, size, vma->vm_start);

	switch (key) {
	case 0: /* cmdq-sq buf */
		dprint(DBG_CTRL, "vm_start:%lx, vm_end:%lx.\n", vma->vm_start, vma->vm_end);
		/*
		 * Map WQ or CQ contig dma memory...
		 */
		pfn = edev->cmdq.sq.dma_addr >> PAGE_SHIFT;
		err = remap_pfn_range(vma, vma->vm_start,
			pfn, size, vma->vm_page_prot);
		break;
	case 1: /* cmdq-cq buf */
		dprint(DBG_CTRL, "vm_start:%lx, vm_end:%lx.\n", vma->vm_start, vma->vm_end);
		/*
		 * Map WQ or CQ contig dma memory...
		 */
		pfn = edev->cmdq.cq.dma_addr >> PAGE_SHIFT;
		err = remap_pfn_range(vma, vma->vm_start,
			pfn, size, vma->vm_page_prot);
		break;
	case 2:
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		pfn = (edev->func_bar_addr + 4096) >> PAGE_SHIFT;
		err = io_remap_pfn_range(vma, vma->vm_start, pfn,
			PAGE_SIZE, vma->vm_page_prot);
		break;
	case 3:
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		pfn = (edev->func_bar_addr + 4096 + 128 * 1024 + 32 * 1024) >> PAGE_SHIFT;
		err = io_remap_pfn_range(vma, vma->vm_start, pfn,
			PAGE_SIZE, vma->vm_page_prot);
		break;
	default:
		err = -1;
		break;
	}

out:
	return err;
}

static int chardev_close(struct inode *inode, struct file *filp)
{

	return 0;
}

static const struct file_operations chardev_fops = {
	.owner = THIS_MODULE,
	.open = chardev_open,
	.release = chardev_close,
	.read = chardev_read,
	.mmap = chardev_mmap,
	.unlocked_ioctl = chardev_ioctl
};

static int erdma_chrdev_init(struct erdma_dev *dev, int devnum)
{
	dev_t devno = MKDEV(erdma_chrdev_major, devnum);
	int err = -EMFILE;

	if (devnum >= ERDMA_MAX_DEVICES)
		return err;

	cdev_init(&dev->cdev, &chardev_fops);
	dev->cdev.owner = THIS_MODULE;

	err = cdev_add(&dev->cdev, devno, 1);
	if (err)
		return err;

	dev->chrdev = device_create(erdma_chrdev_class,
				    &dev->pdev->dev,
				    devno,
				    dev,
				    ERDMA_CHRDEV_NAME "%d",
				    devnum);
	if (IS_ERR(dev->chrdev)) {
		err = PTR_ERR(dev->chrdev);
		ibdev_err(&dev->ibdev, "Failed to create device: %s%d [%d]\n",
			  ERDMA_CHRDEV_NAME, devnum, err);
		goto err;
	}

	return 0;

err:
	cdev_del(&dev->cdev);
	return err;
}

static void erdma_chrdev_destroy(struct erdma_dev *dev)
{
	if (!dev->chrdev)
		return;

	device_destroy(erdma_chrdev_class, dev->cdev.dev);
	cdev_del(&dev->cdev);
	dev->chrdev = NULL;
}

static void erdma_stats_init(struct erdma_dev *dev)
{
	atomic64_t *s = (atomic64_t *)&dev->stats;
	int i;

	for (i = 0; i < sizeof(dev->stats) / sizeof(*s); i++, s++)
		atomic64_set(s, 0);
}

static void erdma_dev_attrs_init(struct erdma_dev *dev)
{
	/*
	 * set and register sw version + user if type
	 */
	dev->attrs.version = VERSION_ID_ERDMA;

	dev->attrs.vendor_id = ERDMA_VENDOR_ID;
	dev->attrs.sw_version = VERSION_ID_ERDMA;
	dev->attrs.max_qp = ERDMA_MAX_QP;
	dev->attrs.max_send_wr = ERDMA_MAX_QP_WR / 4;
	dev->attrs.max_recv_wr = ERDMA_MAX_QP_WR;
	dev->attrs.max_ord = ERDMA_MAX_ORD;
	dev->attrs.max_ird = ERDMA_MAX_IRD;
	dev->attrs.cap_flags = 0;
	dev->attrs.max_send_sge = ERDMA_MAX_SEND_SGE;
	dev->attrs.max_recv_sge = ERDMA_MAX_RECV_SGE;
	dev->attrs.max_sge_rd = ERDMA_MAX_SGE_RD;
	dev->attrs.max_cq = ERDMA_MAX_CQ;
	dev->attrs.max_cqe = ERDMA_MAX_CQE;
	dev->attrs.max_mr = ERDMA_MAX_MR;
	dev->attrs.max_mr_size = ERDMA_MAX_MR_SIZE;
	dev->attrs.max_pd = ERDMA_MAX_PD;
	dev->attrs.max_mw = ERDMA_MAX_MW;
	dev->attrs.max_srq = ERDMA_MAX_SRQ;
	dev->attrs.max_srq_wr = ERDMA_MAX_SRQ_WR;
	dev->attrs.max_srq_sge = ERDMA_MAX_SRQ_SGE;
}

static void erdma_host_info_init(struct erdma_dev *dev)
{
	/* TBD: get host info, and set to MOC. */
}

static const struct ib_device_ops erdma_device_ops = {
	.owner = THIS_MODULE,
	.uverbs_abi_ver = ERDMA_ABI_VERSION,
	.driver_id = 19,

	.query_device = erdma_query_device,
	.query_port = erdma_query_port,
	.get_port_immutable = erdma_get_port_immutable,
	.query_qp = erdma_query_qp,
	.modify_port = erdma_modify_port,
	.query_pkey = erdma_query_pkey,
	.query_gid = erdma_query_gid,
	.alloc_ucontext = erdma_alloc_ucontext,
	.dealloc_ucontext = erdma_dealloc_ucontext,
	.mmap = erdma_mmap,
	.alloc_pd = erdma_alloc_pd,
	.dealloc_pd = erdma_dealloc_pd,
	.create_qp = erdma_create_qp,
	.modify_qp = erdma_modify_qp,
	.destroy_qp = erdma_destroy_qp,
	.create_cq = erdma_create_cq,
	.destroy_cq = erdma_destroy_cq,
	.resize_cq = NULL,
	.poll_cq = erdma_poll_cq,
	.get_dma_mr = erdma_get_dma_mr,
	.reg_user_mr = erdma_reg_user_mr,
	.dereg_mr = erdma_dereg_mr,
	.alloc_mw = NULL,
	.dealloc_mw = NULL,
	.post_send = erdma_post_send,
	.post_recv = erdma_post_recv,
	.get_netdev = erdma_get_netdev,

	.alloc_mr = erdma_ib_alloc_mr,
	.map_mr_sg = erdma_map_mr_sg,

	.req_notify_cq = erdma_req_notify_cq,

	.iw_connect = erdma_connect,
	.iw_accept = erdma_accept,
	.iw_reject = erdma_reject,
	.iw_create_listen = erdma_create_listen,
	.iw_destroy_listen = erdma_destroy_listen,
	.iw_add_ref = erdma_qp_get_ref,
	.iw_rem_ref = erdma_qp_put_ref,
	.iw_get_qp = erdma_get_ibqp,

	.disassociate_ucontext = erdma_disassociate_ucontext,

	INIT_RDMA_OBJ_SIZE(ib_cq, erdma_cq, ibcq),
	INIT_RDMA_OBJ_SIZE(ib_pd, erdma_pd, ibpd),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, erdma_ucontext, ib_ucontext)
};

static int erdma_ib_device_add(struct pci_dev *pdev)
{
	struct erdma_dev *dev   = pci_get_drvdata(pdev);
	struct ib_device *ibdev = &dev->ibdev;
	__u32            mac_h, mac_l;
	int              err    = 0;

	dprint(DBG_INIT, "init erdma_dev(%p)\n", dev);

	erdma_stats_init(dev);

	erdma_dev_attrs_init(dev);

	erdma_host_info_init(dev);

	ibdev->uverbs_cmd_mask =
	    (1ull << IB_USER_VERBS_CMD_GET_CONTEXT) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_DEVICE) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_PORT) |
	    (1ull << IB_USER_VERBS_CMD_ALLOC_PD) |
	    (1ull << IB_USER_VERBS_CMD_DEALLOC_PD) |
	    (1ull << IB_USER_VERBS_CMD_REG_MR) |
	    (1ull << IB_USER_VERBS_CMD_DEREG_MR) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_CQ) |
	    (1ull << IB_USER_VERBS_CMD_DESTROY_CQ) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_QP) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_QP) |
	    (1ull << IB_USER_VERBS_CMD_MODIFY_QP) |
	    (1ull << IB_USER_VERBS_CMD_DESTROY_QP);

	ibdev->node_type = RDMA_NODE_RNIC;
	memcpy(ibdev->node_desc, ERDMA_NODE_DESC_COMMON, sizeof(ERDMA_NODE_DESC_COMMON));

	/*
	 * Current model (one-to-one device association):
	 * One ERDMA device per net_device or, equivalently,
	 * per physical port.
	 */
	ibdev->phys_port_cnt = 1;

	ibdev->num_comp_vectors = dev->irq_num - 1;

	ib_set_device_ops(ibdev, &erdma_device_ops);

	INIT_LIST_HEAD(&dev->qp_list);
	INIT_LIST_HEAD(&dev->cep_list);

	erdma_idr_init(dev);
	dev->next_alloc_cqn = cqn_start;
	dev->next_alloc_qpn = qpn_start;

	spin_lock_init(&dev->db_bitmap_lock);
	bitmap_zero(dev->sdb_page, ERDMA_SDB_NPAGE);
	bitmap_zero(dev->sdb_entry, ERDMA_SQB_NENTRY);

	atomic_set(&dev->num_ctx, 0);
	atomic_set(&dev->num_qp, 0);
	atomic_set(&dev->num_cq, 0);
	atomic_set(&dev->num_mem, 0);
	atomic_set(&dev->num_pd, 0);
	atomic_set(&dev->num_cep, 0);

	dprint(DBG_INIT, "ib device create ok.\n");

	mac_l = erdma_reg_read32(dev, ERDMA_REGS_NETDEV_MAC_L_REG);
	mac_h = erdma_reg_read32(dev, ERDMA_REGS_NETDEV_MAC_H_REG);

	pr_info("assoc netdev mac addr is 0x%x-0x%x.\n", mac_h, mac_l);

	dev->peer_addr[0] = (mac_h >> 8) & 0xFF;
	dev->peer_addr[1] = mac_h & 0xFF;
	dev->peer_addr[2] = (mac_l >> 24) & 0xFF;
	dev->peer_addr[3] = (mac_l >> 16) & 0xFF;
	dev->peer_addr[4] = (mac_l >> 8) & 0xFF;
	dev->peer_addr[5] = mac_l & 0xFF;

	err = erdma_chrdev_init(dev, dev->dev_id);
	if (err)
		goto out;

	spin_lock_init(&dev->netdev_nb_lock);
	dev->netdev_nb.notifier_call = erdma_netdev_event;
	dev->netdev = NULL;

	err = register_netdevice_notifier(&dev->netdev_nb);
	if (err) {
		erdma_chrdev_destroy(dev);
		goto out;
	}

out:
	return err;
}

static void erdma_ib_device_remove(struct pci_dev *pdev)
{
	struct erdma_dev *dev = pci_get_drvdata(pdev);

	dprint(DBG_INIT, "remove netdev notify.\n");

	spin_lock(&dev->netdev_nb_lock);
	unregister_netdevice_notifier(&dev->netdev_nb);
	spin_unlock(&dev->netdev_nb_lock);

	erdma_chrdev_destroy(dev);

	if (dev->is_registered) {
		erdma_device_deregister(dev);
		dev->is_registered = 0;
	}
}

static int erdma_sriov_pf_probe(struct pci_dev *dev)
{
	int err = 0;

	/*
	 * enable device: ask low-level code to enable I/O and
	 * memory
	 */
	err = pci_enable_device(dev);
	if (err != 0) {
		dev_err(&dev->dev, "Cannot enable PCI device\n");
		return err;
	}

	/* enable bus mastering on the device */
	pci_set_master(dev);

	/* set 64-bit DMA mask */
	err = pci_set_dma_mask(dev,  DMA_BIT_MASK(64));
	if (err != 0) {
		dev_err(&dev->dev, "Cannot set DMA mask\n");
		goto error;
	}

	err = pci_set_consistent_dma_mask(dev, DMA_BIT_MASK(64));
	if (err != 0) {
		dev_err(&dev->dev, "Cannot set consistent DMA mask\n");
		goto error;
	}

	/* VF number fixed as 255, will change to a parameter later */
	if (dev->is_physfn) {
		err = pci_enable_sriov(dev, 8);
		if (err) {
			dev_err(&dev->dev, "Failed to enable PCI sriov: %d\n",
			err);
			goto error;
		}
	}

	return 0;

 error:
	pci_disable_device(dev);

	return err;
}

static int erdma_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int ret;

	if (pdev->device == ERDMA_SRIOV_PF_ID && pdev->is_physfn)
		return erdma_sriov_pf_probe(pdev);

	ret = erdma_probe_dev(pdev);
	if (ret)
		return ret;

	ret = erdma_ib_device_add(pdev);
	if (ret) {
		erdma_remove_dev(pdev);
		return ret;
	}

	return 0;
}

static void erdma_remove(struct pci_dev *pdev)
{
	if (pdev->device == ERDMA_SRIOV_PF_ID && pdev->is_physfn) {
		/* disable iov and allow time for transactions to clear */
		pci_disable_sriov(pdev);
		msleep(500);
		pci_disable_device(pdev);
	} else {
		erdma_ib_device_remove(pdev);
		erdma_remove_dev(pdev);
	}
}

static struct pci_driver erdma_pci_driver = {
	.name = DRV_MODULE_NAME,
	.id_table = erdma_pci_tbl,
	.probe = erdma_probe,
	.remove = erdma_remove
};

MODULE_DEVICE_TABLE(pci, erdma_pci_tbl);
/*
 * erdma_init_module - Initialize ElasticRDMA module and register with netdev
 *                   subsystem to create ElasticRDMA devices per net_device
 */
static __init int erdma_init_module(void)
{
	int rv;
	dev_t dev;

	pr_info("erdma driver version: %d.%d.%d\n", DRV_VER_MAJOR,
		DRV_VER_MINOR, DRV_VER_BUILD);

	bitmap_zero(erdma_devid, ERDMA_MAX_DEVICES);

	rv = alloc_chrdev_region(&dev, 0, ERDMA_MAX_DEVICES, ERDMA_CHRDEV_NAME);
	if (rv) {
		pr_err("alloc chrdev failed.\n");
		goto out;
	}
	erdma_chrdev_major = MAJOR(dev);

	erdma_chrdev_class = class_create(THIS_MODULE, ERDMA_CHRDEV_NAME);
	if (IS_ERR(erdma_chrdev_class)) {
		rv = PTR_ERR(erdma_chrdev_class);
		pr_err("create class failed.\n");
		goto uninit_chrdev;
	}

	erdma_chrdev_class->devnode = erdma_chrdev_devnode;

	erdma_debug_init();
	avx_check();

	rv = erdma_cm_init();
	if (rv)
		goto uninit_dbgfs;

	rv = pci_register_driver(&erdma_pci_driver);
	if (rv) {
		pr_err("Couldn't register erdma driver.\n");
		goto uninit_cm;
	}

	return rv;

uninit_cm:
	erdma_cm_exit();

uninit_dbgfs:
	erdma_dbg_exit();

uninit_chrdev:
	unregister_chrdev_region(dev, ERDMA_MAX_DEVICES);

out:
	return rv;
}

static void __exit erdma_exit_module(void)
{
	pci_unregister_driver(&erdma_pci_driver);

	erdma_cm_exit();
	erdma_dbg_exit();
	class_destroy(erdma_chrdev_class);
	unregister_chrdev_region(MKDEV(erdma_chrdev_major, 0),
		ERDMA_MAX_DEVICES);
}

module_init(erdma_init_module);
module_exit(erdma_exit_module);
