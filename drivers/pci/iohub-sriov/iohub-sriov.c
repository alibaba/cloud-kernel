// SPDX-License-Identifier: GPL-2.0
/*
 * Alibaba PCIe IOHub SRIOV support
 *   It enables SRIOV of PCIe devices of Alibaba MOC,
 *   then VFs can be used by other applications.
 *
 * Copyright (C) 2018 Alibaba Corporation,
 * Shanghui.lsh <shanghui.lsh@alibaba-inc.com>
 */

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/io.h>
#include <linux/version.h>
#include <linux/slab.h>

#define PCI_VENDOR_ID_ALIBABA		0x1ded
#define PCI_DEVICE_ID_IOHUB_NETWORK_1	0x1000
#define PCI_DEVICE_ID_IOHUB_BLOCK_1	0x1001
#define PCI_DEVICE_ID_IOHUB_NETWORK_2	0x5002
#define PCI_DEVICE_ID_IOHUB_BLOCK_2	0x5003

static int
xdragon_sriov_pci_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int err = 0;

	dev_info(&dev->dev, "iohub device probe\n");

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
		err = pci_enable_sriov(dev, 255);
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

static void
xdragon_sriov_pci_remove(struct pci_dev *dev)
{
	/* disable iov and allow time for transactions to clear */
	pci_disable_sriov(dev);
	msleep(500);

	pci_disable_device(dev);
}

static struct pci_device_id xdragon_pci_ids[] = {
	{
		.vendor =	PCI_VENDOR_ID_ALIBABA,
		.device =	PCI_DEVICE_ID_IOHUB_NETWORK_1,
		.subvendor = PCI_ANY_ID,
		.subdevice = PCI_ANY_ID,
	},
	{
		.vendor =	PCI_VENDOR_ID_ALIBABA,
		.device =	PCI_DEVICE_ID_IOHUB_BLOCK_1,
		.subvendor = PCI_ANY_ID,
		.subdevice = PCI_ANY_ID,
	},
	{
		.vendor =	PCI_VENDOR_ID_ALIBABA,
		.device =	PCI_DEVICE_ID_IOHUB_NETWORK_2,
		.subvendor = PCI_ANY_ID,
		.subdevice = PCI_ANY_ID,
	},
	{
		.vendor =	PCI_VENDOR_ID_ALIBABA,
		.device =	PCI_DEVICE_ID_IOHUB_BLOCK_2,
		.subvendor = PCI_ANY_ID,
		.subdevice = PCI_ANY_ID,
	},

	{ 0, }
};


static struct pci_driver xdragon_sriov_pci_driver = {
	.name = "iohub_sriov",
	.id_table = xdragon_pci_ids,
	.probe = xdragon_sriov_pci_probe,
	.remove = xdragon_sriov_pci_remove,
};

static int __init
xdragon_sriov_pci_init_module(void)
{
	return pci_register_driver(&xdragon_sriov_pci_driver);
}

static void __exit
xdragon_sriov_pci_exit_module(void)
{
	pci_unregister_driver(&xdragon_sriov_pci_driver);
}

module_init(xdragon_sriov_pci_init_module);
module_exit(xdragon_sriov_pci_exit_module);
MODULE_DEVICE_TABLE(pci, xdragon_pci_ids);
MODULE_LICENSE("GPL v2");
