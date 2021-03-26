// SPDX-License-Identifier: GPL-2.0-only
/*
 *  sata_zhaoxin.c - ZhaoXin Serial ATA controllers
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_host.h>
#include <linux/libata.h>

#define DRV_NAME	"sata_zx"
#define DRV_VERSION	"2.6.1"

enum board_ids_enum {
	cnd001,
};

enum {
	SATA_CHAN_ENAB		= 0x40, /* SATA channel enable */
	SATA_INT_GATE		= 0x41, /* SATA interrupt gating */
	SATA_NATIVE_MODE	= 0x42, /* Native mode enable */
	PATA_UDMA_TIMING	= 0xB3, /* PATA timing for DMA/ cable detect */
	PATA_PIO_TIMING		= 0xAB, /* PATA timing register */

	PORT0			= (1 << 1),
	PORT1			= (1 << 0),
	ALL_PORTS		= PORT0 | PORT1,

	NATIVE_MODE_ALL		= (1 << 7) | (1 << 6) | (1 << 5) | (1 << 4),

	SATA_EXT_PHY		= (1 << 6), /* 0==use PATA, 1==ext phy */
};

static int szx_init_one(struct pci_dev *pdev, const struct pci_device_id *ent);
static int cnd001_scr_read(struct ata_link *link, unsigned int scr, u32 *val);
static int cnd001_scr_write(struct ata_link *link, unsigned int scr, u32 val);
static int szx_hardreset(struct ata_link *link, unsigned int *class,
				unsigned long deadline);

static void szx_tf_load(struct ata_port *ap, const struct ata_taskfile *tf);

static const struct pci_device_id szx_pci_tbl[] = {
	{ PCI_VDEVICE(ZHAOXIN, 0x9002), cnd001 },
	{ PCI_VDEVICE(ZHAOXIN, 0x9003), cnd001 },

	{ }	/* terminate list */
};

static struct pci_driver szx_pci_driver = {
	.name			= DRV_NAME,
	.id_table		= szx_pci_tbl,
	.probe			= szx_init_one,
#ifdef CONFIG_PM_SLEEP
	.suspend		= ata_pci_device_suspend,
	.resume			= ata_pci_device_resume,
#endif
	.remove			= ata_pci_remove_one,
};

static struct scsi_host_template szx_sht = {
	ATA_BMDMA_SHT(DRV_NAME),
};

static struct ata_port_operations szx_base_ops = {
	.inherits		= &ata_bmdma_port_ops,
	.sff_tf_load		= szx_tf_load,
};

static struct ata_port_operations cnd001_ops = {
	.inherits		= &szx_base_ops,
	.hardreset		= szx_hardreset,
	.scr_read		= cnd001_scr_read,
	.scr_write		= cnd001_scr_write,
};

static struct ata_port_info cnd001_port_info = {
	.flags		= ATA_FLAG_SATA | ATA_FLAG_SLAVE_POSS,
	.pio_mask	= ATA_PIO4,
	.mwdma_mask	= ATA_MWDMA2,
	.udma_mask	= ATA_UDMA6,
	.port_ops	= &cnd001_ops,
};


static int szx_hardreset(struct ata_link *link, unsigned int *class,
				unsigned long deadline)
{
	int rc;

	rc = sata_std_hardreset(link, class, deadline);
	if (!rc || rc == -EAGAIN) {
		struct ata_port *ap = link->ap;
		int pmp = link->pmp;
		int tmprc;

		if (pmp) {
			ap->ops->sff_dev_select(ap, pmp);
			tmprc = ata_sff_wait_ready(&ap->link, deadline);
		} else {
			tmprc = ata_sff_wait_ready(link, deadline);
		}
		if (tmprc)
			ata_link_err(link, "COMRESET failed for wait (errno=%d)\n",
					rc);
		else
			ata_link_err(link, "wait for bsy success\n");

		ata_link_err(link, "COMRESET success (errno=%d) ap=%d link %d\n",
					rc, link->ap->port_no, link->pmp);
	} else {
		ata_link_err(link, "COMRESET failed (errno=%d) ap=%d link %d\n",
					rc, link->ap->port_no, link->pmp);
	}
	return rc;
}

static int cnd001_scr_read(struct ata_link *link, unsigned int scr, u32 *val)
{
	static const u8 ipm_tbl[] = { 1, 2, 6, 0 };
	struct pci_dev *pdev = to_pci_dev(link->ap->host->dev);
	int slot = 2 * link->ap->port_no + link->pmp;
	u32 v = 0;
	u8 raw;

	switch (scr) {
	case SCR_STATUS:
		pci_read_config_byte(pdev, 0xA0 + slot, &raw);

		/* read the DET field, bit0 and 1 of the config byte */
		v |= raw & 0x03;

		/* read the SPD field, bit4 of the configure byte */
		v |= raw & 0x30;

		/* read the IPM field, bit2 and 3 of the config byte */
		v |= ((ipm_tbl[(raw >> 2) & 0x3])<<8);
		break;

	case SCR_ERROR:
		/* devices other than 5287 uses 0xA8 as base */
		WARN_ON(pdev->device != 0x9002 && pdev->device != 0x9003);
		pci_write_config_byte(pdev, 0x42, slot);
		pci_read_config_dword(pdev, 0xA8, &v);
		break;

	case SCR_CONTROL:
		pci_read_config_byte(pdev, 0xA4 + slot, &raw);

		/* read the DET field, bit0 and bit1 */
		v |= ((raw & 0x02) << 1) | (raw & 0x01);

		/* read the IPM field, bit2 and bit3 */
		v |= ((raw >> 2) & 0x03) << 8;

		break;

	default:
		return -EINVAL;
	}

	*val = v;
	return 0;
}

static int cnd001_scr_write(struct ata_link *link, unsigned int scr, u32 val)
{
	struct pci_dev *pdev = to_pci_dev(link->ap->host->dev);
	int slot = 2 * link->ap->port_no + link->pmp;
	u32 v = 0;

	WARN_ON(pdev == NULL);

	switch (scr) {
	case SCR_ERROR:
		/* devices 0x9002 uses 0xA8 as base */
		WARN_ON(pdev->device != 0x9002 && pdev->device != 0x9003);
		pci_write_config_byte(pdev, 0x42, slot);
		pci_write_config_dword(pdev, 0xA8, val);
		return 0;

	case SCR_CONTROL:
		/* set the DET field */
		v |= ((val & 0x4) >> 1) | (val & 0x1);

		/* set the IPM field */
		v |= ((val >> 8) & 0x3) << 2;


		pci_write_config_byte(pdev, 0xA4 + slot, v);


		return 0;

	default:
		return -EINVAL;
	}
}


/**
 *	szx_tf_load - send taskfile registers to host controller
 *	@ap: Port to which output is sent
 *	@tf: ATA taskfile register set
 *
 *	Outputs ATA taskfile to standard ATA host controller.
 *
 *	This is to fix the internal bug of zx chipsets, which will
 *	reset the device register after changing the IEN bit on ctl
 *	register.
 */
static void szx_tf_load(struct ata_port *ap, const struct ata_taskfile *tf)
{
	struct ata_taskfile ttf;

	if (tf->ctl != ap->last_ctl)  {
		ttf = *tf;
		ttf.flags |= ATA_TFLAG_DEVICE;
		tf = &ttf;
	}
	ata_sff_tf_load(ap, tf);
}

static const unsigned int szx_bar_sizes[] = {
	8, 4, 8, 4, 16, 256
};

static const unsigned int cnd001_bar_sizes0[] = {
	8, 4, 8, 4, 16, 0
};

static const unsigned int cnd001_bar_sizes1[] = {
	8, 4, 0, 0, 16, 0
};

static int cnd001_prepare_host(struct pci_dev *pdev, struct ata_host **r_host)
{
	const struct ata_port_info *ppi0[] = {
		&cnd001_port_info, NULL
	};
	const struct ata_port_info *ppi1[] = {
		&cnd001_port_info, &ata_dummy_port_info
	};
	struct ata_host *host;
	int i, rc;

	if (pdev->device == 0x9002)
		rc = ata_pci_bmdma_prepare_host(pdev, ppi0, &host);
	else if (pdev->device == 0x9003)
		rc = ata_pci_bmdma_prepare_host(pdev, ppi1, &host);
	else
		rc = -EINVAL;

	if (rc)
		return rc;

	*r_host = host;

	/* cnd001 9002 hosts four sata ports as M/S of the two channels */
	/* cnd001 9003 hosts two sata ports as M/S of the one channel */
	for (i = 0; i < host->n_ports; i++)
		ata_slave_link_init(host->ports[i]);

	return 0;
}

static void szx_configure(struct pci_dev *pdev, int board_id)
{
	u8 tmp8;

	pci_read_config_byte(pdev, PCI_INTERRUPT_LINE, &tmp8);
	dev_info(&pdev->dev, "routed to hard irq line %d\n",
		 (int) (tmp8 & 0xf0) == 0xf0 ? 0 : tmp8 & 0x0f);

	/* make sure SATA channels are enabled */
	pci_read_config_byte(pdev, SATA_CHAN_ENAB, &tmp8);
	if ((tmp8 & ALL_PORTS) != ALL_PORTS) {
		dev_dbg(&pdev->dev, "enabling SATA channels (0x%x)\n",
			(int)tmp8);
		tmp8 |= ALL_PORTS;
		pci_write_config_byte(pdev, SATA_CHAN_ENAB, tmp8);
	}

	/* make sure interrupts for each channel sent to us */
	pci_read_config_byte(pdev, SATA_INT_GATE, &tmp8);
	if ((tmp8 & ALL_PORTS) != ALL_PORTS) {
		dev_dbg(&pdev->dev, "enabling SATA channel interrupts (0x%x)\n",
			(int) tmp8);
		tmp8 |= ALL_PORTS;
		pci_write_config_byte(pdev, SATA_INT_GATE, tmp8);
	}

	/* make sure native mode is enabled */
	pci_read_config_byte(pdev, SATA_NATIVE_MODE, &tmp8);
	if ((tmp8 & NATIVE_MODE_ALL) != NATIVE_MODE_ALL) {
		dev_dbg(&pdev->dev,
			"enabling SATA channel native mode (0x%x)\n",
			(int) tmp8);
		tmp8 |= NATIVE_MODE_ALL;
		pci_write_config_byte(pdev, SATA_NATIVE_MODE, tmp8);
	}
}

static int szx_init_one(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	unsigned int i;
	int rc;
	struct ata_host *host = NULL;
	int board_id = (int) ent->driver_data;
	const unsigned int *bar_sizes;
	int legacy_mode = 0;

	ata_print_version_once(&pdev->dev, DRV_VERSION);

	if (pdev->device == 0x9002 || pdev->device == 0x9003) {
		if ((pdev->class >> 8) == PCI_CLASS_STORAGE_IDE) {
			u8 tmp8, mask;

			/* TODO: What if one channel is in native mode ... */
			pci_read_config_byte(pdev, PCI_CLASS_PROG, &tmp8);
			mask = (1 << 2) | (1 << 0);
			if ((tmp8 & mask) != mask)
				legacy_mode = 1;
		}
		if (legacy_mode)
			return -EINVAL;
	}

	rc = pcim_enable_device(pdev);
	if (rc)
		return rc;

	if (board_id == cnd001 && pdev->device == 0x9002)
		bar_sizes = &cnd001_bar_sizes0[0];
	else if (board_id == cnd001 && pdev->device == 0x9003)
		bar_sizes = &cnd001_bar_sizes1[0];
	else
		bar_sizes = &szx_bar_sizes[0];

	for (i = 0; i < ARRAY_SIZE(szx_bar_sizes); i++) {
		if ((pci_resource_start(pdev, i) == 0) ||
		    (pci_resource_len(pdev, i) < bar_sizes[i])) {
			if (bar_sizes[i] == 0)
				continue;

			dev_err(&pdev->dev,
				"invalid PCI BAR %u (sz 0x%llx, val 0x%llx)\n",
				i,
				(unsigned long long)pci_resource_start(pdev, i),
				(unsigned long long)pci_resource_len(pdev, i));

			return -ENODEV;
		}
	}

	switch (board_id) {
	case cnd001:
		rc = cnd001_prepare_host(pdev, &host);
		break;
	default:
		rc = -EINVAL;
	}
	if (rc)
		return rc;

	szx_configure(pdev, board_id);

	pci_set_master(pdev);
	return ata_host_activate(host, pdev->irq, ata_bmdma_interrupt,
				 IRQF_SHARED, &szx_sht);
}

module_pci_driver(szx_pci_driver);

MODULE_AUTHOR("Yanchen:YanchenSun@zhaoxin.com");
MODULE_DESCRIPTION("SCSI low-level driver for ZX SATA controllers");
MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(pci, szx_pci_tbl);
MODULE_VERSION(DRV_VERSION);
