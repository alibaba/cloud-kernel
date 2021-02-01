// SPDX-License-Identifier: GPL-2.0+
/*
 * Phytium Real Time Clock Driver
 *
 * Copyright (c) 2019, Phytium Technology Co., Ltd.
 *
 * Chen Baozi <chenbaozi@phytium.com.cn>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/clk.h>
#include <linux/rtc.h>
#include <linux/acpi.h>

#define RTC_CMR                 0x04
#define RTC_AES_SEL             0x08
#define RTC_AES_SEL_COUNTER     0x100
#define RTC_CCR                 0x0C
#define RTC_CCR_IE              BIT(0)
#define RTC_CCR_MASK            BIT(1)
#define RTC_CCR_EN              BIT(2)
#define RTC_CCR_WEN             BIT(3)
#define RTC_STAT                0x10
#define RTC_STAT_BIT            BIT(0)
#define RTC_RSTAT               0x14
#define RTC_EOI                 0x18
#define RTC_VER                 0x1C
#define RTC_CDR_LOW             0x20
#define RTC_CCVR                0x24
#define RTC_CLR_LOW             0x28
#define RTC_CLR                 0x2c
#define RTC_COUNTER_HB_OFFSET   15
#define RTC_COUNTER_LB_MASK     GENMASK(14, 0)

struct phytium_rtc_dev {
	struct rtc_device *rtc;
	struct device *dev;
	unsigned long alarm_time;
	void __iomem *csr_base;
	struct clk *clk;
	unsigned int irq_wake;
	unsigned int irq_enabled;
};

static int phytium_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	struct phytium_rtc_dev *pdata = dev_get_drvdata(dev);

	unsigned long counter;
	unsigned long tmp;

	writel(RTC_AES_SEL_COUNTER, pdata->csr_base + RTC_AES_SEL);
	counter = readl(pdata->csr_base + RTC_CCVR);
	tmp = readl(pdata->csr_base + RTC_CDR_LOW);

	rtc_time_to_tm(counter, tm);
	return rtc_valid_tm(tm);
}

static int phytium_rtc_set_mmss(struct device *dev, unsigned long secs)
{
	struct phytium_rtc_dev *pdata = dev_get_drvdata(dev);
	unsigned long counter;
	unsigned long tmp;

	writel(RTC_AES_SEL_COUNTER, pdata->csr_base + RTC_AES_SEL);
	writel(0x00000000, pdata->csr_base + RTC_CLR_LOW);
	writel((u32)secs, pdata->csr_base + RTC_CLR);
	writel(RTC_AES_SEL_COUNTER, pdata->csr_base + RTC_AES_SEL);
	counter = readl(pdata->csr_base + RTC_CLR);
	tmp = readl(pdata->csr_base + RTC_CLR_LOW);

	return 0;
}

static int phytium_rtc_read_alarm(struct device *dev, struct rtc_wkalrm *alrm)
{
	struct phytium_rtc_dev *pdata = dev_get_drvdata(dev);

	rtc_time_to_tm(pdata->alarm_time, &alrm->time);
	alrm->enabled = readl(pdata->csr_base + RTC_CCR) & RTC_CCR_IE;

	return 0;
}

static int phytium_rtc_alarm_irq_enable(struct device *dev, u32 enabled)
{
	struct phytium_rtc_dev *pdata = dev_get_drvdata(dev);
	u32 ccr;

	ccr = readl(pdata->csr_base + RTC_CCR);
	if (enabled) {
		ccr &= ~RTC_CCR_MASK;
		ccr |= RTC_CCR_IE;
	} else {
		ccr &= ~RTC_CCR_IE;
		ccr |= RTC_CCR_MASK;
	}
	writel(ccr, pdata->csr_base + RTC_CCR);

	return 0;
}

static int phytium_rtc_alarm_irq_enabled(struct device *dev)
{
	struct phytium_rtc_dev *pdata = dev_get_drvdata(dev);

	return readl(pdata->csr_base + RTC_CCR) & RTC_CCR_IE ? 1 : 0;
}

static int phytium_rtc_set_alarm(struct device *dev, struct rtc_wkalrm *alrm)
{
	struct phytium_rtc_dev *pdata = dev_get_drvdata(dev);
	unsigned long alarm_time;

	rtc_tm_to_time(&alrm->time, &alarm_time);

	pdata->alarm_time = alarm_time;
	writel((u32) pdata->alarm_time, pdata->csr_base + RTC_CMR);

	phytium_rtc_alarm_irq_enable(dev, alrm->enabled);

	return 0;
}

static const struct rtc_class_ops phytium_rtc_ops = {
	.read_time	= phytium_rtc_read_time,
	.set_mmss	= phytium_rtc_set_mmss,
	.read_alarm	= phytium_rtc_read_alarm,
	.set_alarm	= phytium_rtc_set_alarm,
	.alarm_irq_enable = phytium_rtc_alarm_irq_enable,
};

static irqreturn_t phytium_rtc_interrupt(int irq, void *id)
{
	struct phytium_rtc_dev *pdata = (struct phytium_rtc_dev *) id;

	/* Check if interrupt asserted */
	if (!(readl(pdata->csr_base + RTC_STAT) & RTC_STAT_BIT))
		return IRQ_NONE;

	/* Clear interrupt */
	readl(pdata->csr_base + RTC_EOI);

	rtc_update_irq(pdata->rtc, 1, RTC_IRQF | RTC_AF);

	return IRQ_HANDLED;
}

static int phytium_rtc_probe(struct platform_device *pdev)
{
	struct phytium_rtc_dev *pdata;
	struct resource *res;
	int ret;
	int irq;

	pdata = devm_kzalloc(&pdev->dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;
	platform_set_drvdata(pdev, pdata);
	pdata->dev = &pdev->dev;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	pdata->csr_base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(pdata->csr_base))
		return PTR_ERR(pdata->csr_base);

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		dev_err(&pdev->dev, "No IRQ resource\n");
		return irq;
	}
	ret = devm_request_irq(&pdev->dev, irq, phytium_rtc_interrupt, 0,
			       dev_name(&pdev->dev), pdata);
	if (ret) {
		dev_err(&pdev->dev, "Could not request IRQ\n");
		return ret;
	}

#ifndef CONFIG_ACPI
	pdata->clk = devm_clk_get(&pdev->dev, NULL);
	if (IS_ERR(pdata->clk)) {
		dev_err(&pdev->dev, "Couldn't get the clock for RTC\n");
		return -ENODEV;
	}

	ret = clk_prepare_enable(pdata->clk);
	if (ret)
		return ret;
#endif

	/* Turn on the clock and the crystal */
	writel(RTC_CCR_EN, pdata->csr_base + RTC_CCR);

	ret = device_init_wakeup(&pdev->dev, 1);
	if (ret) {
		clk_disable_unprepare(pdata->clk);
		return ret;
	}

	pdata->rtc = devm_rtc_device_register(&pdev->dev, pdev->name,
					 &phytium_rtc_ops, THIS_MODULE);
	if (IS_ERR(pdata->rtc)) {
		clk_disable_unprepare(pdata->clk);
		return PTR_ERR(pdata->rtc);
	}

	/* HW does not support update faster than 1 seconds */
	pdata->rtc->uie_unsupported = 1;

	return 0;
}

static int phytium_rtc_remove(struct platform_device *pdev)
{
	struct phytium_rtc_dev *pdata = platform_get_drvdata(pdev);

	phytium_rtc_alarm_irq_enable(&pdev->dev, 0);
	device_init_wakeup(&pdev->dev, 0);
	clk_disable_unprepare(pdata->clk);
	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int phytium_rtc_suspend(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct phytium_rtc_dev *pdata = platform_get_drvdata(pdev);
	int irq;

	/*
	 * If this RTC alarm will be used for waking the system up,
	 * don't disable it of course. Else we just disable the alarm
	 * and await suspension.
	 */
	irq = platform_get_irq(pdev, 0);
	if (device_may_wakeup(&pdev->dev)) {
		if (!enable_irq_wake(irq))
			pdata->irq_wake = 1;
	} else {
		pdata->irq_enabled = phytium_rtc_alarm_irq_enabled(dev);
		phytium_rtc_alarm_irq_enable(dev, 0);
		clk_disable_unprepare(pdata->clk);
	}

	return 0;
}

static int phytium_rtc_resume(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct phytium_rtc_dev *pdata = platform_get_drvdata(pdev);
	int irq;
	int rc;

	irq = platform_get_irq(pdev, 0);
	if (device_may_wakeup(&pdev->dev)) {
		if (pdata->irq_wake) {
			disable_irq_wake(irq);
			pdata->irq_wake = 0;
		}
	} else {
		rc = clk_prepare_enable(pdata->clk);
		if (rc) {
			dev_err(dev, "Unable to enable clock error %d\n", rc);
			return rc;
		}
		phytium_rtc_alarm_irq_enable(dev, pdata->irq_enabled);
	}

	return 0;
}
#endif

static SIMPLE_DEV_PM_OPS(phytium_rtc_pm_ops, phytium_rtc_suspend, phytium_rtc_resume);

#ifdef CONFIG_OF
static const struct of_device_id phytium_rtc_of_match[] = {
	{ .compatible = "phytium,rtc" },
	{ }
};
MODULE_DEVICE_TABLE(of, phytium_rtc_of_match);
#endif

#ifdef CONFIG_ACPI
static const struct acpi_device_id phytium_rtc_acpi_match[] = {
	{ "PHYT0002", 0 },
	{ }
};
#endif

static struct platform_driver phytium_rtc_driver = {
	.probe		= phytium_rtc_probe,
	.remove		= phytium_rtc_remove,
	.driver		= {
		.name	= "phytium-rtc",
		.pm = &phytium_rtc_pm_ops,
		.of_match_table	= of_match_ptr(phytium_rtc_of_match),
		.acpi_match_table = ACPI_PTR(phytium_rtc_acpi_match),
	},
};

module_platform_driver(phytium_rtc_driver);

MODULE_DESCRIPTION("Phytium RTC driver");
MODULE_AUTHOR("Chen Baozi <chenbaozi@phytium.com.cn>");
MODULE_LICENSE("GPL");
