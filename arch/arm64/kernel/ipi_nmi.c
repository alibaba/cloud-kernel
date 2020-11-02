// SPDX-License-Identifier: GPL-2.0-only
/*
 * NMI support for IPIs
 *
 * Copyright (C) 2020 Linaro Limited
 * Author: Sumit Garg <sumit.garg@linaro.org>
 */

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/smp.h>

#include <asm/nmi.h>

static struct irq_desc *ipi_nmi_desc __read_mostly;
static int ipi_nmi_id __read_mostly;

bool arm64_supports_nmi(void)
{
	if (ipi_nmi_desc)
		return true;

	return false;
}

void arm64_send_nmi(cpumask_t *mask)
{
	if (WARN_ON_ONCE(!ipi_nmi_desc))
		return;

	__ipi_send_mask(ipi_nmi_desc, mask);
}

static irqreturn_t ipi_nmi_handler(int irq, void *data)
{
	/* nop, NMI handlers for special features can be added here. */

	return IRQ_NONE;
}

void dynamic_ipi_setup(int cpu)
{
	if (!ipi_nmi_desc)
		return;

	if (!prepare_percpu_nmi(ipi_nmi_id))
		enable_percpu_nmi(ipi_nmi_id, IRQ_TYPE_NONE);
}

void dynamic_ipi_teardown(int cpu)
{
	if (!ipi_nmi_desc)
		return;

	disable_percpu_nmi(ipi_nmi_id);
	teardown_percpu_nmi(ipi_nmi_id);
}

void __init set_smp_dynamic_ipi(int ipi)
{
	if (!request_percpu_nmi(ipi, ipi_nmi_handler, "IPI", &cpu_number)) {
		ipi_nmi_desc = irq_to_desc(ipi);
		ipi_nmi_id = ipi;
	}
}
