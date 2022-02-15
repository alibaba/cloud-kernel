// SPDX-License-Identifier: GPL-2.0-only
/*
 * This file implements handling of
 * Arm Generic Diagnostic Dump and Reset Interface table (AGDI)
 *
 * Copyright (c) 2022, Ampere Computing LLC
 */

#define pr_fmt(fmt) "ACPI: AGDI: " fmt

#include <linux/acpi.h>
#include <linux/arm_sdei.h>
#include <linux/io.h>
#include <linux/kernel.h>

static int agdi_sdei_handler(u32 sdei_event, struct pt_regs *regs, void *arg)
{
	nmi_panic(regs, "Arm Generic Diagnostic Dump and Reset SDEI event issued");
	return 0;
}

void __init acpi_agdi_init(void)
{
	struct acpi_table_agdi *agdi_table;
	acpi_status status;
	int sdei_event;

	status = acpi_get_table(ACPI_SIG_AGDI, 0,
				(struct acpi_table_header **) &agdi_table);
	if (ACPI_FAILURE(status))
		return;

	if (agdi_table->flags & ACPI_AGDI_SIGNALING_MODE) {
		pr_warn("Interrupt signaling is not supported");
		acpi_put_table((struct acpi_table_header *)agdi_table);
		return;
	}

	sdei_event = agdi_table->sdei_event;
	acpi_put_table((struct acpi_table_header *)agdi_table);

	if (sdei_event_register(sdei_event, agdi_sdei_handler, NULL)) {
		pr_err("Failed to register for SDEI event %d", sdei_event);
		return;
	}

	if (sdei_event_enable(sdei_event)) {
		pr_err("Failed to enable SDEI event %d\n", sdei_event);
		sdei_event_unregister(sdei_event);
		return;
	}
}
