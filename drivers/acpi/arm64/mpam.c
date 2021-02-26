// SPDX-License-Identifier: GPL-2.0+
/*
 * Common code for ARM v8 MPAM ACPI
 *
 * Copyright (C) 2019-2020 Huawei Technologies Co., Ltd
 *
 * Author: Wang ShaoBo <bobo.shaobowang@huawei.com>
 *
 * Code was partially borrowed from http://www.linux-arm.org/git?p=
 * linux-jm.git;a=commit;h=10fe7d6363ae96b25f584d4a91f9d0f2fd5faf3b.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

/* Parse the MPAM ACPI table feeding the discovered nodes into the driver */
#define pr_fmt(fmt) "ACPI MPAM: " fmt

#include <linux/acpi.h>
#include <acpi/processor.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/cacheinfo.h>
#include <linux/string.h>
#include <linux/nodemask.h>
#include <linux/arm_mpam.h>

/**
 * acpi_mpam_label_cache_component_id() - Recursivly find @min_physid
 * for all leaf CPUs below @cpu_node, use numa node id of @min_cpu_node
 * to label mpam cache node, which be signed by @component_id.
 * @table_hdr: Pointer to the head of the PPTT table
 * @cpu_node:  The point in the toplogy to start the walk
 * @component_id: The id labels the structure mpam_node cache
 */
static int
acpi_mpam_label_cache_component_id(struct acpi_table_header *table_hdr,
					struct acpi_pptt_processor *cpu_node,
					u32 *component_id)
{
	phys_cpuid_t min_physid = PHYS_CPUID_INVALID;
	struct acpi_pptt_processor *min_cpu_node = NULL;
	u32 logical_cpuid;
	u32 acpi_processor_id;

	acpi_pptt_find_min_physid_cpu_node(table_hdr,
					cpu_node,
					&min_physid,
					&min_cpu_node);
	WARN_ON_ONCE(invalid_phys_cpuid(min_physid));
	if (min_cpu_node == NULL)
		return -EINVAL;

	acpi_processor_id = min_cpu_node->acpi_processor_id;
	logical_cpuid = acpi_map_cpuid(min_physid, acpi_processor_id);
	if (invalid_logical_cpuid(logical_cpuid) ||
		!cpu_present(logical_cpuid)) {
		pr_err_once("Invalid logical cpuid.\n");
		return -EINVAL;
	}

	*component_id = cpu_to_node(logical_cpuid);

	return 0;
}

/**
 * acpi_mpam_label_memory_component_id() - Use proximity_domain id to
 * label mpam memory node, which be signed by @component_id.
 * @proximity_domain: proximity_domain of ACPI MPAM memory node
 * @component_id: The id labels the structure mpam_node memory
 */
static int acpi_mpam_label_memory_component_id(u8 proximity_domain,
					u32 *component_id)
{
	u32 nid = (u32)proximity_domain;

	if (nid >= nr_online_nodes) {
		pr_err_once("Invalid proximity domain\n");
		return -EINVAL;
	}

	*component_id = nid;
	return 0;
}

static int __init acpi_mpam_parse_memory(struct acpi_mpam_header *h)
{
	int ret;
	u32 component_id;
	struct mpam_device *dev;
	struct acpi_mpam_node_memory *node = (struct acpi_mpam_node_memory *)h;

	ret = acpi_mpam_label_memory_component_id(node->proximity_domain,
							&component_id);
	if (ret) {
		pr_err("Failed to label memory component id\n");
		return -EINVAL;
	}

	dev = mpam_device_create_memory(component_id,
					node->header.base_address);
	if (IS_ERR(dev)) {
		pr_err("Failed to create memory node\n");
		return -EINVAL;
	}

	return mpam_register_device_irq(dev,
		node->header.overflow_interrupt, node->header.overflow_flags,
		node->header.error_interrupt, node->header.error_interrupt_flags);
}

static int __init acpi_mpam_parse_cache(struct acpi_mpam_header *h,
						struct acpi_table_header *pptt)
{
	int ret = 0;
	int level;
	u32 component_id;
	struct mpam_device *dev;
	struct cacheinfo *ci;
	struct acpi_pptt_cache *pptt_cache;
	struct acpi_pptt_processor *pptt_cpu_node;
	struct acpi_mpam_node_cache *node = (struct acpi_mpam_node_cache *)h;

	if (!pptt) {
		pr_err("No PPTT table found, MPAM cannot be configured\n");
		return -EINVAL;
	}

	pptt_cache = acpi_pptt_validate_cache_node(pptt, node->PPTT_ref);
	if (!pptt_cache) {
		pr_err("Broken PPTT reference in the MPAM table\n");
		return -EINVAL;
	}

	/*
	 * We actually need a cpu_node, as a pointer to the PPTT cache
	 * description isn't unique.
	 */
	pptt_cpu_node = acpi_pptt_find_cache_backwards(pptt, pptt_cache);

	ret = acpi_mpam_label_cache_component_id(pptt, pptt_cpu_node,
					&component_id);

	if (ret) {
		pr_err("Failed to label cache component id\n");
		return -EINVAL;
	}

	cpus_read_lock();
	ci = cacheinfo_shared_cpu_map_search(pptt_cpu_node);
	if (!ci) {
		pr_err_once("No CPU has cache with PPTT reference 0x%x",
				node->PPTT_ref);
		pr_err_once("All CPUs must be online to probe mpam.\n");
		cpus_read_unlock();
		return -ENODEV;
	}

	level = ci->level;
	ci = NULL;
	cpus_read_unlock();

	/*
	 * Possible we can get cpu-affinity in next MPAM ACPI version,
	 * now we have to set it to NULL and use default possible_aff-
	 * inity.
	 */
	dev = mpam_device_create_cache(level, component_id, NULL,
				node->header.base_address);
	if (IS_ERR(dev)) {
		pr_err("Failed to create cache node\n");
		return -EINVAL;
	}

	return mpam_register_device_irq(dev,
		node->header.overflow_interrupt, node->header.overflow_flags,
		node->header.error_interrupt, node->header.error_interrupt_flags);
}

static int __init acpi_mpam_parse_table(struct acpi_table_header *table,
					struct acpi_table_header *pptt)
{
	char *table_offset = (char *)(table + 1);
	char *table_end = (char *)table + table->length;
	struct acpi_mpam_header *node_hdr;
	int ret = 0;

	ret = mpam_discovery_start();

	if (ret)
		return ret;

	node_hdr = (struct acpi_mpam_header *)table_offset;
	while (table_offset < table_end) {
		switch (node_hdr->type) {

		case ACPI_MPAM_TYPE_CACHE:
			ret = acpi_mpam_parse_cache(node_hdr, pptt);
			break;
		case ACPI_MPAM_TYPE_MEMORY:
			ret = acpi_mpam_parse_memory(node_hdr);
			break;
		default:
			pr_warn_once("Unknown node type %u offset %ld.",
					node_hdr->type,
					(table_offset-(char *)table));
			/* fall through */
		case ACPI_MPAM_TYPE_SMMU:
			/* not yet supported */
			/* fall through */
		case ACPI_MPAM_TYPE_UNKNOWN:
			break;
		}
		if (ret)
			break;

		table_offset += node_hdr->length;
		node_hdr = (struct acpi_mpam_header *)table_offset;
	}

	if (ret) {
		pr_err("discovery failed: %d\n", ret);
		mpam_discovery_failed();
	} else {
		ret = mpam_discovery_complete();
		if (!ret)
			pr_info("Successfully init mpam by ACPI.\n");
	}

	return ret;
}

int __init acpi_mpam_parse(void)
{
	struct acpi_table_header *mpam, *pptt;
	acpi_status status;
	int ret;

	if (!cpus_have_const_cap(ARM64_HAS_MPAM))
		return 0;

	if (acpi_disabled || mpam_enabled != MPAM_ENABLE_ACPI)
		return 0;

	status = acpi_get_table(ACPI_SIG_MPAM, 0, &mpam);
	if (ACPI_FAILURE(status))
		return -ENOENT;

	/* PPTT is optional, there may be no mpam cache controls */
	acpi_get_table(ACPI_SIG_PPTT, 0, &pptt);
	if (ACPI_FAILURE(status))
		pptt = NULL;

	ret = acpi_mpam_parse_table(mpam, pptt);
	acpi_put_table(pptt);
	acpi_put_table(mpam);

	return ret;
}

/*
 * We want to run after cacheinfo_sysfs_init() has caused the cacheinfo
 * structures to be populated. That runs as a device_initcall.
 */
device_initcall_sync(acpi_mpam_parse);
