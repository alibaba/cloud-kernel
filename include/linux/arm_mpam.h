/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_ARM_MPAM_H
#define __LINUX_ARM_MPAM_H

#include <linux/err.h>
#include <linux/cpumask.h>
#include <linux/types.h>

struct mpam_device;

enum mpam_class_types {
	MPAM_CLASS_SMMU,
	MPAM_CLASS_CACHE,   /* Well known caches, e.g. L2 */
	MPAM_CLASS_MEMORY,  /* Main memory */
	MPAM_CLASS_UNKNOWN, /* Everything else, e.g. TLBs etc */
};

struct mpam_device * __init
__mpam_device_create(u8 level_idx, enum mpam_class_types type,
			int component_id, const struct cpumask *fw_affinity,
			phys_addr_t hwpage_address);

/*
 * Create a device for a well known cache, e.g. L2.
 * @level_idx and @cache_id will be used to match the cache via cacheinfo
 * to learn the component affinity and export domain/resources via resctrl.
 * If the device can only be accessed from a smaller set of CPUs, provide
 * this as @device_affinity, which can otherwise be NULL.
 *
 * Returns the new device, or an ERR_PTR().
 */
static inline struct mpam_device * __init
mpam_device_create_cache(u8 level_idx, int cache_id,
			const struct cpumask *device_affinity,
			phys_addr_t hwpage_address)
{
	return __mpam_device_create(level_idx, MPAM_CLASS_CACHE, cache_id,
			device_affinity, hwpage_address);
}
/*
 * Create a device for a main memory.
 * For NUMA systems @nid allows multiple components to be created,
 * which will be exported as resctrl domains. MSCs for memory must
 * be accessible from any cpu.
 */
static inline struct mpam_device * __init
mpam_device_create_memory(int nid, phys_addr_t hwpage_address)
{
	struct cpumask dev_affinity;

	cpumask_copy(&dev_affinity, cpumask_of_node(nid));

	return __mpam_device_create(~0, MPAM_CLASS_MEMORY, nid,
			&dev_affinity, hwpage_address);
}
int __init mpam_discovery_start(void);
int __init mpam_discovery_complete(void);
void __init mpam_discovery_failed(void);

enum mpam_enable_type {
	MPAM_ENABLE_DENIED = 0,
	MPAM_ENABLE_ACPI,
};

extern enum mpam_enable_type mpam_enabled;

#endif
