/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_ARM_MPAM_H
#define __LINUX_ARM_MPAM_H

#include <linux/acpi.h>
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

#define MPAM_IRQ_MODE_LEVEL    0x1
#define MPAM_IRQ_FLAGS_MASK    0x7f

#define mpam_irq_flags_to_acpi(x) ((x & MPAM_IRQ_MODE_LEVEL) ?  \
			ACPI_LEVEL_SENSITIVE : ACPI_EDGE_SENSITIVE)

void __init mpam_device_set_error_irq(struct mpam_device *dev, u32 irq,
			u32 flags);
void __init mpam_device_set_overflow_irq(struct mpam_device *dev, u32 irq,
			u32 flags);

static inline int __init mpam_register_device_irq(struct mpam_device *dev,
			u32 overflow_interrupt, u32 overflow_flags,
			u32 error_interrupt, u32 error_flags)
{
	int irq, trigger;
	int ret = 0;
	u8 irq_flags;

	if (overflow_interrupt) {
		irq_flags = overflow_flags & MPAM_IRQ_FLAGS_MASK;
		trigger = mpam_irq_flags_to_acpi(irq_flags);

		irq = acpi_register_gsi(NULL, overflow_interrupt, trigger,
				ACPI_ACTIVE_HIGH);
		if (irq < 0) {
			pr_err_once("Failed to register overflow interrupt with ACPI\n");
			return ret;
		}

		mpam_device_set_overflow_irq(dev, irq, irq_flags);
	}

	if (error_interrupt) {
		irq_flags = error_flags & MPAM_IRQ_FLAGS_MASK;
		trigger = mpam_irq_flags_to_acpi(irq_flags);

		irq = acpi_register_gsi(NULL, error_interrupt, trigger,
				ACPI_ACTIVE_HIGH);
		if (irq < 0) {
			pr_err_once("Failed to register error interrupt with ACPI\n");
			return ret;
		}

		mpam_device_set_error_irq(dev, irq, irq_flags);
	}

	return ret;
}

#endif
