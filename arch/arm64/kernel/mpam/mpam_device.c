// SPDX-License-Identifier: GPL-2.0+
/*
 * Common code for ARM v8 MPAM
 *
 * Copyright (C) 2020-2021 Huawei Technologies Co., Ltd
 *
 * Author: Wang Shaobo <bobo.shaobowang@huawei.com>
 *
 * Code was partially borrowed from http://www.linux-arm.org/
 * git?p=linux-jm.git;a=shortlog;h=refs/heads/mpam/snapshot/may.
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
 * More information about MPAM be found in the Arm Architecture Reference
 * Manual.
 *
 * https://static.docs.arm.com/ddi0598/a/DDI0598_MPAM_supp_armv8a.pdf
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/io.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "mpam_device.h"

/*
 * During discovery this lock protects writers to class, components and devices.
 * Once all devices are successfully probed, the system_supports_mpam() static
 * key is enabled, and these lists become read only.
 */
static DEFINE_MUTEX(mpam_devices_lock);

/* Devices are MSCs */
static LIST_HEAD(mpam_all_devices);

/* Classes are the set of MSCs that make up components of the same type. */
LIST_HEAD(mpam_classes);

static struct mpam_device * __init
mpam_device_alloc(struct mpam_component *comp)
{
	struct mpam_device *dev;

	lockdep_assert_held(&mpam_devices_lock);

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&dev->lock);
	INIT_LIST_HEAD(&dev->comp_list);
	INIT_LIST_HEAD(&dev->glbl_list);

	dev->comp = comp;
	list_add(&dev->comp_list, &comp->devices);
	list_add(&dev->glbl_list, &mpam_all_devices);

	return dev;
}

static void mpam_devices_destroy(struct mpam_component *comp)
{
	struct mpam_device *dev, *tmp;

	lockdep_assert_held(&mpam_devices_lock);

	list_for_each_entry_safe(dev, tmp, &comp->devices, comp_list) {
		list_del(&dev->comp_list);
		list_del(&dev->glbl_list);
		kfree(dev);
	}
}

static struct mpam_component * __init mpam_component_alloc(int id)
{
	struct mpam_component *comp;

	comp = kzalloc(sizeof(*comp), GFP_KERNEL);
	if (!comp)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&comp->devices);
	INIT_LIST_HEAD(&comp->class_list);

	comp->comp_id = id;

	return comp;
}

struct mpam_component *mpam_component_get(struct mpam_class *class, int id,
						bool alloc)
{
	struct mpam_component *comp;

	list_for_each_entry(comp, &class->components, class_list) {
		if (comp->comp_id == id)
			return comp;
	}

	if (!alloc)
		return ERR_PTR(-ENOENT);

	comp = mpam_component_alloc(id);
	if (IS_ERR(comp))
		return comp;

	list_add(&comp->class_list, &class->components);

	return comp;
}

static struct mpam_class * __init mpam_class_alloc(u8 level_idx,
			enum mpam_class_types type)
{
	struct mpam_class *class;

	lockdep_assert_held(&mpam_devices_lock);

	class = kzalloc(sizeof(*class), GFP_KERNEL);
	if (!class)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&class->components);
	INIT_LIST_HEAD(&class->classes_list);

	mutex_init(&class->lock);

	class->level = level_idx;
	class->type = type;

	list_add(&class->classes_list, &mpam_classes);

	return class;
}

/* free all components and devices of this class */
static void mpam_class_destroy(struct mpam_class *class)
{
	struct mpam_component *comp, *tmp;

	lockdep_assert_held(&mpam_devices_lock);

	list_for_each_entry_safe(comp, tmp, &class->components, class_list) {
		mpam_devices_destroy(comp);
		list_del(&comp->class_list);
		kfree(comp);
	}
}

static struct mpam_class * __init mpam_class_get(u8 level_idx,
						enum mpam_class_types type,
						bool alloc)
{
	bool found = false;
	struct mpam_class *class;

	lockdep_assert_held(&mpam_devices_lock);

	list_for_each_entry(class, &mpam_classes, classes_list) {
		if (class->type == type && class->level == level_idx) {
			found = true;
			break;
		}
	}

	if (found)
		return class;

	if (!alloc)
		return ERR_PTR(-ENOENT);

	return mpam_class_alloc(level_idx, type);
}

/*
 * Create a a device with this @hwpage_address, of class type:level_idx.
 * class/component structures may be allocated.
 * Returns the new device, or an ERR_PTR().
 */
struct mpam_device * __init
__mpam_device_create(u8 level_idx, enum mpam_class_types type,
			int component_id, const struct cpumask *fw_affinity,
			phys_addr_t hwpage_address)
{
	struct mpam_device *dev;
	struct mpam_class *class;
	struct mpam_component *comp;

	if (!fw_affinity)
		fw_affinity = cpu_possible_mask;

	mutex_lock(&mpam_devices_lock);
	do {
		class = mpam_class_get(level_idx, type, true);
		if (IS_ERR(class)) {
			dev = (void *)class;
			break;
		}

		comp = mpam_component_get(class, component_id, true);
		if (IS_ERR(comp)) {
			dev = (void *)comp;
			break;
		}

		/*
		 * For caches we learn the affinity from the cache-id as CPUs
		 * come online. For everything else, we have to be told.
		 */
		if (type != MPAM_CLASS_CACHE)
			cpumask_or(&comp->fw_affinity, &comp->fw_affinity,
					fw_affinity);

		dev = mpam_device_alloc(comp);
		if (IS_ERR(dev))
			break;

		dev->fw_affinity = *fw_affinity;
		dev->hwpage_address = hwpage_address;
		dev->mapped_hwpage = ioremap(hwpage_address, SZ_MPAM_DEVICE);
		if (!dev->mapped_hwpage)
			dev = ERR_PTR(-ENOMEM);
	} while (0);
	mutex_unlock(&mpam_devices_lock);

	return dev;
}

static int mpam_cpus_have_feature(void)
{
	if (!cpus_have_const_cap(ARM64_HAS_MPAM))
		return 0;
	return 1;
}

/*
 * prepare for initializing devices.
 */
int __init mpam_discovery_start(void)
{
	if (!mpam_cpus_have_feature())
		return -EOPNOTSUPP;

	return 0;
}

int __init mpam_discovery_complete(void)
{
	return 0;
}

void __init mpam_discovery_failed(void)
{
	struct mpam_class *class, *tmp;

	mutex_lock(&mpam_devices_lock);
	list_for_each_entry_safe(class, tmp, &mpam_classes, classes_list) {
		mpam_class_destroy(class);
		list_del(&class->classes_list);
		kfree(class);
	}
	mutex_unlock(&mpam_devices_lock);
}
