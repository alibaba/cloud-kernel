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
#include <linux/cpu.h>
#include <linux/cacheinfo.h>
#include <linux/arm_mpam.h>
#include <asm/mpam_resource.h>

#include "mpam_device.h"
#include "mpam_internal.h"

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

static DEFINE_MUTEX(mpam_cpuhp_lock);
static int mpam_cpuhp_state;

static bool resctrl_registered;

static inline int mpam_cpu_online(unsigned int cpu);
static inline int mpam_cpu_offline(unsigned int cpu);

static struct mpam_sysprops_prop mpam_sysprops;

/*
 * mpam is enabled once all devices have been probed from CPU online callbacks,
 * scheduled via this work_struct.
 */
static struct work_struct mpam_enable_work;

/*
 * This gets set if something terrible happens, it prevents future attempts
 * to configure devices.
 */
static int mpam_broken;
static struct work_struct mpam_failed_work;

void mpam_class_list_lock_held(void)
{
	lockdep_assert_held(&mpam_devices_lock);
}

static inline u32 mpam_read_reg(struct mpam_device *dev, u16 reg)
{
	WARN_ON_ONCE(reg > SZ_MPAM_DEVICE);
	assert_spin_locked(&dev->lock);

	/*
	 * If we touch a device that isn't accessible from this CPU we may get
	 * an external-abort.
	 */
	WARN_ON_ONCE(preemptible());
	WARN_ON_ONCE(!cpumask_test_cpu(smp_processor_id(), &dev->fw_affinity));

	return readl_relaxed(dev->mapped_hwpage + reg);
}

static inline void mpam_write_reg(struct mpam_device *dev, u16 reg, u32 val)
{
	WARN_ON_ONCE(reg > SZ_MPAM_DEVICE);
	assert_spin_locked(&dev->lock);

	/*
	 * If we touch a device that isn't accessible from this CPU we may get
	 * an external-abort. If we're lucky, we corrupt another mpam:component.
	 */
	WARN_ON_ONCE(preemptible());
	WARN_ON_ONCE(!cpumask_test_cpu(smp_processor_id(), &dev->fw_affinity));

	writel_relaxed(val, dev->mapped_hwpage + reg);
}

static void
mpam_probe_update_sysprops(u16 max_partid, u16 max_pmg)
{
	lockdep_assert_held(&mpam_devices_lock);

	mpam_sysprops.max_partid =
				(mpam_sysprops.max_partid < max_partid) ?
				mpam_sysprops.max_partid : max_partid;
	mpam_sysprops.max_pmg =
				(mpam_sysprops.max_pmg < max_pmg) ?
				mpam_sysprops.max_pmg : max_pmg;
}

static int mpam_device_probe(struct mpam_device *dev)
{
	u32 hwfeatures, part_sel;
	u16 max_intpartid = 0;
	u16 max_partid, max_pmg;

	if (mpam_read_reg(dev, MPAMF_AIDR) != MPAM_ARCHITECTURE_V1) {
		pr_err_once("device at 0x%llx does not match MPAM architecture v1.0\n",
			dev->hwpage_address);
		return -EIO;
	}

	hwfeatures = mpam_read_reg(dev, MPAMF_IDR);
	max_partid = hwfeatures & MPAMF_IDR_PARTID_MAX_MASK;
	max_pmg = (hwfeatures & MPAMF_IDR_PMG_MAX_MASK) >> MPAMF_IDR_PMG_MAX_SHIFT;

	dev->num_partid = max_partid + 1;
	dev->num_pmg = max_pmg + 1;

    /* Partid Narrowing*/
	if (MPAMF_IDR_HAS_PARTID_NRW(hwfeatures)) {
		u32 partid_nrw_features = mpam_read_reg(dev, MPAMF_PARTID_NRW_IDR);

		max_intpartid = partid_nrw_features & MPAMF_PARTID_NRW_IDR_MASK;
		dev->num_intpartid = max_intpartid + 1;
		mpam_set_feature(mpam_feat_part_nrw, &dev->features);
	}

	mpam_probe_update_sysprops(max_partid, max_pmg);

	/* Cache Capacity Partitioning */
	if (MPAMF_IDR_HAS_CCAP_PART(hwfeatures)) {
		u32 ccap_features = mpam_read_reg(dev, MPAMF_CCAP_IDR);

		pr_debug("probe: probed CCAP_PART\n");

		dev->cmax_wd = ccap_features & MPAMF_CCAP_IDR_CMAX_WD;
		if (dev->cmax_wd)
			mpam_set_feature(mpam_feat_ccap_part, &dev->features);
	}

	/* Cache Portion partitioning */
	if (MPAMF_IDR_HAS_CPOR_PART(hwfeatures)) {
		u32 cpor_features = mpam_read_reg(dev, MPAMF_CPOR_IDR);

		pr_debug("probe: probed CPOR_PART\n");

		dev->cpbm_wd = cpor_features & MPAMF_CPOR_IDR_CPBM_WD;
		if (dev->cpbm_wd)
			mpam_set_feature(mpam_feat_cpor_part, &dev->features);
	}

	/* Memory bandwidth partitioning */
	if (MPAMF_IDR_HAS_MBW_PART(hwfeatures)) {
		u32 mbw_features = mpam_read_reg(dev, MPAMF_MBW_IDR);

		pr_debug("probe: probed MBW_PART\n");

		/* portion bitmap resolution */
		dev->mbw_pbm_bits = (mbw_features & MPAMF_MBW_IDR_BWPBM_WD) >>
				MPAMF_MBW_IDR_BWPBM_WD_SHIFT;
		if (dev->mbw_pbm_bits && (mbw_features &
				MPAMF_MBW_IDR_HAS_PBM))
			mpam_set_feature(mpam_feat_mbw_part, &dev->features);

		dev->bwa_wd = (mbw_features & MPAMF_MBW_IDR_BWA_WD);
		if (dev->bwa_wd && (mbw_features & MPAMF_MBW_IDR_HAS_MAX)) {
			mpam_set_feature(mpam_feat_mbw_max, &dev->features);
			/* we want to export MBW hardlimit support */
			mpam_set_feature(mpam_feat_part_hdl, &dev->features);
		}

		if (dev->bwa_wd && (mbw_features & MPAMF_MBW_IDR_HAS_MIN))
			mpam_set_feature(mpam_feat_mbw_min, &dev->features);

		if (dev->bwa_wd && (mbw_features & MPAMF_MBW_IDR_HAS_PROP)) {
			mpam_set_feature(mpam_feat_mbw_prop, &dev->features);
			/* we want to export MBW hardlimit support */
			mpam_set_feature(mpam_feat_part_hdl, &dev->features);
		}
	}

	/* Priority partitioning */
	if (MPAMF_IDR_HAS_PRI_PART(hwfeatures)) {
		u32 pri_features, hwdef_pri;
		/*
		 * if narrow support, MPAMCFG_PART_SEL.INTERNAL must be 1 when
		 * reading/writing MPAMCFG register other than MPAMCFG_INTPARTID.
		 */
		if (mpam_has_feature(mpam_feat_part_nrw, dev->features)) {
			part_sel = MPAMCFG_PART_SEL_INTERNAL;
			mpam_write_reg(dev, MPAMCFG_PART_SEL, part_sel);
		}
		pri_features = mpam_read_reg(dev, MPAMF_PRI_IDR);
		hwdef_pri = mpam_read_reg(dev, MPAMCFG_PRI);

		pr_debug("probe: probed PRI_PART\n");

		dev->intpri_wd = (pri_features & MPAMF_PRI_IDR_INTPRI_WD) >>
				MPAMF_PRI_IDR_INTPRI_WD_SHIFT;
		if (dev->intpri_wd && (pri_features & MPAMF_PRI_IDR_HAS_INTPRI)) {
			mpam_set_feature(mpam_feat_intpri_part, &dev->features);
			dev->hwdef_intpri = MPAMCFG_INTPRI_GET(hwdef_pri);
			if (pri_features & MPAMF_PRI_IDR_INTPRI_0_IS_LOW)
				mpam_set_feature(mpam_feat_intpri_part_0_low,
					&dev->features);
			else
				/* keep higher value higher priority */
				dev->hwdef_intpri = GENMASK(dev->intpri_wd - 1, 0) &
					~dev->hwdef_intpri;

		}

		dev->dspri_wd = (pri_features & MPAMF_PRI_IDR_DSPRI_WD) >>
				MPAMF_PRI_IDR_DSPRI_WD_SHIFT;
		if (dev->dspri_wd && (pri_features & MPAMF_PRI_IDR_HAS_DSPRI)) {
			mpam_set_feature(mpam_feat_dspri_part, &dev->features);
			dev->hwdef_dspri = MPAMCFG_DSPRI_GET(hwdef_pri);
			if (pri_features & MPAMF_PRI_IDR_DSPRI_0_IS_LOW)
				mpam_set_feature(mpam_feat_dspri_part_0_low,
					&dev->features);
			else
				/* keep higher value higher priority */
				dev->hwdef_dspri = GENMASK(dev->dspri_wd - 1, 0) &
					~dev->hwdef_dspri;
		}
	}

	/* Performance Monitoring */
	if (MPAMF_IDR_HAS_MSMON(hwfeatures)) {
		u32 msmon_features = mpam_read_reg(dev, MPAMF_MSMON_IDR);

		pr_debug("probe: probed MSMON\n");

		if (msmon_features & MPAMF_MSMON_IDR_MSMON_CSU) {
			u32 csumonidr;

			csumonidr = mpam_read_reg(dev, MPAMF_CSUMON_IDR);
			dev->num_csu_mon = csumonidr & MPAMF_CSUMON_IDR_NUM_MON;
			if (dev->num_csu_mon)
				mpam_set_feature(mpam_feat_msmon_csu,
					&dev->features);
		}
		if (msmon_features & MPAMF_MSMON_IDR_MSMON_MBWU) {
			u32 mbwumonidr = mpam_read_reg(dev, MPAMF_MBWUMON_IDR);

			dev->num_mbwu_mon = mbwumonidr &
					MPAMF_MBWUMON_IDR_NUM_MON;
			if (dev->num_mbwu_mon)
				mpam_set_feature(mpam_feat_msmon_mbwu,
					&dev->features);
		}
	}
	dev->probed = true;

	return 0;
}

/*
 * If device doesn't match class feature/configuration, do the right thing.
 * For 'num' properties we can just take the minimum.
 * For properties where the mismatched unused bits would make a difference, we
 * nobble the class feature, as we can't configure all the devices.
 * e.g. The L3 cache is composed of two devices with 13 and 17 portion
 * bitmaps respectively.
 */
static void __device_class_feature_mismatch(struct mpam_device *dev,
					struct mpam_class *class)
{
	lockdep_assert_held(&mpam_devices_lock); /* we modify class */

	if (class->cpbm_wd != dev->cpbm_wd)
		mpam_clear_feature(mpam_feat_cpor_part, &class->features);
	if (class->mbw_pbm_bits != dev->mbw_pbm_bits)
		mpam_clear_feature(mpam_feat_mbw_part, &class->features);

	/* For num properties, take the minimum */
	if (class->num_partid != dev->num_partid)
		class->num_partid = min(class->num_partid, dev->num_partid);
	if (class->num_intpartid != dev->num_intpartid)
		class->num_intpartid = min(class->num_intpartid, dev->num_intpartid);
	if (class->num_pmg != dev->num_pmg)
		class->num_pmg = min(class->num_pmg, dev->num_pmg);
	if (class->num_csu_mon != dev->num_csu_mon)
		class->num_csu_mon = min(class->num_csu_mon, dev->num_csu_mon);
	if (class->num_mbwu_mon != dev->num_mbwu_mon)
		class->num_mbwu_mon = min(class->num_mbwu_mon,
			dev->num_mbwu_mon);

	/* bwa_wd is a count of bits, fewer bits means less precision */
	if (class->bwa_wd != dev->bwa_wd)
		class->bwa_wd = min(class->bwa_wd, dev->bwa_wd);

	if (class->intpri_wd != dev->intpri_wd)
		class->intpri_wd = min(class->intpri_wd, dev->intpri_wd);
	if (class->dspri_wd != dev->dspri_wd)
		class->dspri_wd = min(class->dspri_wd, dev->dspri_wd);

	/* {int,ds}pri may not have differing 0-low behaviour */
	if (mpam_has_feature(mpam_feat_intpri_part_0_low, class->features) !=
		mpam_has_feature(mpam_feat_intpri_part_0_low, dev->features))
		mpam_clear_feature(mpam_feat_intpri_part, &class->features);
	if (mpam_has_feature(mpam_feat_dspri_part_0_low, class->features) !=
		mpam_has_feature(mpam_feat_dspri_part_0_low, dev->features))
		mpam_clear_feature(mpam_feat_dspri_part, &class->features);
}

/*
 * Squash common class=>component=>device->features down to the
 * class->features
 */
static void mpam_enable_squash_features(void)
{
	unsigned long flags;
	struct mpam_device *dev;
	struct mpam_class *class;
	struct mpam_component *comp;

	lockdep_assert_held(&mpam_devices_lock);

	list_for_each_entry(class, &mpam_classes, classes_list) {
		/*
		 * Copy the first component's first device's properties and
		 * features to the class. __device_class_feature_mismatch()
		 * will fix them as appropriate.
		 * It is not possible to have a component with no devices.
		 */
		if (!list_empty(&class->components)) {
			comp = list_first_entry_or_null(&class->components,
					struct mpam_component, class_list);
			if (WARN_ON(!comp))
				break;

			dev = list_first_entry_or_null(&comp->devices,
						struct mpam_device, comp_list);
			if (WARN_ON(!dev))
				break;

			spin_lock_irqsave(&dev->lock, flags);
			class->features = dev->features;
			class->cpbm_wd = dev->cpbm_wd;
			class->mbw_pbm_bits = dev->mbw_pbm_bits;
			class->bwa_wd = dev->bwa_wd;
			class->intpri_wd = dev->intpri_wd;
			class->dspri_wd = dev->dspri_wd;
			class->num_partid = dev->num_partid;
			class->num_intpartid = dev->num_intpartid;
			class->num_pmg = dev->num_pmg;
			class->num_csu_mon = dev->num_csu_mon;
			class->num_mbwu_mon = dev->num_mbwu_mon;
			class->hwdef_intpri = dev->hwdef_intpri;
			class->hwdef_dspri = dev->hwdef_dspri;
			spin_unlock_irqrestore(&dev->lock, flags);
		}

		list_for_each_entry(comp, &class->components, class_list) {
			list_for_each_entry(dev, &comp->devices, comp_list) {
				spin_lock_irqsave(&dev->lock, flags);
				__device_class_feature_mismatch(dev, class);
				class->features &= dev->features;
				spin_unlock_irqrestore(&dev->lock, flags);
			}
		}
	}
}

static int mpam_allocate_config(void)
{
	struct mpam_class *class;
	struct mpam_component *comp;

	lockdep_assert_held(&mpam_devices_lock);

	list_for_each_entry(class, &mpam_classes, classes_list) {
		list_for_each_entry(comp, &class->components, class_list) {
			comp->cfg = kcalloc(mpam_sysprops_num_partid(), sizeof(*comp->cfg),
				GFP_KERNEL);
			if (!comp->cfg)
				return -ENOMEM;
		}
	}

	return 0;
}

static const char *mpam_msc_err_str[_MPAM_NUM_ERRCODE] = {
	[MPAM_ERRCODE_NONE] = "No Error",
	[MPAM_ERRCODE_PARTID_SEL_RANGE] = "Out of range PARTID selected",
	[MPAM_ERRCODE_REQ_PARTID_RANGE] = "Out of range PARTID requested",
	[MPAM_ERRCODE_REQ_PMG_RANGE] = "Out of range PMG requested",
	[MPAM_ERRCODE_MONITOR_RANGE] = "Out of range Monitor selected",
	[MPAM_ERRCODE_MSMONCFG_ID_RANGE] = "Out of range Monitor:PARTID or PMG written",

	/* These two are about PARTID narrowing, which we don't support */
	[MPAM_ERRCODE_INTPARTID_RANGE] = "Out or range Internal-PARTID written",
	[MPAM_ERRCODE_UNEXPECTED_INTERNAL] = "Internal-PARTID set but not expected",
};


static irqreturn_t mpam_handle_error_irq(int irq, void *data)
{
	u32 device_esr;
	u16 device_errcode;
	struct mpam_device *dev = data;

	spin_lock(&dev->lock);
	device_esr = mpam_read_reg(dev, MPAMF_ESR);
	spin_unlock(&dev->lock);

	device_errcode = (device_esr & MPAMF_ESR_ERRCODE) >> MPAMF_ESR_ERRCODE_SHIFT;
	if (device_errcode == MPAM_ERRCODE_NONE)
		return IRQ_NONE;

	/* No-one expects MPAM errors! */
	if (device_errcode <= _MPAM_NUM_ERRCODE)
		pr_err_ratelimited("unexpected error '%s' [esr:%x]\n",
					mpam_msc_err_str[device_errcode],
					device_esr);
	else
		pr_err_ratelimited("unexpected error %d [esr:%x]\n",
					device_errcode, device_esr);

	if (!cmpxchg(&mpam_broken, -EINTR, 0))
		schedule_work(&mpam_failed_work);

	/* A write of 0 to MPAMF_ESR.ERRCODE clears level interrupts */
	spin_lock(&dev->lock);
	mpam_write_reg(dev, MPAMF_ESR, 0);
	spin_unlock(&dev->lock);

	return IRQ_HANDLED;
}
/* register and enable all device error interrupts */
static void mpam_enable_irqs(void)
{
	struct mpam_device *dev;
	int rc, irq, request_flags;
	unsigned long irq_save_flags;

	list_for_each_entry(dev, &mpam_all_devices, glbl_list) {
		spin_lock_irqsave(&dev->lock, irq_save_flags);
		irq = dev->error_irq;
		request_flags = dev->error_irq_flags;
		spin_unlock_irqrestore(&dev->lock, irq_save_flags);

		if (request_flags & MPAM_IRQ_MODE_LEVEL) {
			struct cpumask tmp;
			bool inaccessible_cpus;

			request_flags = IRQF_TRIGGER_LOW | IRQF_SHARED;

			/*
			 * If the MSC is not accessible from any CPU the IRQ
			 * may be migrated to, we won't be able to clear it.
			 * ~dev->fw_affinity is all the CPUs that can't access
			 * the MSC. 'and' cpu_possible_mask tells us whether we
			 * care.
			 */
			spin_lock_irqsave(&dev->lock, irq_save_flags);
			inaccessible_cpus = cpumask_andnot(&tmp,
							cpu_possible_mask,
							&dev->fw_affinity);
			spin_unlock_irqrestore(&dev->lock, irq_save_flags);

			if (inaccessible_cpus) {
				pr_err_once("NOT registering MPAM error level-irq that isn't globally reachable");
				continue;
			}
		} else {
			request_flags = IRQF_TRIGGER_RISING | IRQF_SHARED;
		}

		rc = request_irq(irq, mpam_handle_error_irq, request_flags,
				"MPAM ERR IRQ", dev);
		if (rc) {
			pr_err_ratelimited("Failed to register irq %u\n", irq);
			continue;
		}

		/*
		 * temporary: the interrupt will only be enabled when cpus
		 * subsequently come online after mpam_enable().
		 */
		spin_lock_irqsave(&dev->lock, irq_save_flags);
		dev->enable_error_irq = true;
		spin_unlock_irqrestore(&dev->lock, irq_save_flags);
	}
}

static void mpam_disable_irqs(void)
{
	int irq;
	bool do_unregister;
	struct mpam_device *dev;
	unsigned long irq_save_flags;

	list_for_each_entry(dev, &mpam_all_devices, glbl_list) {
		spin_lock_irqsave(&dev->lock, irq_save_flags);
		irq = dev->error_irq;
		do_unregister = dev->enable_error_irq;
		dev->enable_error_irq = false;
		spin_unlock_irqrestore(&dev->lock, irq_save_flags);

		if (do_unregister)
			free_irq(irq, dev);
	}
}

/*
 * Enable mpam once all devices have been probed.
 * Scheduled by mpam_discovery_complete() once all devices have been created.
 * Also scheduled when new devices are probed when new CPUs come online.
 */
static void __init mpam_enable(struct work_struct *work)
{
	int err;
	unsigned long flags;
	struct mpam_device *dev;
	bool all_devices_probed = true;

	/* Have we probed all the devices? */
	mutex_lock(&mpam_devices_lock);
	list_for_each_entry(dev, &mpam_all_devices, glbl_list) {
		spin_lock_irqsave(&dev->lock, flags);
		if (!dev->probed)
			all_devices_probed = false;
		spin_unlock_irqrestore(&dev->lock, flags);

		if (!all_devices_probed)
			break;
	}
	mutex_unlock(&mpam_devices_lock);

	if (!all_devices_probed)
		return;

	mutex_lock(&mpam_devices_lock);
	mpam_enable_squash_features();
	err = mpam_allocate_config();
	if (err)
		return;
	mutex_unlock(&mpam_devices_lock);

	mpam_enable_irqs();

	/*
	 * mpam_enable() runs in parallel with cpuhp callbacks bringing other
	 * CPUs online, as we eagerly schedule the work. To give resctrl a
	 * clean start, we make all cpus look offline, set resctrl_registered,
	 * and then bring them back.
	 */
	mutex_lock(&mpam_cpuhp_lock);
	if (!mpam_cpuhp_state) {
		/* We raced with mpam_failed(). */
		mutex_unlock(&mpam_cpuhp_lock);
		return;
	}
	cpuhp_remove_state(mpam_cpuhp_state);

	mutex_lock(&mpam_devices_lock);
	err = mpam_resctrl_setup();
	if (!err) {
		err = mpam_resctrl_init();
		if (!err)
			resctrl_registered = true;
	}
	if (err)
		pr_err("Failed to setup/init resctrl\n");
	mutex_unlock(&mpam_devices_lock);

	mpam_cpuhp_state = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
						"mpam:online", mpam_cpu_online,
						mpam_cpu_offline);
	if (mpam_cpuhp_state <= 0)
		pr_err("Failed to re-register 'dyn' cpuhp callbacks");
	mutex_unlock(&mpam_cpuhp_lock);
}

static void mpam_failed(struct work_struct *work)
{
	/*
	 * Make it look like all CPUs are offline. This also resets the
	 * cpu default values and disables interrupts.
	 */
	mutex_lock(&mpam_cpuhp_lock);
	if (mpam_cpuhp_state) {
		cpuhp_remove_state(mpam_cpuhp_state);
		mpam_cpuhp_state = 0;

		mpam_disable_irqs();
	}
	mutex_unlock(&mpam_cpuhp_lock);
}

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
		kfree(comp->cfg);
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

void __init mpam_device_set_error_irq(struct mpam_device *dev, u32 irq,
					u32 flags)
{
	unsigned long irq_save_flags;

	spin_lock_irqsave(&dev->lock, irq_save_flags);
	dev->error_irq = irq;
	dev->error_irq_flags = flags & MPAM_IRQ_FLAGS_MASK;
	spin_unlock_irqrestore(&dev->lock, irq_save_flags);
}

void __init mpam_device_set_overflow_irq(struct mpam_device *dev, u32 irq,
					u32 flags)
{
	unsigned long irq_save_flags;

	spin_lock_irqsave(&dev->lock, irq_save_flags);
	dev->overflow_irq = irq;
	dev->overflow_irq_flags = flags & MPAM_IRQ_FLAGS_MASK;
	spin_unlock_irqrestore(&dev->lock, irq_save_flags);
}

static int mpam_cpus_have_feature(void)
{
	if (!cpus_have_const_cap(ARM64_HAS_MPAM))
		return 0;
	return 1;
}

/*
 * get max partid from reading SYS_MPAMIDR_EL1.
 */
static inline u16 mpam_cpu_max_partid(void)
{
	u64 reg;

	reg = mpam_read_sysreg_s(SYS_MPAMIDR_EL1, "SYS_MPAMIDR_EL1");
	return reg & PARTID_MAX_MASK;
}

/*
 * get max pmg from reading SYS_MPAMIDR_EL1.
 */
static inline u16 mpam_cpu_max_pmg(void)
{
	u64 reg;

	reg = mpam_read_sysreg_s(SYS_MPAMIDR_EL1, "SYS_MPAMIDR_EL1");
	return (reg & PMG_MAX_MASK) >> PMG_MAX_SHIFT;
}

/*
 * prepare for initializing devices.
 */
int __init mpam_discovery_start(void)
{
	if (!mpam_cpus_have_feature())
		return -EOPNOTSUPP;

	mpam_sysprops.max_partid = mpam_cpu_max_partid();
	mpam_sysprops.max_pmg = mpam_cpu_max_pmg();

	INIT_WORK(&mpam_enable_work, mpam_enable);
	INIT_WORK(&mpam_failed_work, mpam_failed);

	return 0;
}

static void mpam_reset_device_bitmap(struct mpam_device *dev, u16 reg, u16 wd)
{
	u32 bm = ~0;
	int i;

	lockdep_assert_held(&dev->lock);

	/* write all but the last full-32bit-word */
	for (i = 0; i < wd / 32; i++, reg += sizeof(bm))
		mpam_write_reg(dev, reg, bm);

	/* and the last partial 32bit word */
	bm = GENMASK(wd % 32, 0);
	if (bm)
		mpam_write_reg(dev, reg, bm);
}

static void mpam_reset_device_config(struct mpam_component *comp,
				struct mpam_device *dev, u32 partid)
{
	u16 intpri, dspri;
	u32 pri_val = 0;
	u32 mbw_max;

	lockdep_assert_held(&dev->lock);

	if (mpam_has_feature(mpam_feat_part_nrw, dev->features))
		partid = partid | MPAMCFG_PART_SEL_INTERNAL;
	mpam_write_reg(dev, MPAMCFG_PART_SEL, partid);
	wmb(); /* subsequent writes must be applied to our new partid */

	if (mpam_has_feature(mpam_feat_cpor_part, dev->features))
		mpam_reset_device_bitmap(dev, MPAMCFG_CPBM, dev->cpbm_wd);
	if (mpam_has_feature(mpam_feat_mbw_part, dev->features))
		mpam_reset_device_bitmap(dev, MPAMCFG_MBW_PBM,
				dev->mbw_pbm_bits);
	if (mpam_has_feature(mpam_feat_mbw_max, dev->features)) {
		mbw_max = MBW_MAX_SET(MBW_MAX_BWA_FRACT(dev->bwa_wd), dev->bwa_wd);
		mbw_max = MBW_MAX_SET_HDL(mbw_max);
		mpam_write_reg(dev, MPAMCFG_MBW_MAX, mbw_max);
	}
	if (mpam_has_feature(mpam_feat_mbw_min, dev->features)) {
		mpam_write_reg(dev, MPAMCFG_MBW_MIN, 0);
	}

	if (mpam_has_feature(mpam_feat_intpri_part, dev->features) ||
		mpam_has_feature(mpam_feat_dspri_part, dev->features)) {
		intpri = dev->hwdef_intpri;
		dspri = dev->hwdef_dspri;

		if (mpam_has_feature(mpam_feat_intpri_part, dev->features)) {
			if (!mpam_has_feature(mpam_feat_intpri_part_0_low, dev->features))
				intpri = GENMASK(dev->intpri_wd - 1, 0) & ~intpri;
			pri_val |= intpri;
		}

		if (mpam_has_feature(mpam_feat_dspri_part, dev->features)) {
			if (!mpam_has_feature(mpam_feat_dspri_part_0_low, dev->features))
				dspri = GENMASK(dev->dspri_wd - 1, 0) & ~dspri;
			pri_val |= (dspri << MPAMCFG_PRI_DSPRI_SHIFT);
		}

		mpam_write_reg(dev, MPAMCFG_PRI, pri_val);
	}
	mb(); /* complete the configuration before the cpu can use this partid */
}

/*
 * Called from cpuhp callbacks and with the cpus_read_lock() held from
 * mpam_reset_devices().
 */
static void mpam_reset_device(struct mpam_component *comp,
				struct mpam_device *dev)
{
	u32 partid;

	lockdep_assert_held(&dev->lock);

	if (dev->enable_error_irq)
		mpam_write_reg(dev, MPAMF_ECR, MPAMF_ECR_INTEN);

	if (!mpam_has_feature(mpam_feat_part_nrw, dev->features)) {
		for (partid = 0; partid < dev->num_partid; partid++)
			mpam_reset_device_config(comp, dev, partid);
	} else {
		for (partid = 0; partid < dev->num_intpartid; partid++)
			mpam_reset_device_config(comp, dev, partid);
	}
}

static int __online_devices(struct mpam_component *comp, int cpu)
{
	int err = 0;
	unsigned long flags;
	struct mpam_device *dev;
	bool new_device_probed = false;

	list_for_each_entry(dev, &comp->devices, comp_list) {
		if (!cpumask_test_cpu(cpu, &dev->fw_affinity))
			continue;

		spin_lock_irqsave(&dev->lock, flags);
		if (!dev->probed) {
			err = mpam_device_probe(dev);
			if (!err)
				new_device_probed = true;
		}

		if (!err && cpumask_empty(&dev->online_affinity))
			mpam_reset_device(comp, dev);

		cpumask_set_cpu(cpu, &dev->online_affinity);
		spin_unlock_irqrestore(&dev->lock, flags);

		if (err)
			return err;
	}

	if (new_device_probed)
		return 1;

	return 0;
}

/*
 * Firmware didn't give us an affinity, but a cache-id, if this cpu has that
 * cache-id, update the fw_affinity for this component.
 */
static void
mpam_sync_cpu_cache_component_fw_affinity(struct mpam_class *class, int cpu)
{
	int cpu_cache_id;
	struct mpam_component *comp;

	lockdep_assert_held(&mpam_devices_lock); /* we modify mpam_sysprops */

	if (class->type != MPAM_CLASS_CACHE)
		return;

	cpu_cache_id = cpu_to_node(cpu);
	comp = mpam_component_get(class, cpu_cache_id, false);

	/* This cpu does not have a component of this class */
	if (IS_ERR(comp))
		return;

	cpumask_set_cpu(cpu, &comp->fw_affinity);
	cpumask_set_cpu(cpu, &class->fw_affinity);
}

static int mpam_cpu_online(unsigned int cpu)
{
	int err = 0;
	struct mpam_class *class;
	struct mpam_component *comp;
	bool new_device_probed = false;

	mutex_lock(&mpam_devices_lock);

	list_for_each_entry(class, &mpam_classes, classes_list) {
		mpam_sync_cpu_cache_component_fw_affinity(class, cpu);

		list_for_each_entry(comp, &class->components, class_list) {
			if (!cpumask_test_cpu(cpu, &comp->fw_affinity))
				continue;

			err = __online_devices(comp, cpu);
			if (err > 0)
				new_device_probed = true;
			if (err < 0)
				break; // mpam_broken
		}
	}

	if (new_device_probed && err >= 0)
		schedule_work(&mpam_enable_work);

	mutex_unlock(&mpam_devices_lock);
	if (err < 0) {
		if (!cmpxchg(&mpam_broken, err, 0))
			schedule_work(&mpam_failed_work);
		return err;
	}

	if (resctrl_registered)
		mpam_resctrl_cpu_online(cpu);

	return 0;
}

static int mpam_cpu_offline(unsigned int cpu)
{
	unsigned long flags;
	struct mpam_device *dev;

	mutex_lock(&mpam_devices_lock);
	list_for_each_entry(dev, &mpam_all_devices, glbl_list) {
		if (!cpumask_test_cpu(cpu, &dev->online_affinity))
			continue;
		cpumask_clear_cpu(cpu, &dev->online_affinity);

		if (cpumask_empty(&dev->online_affinity)) {
			spin_lock_irqsave(&dev->lock, flags);
			mpam_write_reg(dev, MPAMF_ECR, 0);
			spin_unlock_irqrestore(&dev->lock, flags);
		}
	}

	mutex_unlock(&mpam_devices_lock);

	if (resctrl_registered)
		mpam_resctrl_cpu_offline(cpu);

	return 0;
}

int __init mpam_discovery_complete(void)
{
	int ret = 0;

	mutex_lock(&mpam_cpuhp_lock);
	mpam_cpuhp_state = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
						"mpam:online", mpam_cpu_online,
						 mpam_cpu_offline);
	if (mpam_cpuhp_state <= 0) {
		pr_err("Failed to register 'dyn' cpuhp callbacks");
		ret = -EINVAL;
	}
	mutex_unlock(&mpam_cpuhp_lock);

	return ret;
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

u16 mpam_sysprops_num_partid(void)
{
	/* At least one partid for system width */
	return mpam_sysprops.max_partid + 1;
}

u16 mpam_sysprops_num_pmg(void)
{
	/* At least one pmg for system width */
	return mpam_sysprops.max_pmg + 1;
}

static u32 mpam_device_read_csu_mon(struct mpam_device *dev,
			struct sync_args *args)
{
	u16 mon;
	u32 clt, flt, cur_clt, cur_flt;

	mon = args->mon;

	mpam_write_reg(dev, MSMON_CFG_MON_SEL, mon);
	wmb(); /* subsequent writes must be applied to this mon */

	/*
	 * We don't bother with capture as we don't expose a way of measuring
	 * multiple partid:pmg with a single capture.
	 */
	clt = MSMON_CFG_CTL_MATCH_PARTID | MSMON_CFG_CSU_TYPE;
	if (args->match_pmg)
		clt |= MSMON_CFG_CTL_MATCH_PMG;
	flt = args->closid.reqpartid |
		(args->pmg << MSMON_CFG_CSU_FLT_PMG_SHIFT);

	/*
	 * We read the existing configuration to avoid re-writing the same
	 * values.
	 */
	cur_flt = mpam_read_reg(dev, MSMON_CFG_CSU_FLT);
	cur_clt = mpam_read_reg(dev, MSMON_CFG_CSU_CTL);

	if (cur_flt != flt || cur_clt != (clt | MSMON_CFG_CTL_EN)) {
		mpam_write_reg(dev, MSMON_CFG_CSU_FLT, flt);

		/*
		 * Write the ctl with the enable bit cleared, reset the
		 * counter, then enable counter.
		 */
		mpam_write_reg(dev, MSMON_CFG_CSU_CTL, clt);
		wmb();

		mpam_write_reg(dev, MSMON_CSU, 0);
		wmb();

		clt |= MSMON_CFG_CTL_EN;
		mpam_write_reg(dev, MSMON_CFG_CSU_CTL, clt);
		wmb();
	}

	return mpam_read_reg(dev, MSMON_CSU);
}

static u32 mpam_device_read_mbwu_mon(struct mpam_device *dev,
			struct sync_args *args)
{
	u16 mon;
	u32 clt, flt, cur_clt, cur_flt;

	mon = args->mon;

	mpam_write_reg(dev, MSMON_CFG_MON_SEL, mon);
	wmb(); /* subsequent writes must be applied to this mon */

	/*
	 * We don't bother with capture as we don't expose a way of measuring
	 * multiple partid:pmg with a single capture.
	 */
	clt = MSMON_CFG_CTL_MATCH_PARTID | MSMON_CFG_MBWU_TYPE;
	if (args->match_pmg)
		clt |= MSMON_CFG_CTL_MATCH_PMG;
	flt = args->closid.reqpartid |
		(args->pmg << MSMON_CFG_MBWU_FLT_PMG_SHIFT);

	/*
	 * We read the existing configuration to avoid re-writing the same
	 * values.
	 */
	cur_flt = mpam_read_reg(dev, MSMON_CFG_MBWU_FLT);
	cur_clt = mpam_read_reg(dev, MSMON_CFG_MBWU_CTL);

	if (cur_flt != flt || cur_clt != (clt | MSMON_CFG_CTL_EN)) {
		mpam_write_reg(dev, MSMON_CFG_MBWU_FLT, flt);

		/*
		 * Write the ctl with the enable bit cleared, reset the
		 * counter, then enable counter.
		 */
		mpam_write_reg(dev, MSMON_CFG_MBWU_CTL, clt);
		wmb();

		mpam_write_reg(dev, MSMON_MBWU, 0);
		wmb();

		clt |= MSMON_CFG_CTL_EN;
		mpam_write_reg(dev, MSMON_CFG_MBWU_CTL, clt);
		wmb();
	}

	return mpam_read_reg(dev, MSMON_MBWU);
}

static int mpam_device_frob_mon(struct mpam_device *dev,
				struct mpam_device_sync *ctx)
{
	struct sync_args *args = ctx->args;
	u32 val;

	lockdep_assert_held(&dev->lock);

	if (mpam_broken)
		return -EIO;

	if (!args)
		return -EINVAL;

	if (args->eventid == QOS_L3_OCCUP_EVENT_ID &&
		mpam_has_feature(mpam_feat_msmon_csu, dev->features))
		val = mpam_device_read_csu_mon(dev, args);
	else if (args->eventid == QOS_L3_MBM_LOCAL_EVENT_ID &&
		mpam_has_feature(mpam_feat_msmon_mbwu, dev->features))
		val = mpam_device_read_mbwu_mon(dev, args);
	else
		return -EOPNOTSUPP;

	if (val & MSMON___NRDY)
		return -EBUSY;

	val = val & MSMON___VALUE;
	atomic64_add(val, &ctx->mon_value);
	return 0;
}

static void mpam_device_narrow_map(struct mpam_device *dev, u32 partid,
					u32 intpartid)
{
	int cur_intpartid;

	lockdep_assert_held(&dev->lock);

	mpam_write_reg(dev, MPAMCFG_PART_SEL, partid);
	wmb(); /* subsequent writes must be applied to our new partid */

	cur_intpartid = mpam_read_reg(dev, MPAMCFG_INTPARTID);
	/* write association, this need set 16 bit to 1 */
	intpartid = intpartid | MPAMCFG_INTPARTID_INTERNAL;
	/* reqpartid has already been associated to this intpartid */
	if (cur_intpartid == intpartid)
		return;

	mpam_write_reg(dev, MPAMCFG_INTPARTID, intpartid);
}

/*
 * partid should be narrowed to intpartid if this feature implemented,
 * before writing to register MPAMCFG_PART_SEL should we check this.
 */
static int try_to_narrow_device_intpartid(struct mpam_device *dev,
			u32 *partid, u32 intpartid)
{
	if (!mpam_has_part_sel(dev->features))
		return -EINVAL;

	if (mpam_has_feature(mpam_feat_part_nrw, dev->features)) {
		mpam_device_narrow_map(dev, *partid, intpartid);
		/* narrowing intpartid success, then set 16 bit to 1*/
		*partid = intpartid | MPAMCFG_PART_SEL_INTERNAL;
	}

	return 0;
}

static int
mpam_device_config(struct mpam_device *dev, struct sd_closid *closid,
					struct mpam_config *cfg)
{
	u16 cmax = GENMASK(dev->cmax_wd, 0);
	u32 pri_val = 0;
	u16 intpri, dspri, max_intpri, max_dspri;
	u32 mbw_pbm, mbw_max;
	/*
	 * if dev supports narrowing, narrowing first and then apply this slave's
	 * configuration.
	 */
	u32 intpartid = closid->intpartid;
	u32 partid = closid->reqpartid;

	lockdep_assert_held(&dev->lock);

	if (try_to_narrow_device_intpartid(dev, &partid, intpartid))
		return -EINVAL;

	mpam_write_reg(dev, MPAMCFG_PART_SEL, partid);
	wmb(); /* subsequent writes must be applied to our new partid */

	if (mpam_has_feature(mpam_feat_ccap_part, dev->features))
		mpam_write_reg(dev, MPAMCFG_CMAX, cmax);

	if (mpam_has_feature(mpam_feat_cpor_part, dev->features)) {
		if (cfg && mpam_has_feature(mpam_feat_cpor_part, cfg->valid)) {
			/*
			 * cpor_part being valid implies the bitmap fits in a
			 * single write.
			 */
			mpam_write_reg(dev, MPAMCFG_CPBM, cfg->cpbm);
		}
	}

	if (mpam_has_feature(mpam_feat_mbw_part, dev->features)) {
		mbw_pbm = cfg->mbw_pbm;
		if (cfg && mpam_has_feature(mpam_feat_mbw_part, cfg->valid)) {
			if (!mpam_has_feature(mpam_feat_part_hdl, cfg->valid) ||
				(mpam_has_feature(mpam_feat_part_hdl, cfg->valid) && cfg->hdl))
				mbw_pbm = MBW_PROP_SET_HDL(cfg->mbw_pbm);
			mpam_write_reg(dev, MPAMCFG_MBW_PBM, mbw_pbm);
		}
	}

	if (mpam_has_feature(mpam_feat_mbw_max, dev->features)) {
		if (cfg && mpam_has_feature(mpam_feat_mbw_max, cfg->valid)) {
			mbw_max = MBW_MAX_SET(cfg->mbw_max, dev->bwa_wd);
			if (!mpam_has_feature(mpam_feat_part_hdl, cfg->valid) ||
				(mpam_has_feature(mpam_feat_part_hdl, cfg->valid) && cfg->hdl))
				mbw_max = MBW_MAX_SET_HDL(mbw_max);
			mpam_write_reg(dev, MPAMCFG_MBW_MAX, mbw_max);
		}
	}

	if (mpam_has_feature(mpam_feat_intpri_part, dev->features) ||
		mpam_has_feature(mpam_feat_dspri_part, dev->features)) {
		if (mpam_has_feature(mpam_feat_intpri_part, cfg->valid) &&
			mpam_has_feature(mpam_feat_intpri_part, dev->features)) {
			max_intpri = GENMASK(dev->intpri_wd - 1, 0);
			/*
			 * Each priority portion only occupys a bit, not only that
			 * we leave lowest priority, which may be not suitable when
			 * owning large dspri_wd or intpri_wd.
			 * dspri and intpri are from same input, so if one
			 * exceeds it's max width, set it to max priority.
			 */
			intpri = (cfg->intpri > max_intpri) ? max_intpri : cfg->intpri;
			if (!mpam_has_feature(mpam_feat_intpri_part_0_low,
						dev->features))
				intpri = GENMASK(dev->intpri_wd - 1, 0) & ~intpri;
			pri_val |= intpri;
		}
		if (mpam_has_feature(mpam_feat_dspri_part, cfg->valid) &&
			mpam_has_feature(mpam_feat_dspri_part, dev->features)) {
			max_dspri = GENMASK(dev->dspri_wd - 1, 0);
			dspri = (cfg->dspri > max_dspri) ? max_dspri : cfg->dspri;
			if (!mpam_has_feature(mpam_feat_dspri_part_0_low,
						dev->features))
				dspri = GENMASK(dev->dspri_wd - 1, 0) & ~dspri;
			pri_val |= (dspri << MPAMCFG_PRI_DSPRI_SHIFT);
		}

		mpam_write_reg(dev, MPAMCFG_PRI, pri_val);
	}

	/*
	 * complete the configuration before the cpu can
	 * use this partid
	 */
	mb();

	return 0;
}

static void mpam_component_device_sync(void *__ctx)
{
	int err = 0;
	u32 reqpartid;
	unsigned long flags;
	struct mpam_device *dev;
	struct mpam_device_sync *ctx = (struct mpam_device_sync *)__ctx;
	struct mpam_component *comp = ctx->comp;
	struct sync_args *args = ctx->args;

	list_for_each_entry(dev, &comp->devices, comp_list) {
		if (cpumask_intersects(&dev->online_affinity,
					&ctx->updated_on))
			continue;

		/* This device needs updating, can I reach it? */
		if (!cpumask_test_cpu(smp_processor_id(),
			&dev->online_affinity))
			continue;

		/* Apply new configuration to this device */
		err = 0;
		spin_lock_irqsave(&dev->lock, flags);
		if (args) {
			/*
			 * at this time reqpartid shows where the
			 * configuration was stored.
			 */
			reqpartid = args->closid.reqpartid;
			if (ctx->config_mon)
				err = mpam_device_frob_mon(dev, ctx);
			else
				err = mpam_device_config(dev, &args->closid,
					&comp->cfg[reqpartid]);
		} else {
			mpam_reset_device(comp, dev);
		}
		spin_unlock_irqrestore(&dev->lock, flags);
		if (err)
			cmpxchg(&ctx->error, 0, err);
	}

	cpumask_set_cpu(smp_processor_id(), &ctx->updated_on);
}

/**
 * in some cases/platforms the MSC register access is only possible with
 * the associated CPUs. And need to check if those CPUS are online before
 * accessing it. So we use those CPUs dev->online_affinity to apply config.
 */
static int do_device_sync(struct mpam_component *comp,
				struct mpam_device_sync *sync_ctx)
{
	int cpu;
	struct mpam_device *dev;

	lockdep_assert_cpus_held();

	cpu = get_cpu();
	if (cpumask_test_cpu(cpu, &comp->fw_affinity))
		mpam_component_device_sync(sync_ctx);
	put_cpu();

	/*
	 * Find the set of other CPUs we need to run on to update
	 * this component
	 */
	list_for_each_entry(dev, &comp->devices, comp_list) {
		if (sync_ctx->error)
			break;

		if (cpumask_intersects(&dev->online_affinity,
					&sync_ctx->updated_on))
			continue;

		/*
		 * This device needs the config applying, and hasn't been
		 * reachable by any cpu so far.
		 */
		cpu = cpumask_any(&dev->online_affinity);
		smp_call_function_single(cpu, mpam_component_device_sync,
					sync_ctx, 1);
	}

	return sync_ctx->error;
}

static inline void
mpam_device_sync_config_prepare(struct mpam_component *comp,
		struct mpam_device_sync *sync_ctx, struct sync_args *args)
{
	sync_ctx->comp = comp;
	sync_ctx->args = args;
	sync_ctx->config_mon = false;
	sync_ctx->error = 0;
	cpumask_clear(&sync_ctx->updated_on);
}

int mpam_component_config(struct mpam_component *comp, struct sync_args *args)
{
	struct mpam_device_sync sync_ctx;

	mpam_device_sync_config_prepare(comp, &sync_ctx, args);

	return do_device_sync(comp, &sync_ctx);
}

/*
 * Reset every component, configuring every partid unrestricted.
 */
void mpam_reset_devices(void)
{
	struct mpam_class *class;
	struct mpam_component *comp;

	mutex_lock(&mpam_devices_lock);
	list_for_each_entry(class, &mpam_classes, classes_list) {
		list_for_each_entry(comp, &class->components, class_list)
			mpam_component_config(comp, NULL);
	}
	mutex_unlock(&mpam_devices_lock);
}

static inline void
mpam_device_sync_mon_prepare(struct mpam_component *comp,
		struct mpam_device_sync *sync_ctx, struct sync_args *args)
{
	sync_ctx->comp = comp;
	sync_ctx->args = args;
	sync_ctx->error = 0;
	sync_ctx->config_mon = true;
	cpumask_clear(&sync_ctx->updated_on);
	atomic64_set(&sync_ctx->mon_value, 0);
}

int mpam_component_mon(struct mpam_component *comp,
				struct sync_args *args, u64 *result)
{
	int ret;
	struct mpam_device_sync sync_ctx;

	mpam_device_sync_mon_prepare(comp, &sync_ctx, args);

	ret = do_device_sync(comp, &sync_ctx);
	if (!ret && result)
		*result = atomic64_read(&sync_ctx.mon_value);

	return ret;
}

static void mpam_component_read_mpamcfg(void *_ctx)
{
	unsigned long flags;
	struct mpam_device *dev;
	struct mpam_device_sync *ctx = (struct mpam_device_sync *)_ctx;
	struct mpam_component *comp = ctx->comp;
	struct sync_args *args = ctx->args;
	u64 val = 0;
	u32 partid, intpartid;
	u32 dspri = 0;
	u32 intpri = 0;
	u64 range;

	if (!args)
		return;


	partid = args->closid.reqpartid;
	intpartid = args->closid.intpartid;

	list_for_each_entry(dev, &comp->devices, comp_list) {
		if (!cpumask_test_cpu(smp_processor_id(),
			&dev->online_affinity))
			continue;

		spin_lock_irqsave(&dev->lock, flags);
		if (try_to_narrow_device_intpartid(dev, &partid, intpartid)) {
			spin_unlock_irqrestore(&dev->lock, flags);
			return;
		}

		mpam_write_reg(dev, MPAMCFG_PART_SEL, partid);
		wmb();

		switch (args->eventid) {
		case QOS_CAT_CPBM_EVENT_ID:
			if (!mpam_has_feature(mpam_feat_cpor_part, dev->features))
				break;
			val = mpam_read_reg(dev, MPAMCFG_CPBM);
			break;
		case QOS_MBA_MAX_EVENT_ID:
			if (!mpam_has_feature(mpam_feat_mbw_max, dev->features))
				break;
			val = mpam_read_reg(dev, MPAMCFG_MBW_MAX);
			range = MBW_MAX_BWA_FRACT(dev->bwa_wd);
			val = MBW_MAX_GET(val, dev->bwa_wd) * (MAX_MBA_BW - 1) / range;
			break;
		case QOS_MBA_HDL_EVENT_ID:
			if (!mpam_has_feature(mpam_feat_mbw_max, dev->features))
				break;
			val = mpam_read_reg(dev, MPAMCFG_MBW_MAX);
			val = MBW_MAX_GET_HDL(val);
			break;
		case QOS_CAT_PRI_EVENT_ID:
		case QOS_MBA_PRI_EVENT_ID:
			if (mpam_has_feature(mpam_feat_intpri_part, dev->features))
				intpri = MPAMCFG_INTPRI_GET(val);
			if (mpam_has_feature(mpam_feat_dspri_part, dev->features))
				dspri = MPAMCFG_DSPRI_GET(val);
			if (!mpam_has_feature(mpam_feat_intpri_part_0_low,
				dev->features))
				intpri = GENMASK(dev->intpri_wd - 1, 0) & ~intpri;
			if (!mpam_has_feature(mpam_feat_dspri_part_0_low,
				dev->features))
				dspri = GENMASK(dev->intpri_wd - 1, 0) & ~dspri;
			val = (dspri > intpri) ? dspri : intpri;
			break;
		default:
			break;
		}

		atomic64_add(val, &ctx->cfg_value);
		spin_unlock_irqrestore(&dev->lock, flags);

		break;
	}
}

/*
 * reading first device of the this component is enough
 * for getting configuration.
 */
static void
mpam_component_get_config_local(struct mpam_component *comp,
				struct sync_args *args, u32 *result)
{
	int cpu;
	struct mpam_device *dev;
	struct mpam_device_sync sync_ctx;

	sync_ctx.args = args;
	sync_ctx.comp = comp;
	atomic64_set(&sync_ctx.cfg_value, 0);

	dev = list_first_entry_or_null(&comp->devices,
				struct mpam_device, comp_list);
	if (WARN_ON(!dev))
		return;

	cpu = cpumask_any(&dev->online_affinity);
	smp_call_function_single(cpu, mpam_component_read_mpamcfg, &sync_ctx, 1);

	if (result)
		*result = atomic64_read(&sync_ctx.cfg_value);
}

void mpam_component_get_config(struct mpam_component *comp,
			struct sync_args *args, u32 *result)
{
	mpam_component_get_config_local(comp, args, result);
}
