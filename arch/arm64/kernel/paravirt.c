// SPDX-License-Identifier: GPL-2.0-only
/*
 *
 * Copyright (C) 2013 Citrix Systems
 *
 * Author: Stefano Stabellini <stefano.stabellini@eu.citrix.com>
 */

#define pr_fmt(fmt) "arm-pv: " fmt

#include <linux/arm-smccc.h>
#include <linux/cpuhotplug.h>
#include <linux/export.h>
#include <linux/io.h>
#include <linux/jump_label.h>
#include <linux/printk.h>
#include <linux/psci.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <asm/paravirt.h>
#include <asm/pvclock-abi.h>
#include <asm/smp_plat.h>
#include <asm/pvpoll-abi.h>

static bool has_pv_poll_control;
static DEFINE_PER_CPU(struct pv_vcpu_poll_ctl, pv_poll_ctl);
struct static_key paravirt_steal_enabled;
struct static_key paravirt_steal_rq_enabled;

struct paravirt_patch_template pv_ops;
EXPORT_SYMBOL_GPL(pv_ops);

struct pv_time_stolen_time_region {
	struct pvclock_vcpu_stolen_time *kaddr;
};

static DEFINE_PER_CPU(struct pv_time_stolen_time_region, stolen_time_region);

static bool steal_acc = true;
static int __init parse_no_stealacc(char *arg)
{
	steal_acc = false;
	return 0;
}

early_param("no-steal-acc", parse_no_stealacc);

/* return stolen time in ns by asking the hypervisor */
static u64 pv_steal_clock(int cpu)
{
	struct pv_time_stolen_time_region *reg;

	reg = per_cpu_ptr(&stolen_time_region, cpu);

	/*
	 * paravirt_steal_clock() may be called before the CPU
	 * online notification callback runs. Until the callback
	 * has run we just return zero.
	 */
	if (!reg->kaddr)
		return 0;

	return le64_to_cpu(READ_ONCE(reg->kaddr->stolen_time));
}

static int stolen_time_cpu_down_prepare(unsigned int cpu)
{
	struct pv_time_stolen_time_region *reg;

	reg = this_cpu_ptr(&stolen_time_region);
	if (!reg->kaddr)
		return 0;

	memunmap(reg->kaddr);
	memset(reg, 0, sizeof(*reg));

	return 0;
}

static int stolen_time_cpu_online(unsigned int cpu)
{
	struct pv_time_stolen_time_region *reg;
	struct arm_smccc_res res;

	reg = this_cpu_ptr(&stolen_time_region);

	arm_smccc_1_1_invoke(ARM_SMCCC_HV_PV_TIME_ST, &res);

	if (res.a0 == SMCCC_RET_NOT_SUPPORTED)
		return -EINVAL;

	reg->kaddr = memremap(res.a0,
			      sizeof(struct pvclock_vcpu_stolen_time),
			      MEMREMAP_WB);

	if (!reg->kaddr) {
		pr_warn("Failed to map stolen time data structure\n");
		return -ENOMEM;
	}

	if (le32_to_cpu(reg->kaddr->revision) != 0 ||
	    le32_to_cpu(reg->kaddr->attributes) != 0) {
		pr_warn_once("Unexpected revision or attributes in stolen time data\n");
		return -ENXIO;
	}

	return 0;
}

static int __init pv_time_init_stolen_time(void)
{
	int ret;

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
				"hypervisor/arm/pvtime:online",
				stolen_time_cpu_online,
				stolen_time_cpu_down_prepare);
	if (ret < 0)
		return ret;
	return 0;
}

static bool __init has_pv_steal_clock(void)
{
	struct arm_smccc_res res;

	/* To detect the presence of PV time support we require SMCCC 1.1+ */
	if (arm_smccc_1_1_get_conduit() == SMCCC_CONDUIT_NONE)
		return false;

	arm_smccc_1_1_invoke(ARM_SMCCC_ARCH_FEATURES_FUNC_ID,
			     ARM_SMCCC_HV_PV_TIME_FEATURES, &res);

	if (res.a0 != SMCCC_RET_SUCCESS)
		return false;

	arm_smccc_1_1_invoke(ARM_SMCCC_HV_PV_TIME_FEATURES,
			     ARM_SMCCC_HV_PV_TIME_ST, &res);

	return (res.a0 == SMCCC_RET_SUCCESS);
}

int __init pv_time_init(void)
{
	int ret;

	if (!has_pv_steal_clock())
		return 0;

	ret = pv_time_init_stolen_time();
	if (ret)
		return ret;

	pv_ops.time.steal_clock = pv_steal_clock;

	static_key_slow_inc(&paravirt_steal_enabled);
	if (steal_acc)
		static_key_slow_inc(&paravirt_steal_rq_enabled);

	pr_info("using stolen time PV\n");

	return 0;
}

static void kvm_disable_host_haltpoll(void *i)
{
	struct arm_smccc_res res;
	struct pv_vcpu_poll_ctl *poll_ctl;

	poll_ctl = this_cpu_ptr(&pv_poll_ctl);
	poll_ctl->poll_ctl = cpu_to_le64(0);

	arm_smccc_1_1_invoke(ARM_SMCCC_HV_PV_POLLCONTROL_UPDATE,
			     false, &res);
	if (res.a0 == SMCCC_RET_NOT_SUPPORTED)
		pr_err("Failed to disable poll control\n");
}

static void kvm_enable_host_haltpoll(void *i)
{
	struct arm_smccc_res res;
	struct pv_vcpu_poll_ctl *poll_ctl;

	poll_ctl = this_cpu_ptr(&pv_poll_ctl);
	poll_ctl->poll_ctl = cpu_to_le64(1);

	arm_smccc_1_1_invoke(ARM_SMCCC_HV_PV_POLLCONTROL_UPDATE,
			     true, &res);
	if (res.a0 == SMCCC_RET_NOT_SUPPORTED)
		pr_err("Failed to enable poll control\n");
}

void arch_haltpoll_enable(unsigned int cpu)
{
	if (!has_pv_poll_control) {
		pr_warn("Do not support PV poll control\n");
		return;
	}

	/* Enable guest halt poll disables host halt poll */
	smp_call_function_single(cpu, kvm_disable_host_haltpoll, NULL, 1);
}
EXPORT_SYMBOL_GPL(arch_haltpoll_enable);

void arch_haltpoll_disable(unsigned int cpu)
{
	if (!has_pv_poll_control) {
		pr_warn("Do not support PV poll control\n");
		return;
	}

	/* Disable guest halt poll enables host halt poll */
	smp_call_function_single(cpu, kvm_enable_host_haltpoll, NULL, 1);
}
EXPORT_SYMBOL_GPL(arch_haltpoll_disable);

static int poll_ctrl_cpu_online(unsigned int cpu)
{
	struct pv_vcpu_poll_ctl *poll_ctl;
	struct arm_smccc_res res;

	poll_ctl = this_cpu_ptr(&pv_poll_ctl);

	arm_smccc_1_1_invoke(ARM_SMCCC_HV_PV_POLLCONTROL_SET, poll_ctl, &res);
	if (res.a0 == SMCCC_RET_NOT_SUPPORTED) {
		pr_err("Failed to set poll control base\n");
		return -EINVAL;
	}

	poll_ctl->poll_ctl = res.a0;
	return 0;
}

static int poll_ctrl_cpu_down_prepare(unsigned int cpu)
{
	struct pv_vcpu_poll_ctl *poll_ctl;
	struct arm_smccc_res res;

	poll_ctl = this_cpu_ptr(&pv_poll_ctl);

	poll_ctl->poll_ctl = cpu_to_le64(0);
	arm_smccc_1_1_invoke(ARM_SMCCC_HV_PV_POLLCONTROL_SET, -1, &res);
	if (res.a0 == SMCCC_RET_NOT_SUPPORTED)
		pr_warn("Failed to clear poll control base\n");

	return 0;
}

static int __init pv_poll_control_init_base(void)
{
	int ret;

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
				"hypervisor/arm/pollctl:online",
				poll_ctrl_cpu_online,
				poll_ctrl_cpu_down_prepare);
	if (ret < 0)
		return ret;
	return 0;
}

static int __init pv_poll_control_init(void)
{
	struct arm_smccc_res res;
	int ret;

	/* To detect the presence of PV poll control support we require SMCCC 1.1+ */
	if (arm_smccc_1_1_get_conduit() == SMCCC_CONDUIT_NONE) {
		pr_warn("Failed to support SMCCC 1.1+\n");
		return -EINVAL;
	}

	arm_smccc_1_1_invoke(ARM_SMCCC_ARCH_FEATURES_FUNC_ID,
			     ARM_SMCCC_HV_PV_POLLCONTROL_FEATURES, &res);
	if (res.a0 != SMCCC_RET_SUCCESS) {
		pr_warn("Host did not support poll control\n");
		return -EINVAL;
	}

	ret = pv_poll_control_init_base();
	if (ret) {
		pr_warn("Failed to initialize the poll control base\n");
		return ret;
	}

	has_pv_poll_control = true;
	pr_info("Enable PV poll control.\n");

	return 0;
}
arch_initcall(pv_poll_control_init);
