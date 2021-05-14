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
#include <asm/pvlock-abi.h>
#include <asm/smp_plat.h>
#include <asm/pvpoll-abi.h>
#include <asm/qspinlock_paravirt.h>

static bool has_pv_poll_control;
static DEFINE_PER_CPU(struct pv_vcpu_poll_ctl, pv_poll_ctl);
struct static_key paravirt_steal_enabled;
struct static_key paravirt_steal_rq_enabled;

struct paravirt_patch_template pv_ops = {
#ifdef CONFIG_PARAVIRT_SPINLOCKS
	.qspinlock.queued_spin_lock_slowpath	= native_queued_spin_lock_slowpath,
	.qspinlock.queued_spin_unlock		= native_queued_spin_unlock,
#endif
	.lock.vcpu_is_preempted		= __native_vcpu_is_preempted,
};
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
		pr_debug("Do not support PV poll control\n");
		return;
	}

	/* Enable guest halt poll disables host halt poll */
	smp_call_function_single(cpu, kvm_disable_host_haltpoll, NULL, 1);
}
EXPORT_SYMBOL_GPL(arch_haltpoll_enable);

void arch_haltpoll_disable(unsigned int cpu)
{
	if (!has_pv_poll_control) {
		pr_debug("Do not support PV poll control\n");
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

	/*
	 * The KVM will update the defaul polling state, so we do not need to
	 * set the default value explicitly.
	 */
	arm_smccc_1_1_invoke(ARM_SMCCC_HV_PV_POLLCONTROL_SET, __pa(poll_ctl), &res);
	if (res.a0 == SMCCC_RET_NOT_SUPPORTED) {
		pr_err("Failed to set poll control base\n");
		return -EINVAL;
	}

	return 0;
}

static int poll_ctrl_cpu_down_prepare(unsigned int cpu)
{
	struct pv_vcpu_poll_ctl *poll_ctl;
	struct arm_smccc_res res;

	poll_ctl = this_cpu_ptr(&pv_poll_ctl);

	poll_ctl->poll_ctl = cpu_to_le64(0);
	arm_smccc_1_1_invoke(ARM_SMCCC_HV_PV_POLLCONTROL_SET, -1UL, &res);
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

static DEFINE_PER_CPU(struct pv_vcpu_preempted, pv_preempted);

static bool kvm_vcpu_is_preempted(int cpu)
{
	struct pv_vcpu_preempted *pp = per_cpu_ptr(&pv_preempted, cpu);

	return !!le64_to_cpu(READ_ONCE(pp->preempted));
}

static int pv_vcpu_state_dying_cpu(unsigned int cpu)
{
	struct pv_vcpu_preempted *pp = per_cpu_ptr(&pv_preempted, cpu);

	memset(pp, 0, sizeof(*pp));

	return 0;
}

static int init_pv_vcpu_state(unsigned int cpu)
{
	struct pv_vcpu_preempted *pp;
	struct arm_smccc_res res;

	pp = (void *)__pa(this_cpu_ptr(&pv_preempted));

	arm_smccc_1_1_invoke(ARM_SMCCC_HV_PV_LOCK_PREEMPTED, pp, &res);

	if (res.a0 == SMCCC_RET_NOT_SUPPORTED) {
		pr_warn("Failed to init PV lock data structure\n");
		return -EINVAL;
	}

	return 0;
}

static int kvm_arm_init_pvlock(void)
{
	int ret;

	ret = cpuhp_setup_state(CPUHP_AP_ARM_KVM_PVLOCK_STARTING,
			"hypervisor/arm/pvlock:starting",
			init_pv_vcpu_state,
			pv_vcpu_state_dying_cpu);
	if (ret < 0) {
		pr_warn("PV-lock init failed\n");
		return ret;
	}

	return 0;
}

static bool has_kvm_pvlock(void)
{
	struct arm_smccc_res res;

	/* To detect the presence of PV lock support we require SMCCC 1.1+ */
	if (arm_smccc_1_1_get_conduit() == SMCCC_CONDUIT_NONE)
		return false;

	arm_smccc_1_1_invoke(ARM_SMCCC_ARCH_FEATURES_FUNC_ID,
			ARM_SMCCC_HV_PV_LOCK_FEATURES, &res);

	if (res.a0 != SMCCC_RET_SUCCESS)
		return false;

	return true;
}

int __init pv_lock_init(void)
{
	int ret;

	if (is_hyp_mode_available())
		return 0;

	if (!has_kvm_pvlock())
		return 0;

	ret = kvm_arm_init_pvlock();
	if (ret)
		return ret;

	pv_ops.lock.vcpu_is_preempted = kvm_vcpu_is_preempted;
	pr_info("using PV-lock preempted\n");

	return 0;
}

#ifdef CONFIG_PARAVIRT_SPINLOCKS
static bool has_kvm_qspinlock(void)
{
	struct arm_smccc_res res;

	/* To detect the presence of PV lock support we require SMCCC 1.1+ */
	if (arm_smccc_1_1_get_conduit() == SMCCC_CONDUIT_NONE)
		return false;

	arm_smccc_1_1_invoke(ARM_SMCCC_ARCH_FEATURES_FUNC_ID,
			ARM_SMCCC_HV_PV_QSPINLOCK_FEATURES, &res);
	if (res.a0 != SMCCC_RET_SUCCESS)
		return false;

	return true;
}

/* Kick a cpu by its cpuid. Used to wake up a halted vcpu */
static void kvm_kick_cpu(int cpu)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(ARM_SMCCC_HV_PV_QSPINLOCK_KICK_CPU, cpu, &res);
}

static void kvm_wait(u8 *ptr, u8 val)
{
	unsigned long flags;

	if (in_nmi())
		return;

	local_irq_save(flags);

	if (READ_ONCE(*ptr) != val)
		goto out;

	dsb(sy);
	wfi();

out:
	local_irq_restore(flags);
}

static bool pvqspinlock;

static __init int parse_pvqspinlock(char *arg)
{
	pvqspinlock = true;
	return 0;
}
early_param("pvqspinlock", parse_pvqspinlock);

void __init pv_qspinlock_init(void)
{
	/* Don't use the PV qspinlock code if there is only 1 vCPU. */
	if (num_possible_cpus() == 1)
		return;

	if (!pvqspinlock) {
		pr_info("PV qspinlocks disabled\n");
		return;
	}

	if (!has_kvm_qspinlock())
		return;

	pr_info("PV qspinlocks enabled\n");

	__pv_init_lock_hash();
	pv_ops.qspinlock.queued_spin_lock_slowpath = __pv_queued_spin_lock_slowpath;
	pv_ops.qspinlock.queued_spin_unlock = __pv_queued_spin_unlock;
	pv_ops.qspinlock.wait = kvm_wait;
	pv_ops.qspinlock.kick = kvm_kick_cpu;
}
#endif
