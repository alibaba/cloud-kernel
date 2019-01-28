// SPDX-License-Identifier: GPL-2.0
/*
 * Detect hard lockups on a system
 *
 * Note: Most of this code is borrowed heavily from the perf hardlockup
 * detector, so thanks to Don for the initial implementation.
 */

#define pr_fmt(fmt) "SDEI NMI watchdog: " fmt

#include <asm/irq_regs.h>
#include <asm/kvm_hyp.h>
#include <asm/smp_plat.h>
#include <asm/sdei.h>
#include <asm/virt.h>
#include <linux/arm_sdei.h>
#include <linux/nmi.h>

/* We use the arch virt timer as SDEI NMI watchdog timer */
#define SDEI_NMI_WATCHDOG_HWIRQ		27
#define SDEI_TIMER_INTERVAL		3

static int sdei_watchdog_event_num;
static bool disable_sdei_nmi_watchdog;

static void start_arch_virt_timer(int seconds)
{
	int timer_freq = arch_timer_get_rate();

	write_sysreg_el0(1, cntv_ctl);
	write_sysreg_el0(timer_freq * seconds, cntv_tval);
}

static void stop_arch_virt_timer(void)
{
	write_sysreg_el0(0, cntv_ctl);
}

int watchdog_nmi_enable(unsigned int cpu)
{
	int ret;

	ret = sdei_api_event_enable(sdei_watchdog_event_num);
	if (ret) {
		pr_err("Enable NMI Watchdog failed on cpu%d\n",
				smp_processor_id());
		return ret;
	}

	start_arch_virt_timer(SDEI_TIMER_INTERVAL);

	return 0;
}

void watchdog_nmi_disable(unsigned int cpu)
{
	int ret;

	ret = sdei_api_event_disable(sdei_watchdog_event_num);
	if (ret)
		pr_err("Disable NMI Watchdog failed on cpu%d\n",
				smp_processor_id());

	stop_arch_virt_timer();
}

static int sdei_watchdog_callback(u32 event,
		struct pt_regs *regs, void *arg)
{
	/* reprogram the arch virt timer */
	start_arch_virt_timer(SDEI_TIMER_INTERVAL);
	watchdog_hardlockup_check(regs);

	return 0;
}

static void sdei_nmi_watchdog_bind(void *data)
{
	int ret;

	ret = sdei_api_event_interrupt_bind(SDEI_NMI_WATCHDOG_HWIRQ);
	if (ret < 0)
		pr_err("SDEI bind failed on cpu%d, return %d\n",
				smp_processor_id(), ret);
}

/* Before BIOS implements SDEI platform event, the host OS will use arch
 * virt timer as SDEI watchdog timer, so the guest os will failed to start
 * because it can not use arch virt timer. We provide a mechanism to disable
 * SDEI NMI watchdog in the host.
 */
static int __init disable_sdei_nmi_watchdog_setup(char *str)
{
	disable_sdei_nmi_watchdog = true;
	return 1;
}
__setup("disable_sdei_nmi_watchdog", disable_sdei_nmi_watchdog_setup);

int __init watchdog_nmi_probe(void)
{
	int ret;

	if (disable_sdei_nmi_watchdog)
		return -EINVAL;

	/*
	 * When hyp mode is not available and kernel is not in hyp mode, the system
	 * will use arch virt timer, which will conflict with SDEI NMI Watchdog.
	 * Refer to 'arch_timer_select_ppi'.
	 */
	if (!is_kernel_in_hyp_mode() && !is_hyp_mode_available()) {
		pr_err("Disable SDEI NMI Watchdog because the system will use virt timer\n");
		return -EINVAL;
	}

	sdei_watchdog_event_num = sdei_api_event_interrupt_bind(SDEI_NMI_WATCHDOG_HWIRQ);
	if (sdei_watchdog_event_num < 0) {
		pr_err("bind interrupt failed !\n");
		return sdei_watchdog_event_num;
	}

	on_each_cpu(sdei_nmi_watchdog_bind, NULL, true);

	ret = sdei_event_register(sdei_watchdog_event_num,
					sdei_watchdog_callback, NULL);
	if (ret) {
		pr_err("SDEI Watchdog register callback failed\n");
		return ret;
	}

	pr_info("SDEI Watchdog registered successfully\n");

	return 0;
}
