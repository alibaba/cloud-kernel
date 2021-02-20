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
#include <linux/kprobes.h>
#include <linux/nmi.h>

/* We use the secure physical timer as SDEI NMI watchdog timer */
#define SDEI_NMI_WATCHDOG_HWIRQ		29

static int sdei_watchdog_event_num;
static bool disable_sdei_nmi_watchdog;
static bool sdei_watchdog_registered;
static DEFINE_PER_CPU(ktime_t, last_check_time);

int watchdog_nmi_enable(unsigned int cpu)
{
	int ret;

	if (!sdei_watchdog_registered)
		return -EINVAL;

#ifdef CONFIG_HARDLOCKUP_CHECK_TIMESTAMP
	refresh_hld_last_timestamp();
#endif

	__this_cpu_write(last_check_time, ktime_get_mono_fast_ns());
	sdei_api_set_secure_timer_period(watchdog_thresh);

	ret = sdei_api_event_enable(sdei_watchdog_event_num);
	if (ret) {
		pr_err("Enable NMI Watchdog failed on cpu%d\n",
				smp_processor_id());
		return ret;
	}

	return 0;
}

void watchdog_nmi_disable(unsigned int cpu)
{
	int ret;

	if (!sdei_watchdog_registered)
		return;

	ret = sdei_api_event_disable(sdei_watchdog_event_num);
	if (ret)
		pr_err("Disable NMI Watchdog failed on cpu%d\n",
				smp_processor_id());
}

static int sdei_watchdog_callback(u32 event,
		struct pt_regs *regs, void *arg)
{
	ktime_t delta, now = ktime_get_mono_fast_ns();

	delta = now - __this_cpu_read(last_check_time);
	__this_cpu_write(last_check_time, now);

	/*
	 * Set delta to 4/5 of the actual watchdog threshold period so the
	 * hrtimer is guaranteed to fire at least once within the real
	 * watchdog threshold.
	 */
	if (delta < watchdog_thresh * (u64)NSEC_PER_SEC * 4 / 5) {
		pr_err(FW_BUG "SDEI Watchdog event triggered too soon, "
			"time to last check:%lld ns\n", delta);
		WARN_ON(1);
		return 0;
	}

	watchdog_hardlockup_check(regs);

	return 0;
}
NOKPROBE_SYMBOL(sdei_watchdog_callback);

static void sdei_nmi_watchdog_bind(void *data)
{
	int ret;

	ret = sdei_api_event_interrupt_bind(SDEI_NMI_WATCHDOG_HWIRQ);
	if (ret < 0)
		pr_err("SDEI bind failed on cpu%d, return %d\n",
				smp_processor_id(), ret);
}

static int __init disable_sdei_nmi_watchdog_setup(char *str)
{
	disable_sdei_nmi_watchdog = true;
	return 1;
}
__setup("disable_sdei_nmi_watchdog", disable_sdei_nmi_watchdog_setup);

void sdei_watchdog_clear_eoi(void)
{
	if (sdei_watchdog_registered)
		sdei_api_clear_eoi(SDEI_NMI_WATCHDOG_HWIRQ);
}

int __init watchdog_nmi_probe(void)
{
	int ret;

	if (disable_sdei_nmi_watchdog)
		return -EINVAL;

	if (!is_hyp_mode_available()) {
		pr_err("Disable SDEI NMI Watchdog in VM\n");
		return -EINVAL;
	}

	sdei_watchdog_event_num = sdei_api_event_interrupt_bind(SDEI_NMI_WATCHDOG_HWIRQ);
	if (sdei_watchdog_event_num < 0) {
		pr_err("Bind interrupt failed. Firmware may not support SDEI !\n");
		return sdei_watchdog_event_num;
	}

	/*
	 * After we introduced 'sdei_api_set_secure_timer_period', we disselect
	 * 'CONFIG_HARDLOCKUP_CHECK_TIMESTAMP'. So we need to make sure that
	 * firmware can set the period of the secure timer and the timer
	 * interrupt doesn't trigger too soon.
	 */
	if (sdei_api_set_secure_timer_period(watchdog_thresh)) {
		pr_err("Firmware doesn't support setting the secure timer period, please update your BIOS !\n");
		return -EINVAL;
	}

	on_each_cpu(sdei_nmi_watchdog_bind, NULL, true);

	ret = sdei_event_register(sdei_watchdog_event_num,
					sdei_watchdog_callback, NULL);
	if (ret) {
		pr_err("SDEI Watchdog register callback failed\n");
		return ret;
	}

	sdei_watchdog_registered = true;
	pr_info("SDEI Watchdog registered successfully\n");

	return 0;
}
