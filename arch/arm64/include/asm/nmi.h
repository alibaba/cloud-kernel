/* SPDX-License-Identifier: GPL-2.0 */

#if !defined(CONFIG_HARDLOCKUP_DETECTOR)
static inline void arch_touch_nmi_watchdog(void) { }
#endif
