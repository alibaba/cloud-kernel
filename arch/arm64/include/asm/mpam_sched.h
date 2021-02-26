/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_MPAM_SCHED_H
#define _ASM_ARM64_MPAM_SCHED_H

#ifdef CONFIG_MPAM

#include <linux/sched.h>
#include <linux/jump_label.h>

/**
 * struct intel_pqr_state - State cache for the PQR MSR
 * @cur_rmid:		The cached Resource Monitoring ID
 * @cur_closid:	The cached Class Of Service ID
 * @default_rmid:	The user assigned Resource Monitoring ID
 * @default_closid:	The user assigned cached Class Of Service ID
 *
 * The upper 32 bits of IA32_PQR_ASSOC contain closid and the
 * lower 10 bits rmid. The update to IA32_PQR_ASSOC always
 * contains both parts, so we need to cache them. This also
 * stores the user configured per cpu CLOSID and RMID.
 *
 * The cache also helps to avoid pointless updates if the value does
 * not change.
 */
struct intel_pqr_state {
	u32			cur_rmid;
	u32			cur_closid;
	u32			default_rmid;
	u32			default_closid;
};

DECLARE_PER_CPU(struct intel_pqr_state, pqr_state);

extern void __mpam_sched_in(void);
DECLARE_STATIC_KEY_FALSE(resctrl_enable_key);

static inline void mpam_sched_in(void)
{
	if (static_branch_likely(&resctrl_enable_key))
		__mpam_sched_in();
}

enum mpam_enable_type {
	enable_denied = 0,
	enable_default,
	enable_acpi,
};

extern enum mpam_enable_type __read_mostly mpam_enabled;

#else

static inline void mpam_sched_in(void) {}

#endif /* CONFIG_MPAM */

#endif
