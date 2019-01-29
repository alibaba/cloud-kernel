#ifndef _ASM_ARM64_MPAM_SCHED_H
#define _ASM_ARM64_MPAM_SCHED_H

#ifdef CONFIG_MPAM

#include <linux/sched.h>
#include <linux/jump_label.h>

#include <asm/mpam.h>

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

/*
 * __intel_rdt_sched_in() - Writes the task's CLOSid/RMID to IA32_PQR_MSR
 *
 * Following considerations are made so that this has minimal impact
 * on scheduler hot path:
 * - This will stay as no-op unless we are running on an Intel SKU
 *   which supports resource control or monitoring and we enable by
 *   mounting the resctrl file system.
 * - Caches the per cpu CLOSid/RMID values and does the MSR write only
 *   when a task with a different CLOSid/RMID is scheduled in.
 * - We allocate RMIDs/CLOSids globally in order to keep this as
 *   simple as possible.
 * Must be called with preemption disabled.
 */
static void __mpam_sched_in(void)
{
	struct intel_pqr_state *state = this_cpu_ptr(&pqr_state);
	u32 partid = state->default_closid;
	u32 pmg = state->default_rmid;

	/*
	 * If this task has a closid/rmid assigned, use it.
	 * Else use the closid/rmid assigned to this cpu.
	 */
	if (static_branch_likely(&resctrl_alloc_enable_key)) {
		if (current->closid)
			partid = current->closid;
	}

	if (static_branch_likely(&resctrl_mon_enable_key)) {
		if (current->rmid)
			pmg = current->rmid;
	}

	if (partid != state->cur_closid || pmg != state->cur_rmid) {
		u64 reg;
		state->cur_closid = partid;
		state->cur_rmid = pmg;

		/* set in EL0 */
		reg = read_sysreg_s(SYS_MPAM0_EL1);
		reg = reg & (~PARTID_MASK) & partid;
		reg = reg & (~PMG_MASK) & pmg;
		write_sysreg_s(reg, SYS_MPAM0_EL1);

		/* set in EL1 */
		reg = read_sysreg_s(SYS_MPAM1_EL1);
		reg = reg & (~PARTID_MASK) & partid;
		reg = reg & (~PMG_MASK) & pmg;
		write_sysreg_s(reg, SYS_MPAM1_EL1);

		/* set in EL2 */
		reg = read_sysreg_s(SYS_MPAM2_EL2);
		reg = reg & (~PARTID_MASK) & partid;
		reg = reg & (~PMG_MASK) & pmg;
		write_sysreg_s(reg, SYS_MPAM2_EL2);
	}
}

static inline void mpam_sched_in(void)
{
	if (static_branch_likely(&resctrl_enable_key))
		__mpam_sched_in();
}

#else

static inline void mpam_sched_in(void) {}

#endif /* CONFIG_MPAM */

#endif
