// SPDX-License-Identifier: GPL-2.0
#include <linux/tboot.h>

#include <asm/cpufeature.h>
#include <asm/msr-index.h>
#include <asm/processor.h>

void init_ia32_feat_ctl(struct cpuinfo_x86 *c)
{
	u64 msr;

	if (rdmsrl_safe(MSR_IA32_FEATURE_CONTROL, &msr))
		return;

	if (msr & FEATURE_CONTROL_LOCKED)
		return;

	/*
	 * Ignore whatever value BIOS left in the MSR to avoid enabling random
	 * features or faulting on the WRMSR.
	 */
	msr = FEATURE_CONTROL_LOCKED;

	wrmsrl(MSR_IA32_FEATURE_CONTROL, msr);
}
