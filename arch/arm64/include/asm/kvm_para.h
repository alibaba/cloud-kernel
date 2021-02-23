/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_KVM_PARA_H
#define _ASM_ARM64_KVM_PARA_H

#include <uapi/asm-generic/kvm_para.h>

static inline bool kvm_check_and_clear_guest_paused(void)
{
	return false;
}

static inline unsigned int kvm_arch_para_features(void)
{
	return 0;
}

static inline unsigned int kvm_arch_para_hints(void)
{
	return 0;
}

static inline bool kvm_para_available(void)
{
	return IS_ENABLED(CONFIG_PARAVIRT);
}

#endif
