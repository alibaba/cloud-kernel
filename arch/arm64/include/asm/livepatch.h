#ifndef _ASM_ARM64_LIVEPATCH_H
#define _ASM_ARM64_LIVEPATCH_H

#include <linux/module.h>
#include <linux/ftrace.h>

#ifdef CONFIG_LIVEPATCH

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
static inline int klp_check_compiler_support(void)
{
	return 0;
}

static inline void klp_arch_set_pc(struct pt_regs *regs, unsigned long pc)
{
	regs->pc = pc + 2*AARCH64_INSN_SIZE;
}

#define klp_get_ftrace_location klp_get_ftrace_location
static inline unsigned long klp_get_ftrace_location(unsigned long faddr)
{
	return faddr + AARCH64_INSN_SIZE;
}

#else
static inline int  klp_check_compiler_support(void)
{
	return 1;
}

static inline void klp_arch_set_pc(struct pt_regs *regs, unsigned long pc)
{
}

#define klp_get_ftrace_location klp_get_ftrace_location
static inline unsigned long klp_get_ftrace_location(unsigned long faddr)
{
	return faddr + AARCH64_INSN_SIZE;
}
#endif

#else
#error Live patching support is disabled; check CONFIG_LIVEPATCH
#endif

#endif /* _ASM_ARM64_LIVEPATCH_H */
