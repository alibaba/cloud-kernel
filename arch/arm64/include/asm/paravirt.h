/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_PARAVIRT_H
#define _ASM_ARM64_PARAVIRT_H

#ifdef CONFIG_PARAVIRT
struct static_key;
extern struct static_key paravirt_steal_enabled;
extern struct static_key paravirt_steal_rq_enabled;

struct pv_time_ops {
	unsigned long long (*steal_clock)(int cpu);
};

struct paravirt_patch_template {
	struct pv_time_ops time;
};

extern struct paravirt_patch_template pv_ops;

static inline u64 paravirt_steal_clock(int cpu)
{
	return pv_ops.time.steal_clock(cpu);
}

int __init pv_time_init(void);

void arch_haltpoll_enable(unsigned int cpu);
void arch_haltpoll_disable(unsigned int cpu);

#else

#define pv_time_init() do {} while (0)

static inline void arch_haltpoll_enable(unsigned int cpu)
{
}
static inline void arch_haltpoll_disable(unsigned int cpu)
{
}

#endif // CONFIG_PARAVIRT

#endif
