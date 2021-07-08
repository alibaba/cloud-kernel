/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arm64 KFENCE support.
 *
 * Copyright (C) 2020, Google LLC.
 */

#ifndef __ASM_KFENCE_H
#define __ASM_KFENCE_H

#include <linux/kfence.h>

#include <asm/set_memory.h>

static inline bool arch_kfence_init_pool(struct kfence_pool_area *kpa) { return true; }

static inline bool kfence_protect_page(unsigned long addr, bool protect)
{
	set_memory_valid(addr, 1, !protect);

	return true;
}

static inline bool arch_kfence_free_pool(unsigned long addr) { return false; }

#endif /* __ASM_KFENCE_H */
