/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_QSPINLOCK_H__
#define __ASM_QSPINLOCK_H__

#include <asm-generic/qspinlock_types.h>
#include <asm/paravirt.h>

#ifdef CONFIG_PARAVIRT_SPINLOCKS
/* keep the same as x86 */
#define _Q_PENDING_LOOPS	(1 << 9)

extern void native_queued_spin_lock_slowpath(struct qspinlock *lock, u32 val);
extern void __pv_init_lock_hash(void);
extern void __pv_queued_spin_lock_slowpath(struct qspinlock *lock, u32 val);

#define	queued_spin_unlock queued_spin_unlock
/**
 * queued_spin_unlock - release a queued spinlock
 * @lock : Pointer to queued spinlock structure
 *
 * A smp_store_release() on the least-significant byte.
 */
static inline void native_queued_spin_unlock(struct qspinlock *lock)
{
	/*
	 * Now that we have a reference to the (likely)
	 * blocked pv_node, release the lock.
	 */
	smp_store_release(&lock->locked, 0);
}

static inline void queued_spin_lock_slowpath(struct qspinlock *lock, u32 val)
{
	pv_queued_spin_lock_slowpath(lock, val);
}

static inline void queued_spin_unlock(struct qspinlock *lock)
{
	pv_queued_spin_unlock(lock);
}
#endif

#include <asm-generic/qspinlock.h>

#endif /* __ASM_QSPINLOCK_H__ */
