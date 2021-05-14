/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_QSPINLOCK_PARAVIRT_H__
#define __ASM_QSPINLOCK_PARAVIRT_H__

extern void __pv_queued_spin_unlock(struct qspinlock *lock);

#endif
