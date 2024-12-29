/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 */

#ifndef _SPINLOCK_H
#define _SPINLOCK_H

#include <cpu.h>
#include <assert.h>
#include <lockdep.h>

struct spinlock {
	struct lockval lock;
};

#define SPIN_LOCK_INIT(v) ((struct spinlock){LOCKVAL_INIT(v)})

#define SPIN_LOCK(name) \
	struct spinlock name = SPIN_LOCK_INIT(0)

#define spin_lock_init(sl) lock_val_init(&(sl)->lock)

#define spin_lock(sl) do {} while (arch_atomic_acquire(&(sl)->lock))

#define spin_unlock(sl) arch_atomic_release(&(sl)->lock)

#define spin_lock_irq(sl) \
	do { \
		local_irq_disable(); \
		spin_lock(sl); \
	} while (0)

#define spin_unlock_irq(sl) \
	do { \
		spin_unlock(sl); \
		local_irq_enable(); \
	} while (0)

#define spin_lock_irqsave(sl, flags) \
	do { \
		local_irq_save(flags); \
		spin_lock(sl); \
	} while (0)

static inline void spin_unlock_irqrestore(
	struct spinlock *sl, unsigned long flags)
{
	assert(irqs_disabled());
	spin_unlock(sl);
	local_irq_restore(flags);
}

#endif
