/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * pthread lock dependences (spin)
 */

#ifndef _PTHREAD_LOCKDEP_H
#define	_PTHREAD_LOCKDEP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>

static inline void __pthread_lock_init(pthread_spinlock_t *lock)
{
	__atomic_store_n(lock, 0, __ATOMIC_RELAXED);
}

static inline void __pthread_lock(pthread_spinlock_t *lock)
{
	pthread_spinlock_t val = 0;

	/*
	 * Here we use the gcc built-in atomic operations,
	 * it's the ldrex/strex (ll/sc) pairs with memory barriers
	 * with the __ATOMIC_ACQUIRE/__ATOMIC_RELEASE memory models.
	 * weak compare and exchange
	 */
	while (__atomic_compare_exchange_n(lock, &val, 1, 0,
		__ATOMIC_ACQUIRE, __ATOMIC_RELAXED) == 0) {
		while (val) {
			pthread_yield();
			/*
			 * If we are failed, that must be a new successor of this lock,
			 * and the new owner will perform __ATOMIC_ACQUIRE which will
			 * adds barrier after the strex/sc, so we can use __ATOMIC_RELAXED
			 * (which ignores without memory barrier).
			 */
			val = __atomic_load_n(lock, __ATOMIC_RELAXED);
		}
	}
}

static inline unsigned long __pthread_trylock(pthread_spinlock_t *lock)
{
	pthread_spinlock_t val = 0;

	/*
	 * Here we use the gcc built-in atomic operations,
	 * it's the ldrex/strex (ll/sc) pairs with memory barriers
	 * with the __ATOMIC_ACQUIRE/__ATOMIC_RELEASE memory models.
	 * weak compare and exchange
	 */

	while (__atomic_compare_exchange_n(lock, &val, 1, 0,
		__ATOMIC_ACQUIRE, __ATOMIC_RELAXED) == 0) {
		val = __atomic_load_n(lock, __ATOMIC_RELAXED);
		if (val != 0)
			break;
	}

	return val;
}

static inline void __pthread_unlock(pthread_spinlock_t *lock)
{
	/*
	 * Use __ATOMIC_RELEASE to ensure all preceding reads/writes
	 * (done while holding the lock) are visible to the next acquirer.
	 * __ATOMIC_RELEASE adds barrier before the strex/sc
	 */
	__atomic_store_n(lock, 0, __ATOMIC_RELEASE);
}

#ifdef __cplusplus
}
#endif

#endif
