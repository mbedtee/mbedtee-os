/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread lock dependences (spin)
 */

#ifndef _PTHREAD_LOCKDEP_H
#define	_PTHREAD_LOCKDEP_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>

static inline void __pthread_lock_init(uint32_t *lock)
{
	__atomic_store_n(lock, 0, __ATOMIC_RELAXED);
}

static inline void __pthread_lock(uint32_t *lock)
{
	uint32_t val = 0;

	/*
	 * Here we use the gcc built-in atomic operations,
	 * it's the ldrex/strex (ll/sc) pairs with memory barriers
	 * with the __ATOMIC_ACQUIRE/__ATOMIC_REALASE memory models.
	 * weak compare and exchange
	 */
	while (__atomic_compare_exchange_n(lock, &val, 1, 0,
		__ATOMIC_ACQUIRE, __ATOMIC_RELAXED) == 0) {
		while (val) {
			/*
			 * If we are failed, that must be a new successor of this lock,
			 * and the new owner will perform __ATOMIC_ACQUIRE which will
			 * add barrier after the strex/sc, so we can use __ATOMIC_RELAXED
			 * (which ignores without memory barrier).
			 */
			val = __atomic_load_n(lock, __ATOMIC_RELAXED);
		}
	}
}

static inline unsigned long __pthread_trylock(uint32_t *lock)
{
	uint32_t val = 0;

	/*
	 * Here we use the gcc built-in atomic operations,
	 * it's the ldrex/strex (ll/sc) pairs with memory barriers
	 * with the __ATOMIC_ACQUIRE/__ATOMIC_REALASE memory models.
	 * weak compare and exchange
	 */

	/*
	 * The unlock uses the __ATOMIC_RELAXED memory order
	 * so we add a relaxed load to check if the lock is really busy.
	 */
	while (__atomic_compare_exchange_n(lock, &val, 1, 0,
		__ATOMIC_ACQUIRE, __ATOMIC_RELAXED) == 0) {
		val = __atomic_load_n(lock, __ATOMIC_RELAXED);
		if (val != 0)
			break;
	}

	return val;
}

/* Return the number of waiters */
static inline void __pthread_unlock(uint32_t *lock)
{
	/*
	 * strex/sc for __exchange_n(), str/sw for __store_n()
	 *
	 * __ATOMIC_ACQUIRE add memory barrier after strex/sc/str/sw
	 * __ATOMIC_RELEASE add memory barrier before strex/sc/str/sw
	 * __ATOMIC_SEQ_CST add memory barrier before/after strex/sc/str/sw both.
	 */

	/*
	 * The valid memory order variants are
	 * __ATOMIC_RELAXED, __ATOMIC_SEQ_CST, and __ATOMIC_RELEASE.
	 */
	__atomic_store_n(lock, 0, __ATOMIC_RELAXED);
}

#endif
