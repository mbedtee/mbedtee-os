// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread spin lock
 */

#include <errno.h>
#include <pthread.h>

#include "pthread_lockdep.h"

int pthread_spin_init(pthread_spinlock_t *lock, int pshared)
{
	if (pshared == PTHREAD_PROCESS_PRIVATE) {
		__pthread_lock_init(lock);
		return 0;
	}

	/* do not support the PTHREAD_PROCESS_SHARED */
	return ENOTSUP;
}

int pthread_spin_destroy(pthread_spinlock_t *lock)
{
	/* no resource to be released */
	return 0;
}

int pthread_spin_lock(pthread_spinlock_t *lock)
{
	__pthread_lock(lock);
	return 0;
}

int pthread_spin_trylock(pthread_spinlock_t *lock)
{
	return __pthread_trylock(lock) ? EBUSY : 0;
}

int pthread_spin_unlock(pthread_spinlock_t *lock)
{
	__pthread_unlock(lock);
	return 0;
}
