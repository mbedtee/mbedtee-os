// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Retarget the Newlib locking, Newlib allows the
 * target specific locking on different target platforms.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/lock.h>
#include <sys/errno.h>

#include <pthread.h>
#include <pthread_mutexdep.h>

/*
 * newlib-specific static locks
 */
DECLARE_RECURSIVE_PTHREAD_MUTEX(__lock___sinit_recursive_mutex);
DECLARE_RECURSIVE_PTHREAD_MUTEX(__lock___sfp_recursive_mutex);
DECLARE_RECURSIVE_PTHREAD_MUTEX(__lock___atexit_recursive_mutex);
DECLARE_RECURSIVE_PTHREAD_MUTEX(__lock___malloc_recursive_mutex);
DECLARE_RECURSIVE_PTHREAD_MUTEX(__lock___env_recursive_mutex);
DECLARE_RECURSIVE_PTHREAD_MUTEX(__lock___at_quick_exit_mutex);
DECLARE_DEFAULT_PTHREAD_MUTEX(__lock___tz_mutex);
DECLARE_DEFAULT_PTHREAD_MUTEX(__lock___dd_hash_mutex);
DECLARE_DEFAULT_PTHREAD_MUTEX(__lock___arc4random_mutex);

void __retarget_lock_init(_LOCK_T *l)
{
	struct __lock m = DEFAULT_PTHREAD_MUTEX(m);
	struct __lock *__l = NULL;

	__l = malloc(sizeof(struct __lock));

	if (__l) {
		memcpy(__l, &m, sizeof(m));
		*l = __l;
	}
}

void __retarget_lock_init_recursive(_LOCK_T *l)
{
	struct __lock m = RECURSIVE_PTHREAD_MUTEX(m);
	struct __lock *__l = NULL;

	__l = malloc(sizeof(struct __lock));

	if (__l) {
		memcpy(__l, &m, sizeof(m));
		*l = __l;
	}
}

void __retarget_lock_close(_LOCK_T l)
{
	free(l);
}

void __retarget_lock_close_recursive(_LOCK_T l)
{
	free(l);
}

void __retarget_lock_acquire(_LOCK_T l)
{
	__pthread_mutex_lock(l);
}

void __retarget_lock_acquire_recursive(_LOCK_T l)
{
	__pthread_mutex_lock(l);
}

int __retarget_lock_try_acquire(_LOCK_T l)
{
	return __pthread_mutex_trylock(l);
}

int __retarget_lock_try_acquire_recursive(_LOCK_T l)
{
	return __pthread_mutex_trylock(l);
}

void __retarget_lock_release(_LOCK_T l)
{
	__pthread_mutex_unlock(l);
}

void __retarget_lock_release_recursive(_LOCK_T l)
{
	__pthread_mutex_unlock(l);
}
