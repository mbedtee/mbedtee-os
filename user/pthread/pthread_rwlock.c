// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread RW lock
 */

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

#include <__pthread.h>

#include "pthread_time.h"
#include "pthread_lockdep.h"
#include "pthread_waitdep.h"
#include "pthread_object.h"

#define DEFAULT_RWLOCKATTR { \
	true, PTHREAD_PROCESS_PRIVATE \
}

/*
 * using 32-bit Exclusive Instructions
 */
struct __pthread_rwlock {
	pid_t owner;
	uint32_t lock;
	pthread_rwlockattr_t attr;
};

int pthread_rwlockattr_init(pthread_rwlockattr_t *attr)
{
	pthread_rwlockattr_t dattr = DEFAULT_RWLOCKATTR;

	*attr = dattr;
	return 0;
}

int pthread_rwlockattr_destroy(pthread_rwlockattr_t *attr)
{
	return 0;
}

int pthread_rwlockattr_getpshared(
	const pthread_rwlockattr_t *attr,
	int *pshared)
{
	*pshared = attr->process_shared;
	return 0;
}

int pthread_rwlockattr_setpshared(
	pthread_rwlockattr_t *attr,
	int pshared)
{
	if (pshared != PTHREAD_PROCESS_PRIVATE)
		return EINVAL;

	attr->process_shared = pshared;
	return 0;
}

int pthread_rwlock_init(pthread_rwlock_t *rwlock,
	const pthread_rwlockattr_t *attr)
{
	int id = 0;
	struct __pthread_rwlock *l = NULL;
	pthread_rwlockattr_t dattr = DEFAULT_RWLOCKATTR;

	if (attr && (attr->is_initialized == false))
		return EINVAL;

	id = __pthread_object_alloc(sizeof(
			struct __pthread_rwlock));
	if (id < 0)
		return -id;

	l = __pthread_object_of(id);

	l->owner = 0;
	l->lock = 0;

	memcpy(&l->attr, attr ? attr : &dattr, sizeof(dattr));

	*rwlock = id;
	return 0;
}

static inline int pthread_rwlock_init_default
(
	pthread_rwlock_t *rwlock
)
{
	int ret = 0;
	pthread_rwlock_t id = 0;
	pthread_rwlock_t defaultl = PTHREAD_RWLOCK_INITIALIZER;

	ret = pthread_rwlock_init(&id, NULL);
	if (ret)
		return ret;

	/*
	 * there may be a race condition of the rwlock initialized
	 * with the PTHREAD_RWLOCK_INITIALIZER
	 */
	if (__atomic_compare_exchange_n(rwlock, &defaultl, id, 0,
		__ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
		return 0;

	__pthread_object_free(id);
	return 0;
}

int pthread_rwlock_destroy(pthread_rwlock_t *rwlock)
{
	if (rwlock) {
		int id = *rwlock;

		*rwlock = PTHREAD_RWLOCK_INITIALIZER;
		return __pthread_object_free(id);
	}

	return 0;
}

int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock)
{
	int ret = 0;
	uint32_t val = 0, rdval = 0;
	struct __pthread_rwlock *l = NULL;
	struct __pthread *self = __pthread_self;

	if (*rwlock == PTHREAD_RWLOCK_INITIALIZER) {
		ret = pthread_rwlock_init_default(rwlock);
		if (ret)
			return ret;
	}

	l = __pthread_object_of(*rwlock);
	if (!l)
		return EINVAL;

	pthread_enter_critical(self);

	while ((val & PTHREAD_LOCK_WRLOCK) == 0) {
		rdval = (val + PTHREAD_LOCK_READER) | PTHREAD_LOCK_RDLOCK;
		if (__atomic_compare_exchange_n(&l->lock, &val, rdval, 0,
			__ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
			return 0;

		/*
		 * runs here, means the lock is possibly held by writer,
		 * going to increase the nr of waiter, prepare for wait,
		 * but condition maybe change at this critical moment,
		 * just make sure of this
		 */
		val = __atomic_load_n(&l->lock, __ATOMIC_RELAXED);
		if (val & PTHREAD_LOCK_WRLOCK) {
			if (l->owner == gettid()) {
				ret = EDEADLK;
				goto out;
			}

			ret = __pthread_wait_rdlock(&l->lock);
			if (ret)
				goto out;

			return 0;
		}
	}

out:
	pthread_leave_critical(self);
	return ret;
}

int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock)
{
	int ret = 0;
	uint32_t val = 0, rdval = 0;
	struct __pthread_rwlock *l = NULL;
	struct __pthread *self = __pthread_self;

	if (*rwlock == PTHREAD_RWLOCK_INITIALIZER) {
		ret = pthread_rwlock_init_default(rwlock);
		if (ret)
			return ret;
	}

	l = __pthread_object_of(*rwlock);
	if (!l)
		return EINVAL;

	pthread_enter_critical(self);

	rdval = (val + PTHREAD_LOCK_READER) | PTHREAD_LOCK_RDLOCK;
	if (__atomic_compare_exchange_n(&l->lock, &val, rdval, 1,
		__ATOMIC_SEQ_CST, __ATOMIC_RELAXED))
		return 0;

	pthread_leave_critical(self);

	return (l->owner == gettid()) ? EDEADLK : EBUSY;
}

int pthread_rwlock_timedrdlock(pthread_rwlock_t *rwlock,
	const struct timespec *abstime)
{
	int ret = 0;
	long usecs = -1;
	uint32_t val = 0, rdval = 0;
	struct __pthread_rwlock *l = NULL;
	struct __pthread *self = __pthread_self;

	if (*rwlock == PTHREAD_RWLOCK_INITIALIZER) {
		ret = pthread_rwlock_init_default(rwlock);
		if (ret)
			return ret;
	}

	l = __pthread_object_of(*rwlock);
	if (!l)
		return EINVAL;

	pthread_enter_critical(self);

	while ((val & PTHREAD_LOCK_WRLOCK) == 0) {
		rdval = (val + PTHREAD_LOCK_READER) | PTHREAD_LOCK_RDLOCK;
		if (__atomic_compare_exchange_n(&l->lock, &val, rdval, 0,
			__ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
			return 0;

		/*
		 * runs here, means the lock is possibly held by writer,
		 * going to increase the nr of waiter, prepare for wait,
		 * but condition maybe change at this critical moment,
		 * just make sure of this
		 */
		val = __atomic_load_n(&l->lock, __ATOMIC_RELAXED);
		if (val & PTHREAD_LOCK_WRLOCK) {
			if (l->owner == gettid()) {
				ret = EDEADLK;
				goto out;
			}

			ret = __pthread_time2usecs(abstime, &usecs);
			if (ret)
				goto out;

			ret = __pthread_timedwait_rdlock(&l->lock, usecs);
			if (ret)
				goto out;

			return 0;
		}
	}

out:
	pthread_leave_critical(self);
	return ret;
}

int pthread_rwlock_unlock(pthread_rwlock_t *rwlock)
{
	int ret = 0;
	uint32_t val = 0, rdval = 0;
	struct __pthread_rwlock *l = NULL;
	struct __pthread *self = __pthread_self;

	if (*rwlock == PTHREAD_RWLOCK_INITIALIZER) {
		ret = pthread_rwlock_init_default(rwlock);
		if (ret)
			return ret;
	}

	l = __pthread_object_of(*rwlock);
	if (!l)
		return EINVAL;

	/*
	 * check writer firstly, then readers
	 */
	val = __atomic_load_n(&l->lock, __ATOMIC_RELAXED);

	if (l->owner == gettid()) {
		if ((val & PTHREAD_LOCK_WRLOCK) != PTHREAD_LOCK_WRLOCK)
			return EINVAL;
		l->owner = 0;
		val = __atomic_exchange_n(&l->lock, 0, __ATOMIC_RELEASE);
		__pthread_wakeup_lock(&l->lock, val & PTHREAD_LOCK_WAITER);
		pthread_leave_critical(self);
	} else {
		do {
			if ((val & PTHREAD_LOCK_RDLOCK) != PTHREAD_LOCK_RDLOCK)
				return EINVAL;

			rdval = val & PTHREAD_LOCK_READER_MASK;
			if (rdval == 0)
				return EINVAL;

			rdval -= PTHREAD_LOCK_READER;
			if (rdval != 0)
				rdval = val - PTHREAD_LOCK_READER;

			if (__atomic_compare_exchange_n(&l->lock, &val, rdval, 0,
				__ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
				break;
		} while (val);

		if (rdval == 0)
			__pthread_wakeup_lock(&l->lock,	val & PTHREAD_LOCK_WAITER);

		pthread_leave_critical(self);
	}

	return 0;
}

int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock)
{
	int ret = 0;
	uint32_t val = 0;
	struct __pthread_rwlock *l = NULL;
	struct __pthread *self = __pthread_self;

	if (*rwlock == PTHREAD_RWLOCK_INITIALIZER) {
		ret = pthread_rwlock_init_default(rwlock);
		if (ret)
			return ret;
	}

	l = __pthread_object_of(*rwlock);
	if (!l)
		return EINVAL;

	pthread_enter_critical(self);

	while (val == 0) {
		if (__atomic_compare_exchange_n(&l->lock, &val,
			PTHREAD_LOCK_WRLOCK, 0, __ATOMIC_ACQUIRE,
			__ATOMIC_RELAXED))
			goto locked;

		/*
		 * val isn't 0, increase the nr of waiter, goto wait.
		 * runs here, means the lock is possibly held by other
		 * writer or readers, but condition maybe change at this
		 * critical moment, just make sure of this
		 */
		val = __atomic_load_n(&l->lock, __ATOMIC_RELAXED);
		if (val) {
			if (l->owner == gettid()) {
				ret = EDEADLK;
				goto out;
			}

			ret = __pthread_wait_wrlock(&l->lock, 0);
			if (ret != 0)
				goto out;
			goto locked;
		}
	}

locked:
	l->owner = gettid();
	return 0;

out:
	pthread_leave_critical(self);
	return ret;
}

int pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock)
{
	int ret = 0;
	uint32_t val = 0;
	struct __pthread_rwlock *l = NULL;
	struct __pthread *self = __pthread_self;

	if (*rwlock == PTHREAD_RWLOCK_INITIALIZER) {
		ret = pthread_rwlock_init_default(rwlock);
		if (ret)
			return ret;
	}

	l = __pthread_object_of(*rwlock);
	if (!l)
		return EINVAL;

	pthread_enter_critical(self);

	if (__atomic_compare_exchange_n(&l->lock, &val,
		PTHREAD_LOCK_WRLOCK, 1, __ATOMIC_SEQ_CST,
		__ATOMIC_RELAXED)) {
		l->owner = gettid();
		return 0;
	}

	pthread_leave_critical(self);

	return (l->owner == gettid()) ? EDEADLK : EBUSY;
}

int pthread_rwlock_timedwrlock(pthread_rwlock_t *rwlock,
	const struct timespec *abstime)
{
	int ret = 0;
	long usecs = -1;
	uint32_t val = 0;
	struct __pthread_rwlock *l = NULL;
	struct __pthread *self = __pthread_self;

	if (*rwlock == PTHREAD_RWLOCK_INITIALIZER) {
		ret = pthread_rwlock_init_default(rwlock);
		if (ret)
			return ret;
	}

	l = __pthread_object_of(*rwlock);
	if (!l)
		return EINVAL;

	pthread_enter_critical(self);

	while (val == 0) {
		if (__atomic_compare_exchange_n(&l->lock, &val,
			PTHREAD_LOCK_WRLOCK, 0, __ATOMIC_ACQUIRE,
			__ATOMIC_RELAXED))
			goto locked;

		/*
		 * val isn't 0, increase the nr of waiter, goto wait.
		 * runs here, means the lock is possibly held by other
		 * writer or readers, but condition maybe change at this
		 * critical moment, just make sure of this
		 */
		val = __atomic_load_n(&l->lock, __ATOMIC_RELAXED);
		if (val) {
			if (l->owner == gettid()) {
				ret = EDEADLK;
				goto out;
			}

			ret = __pthread_time2usecs(abstime, &usecs);
			if (ret)
				goto out;

			ret = __pthread_timedwait_wrlock(&l->lock, 0, usecs);
			if (ret != 0)
				goto out;
			goto locked;
		}
	}

locked:
	l->owner = gettid();
	return 0;

out:
	pthread_leave_critical(self);
	return ret;
}
