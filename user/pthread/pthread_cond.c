// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread conditional synchronization
 */

#include <stdbool.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include <syscall.h>
#include <list.h>

#include <__pthread.h>

#include "pthread_object.h"
#include "pthread_wait.h"
#include "pthread_time.h"
#include "pthread_cond.h"

int	pthread_condattr_init(pthread_condattr_t *attr)
{
	if (!attr)
		return EINVAL;

	attr->is_initialized = true;
	attr->clock = 0;
	return 0;
}

int	pthread_condattr_destroy(pthread_condattr_t *attr)
{
	if (!attr || !attr->is_initialized)
		return EINVAL;

	attr->is_initialized = false;
	return 0;
}

int	pthread_condattr_getclock(
	const pthread_condattr_t *attr,
	clockid_t *clock_id)
{
	if (!attr || !attr->is_initialized)
		return EINVAL;
	*clock_id = attr->clock;
	return 0;
}

int	pthread_condattr_setclock(
	pthread_condattr_t *attr,
	clockid_t clock_id)
{
	if (!attr)
		return EINVAL;
	attr->clock = clock_id;
	return 0;
}

int	pthread_condattr_getpshared(
	const pthread_condattr_t *attr,
	int *pshared)
{
	if (!attr || !pshared)
		return EINVAL;

	*pshared = PTHREAD_PROCESS_PRIVATE;

	return 0;
}

int	pthread_condattr_setpshared(
	pthread_condattr_t *attr,
	int pshared)
{
	if (pshared != PTHREAD_PROCESS_PRIVATE)
		return ENOTSUP;

	return 0;
}

int	pthread_cond_init(pthread_cond_t *cond,
	const pthread_condattr_t *attr)
{
	int id = 0;
	struct __pthread_waitqueue *q = NULL;

	if (attr && !attr->is_initialized)
		return EINVAL;

	id = __pthread_object_alloc(sizeof
			(struct __pthread_waitqueue));
	if (id < 0)
		return -id;

	q = __pthread_object_of(id);

	__pthread_waitqueue_init(q);

	*cond = id;
	return 0;
}

static inline int pthread_cond_init_default(
	pthread_cond_t *cond)
{
	int ret = 0;
	pthread_cond_t id = 0;
	pthread_cond_t defaultc = PTHREAD_COND_INITIALIZER;

	ret = pthread_cond_init(&id, NULL);
	if (ret)
		return ret;

	/*
	 * there may be a race condition of the cond
	 * initialized with the PTHREAD_COND_INITIALIZER
	 */
	if (__atomic_compare_exchange_n(cond, &defaultc, id, 0,
		__ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
		return 0;

	__pthread_object_free(id);
	return 0;
}

int	pthread_cond_destroy(pthread_cond_t *cond)
{
	if (cond) {
		int id = *cond;
		struct __pthread_waitqueue *q =
				__pthread_object_of(id);

		if (q)
			__pthread_waitqueue_flush(q);

		*cond = PTHREAD_COND_INITIALIZER;
		return __pthread_object_free(id);
	}

	return EINVAL;
}

int	__pthread_cond_signal(pthread_cond_t *cond,
	void *notification)
{
	int ret = 0;
	struct __pthread_waitqueue *q = NULL;

	if (!cond)
		return EINVAL;

	if (*cond == PTHREAD_COND_INITIALIZER) {
		ret = pthread_cond_init_default(cond);
		if (ret)
			return ret;
	}

	q = __pthread_object_of(*cond);
	if (!q)
		return EINVAL;

	return __pthread_wakeup(q, notification);
}

int	pthread_cond_signal(pthread_cond_t *cond)
{
	return __pthread_cond_signal(cond, NULL);
}

int	__pthread_cond_broadcast(pthread_cond_t *cond,
	void *notification)
{
	int ret = 0;
	struct __pthread_waitqueue *q = NULL;

	if (!cond)
		return EINVAL;

	if (*cond == PTHREAD_COND_INITIALIZER) {
		ret = pthread_cond_init_default(cond);
		if (ret)
			return ret;
	}

	q = __pthread_object_of(*cond);
	if (!q)
		return EINVAL;

	return __pthread_wakeup_all(q, notification);
}

int	pthread_cond_broadcast(pthread_cond_t *cond)
{
	return __pthread_cond_broadcast(cond, NULL);
}

int	__pthread_cond_wait(pthread_cond_t *cond,
	pthread_mutex_t *mutex, void **notification)
{
	int ret = 0;
	struct __pthread_waitqueue *q = NULL;
	__pthread_mutex_t *m = NULL;

	if (!cond || !mutex)
		return EINVAL;

	if (*cond == PTHREAD_COND_INITIALIZER) {
		ret = pthread_cond_init_default(cond);
		if (ret)
			return ret;
	}

	q = __pthread_object_of(*cond);
	if (!q)
		return EINVAL;

	m = __pthread_object_of(*mutex);

	ret = __pthread_wait(q, m, notification);

	__pthread_mutex_lock(m);

	return ret;
}

int	pthread_cond_wait(pthread_cond_t *cond,
	pthread_mutex_t *mutex)
{
	pthread_testcancel();

	return __pthread_cond_wait(cond, mutex, NULL);
}

int	__pthread_cond_timedwait(pthread_cond_t *cond,
	pthread_mutex_t *mutex, const struct timespec *abstime,
	void **notification)
{
	int ret = 0;
	long usecs = 0;
	struct __pthread_waitqueue *q = NULL;
	__pthread_mutex_t *m = NULL;

	if (!cond || !abstime || !mutex)
		return EINVAL;

	if (*cond == PTHREAD_COND_INITIALIZER) {
		ret = pthread_cond_init_default(cond);
		if (ret)
			return ret;
	}

	q = __pthread_object_of(*cond);
	if (!q)
		return EINVAL;

	ret = __pthread_time2usecs(abstime, &usecs);
	if (ret)
		return ret;

	m = __pthread_object_of(*mutex);

	ret = __pthread_timedwait(q, m,	notification, usecs);

	__pthread_mutex_lock(m);

	return ret < 0 ? -ret : (ret ? 0 : ETIMEDOUT);
}

int	pthread_cond_timedwait(pthread_cond_t *cond,
	pthread_mutex_t *mutex, const struct timespec *abstime)
{
	pthread_testcancel();

	return __pthread_cond_timedwait(cond, mutex, abstime, NULL);
}
