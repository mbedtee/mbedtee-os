// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread mutex functionalities
 */

#include <sched.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <__pthread.h>

#include "pthread_waitdep.h"
#include "pthread_lockdep.h"
#include "pthread_mutexdep.h"
#include "pthread_wait.h"
#include "pthread_time.h"
#include "pthread_object.h"

static const DECLARE_DEFAULT_PTHREAD_MUTEX_ATTR(local_mattr);

int pthread_mutex_init(pthread_mutex_t *mutex,
	const pthread_mutexattr_t *attr)
{
	int id = 0, ret = -1;
	__pthread_mutex_t *m = NULL;

	id = __pthread_object_alloc(sizeof(
			__pthread_mutex_t));
	if (id < 0)
		return -id;

	m = __pthread_object_of(id);

	ret = __pthread_mutex_init(m, attr);
	if (ret) {
		__pthread_object_free(id);
		return ret;
	}

	*mutex = id;
	return 0;
}

static int pthread_mutex_init_default
(
	pthread_mutex_t *mutex
)
{
	int ret = 0;
	pthread_mutex_t id = 0;
	pthread_mutex_t defaultm = PTHREAD_MUTEX_INITIALIZER;

	ret = pthread_mutex_init(&id, NULL);
	if (ret)
		return ret;

	/*
	 * there may be a race condition of the mutex
	 * initialized with the PTHREAD_MUTEX_INITIALIZER
	 */
	if (__atomic_compare_exchange_n(mutex, &defaultm, id, 0,
		__ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
		return 0;

	__pthread_object_free(id);
	return 0;
}

int	pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	if (mutex) {
		int id = *mutex;

		__pthread_mutex_t *m = __pthread_object_of(id);

		__pthread_mutex_destroy(m);
		*mutex = PTHREAD_MUTEX_INITIALIZER;
		return __pthread_object_free(id);
	}

	return EINVAL;
}

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
	int ret = 0;

	if (!mutex)
		return EINVAL;

	if (*mutex == PTHREAD_MUTEX_INITIALIZER) {
		ret = pthread_mutex_init_default(mutex);
		if (ret)
			return ret;
	}

	return __pthread_mutex_lock(__pthread_object_of(*mutex));
}

int	pthread_mutex_trylock(pthread_mutex_t *mutex)
{
	int ret = 0;

	if (!mutex)
		return EINVAL;

	if (*mutex == PTHREAD_MUTEX_INITIALIZER) {
		ret = pthread_mutex_init_default(mutex);
		if (ret)
			return ret;
	}

	return __pthread_mutex_trylock(__pthread_object_of(*mutex));
}

int	pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	int ret = 0;

	if (!mutex)
		return EINVAL;

	if (*mutex == PTHREAD_MUTEX_INITIALIZER) {
		ret = pthread_mutex_init_default(mutex);
		if (ret)
			return ret;
	}

	return __pthread_mutex_unlock(__pthread_object_of(*mutex));
}

int	pthread_mutex_timedlock(pthread_mutex_t *mutex,
	const struct timespec *abstime)
{
	int ret = 0;

	if (!mutex)
		return EINVAL;

	if (*mutex == PTHREAD_MUTEX_INITIALIZER) {
		ret = pthread_mutex_init_default(mutex);
		if (ret)
			return ret;
	}

	return __pthread_mutex_timedlock(__pthread_object_of(*mutex), abstime);
}

int pthread_mutex_consistent(pthread_mutex_t *mutex)
{
	int ret = 0;
	__pthread_mutex_t *m = NULL;

	if (!mutex)
		return EINVAL;

	if (*mutex == PTHREAD_MUTEX_INITIALIZER) {
		ret = pthread_mutex_init_default(mutex);
		if (ret)
			return ret;
	}

	m = __pthread_object_of(*mutex);
	if (!m)
		return EINVAL;

	if (m->state != MUTEX_STATE_EOWNERDEAD)
		return EINVAL;

	m->state = MUTEX_STATE_NORMAL;
	return 0;
}

int	pthread_mutex_setprioceiling(pthread_mutex_t *mutex,
	int prioceiling, int *old_ceiling)
{
	int ret = 0;
	__pthread_mutex_t *m = NULL;

	if (MUTEX_INVALID_PRIOCEILING(prioceiling))
		return EINVAL;

	if (!mutex)
		return EINVAL;

	if (*mutex == PTHREAD_MUTEX_INITIALIZER) {
		ret = pthread_mutex_init_default(mutex);
		if (ret)
			return ret;
	}

	m = __pthread_object_of(*mutex);
	if (!m)
		return EINVAL;

	if (m->attr.protocol == PTHREAD_PRIO_NONE)
		return EINVAL;

	ret = pthread_mutex_lock(mutex);
	if (ret)
		return ret;
	*old_ceiling = m->attr.prio_ceiling;
	m->attr.prio_ceiling = prioceiling;
	pthread_mutex_unlock(mutex);

	return 0;
}

int	pthread_mutex_getprioceiling(
	pthread_mutex_t *mutex, int *prioceiling)
{
	int ret = 0;
	__pthread_mutex_t *m = NULL;

	if (!mutex)
		return EINVAL;

	if (*mutex == PTHREAD_MUTEX_INITIALIZER) {
		ret = pthread_mutex_init_default(mutex);
		if (ret)
			return ret;
	}

	m = __pthread_object_of(*mutex);
	if (!m)
		return EINVAL;

	*prioceiling = m->attr.prio_ceiling;
	return 0;
}

int	pthread_mutexattr_init(pthread_mutexattr_t *attr)
{
	memcpy(attr, &local_mattr, sizeof(local_mattr));

	attr->prio_ceiling = sched_get_priority_max(SCHED_RR);
	return 0;
}

int	pthread_mutexattr_destroy(pthread_mutexattr_t *attr)
{
	return 0;
}

int	pthread_mutexattr_getpshared(
	const pthread_mutexattr_t *attr, int *pshared)
{
	*pshared = attr->process_shared;
	return 0;
}

int	pthread_mutexattr_setpshared(
	pthread_mutexattr_t *attr, int pshared)
{
	if (MUTEX_INVALID_PSHARE(pshared))
		return ENOTSUP;

	attr->process_shared = pshared;
	return 0;
}

int pthread_mutexattr_gettype(
	const pthread_mutexattr_t *attr, int *type)
{
	*type = attr->type;
	return 0;
}

int pthread_mutexattr_settype(
	pthread_mutexattr_t *attr, int type)
{
	if (MUTEX_INVALID_TYPE(type))
		return EINVAL;

	attr->type = type;
	return 0;
}

int	pthread_mutexattr_setprotocol(
	pthread_mutexattr_t *attr, int protocol)
{
	if (MUTEX_INVALID_PROTOCOL(protocol))
		return EINVAL;

	attr->protocol = protocol;
	return 0;
}

int	pthread_mutexattr_getprotocol(
	const pthread_mutexattr_t *attr, int *protocol)
{
	*protocol = attr->protocol;
	return 0;
}

int	pthread_mutexattr_setprioceiling(
	pthread_mutexattr_t *attr, int prioceiling)
{
	if (MUTEX_INVALID_PRIOCEILING(prioceiling))
		return EINVAL;

	attr->prio_ceiling = prioceiling;

	return 0;
}

int	pthread_mutexattr_getprioceiling(
	const pthread_mutexattr_t *attr, int *prioceiling)
{
	if (!attr->is_initialized)
		return EINVAL;

	if (!attr->prio_ceiling)
		*prioceiling = sched_get_priority_max(SCHED_RR);
	else
		*prioceiling = attr->prio_ceiling;

	return 0;
}
