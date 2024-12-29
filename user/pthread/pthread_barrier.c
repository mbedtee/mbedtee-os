// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread barrier synchronization
 */

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include <__pthread.h>

#include "pthread_wait.h"
#include "pthread_object.h"

#define BARRIER_MAX_COUNT (1024)

#define DEFAULT_BARRIERATTR { \
	true, PTHREAD_PROCESS_PRIVATE \
}

struct __pthread_barrier {
	unsigned int threshold;
	unsigned int waiters;
	struct __pthread_waitqueue wq;
	pthread_barrierattr_t attr;
};

int pthread_barrierattr_init(pthread_barrierattr_t *attr)
{
	pthread_barrierattr_t dattr = DEFAULT_BARRIERATTR;

	*attr = dattr;
	return 0;
}

int pthread_barrierattr_destroy(pthread_barrierattr_t *attr)
{
	return 0;
}

int pthread_barrierattr_getpshared(
	const pthread_barrierattr_t *attr,
	int *pshared)
{
	*pshared = attr->process_shared;
	return 0;
}

int pthread_barrierattr_setpshared(
	pthread_barrierattr_t *attr,
	int pshared)
{
	if (pshared != PTHREAD_PROCESS_PRIVATE)
		return EINVAL;

	attr->process_shared = pshared;
	return 0;
}

int pthread_barrier_init(pthread_barrier_t *barrier,
	const pthread_barrierattr_t *attr, unsigned int count)
{
	int id = 0;
	struct __pthread_barrier *b = NULL;
	pthread_barrierattr_t dattr = DEFAULT_BARRIERATTR;

	if (!count || (count >= BARRIER_MAX_COUNT))
		return EINVAL;

	if (attr && (attr->is_initialized == false))
		return EINVAL;

	id = __pthread_object_alloc(sizeof(
			struct __pthread_barrier));
	if (id < 0)
		return -id;

	b = __pthread_object_of(id);

	b->waiters = 0;
	b->threshold = count;
	memcpy(&b->attr, attr ? attr : &dattr, sizeof(dattr));

	__pthread_waitqueue_init(&b->wq);

	b->wq.mutex.attr.type = PTHREAD_MUTEX_RECURSIVE;

	*barrier = id;
	return 0;
}

int pthread_barrier_destroy(pthread_barrier_t *barrier)
{
	if (barrier) {
		int id = *barrier;
		struct __pthread_barrier *b = NULL;

		b = __pthread_object_of(id);
		if (b)
			return __pthread_object_free(id);
	}

	return EINVAL;
}

int pthread_barrier_wait(pthread_barrier_t *barrier)
{
	struct __pthread_barrier *b = __pthread_object_of(*barrier);

	if (!b)
		return EINVAL;

	pthread_testcancel();

	if (__atomic_add_fetch(&b->waiters, 1,
			__ATOMIC_SEQ_CST) == b->threshold) {
		__atomic_exchange_n(&b->waiters, 0, __ATOMIC_ACQUIRE);
		__pthread_wakeup_nr(&b->wq, b->threshold, NULL);

		return PTHREAD_BARRIER_SERIAL_THREAD;
	}

	__pthread_mutex_lock(&b->wq.mutex);
	__pthread_wait(&b->wq, &b->wq.mutex, NULL);

	return 0;
}
