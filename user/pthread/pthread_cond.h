/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * internal APIs of pthread conditional synchronization
 */

#ifndef _PTHREAD_COND_H
#define	_PTHREAD_COND_H

#include <__pthread.h>

int	__pthread_cond_signal(pthread_cond_t *cond,
	void *notification);

int	__pthread_cond_broadcast(pthread_cond_t *cond,
	void *notification);

int	__pthread_cond_wait(pthread_cond_t *cond,
	pthread_mutex_t *mutex,	void **notification);

int	__pthread_cond_timedwait(pthread_cond_t *cond,
	pthread_mutex_t *mutex,	const struct timespec *abstime,
	void **notification);

#endif
