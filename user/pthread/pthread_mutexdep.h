/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread internal mutex dependences
 */

#ifndef _PTHREAD_MUTEXDEP_H
#define	_PTHREAD_MUTEXDEP_H

#include <sched.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <list.h>

#define MUTEX_INVALID_PSHARE(pshare) \
	((pshare) != PTHREAD_PROCESS_PRIVATE)

#define MUTEX_INVALID_TYPE(type) \
	(((type) != PTHREAD_MUTEX_NORMAL) && \
	((type) != PTHREAD_MUTEX_RECURSIVE) && \
	((type) != PTHREAD_MUTEX_ERRORCHECK) && \
	((type) != PTHREAD_MUTEX_DEFAULT))

#define MUTEX_INVALID_PROTOCOL(protocol) \
	(((protocol) != PTHREAD_PRIO_NONE) && \
	((protocol) != PTHREAD_PRIO_INHERIT) && \
	((protocol) != PTHREAD_PRIO_PROTECT))

#define MUTEX_INVALID_PRIOCEILING(ceiling) \
	(((ceiling) > sched_get_priority_max(SCHED_FIFO)) || \
	((ceiling) < sched_get_priority_min(SCHED_FIFO)))

#define MUTEX_STATE_NORMAL			(0)
#define MUTEX_STATE_EOWNERDEAD		(1)
#define MUTEX_STATE_ENOTRECOVERABLE	(2)

#define DEFAULT_PTHREAD_MUTEX_ATTR { \
	true, PTHREAD_PROCESS_PRIVATE, \
	39, PTHREAD_PRIO_NONE, \
	PTHREAD_MUTEX_NORMAL, 0 \
}
#define RECURSIVE_PTHREAD_MUTEX_ATTR { \
	true, PTHREAD_PROCESS_PRIVATE, \
	39, PTHREAD_PRIO_NONE, \
	PTHREAD_MUTEX_RECURSIVE, 0 \
}

#define DEFAULT_PTHREAD_MUTEX(x) { \
	MUTEX_STATE_NORMAL, \
	0, 0, 0, \
	DEFAULT_PTHREAD_MUTEX_ATTR, \
	LIST_HEAD_INIT((x).node), \
}

#define RECURSIVE_PTHREAD_MUTEX(x) { \
	MUTEX_STATE_NORMAL, \
	0, 0, 0, \
	RECURSIVE_PTHREAD_MUTEX_ATTR, \
	LIST_HEAD_INIT((x).node), \
}

#define DECLARE_DEFAULT_PTHREAD_MUTEX_ATTR(name) \
	pthread_mutexattr_t name = DEFAULT_PTHREAD_MUTEX_ATTR

#define DECLARE_DEFAULT_PTHREAD_MUTEX(name) \
	struct __lock name = DEFAULT_PTHREAD_MUTEX(name)
#define DECLARE_RECURSIVE_PTHREAD_MUTEX(name) \
	struct __lock name = RECURSIVE_PTHREAD_MUTEX(name)

/*
 * essentially we should define the name to 'struct __pthread_mutx'
 * but in order to adapt to newlib retarget lock, we have to define
 * the name to 'struct __lock'
 */
struct __lock {
	/* current state */
	uint32_t state;
	/* lock variable */
	uint32_t lock;
	/* recursive count */
	uint32_t rc;
	/* current owner thread */
	pthread_t owner;

	/* attributes */
	pthread_mutexattr_t attr;
	/* node in the __pthread's mutex list */
	struct list_head node;
};

typedef struct __lock __pthread_mutex_t;

int	__pthread_mutex_init(__pthread_mutex_t *m,
	const pthread_mutexattr_t *attr);
int	__pthread_mutex_destroy(__pthread_mutex_t *m);
int __pthread_mutex_lock(__pthread_mutex_t *m);
int	__pthread_mutex_trylock(__pthread_mutex_t *m);
int	__pthread_mutex_unlock(__pthread_mutex_t *m);
int	__pthread_mutex_timedlock(__pthread_mutex_t *m,
	const struct timespec *abstime);

#endif
