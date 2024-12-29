/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread conditional wait
 */

#ifndef _PTHREAD_WAIT_H
#define _PTHREAD_WAIT_H

#include <list.h>

#include <pthread.h>

#include "pthread_mutexdep.h"

struct __pthread_waitqueue {
	/*
	 * internal condition variable.
	 *
	 * introduced to fix the misordered
	 * wait()/wakeup() sequence
	 */
	int condi;
	/* notification to the waiters */
	void *notification;
	__pthread_mutex_t mutex;
	struct list_head list;
	struct list_head wakelist;
};

struct __pthread_waitqueue_node {
	/* waiter's thread ID */
	pid_t id;
	/* @ which waitqueue */
	struct __pthread_waitqueue *waitq;
	/* node @ the waitqueue's list */
	struct list_head node;
	/* node @ the thread's list for cleanup purpose */
	struct list_head tnode;
};

/*
 * init a wait queue.
 */
#define __pthread_waitqueue_init(q)					\
	do {											\
		INIT_LIST_HEAD(&(q)->list);					\
		INIT_LIST_HEAD(&(q)->wakelist);				\
		__pthread_mutex_init(&(q)->mutex, NULL);	\
		(q)->condi = false;							\
	} while (0)

/*
 * init a wait queue node.
 */
#define __pthread_waitqueue_node_init(n)			\
	do {											\
		INIT_LIST_HEAD(&(n)->node);					\
		INIT_LIST_HEAD(&(n)->tnode);				\
		(n)->waitq = NULL;							\
		(n)->id = 0;								\
	} while (0)

#define __pthread_waitqueue_node_del(n)								\
	do {															\
		if (!list_empty(&(n)->node) || !list_empty(&(n)->tnode)) {	\
			__pthread_mutex_lock(&((n)->waitq)->mutex);				\
			list_del(&(n)->node);									\
			list_del(&(n)->tnode);									\
			__pthread_mutex_unlock(&((n)->waitq)->mutex);			\
		}															\
	} while (0)

/*
 * flush a wait queue, blocked if the old waiter
 * is not completely waked up yet.
 *
 * recliam a wait queue resource.
 */
#define __pthread_waitqueue_flush(q)								\
	do {															\
		/* final confirm if the queue is using by any one else */	\
		__pthread_mutex_lock(&(q)->mutex);							\
		while (!list_empty(&(q)->list) ||							\
			   !list_empty(&(q)->wakelist)) {						\
			__pthread_mutex_unlock(&(q)->mutex);					\
			usleep(5000);											\
			__pthread_mutex_lock(&(q)->mutex);						\
		}															\
		__pthread_mutex_unlock(&(q)->mutex);						\
	} while (0)

/*
 * Wake up the first thread blocked @q
 * @notification will be sent to the waiters
 */
int __pthread_wakeup(struct __pthread_waitqueue *q,
	void *notification);


/*
 * Wake up all the threads blocked @q
 * @notification will be sent to the waiters
 */
int __pthread_wakeup_all(struct __pthread_waitqueue *q,
	void *notification);

/*
 * Wake up nr threads blocked @q
 * @notification will be sent to the waiters
 */
int __pthread_wakeup_nr(struct __pthread_waitqueue *q,
	unsigned long nr, void *notification);

/*
 * Put the calling thread to a waiting queue.
 *
 * @notification is the join_ret value
 * from the waitqueue owner who wakes us.
 */
long __pthread_wait(struct __pthread_waitqueue *q,
	__pthread_mutex_t *m, void **notification);

/*
 * Put the calling thread to a waiting queue.
 *
 * @notification is the join_ret value
 * from the waitqueue owner who wakes us.
 *
 * Returns:
 * negative if the mutex is invalid, or the calling thread is not the owner.
 * 0 if the condition evaluated to false after the timeout elapsed,
 * 1 if the condition evaluated to true after the timeout elapsed,
 * or the remaining microseconds (at least 1) if the condition evaluated
 * to true before the timeout elapsed.
 */
long __pthread_timedwait(struct __pthread_waitqueue *q,
	__pthread_mutex_t *m, void **notification, long usecs);

#endif
