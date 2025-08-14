// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * pthread conditional wait
 */

#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <syscall.h>

#include "pthread_wait.h"
#include "pthread_waitdep.h"
#include "pthread_auxiliary.h"

/*
 * Wake up the first thread blocked @q
 * @notification will be sent to the waiters
 */
int __pthread_wakeup(struct __pthread_waitqueue *q,
	void *notification)
{
	int ret = 0;
	struct __pthread_waitqueue_node *n = NULL;

	__pthread_mutex_lock(&q->mutex);
	q->notification = notification;
	n = list_first_entry_or_null(&q->list, struct
			__pthread_waitqueue_node, node);

	if (n) {
		if (q->condi >= 0)
			q->condi++;
		list_move_tail(&n->node, &q->wakelist);
		ret = __pthread_sys_wake(n->id);
	} else {
		if (q->condi >= 0)
			q->condi = 1;
	}
	__pthread_mutex_unlock(&q->mutex);

	return ret;
}

/*
 * Wake up all the threads blocked @q
 * @notification will be sent to the waiters
 */
int __pthread_wakeup_all(struct __pthread_waitqueue *q,
	void *notification)
{
	struct __pthread_waitqueue_node *n = NULL;
	struct __pthread_waitqueue_node *_n = NULL;

	__pthread_mutex_lock(&q->mutex);
	q->notification = notification;
	if (!list_empty(&q->list)) {
		list_for_each_entry_safe(n, _n, &q->list, node) {
			if (q->condi >= 0)
				q->condi++;
			list_move_tail(&n->node, &q->wakelist);
			__pthread_sys_wake(n->id);
		}
	} else {
		if (q->condi >= 0)
			q->condi = 1;
	}
	__pthread_mutex_unlock(&q->mutex);

	return 0;
}

/*
 * Wake up all the threads blocked @q
 * @notification will be sent to the waiters
 *
 * no threads will be blocked in this waitqueue any more
 */
int __pthread_wakeup_dissolved(struct __pthread_waitqueue *q,
	void *notification)
{
	struct __pthread_waitqueue_node *n = NULL;
	struct __pthread_waitqueue_node *_n = NULL;

	__pthread_mutex_lock(&q->mutex);
	q->notification = notification;
	q->condi = -(INT_MAX >> 1);
	list_for_each_entry_safe(n, _n, &q->list, node) {
		list_move_tail(&n->node, &q->wakelist);
		__pthread_sys_wake(n->id);
	}
	__pthread_mutex_unlock(&q->mutex);

	return 0;
}

/*
 * Wake up nr threads blocked @q
 * @notification will be sent to the waiters
 */
int __pthread_wakeup_nr(struct __pthread_waitqueue *q,
	unsigned long nr, void *notification)
{
	unsigned long count = 0;
	struct __pthread_waitqueue_node *n = NULL;
	struct __pthread_waitqueue_node *_n = NULL;

	__pthread_mutex_lock(&q->mutex);
	q->notification = notification;
	if (q->condi >= 0)
		q->condi += nr;
	list_for_each_entry_safe(n, _n, &q->list, node) {
		if (count >= nr)
			break;
		list_move_tail(&n->node, &q->wakelist);
		__pthread_sys_wake(n->id);
		count++;
	}

	__pthread_mutex_unlock(&q->mutex);

	return 0;
}

/*
 * flush a wait queue, blocked if the old waiter
 * is not completely waked up yet.
 *
 * reclaim a wait queue resource.
 */
void __pthread_waitqueue_flush(struct __pthread_waitqueue *q)
{
	__pthread_mutex_lock(&q->mutex);
	while (!list_empty(&q->list) ||
		   !list_empty(&q->wakelist)) {
		__pthread_mutex_unlock(&q->mutex);
		usleep(5000);
		__pthread_mutex_lock(&q->mutex);
	}
	__pthread_mutex_unlock(&q->mutex);
}

/*
 * Put the calling thread to a waiting queue.
 *
 * @notification is the join_ret value
 * from the waitqueue owner who wakes us.
 *
 * Note: mutex will be released !!!
 */
int __pthread_wait(struct __pthread_waitqueue *q,
	struct __pthread_mutex *m, void **notification)
{
	struct __pthread_aux *aux = pthread_aux(__pthread_self);
	struct __pthread_waitqueue_node n;

	__pthread_mutex_lock(&q->mutex);

	__pthread_mutex_unlock(m);

	__pthread_waitqueue_node_init(&n);

	while (q->condi == 0) {
		n.waitq = q;
		n.id = gettid();

		list_move_tail(&n.node, &q->list);
		if (list_empty(&n.tnode))
			list_add_tail(&n.tnode, &aux->wqnodes);
		__pthread_mutex_unlock(&q->mutex);

		__pthread_sys_wait(0);

		__pthread_mutex_lock(&q->mutex);
	}

	if (q->condi > 0)
		q->condi--;

	list_del(&n.node);
	list_del(&n.tnode);

	if (notification)
		*notification = q->notification;
	__pthread_mutex_unlock(&q->mutex);

	return 0;
}

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
	struct __pthread_mutex *m, void **notification, long usecs)
{
	long remain = usecs, ret = 0;
	struct __pthread_aux *aux = pthread_aux(__pthread_self);
	struct __pthread_waitqueue_node n;

	if (usecs <= 0)
		return 0;

	__pthread_mutex_lock(&q->mutex);

	__pthread_mutex_unlock(m);

	__pthread_waitqueue_node_init(&n);

	while (q->condi == 0 && remain != 0) {
		n.waitq = q;
		n.id = gettid();

		list_move_tail(&n.node, &q->list);
		if (list_empty(&n.tnode))
			list_add_tail(&n.tnode, &aux->wqnodes);
		__pthread_mutex_unlock(&q->mutex);

		ret = __pthread_sys_wait(remain);

		if (ret >= 0)
			remain = ret;
		/* EINTR: keep remain unchanged for retry */

		__pthread_mutex_lock(&q->mutex);
	}

	if (q->condi > 0) {
		q->condi--;

		if (remain == 0)
			remain = 1;
	}

	list_del(&n.node);
	list_del(&n.tnode);

	if (notification)
		*notification = q->notification;
	__pthread_mutex_unlock(&q->mutex);

	return remain;
}
