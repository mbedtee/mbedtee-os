/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * wait()/wait_event()/wakeup() implementation
 */

#ifndef _WAIT_H
#define _WAIT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <trace.h>
#include <atomic.h>
#include <list.h>
#include <stdbool.h>
#include <spinlock.h>
#include <thread_info.h>

struct waitqueue {
	/*
	 * internal condition variable.
	 *
	 * introduced to fix the misordered
	 * wait()/wakeup() sequence
	 */
	int condi;

	struct spinlock lock;

	/* notification to the waiters */
	long notification;

	struct list_head list;
	struct list_head wakelist;
};

struct waitqueue_node {
	/* waiter's thread ID */
	int id;

	/* for debug purpose */
	int linenr;
	const char *fnname;

	/* belong to which waitqueue */
	struct waitqueue *wq;

	/* wakeup function */
	void (*wake)(struct waitqueue_node *wqnode);

	/* node @ the waitqueue's list */
	struct list_head node;

	/* node @ the thread's list for cleanup purpose */
	struct list_head tnode;

	/* private data */
	void *priv;

	struct atomic_num refcnt;
};

#define DEFAULT_WAITQ(x) {		   \
	0, SPIN_LOCK_INIT(0), 0,	   \
	LIST_HEAD_INIT((x).list),	   \
	LIST_HEAD_INIT((x).wakelist),  \
}

#define DECLARE_DEFAULT_WAITQ(name) \
	struct waitqueue name = DEFAULT_WAITQ(name)

/*
 * Wake up threads blocked on a waiting queue.
 * If @match_priv is not NULL, only wake nodes whose priv matches it.
 */
void __wakeup(struct waitqueue *waitq, void *match_priv);
/*
 * Wake up a thread blocked on a waiting queue.
 */
void __wakeup_node(struct waitqueue_node *n);

/*
 * flush a wait queue, blocked if the old waiter
 * is not completely waked up yet.
 */
#define waitqueue_flush(waitq)									\
	do {														\
	/* final confirm if the queue is using by any one else */	\
		unsigned long __flags = 0;								\
		spin_lock_irqsave(&(waitq)->lock, __flags);				\
		while (!list_empty(&(waitq)->list) ||					\
			   !list_empty(&(waitq)->wakelist)) {				\
			spin_unlock(&(waitq)->lock);						\
			usleep(5000);										\
			spin_lock(&(waitq)->lock);							\
		}														\
		spin_unlock_irqrestore(&(waitq)->lock, __flags);		\
	} while (0)

/*
 * init a wait queue.
 */
#define waitqueue_init(waitq)						\
	do {											\
		INIT_LIST_HEAD(&(waitq)->list);				\
		INIT_LIST_HEAD(&(waitq)->wakelist);			\
		spin_lock_init(&(waitq)->lock);				\
		(waitq)->condi = false;						\
		(waitq)->notification = 0;					\
	} while (0)

/*
 * init a wait queue node.
 */
#define waitqueue_node_init(n)						\
	do {											\
		(n)->id = 0;								\
		(n)->priv = NULL;							\
		(n)->wake = NULL;							\
		(n)->linenr = 0;							\
		(n)->fnname = NULL;							\
		(n)->wq = NULL;								\
		atomic_set(&(n)->refcnt, 1);				\
		INIT_LIST_HEAD(&(n)->node);					\
		INIT_LIST_HEAD(&(n)->tnode);				\
	} while (0)

#define waitqueue_node_get(n)						\
	atomic_inc(&(n)->refcnt)

#define waitqueue_node_put(n)						\
	atomic_dec_return(&(n)->refcnt)

/*
 * Wait for any in-flight wake callback to finish.
 *
 * NOTE: This will sleep, so must NOT be called under a spinlock.
 */
#define waitqueue_node_release(n)					\
	do {											\
		if (waitqueue_node_put(n) != 0) {			\
			while (atomic_read(&(n)->refcnt) != 0)	\
				usleep(2000);						\
		}											\
	} while (0)

/*
 * Delete from waitqueue and wait for any in-flight wake callback
 * to finish before the node can be freed.
 *
 * NOTE: This will sleep, so must NOT be called under a spinlock.
 */
#define waitqueue_node_del_release(n)						\
	do {													\
		unsigned long __flags = 0;							\
		struct waitqueue *__wq = (n)->wq;					\
		if (__wq)  {										\
			spin_lock_irqsave(&__wq->lock, __flags);		\
			(n)->wq = NULL;									\
			(n)->wake = NULL;								\
			list_del(&(n)->node);							\
			list_del(&(n)->tnode);							\
			spin_unlock_irqrestore(&__wq->lock, __flags);	\
		}													\
		waitqueue_node_release(n);							\
	} while (0)

/*
 * Wake up all threads blocked on a waiting queue.
 */
#define wakeup(waitq) __wakeup((waitq), NULL)

/*
 * Wake up all threads blocked on a waiting queue.
 *
 * The notification will be sent to all the waiters,
 * waiters can get it from the return value of
 * wait() or wait_event() etc.
 */
#define wakeup_notify(waitq, notify)								\
	do {															\
		(waitq)->notification = (long)(notify);						\
		wakeup(waitq);												\
	} while (0)

/*
 * Prepare and enqueue a waitqueue node with a custom wake callback.
 * Used by poll/epoll. Must be called with waitqueue spinlock HELD.
 */
#define waitqueue_node_enqueue(waitq, n, wakefn, privdata)			\
	do {															\
		(n)->wq = (waitq);											\
		(n)->id = current_id;										\
		(n)->wake = (wakefn);										\
		(n)->priv = (void *)(privdata);								\
		atomic_set(&(n)->refcnt, 1);								\
		(n)->linenr = __LINE__;										\
		(n)->fnname = __func__;										\
		INIT_LIST_HEAD(&(n)->tnode);								\
		list_add_tail(&(n)->node, &(waitq)->list);					\
	} while (0)

struct mutex;

/*
 * Prepare a wait node and lock the waitqueue.
 * Returns with the waitqueue spinlock HELD.
 */
unsigned long __wait_prepare(struct waitqueue *waitq,
	struct waitqueue_node *n, void *priv);

/*
 * Sleep once on a waitqueue (with optional mutex release).
 * Called with spinlock HELD. Returns with spinlock HELD.
 * Returns 0 to continue waiting, non-zero to break (signal pending).
 */
int __wait_sleep(struct waitqueue *waitq, struct waitqueue_node *n,
	struct mutex *mlock, int interruptible);

/*
 * Sleep once on a waitqueue with timeout (with optional mutex release).
 * Called with spinlock HELD. Returns with spinlock HELD.
 * Sets *remain to the remaining microseconds.
 * Returns 0 to continue waiting, non-zero to break (signal pending).
 */
int __wait_sleep_timeout(struct waitqueue *waitq, struct waitqueue_node *n,
	struct mutex *mlock, int interruptible, uint64_t *remain);

/*
 * Finish a non-timeout wait: cleanup, unlock, refcnt wait.
 * Called with spinlock HELD. Releases the spinlock.
 * condi: result of the condition expression (nonzero = condition met).
 * Returns waitq->notification on success, -EINTR if interrupted.
 */
long __wait_finish(struct waitqueue *waitq, struct waitqueue_node *n,
	long condi, unsigned long flags);

/*
 * Finish a timeout wait: cleanup, unlock, refcnt wait.
 * Called with spinlock HELD. Releases the spinlock.
 * condi: result of the condition expression (nonzero = condition met).
 * Returns remaining usecs (>= 1) if condition met before timeout,
 * 1 if met exactly at timeout, 0 if timeout elapsed,
 * -EINTR if interrupted by signal.
 */
long __wait_finish_timeout(struct waitqueue *waitq, struct waitqueue_node *n,
	long condi, unsigned long flags, uint64_t remain);

/*
 * Base wait macro (no timeout).
 * condition: C expression evaluated under waitqueue spinlock.
 * priv: optional private data for selective wakeup matching.
 * interruptible: if true, signals can break the wait.
 *
 * Returns waitq->notification on success, -EINTR if interrupted.
 */
#define __wait_event(waitq, condition, priv, interruptible)				\
({																		\
	struct waitqueue_node __n;											\
	long __condi = 0;													\
	unsigned long __flags = __wait_prepare(waitq, &__n, priv);			\
	__n.linenr = __LINE__;												\
	__n.fnname = __func__;												\
	while (!(__condi = (condition)))									\
		if (__wait_sleep(waitq, &__n, NULL, interruptible)) 			\
			break;														\
	__wait_finish(waitq, &__n, __condi, __flags);						\
})

/*
 * Base timed wait macro (with timeout).
 * Returns remaining usecs (>= 1) if condition met before timeout,
 * 1 if condition met exactly at timeout, 0 if timeout elapsed,
 * -EINTR if interrupted by signal (interruptible only).
 */
#define __wait_event_timeout(waitq, condition, timeout, priv,			\
		interruptible)													\
({																		\
	uint64_t __remain = (timeout);										\
	struct waitqueue_node __n;											\
	long __condi = 0;													\
	unsigned long __flags = __wait_prepare(waitq, &__n, priv);			\
	__n.linenr = __LINE__;												\
	__n.fnname = __func__;												\
	while (!(__condi = (condition)) && __remain)						\
		if (__wait_sleep_timeout(waitq, &__n, NULL,						\
				interruptible, &__remain))								\
			break;														\
	__wait_finish_timeout(waitq, &__n, __condi, __flags, __remain);		\
})

/*
 * Base locked wait macro (with mutex, no timeout).
 * mlock: mutex released during sleep and re-acquired after.
 */
#define __wait_event_locked(waitq, condition, mlock, priv, intr)		\
({																		\
	struct waitqueue_node __n;											\
	long __condi = 0;													\
	unsigned long __flags = __wait_prepare(waitq, &__n, priv);			\
	__n.linenr = __LINE__;												\
	__n.fnname = __func__;												\
	while (!(__condi = (condition)))									\
		if (__wait_sleep(waitq, &__n, mlock, intr))						\
			break;														\
	__wait_finish(waitq, &__n, __condi, __flags);						\
})

/*
 * Base locked timed wait macro (with mutex + timeout).
 */
#define __wait_event_timeout_locked(waitq, condition, timeout,			\
		mlock, priv, interruptible)										\
({																		\
	uint64_t __remain = (timeout);										\
	struct waitqueue_node __n;											\
	long __condi = 0;													\
	unsigned long __flags = __wait_prepare(waitq, &__n, priv);			\
	__n.linenr = __LINE__;												\
	__n.fnname = __func__;												\
	while (!(__condi = (condition)) && __remain)						\
		if (__wait_sleep_timeout(waitq, &__n, mlock,					\
				interruptible, &__remain))								\
			break;														\
	__wait_finish_timeout(waitq, &__n, __condi, __flags, __remain);		\
})

/* Internal condition (waitq->condi) */
#define wait(waitq) \
	__wait_event(waitq, (waitq)->condi, NULL, false)

#define wait_interruptible(waitq) \
	__wait_event(waitq, (waitq)->condi, NULL, true)

/* External condition */
#define wait_event(waitq, condition) \
	__wait_event(waitq, condition, NULL, false)

#define wait_event_interruptible(waitq, condition) \
	__wait_event(waitq, condition, NULL, true)

/* External condition with priv for selective wakeup */
#define wait_event_priv_interruptible(waitq, condition, priv)		\
	__wait_event(waitq, condition, priv, true)

/* Timed wait - internal condition */
#define wait_timeout(waitq, timeout)								\
	__wait_event_timeout(waitq, (waitq)->condi, timeout, NULL, false)

#define wait_timeout_interruptible(waitq, timeout)					\
	__wait_event_timeout(waitq, (waitq)->condi, timeout, NULL, true)

/* Timed wait - external condition */
#define wait_event_timeout(waitq, condition, timeout)				\
	__wait_event_timeout(waitq, condition, timeout, NULL, false)

#define wait_event_timeout_interruptible(waitq, condition, timeout)	\
	__wait_event_timeout(waitq, condition, timeout, NULL, true)

/* Timed wait - external condition with priv for selective wakeup */
#define wait_event_timeout_priv_interruptible(waitq, condition,		\
		timeout, priv)												\
	__wait_event_timeout(waitq, condition, timeout, priv, true)

/* Locked wait - internal condition */
#define wait_locked(waitq, mlock)									\
	__wait_event_locked(waitq, (waitq)->condi, mlock, NULL, false)

#define wait_locked_interruptible(waitq, mlock)						\
	__wait_event_locked(waitq, (waitq)->condi, mlock, NULL, true)

/* Locked wait - external condition */
#define wait_event_locked(waitq, condition, mlock)					\
	__wait_event_locked(waitq, condition, mlock, NULL, false)

#define wait_event_locked_interruptible(waitq, condition, mlock)	\
	__wait_event_locked(waitq, condition, mlock, NULL, true)

/* Locked timed wait - external condition */
#define wait_event_timeout_locked(waitq, condition, timeout, mlock) \
	__wait_event_timeout_locked(waitq, condition, timeout,			\
		mlock, NULL, false)

#define wait_event_timeout_locked_interruptible(waitq, condition,	\
		timeout, mlock)												\
	__wait_event_timeout_locked(waitq, condition, timeout,			\
		mlock, NULL, true)

/* Locked timed wait - internal condition */
#define wait_timeout_locked(waitq, timeout, mlock)					\
	__wait_event_timeout_locked(waitq, (waitq)->condi, timeout,		\
		mlock, NULL, false)

#define wait_timeout_locked_interruptible(waitq, timeout, mlock)	\
	__wait_event_timeout_locked(waitq, (waitq)->condi, timeout,		\
		mlock, NULL, true)

#ifdef __cplusplus
}
#endif

#endif
