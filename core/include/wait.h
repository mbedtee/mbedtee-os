/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * wait()/wait_event()/wakeup() implementation
 */

#ifndef _WAIT_H
#define _WAIT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <trace.h>
#include <spinlock.h>
#include <thread_info.h>
#include <list.h>
#include <stdbool.h>

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
};

#define DEFAULT_WAITQ(x) {		   \
	0, SPIN_LOCK_INIT(0), 0,	   \
	LIST_HEAD_INIT((x).list),	   \
	LIST_HEAD_INIT((x).wakelist),  \
}

#define DECLARE_DEFAULT_WAITQ(name) \
	struct waitqueue name = DEFAULT_WAITQ(name)

/*
 * Wake up all threads blocked on a waiting queue.
 */
void __wakeup(struct waitqueue *waitq);
/*
 * Wake up a thread blocked on a waiting queue.
 */
void __wakeup_node(struct waitqueue_node *n);

/*
 * init a wait queue.
 */
#define waitqueue_init(waitq)					\
	do {										\
		INIT_LIST_HEAD(&(waitq)->list);			\
		INIT_LIST_HEAD(&(waitq)->wakelist);		\
		spin_lock_init(&(waitq)->lock);			\
		(waitq)->condi = false;					\
		(waitq)->notification = 0;				\
	} while (0)

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

#define waitqueue_node_del(n)										\
	do {															\
		if (!list_empty(&(n)->node) || !list_empty(&(n)->tnode))  {	\
			unsigned long __flags = 0;								\
			spin_lock_irqsave(&(n)->wq->lock, __flags);				\
			list_del(&(n)->node);									\
			list_del(&(n)->tnode);									\
			spin_unlock_irqrestore(&(n)->wq->lock, __flags);		\
		}															\
	} while (0)

/*
 * init a wait queue node.
 */
#define waitqueue_node_init(n)			\
	do {								\
		(n)->id = 0;					\
		(n)->priv = NULL;				\
		(n)->wake = NULL;				\
		(n)->linenr = 0;				\
		(n)->fnname = NULL;				\
		(n)->wq = NULL;					\
		INIT_LIST_HEAD(&(n)->node);		\
		INIT_LIST_HEAD(&(n)->tnode);	\
	} while (0)

/*
 * Wake up all threads blocked on a waiting queue.
 */
#define wakeup(waitq) __wakeup(waitq)

/*
 * Wake up all threads blocked on a waiting queue.
 *
 * The notification will be sent to all the waiters,
 * waiters can get it from the return value of
 * wait() or wait_event() etc.
 */
#define wakeup_notify(waitq, notify)			\
	do {										\
		(waitq)->notification = (long)(notify);	\
		wakeup(waitq);							\
	} while (0)

#define __prepare_node(waitq, n, wakefn, privdata)			\
	do {													\
		(n)->wq = (waitq);									\
		(n)->id = __curr->id;								\
		(n)->wake = (wakefn);								\
		(n)->priv = (void *)(privdata);						\
		INIT_LIST_HEAD(&(n)->node);							\
		INIT_LIST_HEAD(&(n)->tnode);						\
		(n)->linenr = __LINE__;								\
		(n)->fnname = __func__;								\
	} while (0)

#define __prepare_wait(waitq, n, interruptible, condition)		\
	do {														\
		if (!(condition)) {										\
			list_move_tail(&(n)->node, &(waitq)->list);			\
			if ((interruptible) && list_empty(&(n)->tnode))		\
				list_add_tail(&(n)->tnode, &__curr->wqnodes);	\
			sched_wait();										\
			spin_unlock(&(waitq)->lock);						\
			thread_schedule(__curr, interruptible);				\
			spin_lock(&(waitq)->lock);							\
		}														\
	} while (0)

#define __prepare_ret(waitq, n)								\
	do {													\
		if ((waitq)->condi)									\
			(waitq)->condi--;								\
		list_del(&(n)->node);								\
		list_del(&(n)->tnode);								\
	} while (0)

#define __wait_event(waitq, condition, priv, interruptible)		\
({																\
	long __condi;												\
	unsigned long __flags;										\
	struct waitqueue_node __n;									\
	struct thread *__curr = current;							\
	spin_lock_irqsave(&(waitq)->lock, __flags);					\
	__prepare_node(waitq, &__n, __wakeup_node, priv);			\
	do {														\
		__condi = (condition);									\
		__prepare_wait(waitq, &__n, interruptible, __condi);	\
	} while (!__condi);											\
	__prepare_ret(waitq, &__n);									\
	spin_unlock_irqrestore(&(waitq)->lock, __flags);			\
	(waitq)->notification;										\
})

/*
 * Put the calling thread in a waiting queue.
 * wake up depends on the queue-internal condition, internal condition
 * is introduced to fix the misordered wait/wakeup sequence.
 *
 * return the 'notification' from the wakeup_notify(), if the wakeup() is used,
 * this return value should not be referenced by the waiters.
 */
#define wait(waitq) \
	__wait_event(waitq, (waitq)->condi, NULL, false)

#define wait_interruptible(waitq) \
	__wait_event(waitq, (waitq)->condi, NULL, true)

/*
 * Put the calling thread in a waiting queue.
 * The thread will be woken up after the external
 * condition is evaluated to true.
 *
 * return the 'notification' from the wakeup_notify(), if the wakeup() is used,
 * this return value should not be referenced by the waiters.
 */
#define wait_event(waitq, condition) \
	__wait_event(waitq, condition, NULL, false)

#define wait_event_interruptible(waitq, condition) \
	__wait_event(waitq, condition, NULL, true)

#define __prepare_timedwait(waitq, n, condition, usecs, intr)			\
	do {																\
		if (!(condition) && (usecs)) {									\
			list_move_tail(&(n)->node, &(waitq)->list);					\
			if ((intr) && list_empty(&(n)->tnode))						\
				list_add_tail(&(n)->tnode, &__curr->wqnodes);			\
			usecs = sched_timeout_locked(&(waitq)->lock, usecs, intr);	\
		}																\
	} while (0)

/*
 * Put the calling thread in a waiting queue.
 * The calling thread will be woken up after the external
 * condition is evaluated to true.
 *
 * Returns:
 * 0 if the condition evaluated to false after the timeout elapsed,
 * 1 if the condition evaluated to true after the timeout elapsed,
 * or the remaining microseconds (at least 1) if the condition evaluated
 * to true before the timeout elapsed.
 */
#define __wait_event_timeout(waitq, condition, timeout, priv, interruptible)	\
({																				\
	long __condi;																\
	unsigned long __flags;														\
	struct waitqueue_node __n;													\
	uint64_t __timedret = (timeout);											\
	struct thread *__curr = current;											\
	spin_lock_irqsave(&(waitq)->lock, __flags);									\
	__prepare_node(waitq, &__n, __wakeup_node, priv);							\
	do {																		\
		__condi = (condition);													\
		__prepare_timedwait(waitq, &__n, __condi, __timedret, interruptible);	\
	} while (!__condi && __timedret);											\
	if (!__condi)																\
		__condi = (condition);													\
	__prepare_ret(waitq, &__n);													\
	spin_unlock_irqrestore(&(waitq)->lock, __flags);							\
	if (__condi && !__timedret)													\
		__timedret = 1;															\
	__timedret;																	\
})

#define wait_event_timeout(waitq, condition, timeout) \
	__wait_event_timeout(waitq, condition, timeout, NULL, false)

#define wait_event_timeout_interruptible(waitq, condition, timeout) \
	__wait_event_timeout(waitq, condition, timeout, NULL, true)

#define wait_timeout(waitq, timeout) \
	__wait_event_timeout(waitq, (waitq)->condi, timeout, NULL, false)

#define wait_timeout_interruptible(waitq, timeout) \
	__wait_event_timeout(waitq, (waitq)->condi, timeout, NULL, true)

#define __prepare_wait_locked(waitq, n, mlock, intr, condition)		\
	do {															\
		if (!(condition)) {											\
			list_move_tail(&(n)->node, &(waitq)->list);				\
			if ((intr) && list_empty(&(n)->tnode))					\
				list_add_tail(&(n)->tnode, &__curr->wqnodes);		\
			sched_wait();											\
			spin_unlock(&(waitq)->lock);							\
			mutex_unlock(mlock);									\
			thread_schedule(__curr, intr);							\
			mutex_lock(mlock);										\
			spin_lock(&(waitq)->lock);								\
		}															\
	} while (0)

#define __wait_event_locked(waitq, condition, mlock, priv, intr)	\
({																	\
	long __condi;													\
	unsigned long __flags;											\
	struct waitqueue_node __n;										\
	struct thread *__curr = current;								\
	spin_lock_irqsave(&(waitq)->lock, __flags);						\
	__prepare_node(waitq, &__n, __wakeup_node, priv);				\
	do {															\
		__condi = (condition);										\
		__prepare_wait_locked(waitq, &__n, mlock, intr, __condi);	\
	} while (!__condi);												\
	__prepare_ret(waitq, &__n);										\
	spin_unlock_irqrestore(&(waitq)->lock, __flags);				\
	(waitq)->notification;											\
})

/*
 * Put the calling thread in a waiting queue.
 * wake up depends on the queue-internal condition, internal condition
 * is introduced to fix the misordered wait/wakeup sequence.
 *
 * A mutex lock is introduced for critical resource protection. mlock shall
 * be held before calling this function, it will be released before sleep and
 * will be re-acquired after sleep.
 *
 * return the 'notification' from the wakeup_notify(), if the wakeup() is used,
 * this return value should not be referenced by the waiters.
 */
#define wait_locked(waitq, mlock) \
	__wait_event_locked(waitq, (waitq)->condi, mlock, NULL, false)

#define wait_locked_interruptible(waitq, mlock) \
	__wait_event_locked(waitq, (waitq)->condi, mlock, NULL, true)

#define wait_event_locked(waitq, condition, mlock) \
	__wait_event_locked(waitq, condition, mlock, NULL, false)

#define wait_event_locked_interruptible(waitq, condition, mlock) \
	__wait_event_locked(waitq, condition, mlock, NULL, true)


#define __prepare_timedwait_locked(waitq, n, mlock, condition, usecs, intr)			\
	do {																			\
		if ((!(condition)) && (usecs)) {											\
			list_move_tail(&(n)->node, &(waitq)->list);								\
			if ((intr) && list_empty(&(n)->tnode))									\
				list_add_tail(&(n)->tnode, &__curr->wqnodes);						\
			usecs = sched_timeout_mutex_locked(mlock, &(waitq)->lock, usecs, intr);	\
		}																			\
	} while (0)

/*
 * Put the calling thread in a waiting queue.
 * The calling thread will be woken up after the external
 * condition is evaluated to true.
 *
 * A mutex lock is introduced for critical resource protection. mlock shall
 * be held before calling this function, it will be released before sleep and
 * will be re-acquired after sleep.
 *
 * Returns:
 * 0 if the condition evaluated to false after the timeout elapsed,
 * 1 if the condition evaluated to true after the timeout elapsed,
 * or the remaining microseconds (at least 1) if the condition evaluated
 * to true before the timeout elapsed.
 */
#define __wait_event_timeout_locked(waitq, condition, timeout, mlock, priv, interruptible)	\
({																							\
	long __condi;																			\
	unsigned long __flags;																	\
	struct waitqueue_node __n;																\
	uint64_t __timedret = (timeout);														\
	struct thread *__curr = current;														\
	spin_lock_irqsave(&(waitq)->lock, __flags);												\
	__prepare_node(waitq, &__n, __wakeup_node, priv);										\
	do {																					\
		__condi = (condition);																\
		__prepare_timedwait_locked(waitq, &__n, mlock, __condi, __timedret, interruptible);	\
	} while (!__condi && __timedret);														\
	if (!__condi)																			\
		__condi = (condition);																\
	__prepare_ret(waitq, &__n);																\
	spin_unlock_irqrestore(&(waitq)->lock, __flags);										\
	if (__condi && !__timedret)																\
		__timedret = 1;																		\
	__timedret;																				\
})

#define wait_event_timeout_locked(waitq, condition, timeout, mlock) \
	__wait_event_timeout_locked(waitq, condition, timeout, mlock, NULL, false)

#define wait_event_timeout_locked_interruptible(waitq, condition, timeout, mlock) \
	__wait_event_timeout_locked(waitq, condition, timeout, mlock, NULL, true)

#define wait_timeout_locked(waitq, timeout, mlock) \
	__wait_event_timeout_locked(waitq, (waitq)->condi, timeout, mlock, NULL, false)

#define wait_timeout_locked_interruptible(waitq, timeout, mlock) \
	__wait_event_timeout_locked(waitq, (waitq)->condi, timeout, mlock, NULL, true)

#endif
