// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * wait()/wait_event()/wakeup() implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <spinlock.h>
#include <list.h>
#include <sched.h>
#include <wait.h>
#include <mutex.h>
#include <thread.h>
#include <ksignal.h>

static struct waitqueue_node *__wakeup_find_match(
	struct waitqueue *waitq, void *match_priv)
{
	struct waitqueue_node *n = NULL;

	list_for_each_entry(n, &waitq->list, node) {
		if (!match_priv || n->priv == match_priv)
			return n;
	}

	return NULL;
}

/*
 * Wake up threads blocked on a waiting queue.
 */
void __wakeup(struct waitqueue *waitq, void *match_priv)
{
	unsigned long flags = 0;
	struct waitqueue_node *n = NULL;
	void (*wakefn)(struct waitqueue_node *wqnode);

	spin_lock_irqsave(&waitq->lock, flags);

	if (list_empty(&waitq->list)) {
		if (waitq->condi >= 0)
			waitq->condi = 1;
		spin_unlock_irqrestore(&waitq->lock, flags);
		return;
	}

	while ((n = __wakeup_find_match(waitq, match_priv)) != NULL) {
		list_move_tail(&n->node, &waitq->wakelist);
		waitqueue_node_get(n);
		wakefn = n->wake;
		/*
		 * condi is not for the custom wake callbacks
		 * e.g. the callbacks in the poll/epoll
		 */
		if ((wakefn == __wakeup_node) && (waitq->condi >= 0))
			waitq->condi++;

		spin_unlock_irqrestore(&waitq->lock, flags);

		if (wakefn)
			wakefn(n);
		waitqueue_node_put(n);
		spin_lock_irqsave(&waitq->lock, flags);
	}

	spin_unlock_irqrestore(&waitq->lock, flags);
}

/*
 * default wakeup method for each node
 */
void __wakeup_node(struct waitqueue_node *n)
{
	sched_ready(n->id);
}

/*
 * Prepare a wait node and lock the waitqueue.
 * Returns with the waitqueue spinlock HELD.
 */
unsigned long __wait_prepare(struct waitqueue *waitq,
	struct waitqueue_node *n, void *priv)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&waitq->lock, flags);

	n->wq = waitq;
	n->id = current_id;
	n->wake = __wakeup_node;
	n->priv = priv;
	atomic_set(&n->refcnt, 1);
	INIT_LIST_HEAD(&n->node);
	INIT_LIST_HEAD(&n->tnode);

	return flags;
}

/*
 * Sleep once on a waitqueue (with optional mutex release).
 * Called with spinlock HELD. Returns with spinlock HELD.
 * Returns 0 to continue waiting, non-zero to break (signal pending).
 */
int __wait_sleep(struct waitqueue *waitq, struct waitqueue_node *n,
	struct mutex *mlock, int interruptible)
{
	struct thread *curr = current;

	if (interruptible && is_sigpending(curr))
		return -1;

	list_move_tail(&n->node, &waitq->list);
	if (interruptible && list_empty(&n->tnode))
		list_add_tail(&n->tnode, &curr->wqnodes);
	sched_wait();

	if (mlock) {
		spin_unlock(&waitq->lock);
		mutex_unlock(mlock);
		thread_schedule(curr, interruptible);
		mutex_lock(mlock);
		spin_lock(&waitq->lock);
	} else {
		spin_unlock(&waitq->lock);
		thread_schedule(curr, interruptible);
		spin_lock(&waitq->lock);
	}

	if (interruptible && is_sigpending(curr))
		return -1;

	return 0;
}

/*
 * Sleep once on a waitqueue with timeout (with optional mutex release).
 * Called with spinlock HELD. Returns with spinlock HELD.
 * Sets *remain to the remaining microseconds.
 * Returns 0 to continue waiting, non-zero to break (signal pending).
 */
int __wait_sleep_timeout(struct waitqueue *waitq, struct waitqueue_node *n,
	struct mutex *mlock, int interruptible, uint64_t *remain)
{
	struct thread *curr = current;

	if (interruptible && is_sigpending(curr))
		return -1;

	list_move_tail(&n->node, &waitq->list);
	if (interruptible && list_empty(&n->tnode))
		list_add_tail(&n->tnode, &curr->wqnodes);

	if (mlock)
		*remain = sched_timeout_mutex_locked(
			mlock, &waitq->lock, *remain, interruptible);
	else
		*remain = sched_timeout_locked(
			&waitq->lock, *remain, interruptible);

	if (interruptible && is_sigpending(curr))
		return -1;

	return 0;
}

/*
 * Finish a non-timeout wait: cleanup, unlock, refcnt wait.
 * Called with spinlock HELD. Releases spinlock.
 * condi: result of the condition expression (nonzero = condition met).
 * If condi is true, consume wakeup and return notification.
 * If condi is false, the loop was broken by signal - return -EINTR.
 */
long __wait_finish(struct waitqueue *waitq, struct waitqueue_node *n,
	long condi, unsigned long flags)
{
	long notif = 0;

	list_del(&n->node);
	list_del(&n->tnode);

	if (condi) {
		notif = waitq->notification;
		if (waitq->condi > 0)
			waitq->condi--;
	} else {
		notif = -EINTR;
	}

	spin_unlock_irqrestore(&waitq->lock, flags);

	/* wait for any in-flight wakeup callback */
	waitqueue_node_release(n);

	return notif;
}

/*
 * Finish a timeout wait: cleanup, unlock, refcnt wait.
 * Called with spinlock HELD. Releases spinlock.
 * condi: result of the condition expression (nonzero = condition met).
 * If condi is true, consume wakeup; return remain (>= 1).
 * If condi is false and remain > 0, loop was broken by signal - return -EINTR.
 * If condi is false and remain == 0, timeout elapsed - return 0.
 */
long __wait_finish_timeout(struct waitqueue *waitq, struct waitqueue_node *n,
	long condi, unsigned long flags, uint64_t remain)
{
	list_del(&n->node);
	list_del(&n->tnode);

	if (condi) {
		if (waitq->condi > 0)
			waitq->condi--;
	}

	spin_unlock_irqrestore(&waitq->lock, flags);

	if (condi && remain == 0)
		remain = 1;

	/* wait for any in-flight wakeup callback */
	waitqueue_node_release(n);

	if (!condi && remain != 0)
		return -EINTR;

	/* clamp uint64_t to long range */
	if (remain > (uint64_t)LONG_MAX)
		return LONG_MAX;

	return remain;
}

static void waitnode_cleanup_t(struct thread *t)
{
	struct waitqueue_node *n = NULL, *_n = NULL;

	list_for_each_entry_safe(n, _n, &t->wqnodes, tnode) {
		DMSG("%s waiting @ %s() line %d p=%p\n",
			t->name, n->fnname, n->linenr, n->priv);
		waitqueue_node_del_release(n);
	}
}
DECLARE_THREAD_CLEANUP_LOW(waitnode_cleanup_t);
