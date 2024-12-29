// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * wait()/wait_event()/wakeup() implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <spinlock.h>
#include <list.h>
#include <sched.h>
#include <wait.h>

/*
 * Wake up all threads blocked on a waiting queue.
 */
void __wakeup(struct waitqueue *waitq)
{
	unsigned long flags = 0;
	struct waitqueue_node *n = NULL;

	spin_lock_irqsave(&waitq->lock, flags);

	if (!list_empty(&waitq->list)) {
		while ((n = list_first_entry_or_null(&waitq->list,
					struct waitqueue_node, node)) != NULL) {
			list_move_tail(&n->node, &waitq->wakelist);
			waitq->condi++;
			n->wake(n);
		}
	} else {
		if (waitq->condi >= 0)
			waitq->condi = 1;
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
