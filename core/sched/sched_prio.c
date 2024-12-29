// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * handling the priority of the threads
 */

#include <sched.h>
#include "sched_priv.h"
#include "sched_list.h"

int sched_inherit_prio(void *s, pid_t id)
{
	unsigned long flags = 0;
	struct sched_priv *sp = NULL;
	struct sched *dst = NULL;
	struct sched *src = s;
	int src_prio = 0;

	if (src == NULL)
		return -EINVAL;

	dst = sched_get_lock(id, &flags);
	if (dst == NULL)
		return -ESRCH;

	src_prio = src->prio;

	if (src_prio > dst->prio) {
		/* check the userspace thread permission */
		if (src->thread->proc == kproc() ||
			src->thread->proc == dst->thread->proc) {
			sp = dst->sp;
			spin_lock(&sp->lock);
			sched_change_prio(sp, dst, src_prio);

			/* update the userspace __pthread_self backup priority */
			if (dst->thread->tuser)
				dst->thread->tuser->priority_bak = dst->priority;

			spin_unlock(&sp->lock);
		}
	}

	sched_put_lock(dst, flags);

	return 0;
}

int sched_resume_prio(pid_t id)
{
	unsigned long flags = 0;
	struct sched_priv *sp = NULL;
	struct sched *dst = sched_get_lock(id, &flags);

	if (dst == NULL)
		return -ESRCH;

	if (dst->policy != SCHED_OTHER) {
		sp = dst->sp;

		spin_lock(&sp->lock);
		sched_change_prio(sp, dst, dst->priority);
		spin_unlock(&sp->lock);
	}

	sched_put_lock(dst, flags);

	return 0;
}
