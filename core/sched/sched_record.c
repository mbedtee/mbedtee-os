// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * record the scheduler loading/priority
 */

#include <timer.h>
#include <trace.h>
#include <thread.h>
#include <sched.h>
#include <debugfs.h>
#include <__pthread.h>

#include "sched_priv.h"
#include "sched_list.h"
#include "sched_record.h"

/*
 * record timeslice window for all threads
 */
void sched_record_runtime(struct sched_priv *sp)
{
	uint64_t curr = 0;
	uint64_t diff = 0;
	struct sched *s = NULL;
	int cnt = 0;

	curr = read_cycles();

	diff = sub_cycles(curr, sp->stamp);
	/* SCHED_COUNT_PERIOD * 4 - 256ms */
	if (unlikely(diff >= (sp->threshold * 4))) {
		list_for_each_entry(s, &sp->sl, node) {
			s->lruntime = s->runtime;
			s->runtime = 0;
		}
		sp->lruntime = diff;
		sp->stamp = curr;
	} else {
		/* record timeslice window for all threads */
		diff = sub_cycles(curr, sp->stamp_reward);
		/* SCHED_COUNT_PERIOD - 64ms */
		if (unlikely(diff >= sp->threshold)) {
			list_for_each_entry(s, &sp->sl, node) {
				sched_compensate_prio(sp, s);
				if (++cnt == 32)
					break;
			}
			sp->stamp_reward = curr;

			if (cnt == 32)
				list_bulk_move_tail(&sp->sl, sp->sl.next, &s->node);
		}
	}
}

/*
 * Usually For CPU Hot-Plug
 * pick a suitable alive cpu (usually the most idle one)
 */
int sched_pick_mostidle_cpu(void)
{
	unsigned long flags = 0, cpu = 0;
	struct sched_priv *sp = NULL;
	struct sched_gd *gd = sched_gd();

	spin_lock_irqsave(&gd->lock, flags);

	sp = __sched_pick_mostidle_cpu(gd);

	cpu = sp->pc->id;

	spin_unlock_irqrestore(&gd->lock, flags);

	return cpu;
}
