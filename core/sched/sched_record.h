/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * record the CPU loading/priority
 */

#ifndef _SCHED_RECORD_H
#define _SCHED_RECORD_H

#include "sched_list.h"

/*
 * record timeslice window for all threads
 */
void sched_record_runtime(struct sched_priv *sp);

static inline void sched_record_curr(struct sched *old)
{
	uint64_t diff = 0, stamp = 0;

	/* record time */
	if (old) {
		stamp = read_cycles();
		diff = sub_cycles(stamp, old->stamp);
		old->overall = add_cycles(old->overall, diff);
		old->runtime = add_cycles(old->runtime, diff);
		old->prio_consumed = add_cycles(old->prio_consumed, diff);
		old->stamp = stamp;
	}
}

static inline void sched_record_next(struct sched *nxt)
{
	/* record timestamp(cycles) */
	nxt->stamp = read_cycles();
}

#endif
