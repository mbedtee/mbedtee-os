/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * timer for each scheduler entity
 */

#ifndef _SCHED_TIMER_H
#define _SCHED_TIMER_H

#include <timer.h>
#include <tevent.h>

#include "sched_priv.h"

void sched_timeout_event(struct tevent *t);

static inline void sched_timer_init(struct sched *s)
{
	tevent_init(&s->tevent, sched_timeout_event, (void *)(intptr_t)s->id);
}

static inline void sched_timer_start(struct sched *s, struct timespec *time)
{
	tevent_start(&s->tevent, time);
}

static inline void sched_timer_stop(struct sched *s)
{
	tevent_stop(&s->tevent);
}

#endif
