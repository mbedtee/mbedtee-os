/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * tasklets for handling the bottom half of the interrupts serialized,
 * with interrupt enabled and critical priority
 */

#ifndef _TASKLET_H
#define _TASKLET_H

#include <list.h>
#include <atomic.h>
#include <percpu.h>

struct tasklet {
	struct list_head node;
	struct atomic_num state;
	struct atomic_num disable;
	void (*func)(unsigned long data);
	unsigned long data;
};

#define DECLARE_TASKLET(name, func, data) \
struct tasklet name = {LIST_HEAD_INIT(name.node), \
	ATOMIC_INIT(0), ATOMIC_INIT(0), func, data}

void tasklet_init(struct tasklet *t,
	void (*func)(unsigned long),
	unsigned long data);

void tasklet_schedule(struct tasklet *t);

void tasklet_disable(struct tasklet *t);

void tasklet_enable(struct tasklet *t);

void tasklet_kill(struct tasklet *t);

void tasklet_routine_init(void);

#endif
