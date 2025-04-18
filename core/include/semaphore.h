/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Semaphore implementation
 */

#ifndef _SEMAPHORE_H
#define _SEMAPHORE_H

#include <wait.h>
#include <lockdep.h>

struct semaphore {
	struct lockval lock;
	/* number of max. parallel accessors */
	unsigned char limit;
	/* current owner's tid for priority ceiling */
	pid_t owner_id;
	struct waitqueue wq;
};

#define DEFAULT_SEMA(x, l) { \
	LOCKVAL_INIT(l), (l), 0, DEFAULT_WAITQ((x).wq), \
}

#define DECLARE_SEMA(name, limit) \
	struct semaphore name = DEFAULT_SEMA(name, limit)

void sema_init(struct semaphore *sem, char limit);

void down(struct semaphore *sem);

void up(struct semaphore *sem);

int down_trylock(struct semaphore *sem);

#endif
