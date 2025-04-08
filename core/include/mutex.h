/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Mutex implementation
 */

#ifndef _MUTEX_H
#define _MUTEX_H

#include <list.h>
#include <wait.h>
#include <lockdep.h>

struct mutex {
	struct lockval lock;
	struct spinlock slock;
	/* normal or recursive */
	unsigned char type;
	/* recursive count */
	int rc;
	pid_t owner_id;
	struct waitqueue waitq;
	struct list_head node;
};

#define MUTEX_NORMAL    0
#define MUTEX_RECURSIVE 1

#define DEFAULT_MUTEX(x) {                \
	LOCKVAL_INIT(0), SPIN_LOCK_INIT(0),   \
	MUTEX_NORMAL, 0, 0,                   \
	DEFAULT_WAITQ((x).waitq),             \
	LIST_HEAD_INIT((x).node),             \
}

#define RECURSIVE_MUTEX(x) {              \
	LOCKVAL_INIT(0), SPIN_LOCK_INIT(0),   \
	MUTEX_RECURSIVE, 0, 0,                \
	DEFAULT_WAITQ((x).waitq),             \
	LIST_HEAD_INIT((x).node),             \
}

#define DECLARE_MUTEX(name) \
	struct mutex name = DEFAULT_MUTEX(name)
#define DECLARE_RECURSIVE_MUTEX(name) \
	struct mutex name = RECURSIVE_MUTEX(name)

void mutex_init(struct mutex *m);

void mutex_init_recursive(struct mutex *m);

void mutex_lock(struct mutex *m);

void mutex_unlock(struct mutex *m);

int mutex_trylock(struct mutex *m);

void mutex_destroy(struct mutex *m);

#endif
