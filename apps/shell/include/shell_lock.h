/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * shell lock abstraction
 */

#ifndef _SHELL_LOCK_H
#define _SHELL_LOCK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <generated/autoconf.h>

#if defined(CONFIG_KERN_SHELL)
#include <spinlock.h>
#else
#include <pthread.h>
#endif

#if defined(CONFIG_KERN_SHELL)

struct shell_lock {
	struct spinlock lock;
	unsigned long flags;
};

#define SHELL_LOCK_INIT { SPIN_LOCK_INIT(0), 0 }

static inline void shell_lock_init(struct shell_lock *l)
{
	spin_lock_init(&l->lock);
	l->flags = 0;
}

static inline void shell_lock_enter(struct shell_lock *l)
{
	spin_lock_irqsave(&l->lock, l->flags);
}

static inline void shell_lock_exit(struct shell_lock *l)
{
	spin_unlock_irqrestore(&l->lock, l->flags);
}

#else

struct shell_lock {
	pthread_mutex_t lock;
};

#define SHELL_LOCK_INIT { PTHREAD_MUTEX_INITIALIZER }

static inline void shell_lock_init(struct shell_lock *l)
{
	pthread_mutex_init(&l->lock, NULL);
}

static inline void shell_lock_enter(struct shell_lock *l)
{
	pthread_mutex_lock(&l->lock);
}

static inline void shell_lock_exit(struct shell_lock *l)
{
	pthread_mutex_unlock(&l->lock);
}

#endif

#ifdef __cplusplus
}
#endif

#endif
