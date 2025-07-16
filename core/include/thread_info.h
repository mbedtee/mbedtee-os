/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Get the current thread/process information
 */

#ifndef _THREAD_INFO_H
#define _THREAD_INFO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <cpu.h>
#include <sys/types.h>

struct thread;

/*
 * Get the thread by TID,
 * increase the reference counter.
 * return the thread structure
 */
struct thread *thread_get(pid_t tid);

/*
 * Put the thread by thread structure,
 * decrease the reference counter.
 */
void thread_put(struct thread *t);

/*
 * Return whether the thread's stack has overflowed.
 */
bool thread_overflow(struct thread *t);

/*
 * current executing thread's struct pointer
 */
#define current get_current()

/*
 * current thread ID
 */
#define current_id (current->id)

#ifdef __cplusplus
}
#endif
#endif
