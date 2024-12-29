/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Get the current thread/process information
 */

#ifndef _THREAD_INFO_H
#define _THREAD_INFO_H

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
 * return if the thread's stack overflow or not
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

#endif
