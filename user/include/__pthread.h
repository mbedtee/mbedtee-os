/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * pthread internal definitions for both user/kernel space
 */

#ifndef _PTHREAD_PRIV_H
#define _PTHREAD_PRIV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <reent.h>
#include <sched.h>
#include <time.h>
#include <list.h>
#include <misc.h>

#include <pthread.h>

#define PTHREAD_STACK_MIN (4096)
#define PTHREAD_STACK_DEFAULT (PTHREAD_STACK_MIN)
#define PTHREAD_DEFAULT_PRIORITY (16)
#define PTHREAD_RPC_DEFAULT_PRIORITY (16)

/*
 * Macros for read/write locks
 */
#define PTHREAD_LOCK_WRLOCK			(1u << 0)
#define PTHREAD_LOCK_RDLOCK			(1u << 1)
#define PTHREAD_LOCK_WAITER			(1u << 2)

#define PTHREAD_LOCK_READER			(1u << 16)
#define PTHREAD_LOCK_READER_MASK	(0xffff0000u)

struct __pthread {
	/*
	 * inner-process thread ID
	 */
	pthread_t pthread;
	/*
	 * inner-system thread ID
	 */
	pid_t id;
	/*
	 * @ current Processor ID
	 */
	int cpuid;

	/*
	 * Stack Information
	 */
	void *stackaddr;
	size_t stacksize;

	/*
	 * State (PTHREAD_CREATE_DETACHED or
	 * PTHREAD_CREATE_JOINABLE)
	 */
	uint8_t detachstate;

	/*
	 * scheduling contention scope
	 * (PTHREAD_SCOPE_SYSTEM or PTHREAD_SCOPE_PROCESS)
	 */
	uint8_t scope;

	/*
	 * scheduling policy and priority
	 */
	uint8_t policy;
	/* current priority */
	uint8_t priority;
	/* backup value of the 'priority' */
	uint8_t priority_bak;
#define DEFAULT_PRIORITY(p) ((p)->priority_bak != 0 ? \
	(p)->priority_bak : (p)->priority)

	/*
	 * indicate the thread is exiting or not
	 */
	uint8_t exiting;

	uint8_t inited;

	uint8_t sighandling;

	/*
	 * scheduling attributes are inherited from the calling
	 * thread or not.
	 * (PTHREAD_EXPLICIT_SCHED or PTHREAD_INHERIT_SCHED)
	 */
	uint8_t inherit;

	/*
	 * cancel_state (PTHREAD_CANCEL_ENABLE or
	 * PTHREAD_CANCEL_DISABLE)
	 */
	uint8_t cancel_state;

	/*
	 * cancel_type (PTHREAD_CANCEL_DEFERRED or
	 * PTHREAD_CANCEL_ASYNCHRONOUS)
	 */
	uint8_t cancel_type;

	/*
	 * cancel_pending (indicates whether there is
	 * pending cancellation on this thread)
	 */
	uint8_t cancel_pending;

	/*
	 * System's thread ID MAX (nr of threads allowed)
	 */
	short idmax;

	/*
	 * indicate the thread is under critical section or not
	 */
	short critical;

	pthread_spinlock_t initlock;

	/*
	 * indicate the thread is detaching or not
	 * Different from the 'exiting', detaching means a joinable thread
	 * is waiting for detach then exit, ''exiting' means to exit directly.
	 */
	uint8_t detaching;

	/*
	 * contains the current signal handler's arguments
	 */
	struct sigarguments sa;
};

#define DECLARE_DEFAULT_PTHREAD(name) \
struct __pthread name = { \
	0, 0, 0, \
	NULL, PTHREAD_STACK_DEFAULT, \
	PTHREAD_CREATE_JOINABLE, \
	PTHREAD_SCOPE_SYSTEM, \
	SCHED_OTHER, PTHREAD_DEFAULT_PRIORITY, 0, \
	0, 0, 0, PTHREAD_EXPLICIT_SCHED, \
	PTHREAD_CANCEL_ENABLE, PTHREAD_CANCEL_DEFERRED, 0, \
	0, 0, 0, 0, {NULL} \
}

#define DECLARE_DEFAULT_PTHREAD_ATTR(name) \
pthread_attr_t name = { \
	true, NULL, 0, \
	PTHREAD_SCOPE_SYSTEM, \
	PTHREAD_EXPLICIT_SCHED, \
	SCHED_OTHER, {PTHREAD_DEFAULT_PRIORITY}, \
	CLOCK_ALLOWED, PTHREAD_CREATE_JOINABLE \
}

#define DECLARE_DETACHED_PTHREAD_ATTR(name) \
pthread_attr_t name = { \
	true, NULL, 0, \
	PTHREAD_SCOPE_SYSTEM, \
	PTHREAD_EXPLICIT_SCHED, \
	SCHED_OTHER, {PTHREAD_DEFAULT_PRIORITY}, \
	CLOCK_ALLOWED, PTHREAD_CREATE_DETACHED \
}

#define __pthread_self ((struct __pthread *)__builtin_thread_pointer())

#define __pthread_enter_critical(p) ((p)->critical++)
#define __pthread_leave_critical(p) ((p)->critical--)
#define __pthread_clear_critical(p) ((p)->critical = 0)
#define pthread_isnt_critical(p) ((p)->critical == 0)

/*
 * pthread_self() is (pid<<16) | tid
 *
 * kernel always manages the tid/pid value less than 65536
 */
#define tid_of(pthread) ((pid_t)(pthread) & 0xffff)
#define pid_of(pthread) ((pid_t)(((unsigned int)(pthread)) >> 16))

#ifdef __cplusplus
}
#endif

#endif
