/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * common definitions for kernel/user mode threads
 */

#ifndef _THREAD_H
#define _THREAD_H

#include <ida.h>
#include <list.h>
#include <wait.h>
#include <sleep.h>
#include <errno.h>
#include <percpu.h>
#include <sys/types.h>
#include <workqueue.h>
#include <process.h>
#include <sched.h>
#include <ksignal.h>

#include <__pthread.h>

#define THREAD_NAME_LEN (PROCESS_NAME_LEN + 16)

typedef void (*thread_func_t)(void *);

/*
 * Structure for user/kernel mode threads
 */
struct thread {
	/* Global Thread ID */
	pid_t id;

	/* stat for the REE->TEE rpc calls */
	bool rpc_callee;
	/* stat for the TEE->REE rpc calls */
	bool rpc_caller;
	/*
	 * indicate the thread is under critical section or not
	 */
	int16_t critical;

	/* Thread's private mutex */
	struct mutex mlock;

	/* node in Process's thread list */
	struct list_head node;

	void *sched;

	/* Owner Process */
	struct process *proc;

	/*
	 * thread's default waitqueue
	 * for itself to wait something events
	 */
	struct waitqueue wait_q;

	/*
	 * thread's default waitqueue
	 * to notify the joiners, joiners wait at this queue
	 */
	struct waitqueue join_q;

	/* list for thread's wait points */
	struct list_head wqnodes;

	/* Destroy work */
	struct work destroy;

	/* user-stack pages */
	struct page **ustack_pages;
	/* user-stack user va - base */
	void *ustack_uva;

	/* kern-stack size */
	unsigned int kstack_size;
	/* user-stack size */
	unsigned int ustack_size;

	/* user-thread kernel stack - current */
	void *kstack;

	/*
	 * stack for backtrace() when thread abort,
	 * backtrace() uses huge stack, the original kstack
	 * maybe not enough
	 */
	void *brstack;

	/* mutexs held by this thread */
	struct list_head mutexs;

	/* __pthread_self user va */
	struct __pthread *tuser_uva;
	/* __pthread_self kernel va */
	struct __pthread *tuser;
	/* __pthread_self page */
	struct page *tuser_page;

	struct signal_thread sigt;

	/*
	 * User Thread name (cloned based on process's name)
	 * Kernel Thread name (specified by the creater)
	 */
	char name[THREAD_NAME_LEN];
} __aligned(sizeof(long));

#define thread_enter_critical(t) ((t)->critical++)
#define thread_leave_critical(t) ((t)->critical--)
#define thread_isnt_critical(t) ((t)->critical == 0)

/* yield the processor to other threads, accept interruptible flag */
static inline void thread_schedule(struct thread *t, int interruptible)
{
	if (interruptible) {
		thread_leave_critical(t);
		schedule();
		thread_enter_critical(t);
	} else {
		schedule();
	}
}

/*
 * @size - thread's kernel stack size (must align to PAGE)
 * allocate/map the thread struct and kernel stack
 */
static inline struct thread *thread_alloc(size_t size)
{
	struct thread *t = NULL;

	t = pages_alloc_continuous(PG_RW,
			size >> PAGE_SHIFT);
	if (t == NULL)
		return NULL;

	memset(t, 0, sizeof(struct thread));

	t->kstack_size = size;
	t->kstack = (void *)t + size;

	return t;
}

/*
 * @t - thread structure pointer
 * deallocate/unmap the thread struct and kernel stack
 */
static inline void thread_free(struct thread *t)
{
	pages_free_continuous(t);
}

#endif
