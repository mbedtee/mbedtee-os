// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * entry functionalities
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <utrace.h>
#include <syscall.h>
#include <sys/time.h>
#include <sys/fcntl.h>

#include <syscall.h>
#include <backtrace.h>

#include <__pthread.h>

#include "pthread_reent.h"
#include "pthread_lockdep.h"
#include "pthread_waitdep.h"
#include "pthread_mutexdep.h"
#include "pthread_auxiliary.h"
#include "pthread_wait.h"
#include "pthread_cond.h"
#include "pthread_key.h"
#include "pthread_cleanup.h"

static int __sfd = -1;
static LIST_HEAD(__pthreads);
extern uintptr_t __stack_chk_guard;
extern void __sinit(struct _reent *r);
extern void __call_exitprocs(int code, void *d);

static DECLARE_RECURSIVE_PTHREAD_MUTEX(proc_l);

static inline void __process_lock(void)
{
	__pthread_mutex_lock(&proc_l);
}

static inline void __process_unlock(void)
{
	__pthread_mutex_unlock(&proc_l);
}

static void __process_stdfd_init(void)
{
	__process_lock();

	if (__sfd < 0) {
		__sfd = syscall2(SYSCALL_OPEN, "/dev/uart0", O_RDWR | O_NONBLOCK);
		if (__sfd < 0)
			__sfd = syscall2(SYSCALL_OPEN, "/dev/null", O_RDWR);
		dup2(__sfd, STDIN_FILENO);
		dup2(__sfd, STDOUT_FILENO);
		dup2(__sfd, STDERR_FILENO);
	}

	__process_unlock();
}

static inline void __process_need_exit(void *code)
{
	__process_lock();

	if (list_empty(&__pthreads)) {
		__call_exitprocs((intptr_t)code, NULL);

		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		__sfd = -1;
	}

	__process_unlock();
}

static inline void __pthread_enqueue(struct __pthread_aux *aux)
{
	__process_lock();
	list_add_tail(&aux->node, &__pthreads);
	__process_unlock();
}

static inline void __pthread_dequeue(struct __pthread_aux *aux)
{
	__process_lock();
	list_del(&aux->node);
	__process_unlock();
}

struct __pthread *__pthread_get(pthread_t pthread)
{
	struct __pthread *t = NULL, *ret = NULL;
	struct __pthread_aux *aux = NULL;

	do {
		ret = NULL;
		__process_lock();
		list_for_each_entry(aux, &__pthreads, node) {
			t = (struct __pthread *)((long)aux - PTHREAD_AUX_OFFSET);
			if (t->pthread == pthread) {
				ret = t;
				break;
			}
		}
		if (ret != NULL) {
			if (__pthread_mutex_trylock(&aux->cancel_lock) == 0) {
				__process_unlock();
				break;
			}
		}
		__process_unlock();
	} while (ret != NULL);

	return ret;
}

void __pthread_put(struct __pthread *t)
{
	struct __pthread_aux *aux = NULL;

	if (t) {
		aux = aux_of(t);
		__pthread_mutex_unlock(&aux->cancel_lock);
	}
}

static __nosprot void __pthread_stack_guard(void)
{
	if (__stack_chk_guard == 0) {
		struct timespec ts;

		syscall3(SYSCALL_CLOCKGETTIME,
			CLOCK_REALTIME, &ts, NULL);
		__stack_chk_guard = ts.tv_sec + ts.tv_nsec;
		__stack_chk_guard += __pthread_self->proc->id << 23;
	}
}

static void __pthread_reent_init(struct _reent *reent)
{
	struct timespec ts;

	_REENT_INIT_PTR(reent);
	__sinit(reent);

	syscall3(SYSCALL_CLOCKGETTIME,
		CLOCK_REALTIME, &ts, NULL);

	srand((__pthread_self->id << 13) +
		__stack_chk_guard + ts.tv_nsec);
}

void __pthread_init(struct __pthread *t)
{
	struct _reent *reent = reent_of(t);
	struct __pthread_aux *aux = aux_of(t);
	pthread_mutexattr_t attr;

	/*
	 * only init once
	 */
	if (t->inited)
		return;

	if (t->proc->exiting)
		syscall1(SYSCALL_PTHREAD_EXIT, -EINTR);

	pthread_enter_critical(t);

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr,
		PTHREAD_MUTEX_RECURSIVE);

	INIT_LIST_HEAD(&aux->mutexs);
	INIT_LIST_HEAD(&aux->wqnodes);
	INIT_LIST_HEAD(&aux->keys);
	INIT_LIST_HEAD(&aux->node);

	__pthread_waitqueue_init(&aux->join_q);

	__pthread_mutex_init(&aux->cancel_lock, &attr);

	__pthread_reent_init(reent);

	__pthread_enqueue(aux);

	__process_stdfd_init();

	unwind_init();

	t->inited = true;
	pthread_leave_critical(t);

	if (t->proc->exiting)
		__pthread_exit((void *)-EINTR);
}

static void __pthread_cleanup_mutex(struct __pthread_aux *aux)
{
	__pthread_mutex_t *m = NULL;

	while ((m = list_first_entry_or_null(&aux->mutexs,
		__pthread_mutex_t, node)) != NULL) {
		m->rc = 0;
		m->owner = 0;
		list_del(&m->node);
		__atomic_store_n(&m->lock, 0, __ATOMIC_RELAXED);
		__pthread_wakeup_lock(&m->lock, 1);
	}
}

static void __pthread_cleanup_wqnode(struct __pthread_aux *aux)
{
	struct __pthread_waitqueue_node *n = NULL;

	while ((n = list_first_entry_or_null(&aux->wqnodes,
		struct __pthread_waitqueue_node, tnode)) != NULL) {
		__pthread_waitqueue_node_del(n);
	}
}

static void __dead2 __cleanup_exit(long exitcall, void *retval)
{
	struct __pthread *self = __pthread_self;
	struct __pthread_aux *aux = aux_of(self);

	pthread_enter_critical(self);

	if (__atomic_fetch_add(&self->exiting, 1, __ATOMIC_SEQ_CST))
		goto exitdirectly;

	/*
	 * PTHREAD_CANCEL_DISABLE...
	 */
	__atomic_store_n(&self->cancel_state,
		PTHREAD_CANCEL_DISABLE, __ATOMIC_RELEASE);
	__atomic_store_n(&self->cancel_pending,
		false, __ATOMIC_RELEASE);

	/*
	 * Thread is going to exit, but there maybe still
	 * some mutexs held by it, release them.
	 */
	__pthread_cleanup_mutex(aux);
	__pthread_cleanup_wqnode(aux);

	/*
	 * Thread is going to exit now....
	 * rejects new joiners from now on
	 *
	 * Dequeue...
	 */
	__pthread_dequeue(aux);

	/* final confirm if the lock is held by any one else */
	__pthread_mutex_lock(&aux->cancel_lock);
	__pthread_mutex_unlock(&aux->cancel_lock);

	/* wake the joiners which successfully blocked on this thread */
	/* make sure no one will be blocked again */
	aux->join_q.condi = -(INT_MAX >> 1);
	__pthread_wakeup_all(&aux->join_q, retval);

	__pthread_cleanup_exec(self);
	__pthread_key_destructor(self);

	__process_need_exit(retval);

	__pthread_mutex_destroy(&aux->cancel_lock);

	__pthread_waitqueue_flush(&aux->join_q);

	_reclaim_reent(reent_of(self));

exitdirectly:
	if (__atomic_load_n(&self->exiting, __ATOMIC_RELAXED) == 2) {
		__pthread_cleanup_mutex(aux);
		__pthread_cleanup_wqnode(aux);
	}

	for (;;)
		syscall1(exitcall, retval);

	/* never runs to here */
	pthread_leave_critical(self);
}

void __dead2 __pthread_exit(void *retval)
{
	__cleanup_exit(SYSCALL_PTHREAD_EXIT, retval);
}

static void __dead2 __process_exit(long retval)
{
	__cleanup_exit(SYSCALL_EXIT, (void *)retval);
}

extern void __dead2 _exit(int val)
{
	/* kernel only accepts negative number for failure */
	if (val > 0)
		val = -val;
	__process_exit(val);
}

extern void __dead2 exit(int val)
{
	_exit(val);
}

extern void pthread_entry(void *(*routine)(void *),
	void *arg)
{
	__pthread_stack_guard();

	__pthread_init(__pthread_self);

	__pthread_exit(routine ? routine(arg) : arg);
}

extern void process_entry(void *(*routine)(int argc,
	char *argv[]), char *argv[])
{
	int argc = 0;

	__pthread_stack_guard();

	__pthread_init(__pthread_self);

	while (argv[argc] != NULL)
		argc++;

	__pthread_exit(routine ? routine(argc, argv) : (void *)-EINVAL);
}
