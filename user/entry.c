// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * entry functionalities
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <utrace.h>
#include <syscall.h>
#include <sys/time.h>
#include <sys/fcntl.h>

#include <backtrace.h>

#include <__pthread.h>
#include <__process.h>

#include <pthread_reent.h>
#include <pthread_lockdep.h>
#include <pthread_waitdep.h>
#include <pthread_mutexdep.h>
#include <pthread_auxiliary.h>
#include <pthread_wait.h>
#include <pthread_cond.h>
#include <pthread_key.h>
#include <pthread_cleanup.h>

struct proc_info __proc_info;

static int __stdfd_init;
static LIST_HEAD(__pthreads);
extern uintptr_t __stack_chk_guard;
extern void __sinit(struct _reent *r);
extern void __call_exitprocs(int code, void *d);
static bool __process_exiting;

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
	int ret = 0, fd = 0;
	int stdin_ok = 0, stdout_ok = 0, stderr_ok = 0;

	if (__atomic_load_n(&__stdfd_init, __ATOMIC_RELAXED))
		return;

	/*
	 * Don't clobber an existing stdio setup.
	 * This is important for scenarios where a launcher (e.g. shell pipeline)
	 * pre-binds STDIN/STDOUT/STDERR before the process starts.
	 */
	stdin_ok = (fcntl(STDIN_FILENO, F_GETFL) >= 0);
	stdout_ok = (fcntl(STDOUT_FILENO, F_GETFL) >= 0);
	stderr_ok = (fcntl(STDERR_FILENO, F_GETFL) >= 0);

	if (stdin_ok && stdout_ok && stderr_ok) {
		__atomic_store_n(&__stdfd_init, 1, __ATOMIC_SEQ_CST);
		return;
	}

	fd = syscall2(SYSCALL_OPEN, "/dev/uart0", O_RDWR | O_NONBLOCK);
	if (fd < 0)
		fd = syscall2(SYSCALL_OPEN, "/dev/null", O_RDWR);

	if (fd >= 0) {
		if (!stdin_ok)
			ret = syscall2(SYSCALL_DUP2, fd, STDIN_FILENO);
		if (!stdout_ok)
			ret |= syscall2(SYSCALL_DUP2, fd, STDOUT_FILENO);
		if (!stderr_ok)
			ret |= syscall2(SYSCALL_DUP2, fd, STDERR_FILENO);

		__atomic_store_n(&__stdfd_init, 1, __ATOMIC_SEQ_CST);

		if (!syscall_stdfd(fd))
			close(fd);
	} else {
		ret = fd;
	}

	if (ret < 0)
		syscall1(SYSCALL_EXIT, -ret);
}

static inline void __process_need_exit(void *code)
{
	__process_lock();
	if (list_empty(&__pthreads)) {
		__call_exitprocs((intptr_t)code, NULL);

		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		__atomic_store_n(&__stdfd_init, 0, __ATOMIC_RELAXED);
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
	struct __pthread *t = NULL;
	struct __pthread_aux *aux = NULL;

	__process_lock();
	list_for_each_entry(aux, &__pthreads, node) {
		t = pthread_of(aux);
		if (t->pthread == pthread)
			break;
		t = NULL;
	}
	if (t)
		__atomic_add_fetch(&aux->refc, 1, __ATOMIC_ACQUIRE);
	__process_unlock();

	if (!t)
		return NULL;

	__pthread_mutex_lock(&aux->cancel_lock);

	if (__atomic_load_n(&t->exiting, __ATOMIC_ACQUIRE)) {
		__pthread_mutex_unlock(&aux->cancel_lock);
		__atomic_fetch_sub(&aux->refc, 1, __ATOMIC_RELEASE);
		return NULL;
	}

	return t;
}

void __pthread_put(struct __pthread *t)
{
	struct __pthread_aux *aux = NULL;

	if (t) {
		aux = pthread_aux(t);
		__pthread_mutex_unlock(&aux->cancel_lock);
		__atomic_fetch_sub(&aux->refc, 1, __ATOMIC_RELEASE);
	}
}

void __pthread_join_wait(struct __pthread_aux *aux, void **value_ptr)
{
	__pthread_wait(&aux->join_q, &aux->cancel_lock, value_ptr);
	__atomic_fetch_sub(&aux->refc, 1, __ATOMIC_RELEASE);
}

static __nosprot void __process_stack_guard(void)
{
	if (__stack_chk_guard == 0) {
		struct timespec ts;
		uintptr_t guard = 0;
		int fd = -1;

		/* Try kernel entropy source (raw syscall: runs before stdio init) */
		fd = syscall2(SYSCALL_OPEN, "/dev/urandom", O_RDONLY);
		if (fd >= 0) {
			syscall3(SYSCALL_READ, fd, &guard, sizeof(guard));
			syscall1(SYSCALL_CLOSE, fd);
		}

		/* Fallback to clock + thread id if urandom unavailable */
		if (guard == 0) {
			syscall3(SYSCALL_CLOCKGETTIME, CLOCK_REALTIME,
				 &ts, NULL);
			guard = ts.tv_sec + ts.tv_nsec;
			guard *= __pthread_self->pthread;
		}

		__stack_chk_guard = guard;
	}
}

static void __pthread_reent_init(struct _reent *reent)
{
	if (reent->_r48)
		return;

	/* stdio */
	_REENT_INIT_PTR(reent);

	/* srand/rand */
	while ((reent->_r48 = malloc(sizeof(*reent->_r48))) == NULL)
		syscall1(SYSCALL_USLEEP, 5000);
	_REENT_INIT_RAND48(reent);
	_REENT_RAND_NEXT(reent) = __stack_chk_guard + __pthread_self->pthread;
}

void __pthread_init(struct __pthread *t)
{
	pthread_mutexattr_t attr;
	struct __pthread_aux *aux = pthread_aux(t);

	/*
	 * only init once, the aux->mutexes is not ready
	 * at this moment, so use the spinlock
	 */
	__pthread_lock(&t->initlock);

	if (t->inited)
		goto out;

	__pthread_enter_critical(t);

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr,
		PTHREAD_MUTEX_RECURSIVE);

	INIT_LIST_HEAD(&aux->mutexes);
	INIT_LIST_HEAD(&aux->wqnodes);
	INIT_LIST_HEAD(&aux->keys);
	INIT_LIST_HEAD(&aux->node);

	__pthread_waitqueue_init(&aux->join_q);

	__pthread_mutex_init(&aux->cancel_lock, &attr);

	aux->refc = 0;

	__pthread_enqueue(aux);

	__pthread_leave_critical(t);

	t->inited = true;

out:
	__pthread_unlock(&t->initlock);
	if (__process_exiting)
		__pthread_exit((void *)-EINTR);
}

static void __pthread_cleanup_mutex(struct __pthread_aux *aux)
{
	struct __pthread_mutex *m = NULL;

	while ((m = list_first_entry_or_null(&aux->mutexes,
		struct __pthread_mutex, node)) != NULL) {
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

static inline void __pthread_serialize_detach(
	struct __pthread *t, void *retval)
{
	struct __pthread_aux *aux = pthread_aux(t);

	if (t->detachstate == PTHREAD_CREATE_DETACHED)
		return;

	/*
	 * serializes with pthread_join()/pthread_detach()
	 */
	__pthread_mutex_lock(&aux->cancel_lock);

	while (t->detachstate != PTHREAD_CREATE_DETACHED) {
		aux->join_q.notification = retval;
		t->detaching = true;
		__pthread_mutex_unlock(&aux->cancel_lock);
		syscall1(SYSCALL_SCHED_SUSPEND, retval);
		__pthread_mutex_lock(&aux->cancel_lock);
	}
	__pthread_mutex_unlock(&aux->cancel_lock);
}

static void __dead2 __cleanup_exit(long exitcall, void *retval)
{
	struct __pthread *self = __pthread_self;
	struct __pthread_aux *aux = pthread_aux(self);

	/*
	 * PTHREAD_CANCEL_DISABLE...
	 */
	__atomic_store_n(&self->cancel_state,
		PTHREAD_CANCEL_DISABLE, __ATOMIC_RELEASE);
	__atomic_store_n(&self->cancel_pending,
		false, __ATOMIC_SEQ_CST);

	/*
	 * Thread is going to exit, but there maybe still some mutexs
	 * held by it, release them, then clear the critical flag
	 */
	if (!__atomic_load_n(&self->exiting, __ATOMIC_RELAXED)) {
		__pthread_cleanup_mutex(aux);
		__pthread_cleanup_wqnode(aux);
		__pthread_clear_critical(self);
	}

	/*
	 * Joinable threads must not call SYSCALL_PTHREAD_EXIT yet, otherwise
	 * the kernel will reclaim the thread resources, and join/detach can't
	 * observe the join state. Instead, suspend until someone joins/detaches
	 * (which flips detachstate to DETACHED).
	 */
	__pthread_serialize_detach(self, retval);

	__pthread_enter_critical(self);

	__pthread_cleanup_exec(self);
	__pthread_key_destructor(self);

	if (__atomic_fetch_add(&self->exiting, 1, __ATOMIC_SEQ_CST))
		goto exitdirectly;

	/*
	 * Thread is going to exit now....
	 * rejects new joiners from now on
	 *
	 * Dequeue...
	 */
	__pthread_dequeue(aux);

	/* wake the joiners which successfully blocked on this thread */
	/* make sure no one will be blocked again */
	__pthread_wakeup_dissolved(&aux->join_q, retval);

	/*
	 * final confirm if the lock is held by any one else
	 */
	__pthread_mutex_lock(&aux->cancel_lock);
	__pthread_mutex_unlock(&aux->cancel_lock);

	/*
	 * Wait for in-flight __pthread_get callers
	 */
	while (__atomic_load_n(&aux->refc, __ATOMIC_ACQUIRE) > 0)
		syscall1(SYSCALL_USLEEP, 5000);

	__pthread_mutex_destroy(&aux->cancel_lock);

	__process_need_exit(retval);

	__pthread_waitqueue_flush(&aux->join_q);

	/*
	 * shall be the final step
	 */
	_reclaim_reent(reent_of(self));

exitdirectly:
	for (;;)
		syscall1(exitcall, retval);

	/* never runs to here */
	__pthread_leave_critical(self);
}

void __dead2 __pthread_exit(void *retval)
{
	__cleanup_exit(SYSCALL_PTHREAD_EXIT, retval);
}

static void __dead2 __process_exit(long retval)
{
	struct __pthread *t = NULL;
	struct __pthread_aux *aux = NULL;

	__process_lock();

	/* set exiting and detach all */
	if (!__process_exiting) {
		list_for_each_entry(aux, &__pthreads, node) {
			t = pthread_of(aux);
			t->detachstate = PTHREAD_CREATE_DETACHED;
		}

		__process_exiting = true;
	}
	__process_unlock();

	__cleanup_exit(SYSCALL_EXIT, (void *)retval);
}

extern void __dead2 _exit(int val)
{
	__process_exit((long)val);
}

extern void __dead2 exit(int val)
{
	_exit(val);
}

static void __process_tz_init(void)
{
	struct timespec ts;
	struct timezone tz = {0};
	char tzstr[12] = "UTC";
	char *p = tzstr + 3;
	int h = 0, m = 0;

	if (syscall3(SYSCALL_CLOCKGETTIME, CLOCK_REALTIME, &ts, &tz) != 0)
		return;

	if (tz.tz_minuteswest == 0)
		return;

	h = tz.tz_minuteswest / 60;
	m = tz.tz_minuteswest % 60;
	if (m < 0)
		m = -m;

	if (h < 0) {
		*p++ = '-';
		h = -h;
	}
	if (h >= 10)
		*p++ = '0' + h / 10;
	*p++ = '0' + h % 10;
	if (m != 0) {
		*p++ = ':';
		*p++ = '0' + m / 10;
		*p++ = '0' + m % 10;
	}
	*p = '\0';

	setenv("TZ", tzstr, 1);
	tzset();
}

static void __nosprot __pthread_process_init(void)
{
	struct __pthread *t = __pthread_self;

	__process_stack_guard();
	__process_stdfd_init();

	__pthread_init(t);
	__pthread_reent_init(reent_of(t));

	__process_tz_init();

	syscall1(SYSCALL_GET_PROC_INFO, &__proc_info);
	__process_unwind_init();
}

extern void pthread_entry(void *(*routine)(void *),
	void *arg)
{
	__pthread_process_init();

	__pthread_exit(routine ? routine(arg) : arg);
}

extern void process_entry(long (*routine)(int argc,
	char *argv[]), char *argv[])
{
	int argc = 0;

	__pthread_process_init();

	while (argv[argc])
		argc++;

	__process_exit(routine ? routine(argc, argv) : -EINVAL);
}
