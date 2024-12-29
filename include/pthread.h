/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * userspace POSIX thread definitions
 */

#ifndef _PTHREAD_H
#define _PTHREAD_H

#include <cpuset.h>
#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/signal.h>

int	pthread_create(pthread_t *pthread,
	const pthread_attr_t *attr,
	void *(*start_routine)(void *),
	void *arg);

int	pthread_join(pthread_t pthread, void **value_ptr);

int	pthread_detach(pthread_t pthread);

void pthread_exit(void *value_ptr) __dead2;

pthread_t pthread_self(void);

int	pthread_equal(pthread_t t1, pthread_t t2);

int	pthread_getcpuclockid(pthread_t thread,
	clockid_t *clock_id);

int	pthread_setconcurrency(int new_level);

int	pthread_getconcurrency(void);

#define PTHREAD_ONCE_INIT _PTHREAD_ONCE_INIT
int	pthread_once(pthread_once_t *once_ctrl, void (*routine)(void));

int	pthread_attr_init(pthread_attr_t *attr);

int	pthread_attr_destroy(pthread_attr_t *attr);

int	pthread_attr_setstack(pthread_attr_t *attr,
	void *stackaddr, size_t stacksize);

int	pthread_attr_getstack(const pthread_attr_t *attr,
	void **stackaddr, size_t *stacksize);

int	pthread_attr_getstacksize(
	const pthread_attr_t *attr,
	size_t *stacksize);

int	pthread_attr_setstacksize(
	pthread_attr_t *attr,
	size_t stacksize);

int	pthread_attr_getstackaddr(
	const pthread_attr_t *attr,
	void **stackaddr);

int	pthread_attr_setstackaddr(
	pthread_attr_t *attr,
	void *stackaddr);

int	pthread_attr_getdetachstate(
	const pthread_attr_t *attr,
	int *detachstate);

int	pthread_attr_setdetachstate(
	pthread_attr_t *attr,
	int detachstate);

int	pthread_attr_getguardsize(
	const pthread_attr_t *attr,
	size_t *guardsize);

int	pthread_attr_setguardsize(
	pthread_attr_t *attr,
	size_t guardsize);

int	pthread_attr_setscope(
	pthread_attr_t *attr,
	int scope);

int	pthread_attr_getscope(
	const pthread_attr_t *attr,
	int *scope);

int	pthread_attr_setinheritsched(
	pthread_attr_t *attr,
	int inheritsched);

int	pthread_attr_getinheritsched(
	const pthread_attr_t *attr,
	int *inheritsched);

int	pthread_attr_setschedpolicy(
	pthread_attr_t *attr,
	int policy);

int	pthread_attr_getschedpolicy(
	const pthread_attr_t *attr,
	int *policy);

int	pthread_attr_setschedparam(
	pthread_attr_t *attr,
	const struct sched_param *param);

int	pthread_attr_getschedparam(
	const pthread_attr_t *attr,
	struct sched_param *param);

int	pthread_getschedparam(pthread_t pthread,
	int *policy, struct sched_param *param);

int	pthread_setschedparam(pthread_t pthread,
	int policy, struct sched_param *param);

int	pthread_setschedprio(pthread_t pthread, int prio);

int	pthread_setaffinity(pthread_t pthread,
	size_t cpusetsize, const cpu_set_t *cpuset);

int	pthread_getaffinity(pthread_t pthread,
	size_t cpusetsize, cpu_set_t *cpuset);

void pthread_yield(void);

struct __pthread_cleanup {
	void (*routine)(void *arg);
	void *arg;
	struct __pthread_cleanup *next;
};

/* get the pthread dedicated cleanup-handler stack */
struct __pthread_cleanup **__pthread_get_cleanup_stack(void);

#define pthread_cleanup_push(routine, arg) {		\
	struct __pthread_cleanup **__cleanups			\
		= __pthread_get_cleanup_stack();			\
	struct __pthread_cleanup __cleanup = {			\
		routine, arg, *__cleanups					\
	};												\
	/* add barrier before modify the __cleanups */	\
	__atomic_store_n(__cleanups,					\
		&__cleanup, __ATOMIC_RELEASE)

#define pthread_cleanup_pop(execute)				\
	if (execute)									\
		__cleanup.routine(__cleanup.arg);			\
	*__cleanups = __cleanup.next;					\
}

/*
 * The symbolic constant PTHREAD_CANCELED expands to a
 * constant expression of type (void *) whose value matches
 * no pointer to an object in memory nor the value NULL.
 */
#define PTHREAD_CANCELED ((void *)-1)
int	pthread_cancel(pthread_t pthread);

#define PTHREAD_CANCEL_ENABLE  0
#define PTHREAD_CANCEL_DISABLE 1
int	pthread_setcancelstate(int state, int *old_state);

#define PTHREAD_CANCEL_DEFERRED 0
#define PTHREAD_CANCEL_ASYNCHRONOUS 1
int	pthread_setcanceltype(int type, int *old_type);

void pthread_testcancel(void);

int	pthread_key_create(pthread_key_t *key,
	void (*destructor)(void *));

int	pthread_setspecific(pthread_key_t key, const void *value);

void *pthread_getspecific(pthread_key_t key);

int	pthread_key_delete(pthread_key_t key);

int pthread_spin_init(pthread_spinlock_t *lock, int pshared);

int pthread_spin_destroy(pthread_spinlock_t *lock);

int pthread_spin_lock(pthread_spinlock_t *lock);

int pthread_spin_trylock(pthread_spinlock_t *lock);

int pthread_spin_unlock(pthread_spinlock_t *lock);

#define PTHREAD_RWLOCK_INITIALIZER _PTHREAD_RWLOCK_INITIALIZER

int pthread_rwlockattr_init(pthread_rwlockattr_t *attr);

int pthread_rwlockattr_destroy(pthread_rwlockattr_t *attr);

int pthread_rwlockattr_getpshared(const pthread_rwlockattr_t *attr,
	int *pshared);

int pthread_rwlockattr_setpshared(pthread_rwlockattr_t *attr,
	int pshared);

int pthread_rwlock_init(pthread_rwlock_t *rwlock,
			const pthread_rwlockattr_t *attr);

int pthread_rwlock_destroy(pthread_rwlock_t *rwlock);

int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock);

int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock);

int pthread_rwlock_timedrdlock(pthread_rwlock_t *rwlock,
	const struct timespec *abstime);

int pthread_rwlock_timedwrlock(pthread_rwlock_t *rwlock,
	const struct timespec *abstime);

int pthread_rwlock_unlock(pthread_rwlock_t *rwlock);

int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock);

int pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock);

#define PTHREAD_BARRIER_SERIAL_THREAD (-1)

int pthread_barrierattr_init(pthread_barrierattr_t *attr);

int pthread_barrierattr_destroy(pthread_barrierattr_t *attr);

int pthread_barrierattr_getpshared(const pthread_barrierattr_t *attr,
	int *pshared);

int pthread_barrierattr_setpshared(pthread_barrierattr_t *attr,
	int pshared);

int pthread_barrier_init(pthread_barrier_t *barrier,
	const pthread_barrierattr_t *attr, unsigned int count);

int pthread_barrier_destroy(pthread_barrier_t *barrier);

int pthread_barrier_wait(pthread_barrier_t *barrier);

int	pthread_condattr_init(pthread_condattr_t *attr);

int	pthread_condattr_destroy(pthread_condattr_t *attr);

int	pthread_condattr_getclock(const pthread_condattr_t *attr,
	clockid_t *clock_id);

int	pthread_condattr_setclock(pthread_condattr_t *attr,
	clockid_t clock_id);

int	pthread_condattr_getpshared(const pthread_condattr_t *attr,
	int *pshared);

int	pthread_condattr_setpshared(pthread_condattr_t *attr,
	int pshared);

#define PTHREAD_COND_INITIALIZER _PTHREAD_COND_INITIALIZER

int	pthread_cond_init(pthread_cond_t *cond,
	const pthread_condattr_t *attr);

int	pthread_cond_destroy(pthread_cond_t *mutex);

int	pthread_cond_signal(pthread_cond_t *cond);

int	pthread_cond_broadcast(pthread_cond_t *cond);

int	pthread_cond_wait(pthread_cond_t *cond,
	pthread_mutex_t *mutex);

int	pthread_cond_timedwait(pthread_cond_t *cond,
	pthread_mutex_t *mutex, const struct timespec *abstime);

#define PTHREAD_MUTEX_INITIALIZER _PTHREAD_MUTEX_INITIALIZER

int	pthread_mutexattr_init(pthread_mutexattr_t *attr);

int	pthread_mutexattr_destroy(pthread_mutexattr_t *attr);

int	pthread_mutexattr_getpshared(const pthread_mutexattr_t *attr,
	int *pshared);

int	pthread_mutexattr_setpshared(pthread_mutexattr_t *attr,
	int pshared);

int pthread_mutexattr_gettype(const pthread_mutexattr_t *attr, int *type);

int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type);

int	pthread_mutexattr_setprotocol(pthread_mutexattr_t *attr, int protocol);

int	pthread_mutexattr_getprotocol(const pthread_mutexattr_t *attr, int *protocol);

int	pthread_mutexattr_setprioceiling(pthread_mutexattr_t *attr, int prioceiling);

int	pthread_mutexattr_getprioceiling(const pthread_mutexattr_t *attr, int *prioceiling);

int	pthread_mutex_init(pthread_mutex_t *mutex,
	const pthread_mutexattr_t *attr);
int	pthread_mutex_destroy(pthread_mutex_t *mutex);

int	pthread_mutex_lock(pthread_mutex_t *mutex);
int	pthread_mutex_trylock(pthread_mutex_t *mutex);
int	pthread_mutex_unlock(pthread_mutex_t *mutex);

int	pthread_mutex_timedlock(pthread_mutex_t *mutex,
	const struct timespec *timeout);

int pthread_mutex_consistent(pthread_mutex_t *mutex);

int pthread_sigqueue(pthread_t thread, int signo, const union sigval val);

pid_t gettid(void);
pid_t gettid_max(void);

#endif
