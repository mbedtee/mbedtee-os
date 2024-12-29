/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Syscall - Wait the lock or wakeup the waiters
 */

#ifndef _PTHREAD_WAITDEP_H
#define	_PTHREAD_WAITDEP_H

#include <syscall.h>

#include <__pthread.h>

extern void __pthread_testcancelself(void);

static inline long __pthread_sys_wait(long usecs)
{
	__pthread_testcancelself();

	/* if usecs == 0, then wait infinitely */
	return syscall1(SYSCALL_WAIT, usecs);
}

static inline long __pthread_sys_wake(pid_t tid)
{
	return syscall_errno(syscall1(SYSCALL_WAKE, tid));
}

/*
 * the reader waits the lock from the resource owner,
 * the calling thread will be blocked at process's
 * kernelspace waitqueue.
 */
static inline long __pthread_wait_rdlock(void *ptr)
{
	__pthread_testcancelself();

	return syscall_errno(syscall2(SYSCALL_WAIT_RDLOCK, ptr, 0));
}

/*
 * the reader waits the lock from the resource owner,
 * the calling thread will be blocked at process's
 * kernelspace waitqueue.
 *
 * Returns:
 * 0: lock is acquired after the timeout elapsed
 * others: lock is not acquired after the timeout elapsed
 */
static inline long __pthread_timedwait_rdlock(void *ptr, long usecs)
{
	__pthread_testcancelself();

	return syscall_errno(syscall2(SYSCALL_WAIT_RDLOCK, ptr, usecs));
}

/*
 * the writer waits the lock from the resource owner,
 * the calling thread will be blocked at process's
 * kernelspace waitqueue.
 *
 * #owner (tid) is for priority inherit - PTHREAD_PRIO_INHERIT
 *   try to give a more higher priority to
 *   let the original owner run ASAP
 */
static inline long __pthread_wait_wrlock(void *ptr, pid_t owner)
{
	__pthread_testcancelself();

	return syscall_errno(syscall3(SYSCALL_WAIT_WRLOCK, ptr, owner, 0 /*usecs*/));
}

/*
 * the writer waits the lock from the resource owner,
 * the calling thread will be blocked at process's
 * kernelspace waitqueue.
 *
 * #owner (tid) is for priority inherit - PTHREAD_PRIO_INHERIT
 *   try to give a more higher priority to
 *   let the original owner run ASAP
 *
 * Returns:
 * 0: lock is acquired after the timeout elapsed
 * others: lock is not acquired after the timeout elapsed
 */
static inline long __pthread_timedwait_wrlock(void *ptr, pid_t owner, long usecs)
{
	__pthread_testcancelself();

	return syscall_errno(syscall3(SYSCALL_WAIT_WRLOCK, ptr, owner, usecs));
}

/*
 * Resource owner notifies the waiters to wakeup.
 */
static inline void __pthread_wakeup_lock(void *ptr, uint32_t waiters)
{
	if (waiters)
		syscall1(SYSCALL_WAKE_LOCK, ptr);
}

#endif
