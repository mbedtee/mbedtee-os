// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Signal functions
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <reent.h>
#include <signal.h>

#include <syscall.h>
#include <utrace.h>

#include <__pthread.h>

#include "pthread_auxiliary.h"

int sigaction(int signo, const struct sigaction *act, struct sigaction *oldact)
{
	int ret = 0;

	ret = syscall3(SYSCALL_SIGACTION, signo, act, oldact);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	int ret = 0;

	ret = syscall3(SYSCALL_SIGPROCMASK, how, set, oldset);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset)
{
	int ret = 0;

	ret = syscall3(SYSCALL_SIGPROCMASK, how, set, oldset);

	errno = syscall_errno(ret);
	return syscall_errno(ret);
}

sighandler_t signal(int signo, sighandler_t handler)
{
	struct sigaction act, oact;

	if ((handler == SIG_ERR) || (signo < 1) || (signo >= NSIG))
		return SIG_ERR;

	act.sa_handler = handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, signo);
	if (sigaction(signo, &act, &oact) < 0)
		return SIG_ERR;

	return oact.sa_handler;
}

int sigaltstack(const stack_t *ss, stack_t *old_ss)
{
	int ret = 0;

	ret = syscall2(SYSCALL_SIGALTSTACK, ss, old_ss);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int _kill_r(struct _reent *ptr, int pid, int signo)
{
	int ret = 0;

	ret = syscall5(SYSCALL_SIGQUEUE, pid, signo,
				SI_USER, 0, false);

	ptr->_errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int pthread_kill(pthread_t thread, int signo)
{
	int ret = 0;

	ret = syscall5(SYSCALL_SIGQUEUE, tid_of(thread), signo,
				SI_USER, 0, true);

	errno = syscall_errno(ret);
	return syscall_errno(ret);
}

int raise(int signo)
{
	return pthread_kill(pthread_self(), signo);
}

int sigqueue(pid_t pid, int signo, const union sigval val)
{
	int ret = 0;

	ret = syscall5(SYSCALL_SIGQUEUE, pid, signo,
				SI_QUEUE, val.sival_ptr, false);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int pthread_sigqueue(pthread_t thread, int signo, const union sigval val)
{
	int ret = 0;

	ret = syscall5(SYSCALL_SIGQUEUE, tid_of(thread), signo,
				SI_QUEUE, val.sival_ptr, true);

	errno = syscall_errno(ret);
	return syscall_errno(ret);
}

int sigtimedwait(const sigset_t *set, siginfo_t *info,
	const struct timespec *timeout)
{
	int ret = 0;

	ret = syscall3(SYSCALL_SIGTIMEDWAIT, set, info, timeout);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int sigwaitinfo(const sigset_t *set, siginfo_t *info)
{
	return sigtimedwait(set, info, NULL);
}

int sigwait(const sigset_t *set, int *sig)
{
	int ret = 0;
	siginfo_t info;

	do {
		ret = sigtimedwait(set, &info, NULL);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0)
		return errno;

	*sig = info.si_signo;

	return 0;
}

int sigpending(sigset_t *set)
{
	int ret = 0;

	ret = syscall1(SYSCALL_SIGPENDING, set);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int sigsuspend(const sigset_t *set)
{
	int ret = 0;

	ret = syscall1(SYSCALL_SIGSUSPEND, set);

	errno = syscall_errno(ret);

	return -1;
}

int pause(void)
{
	int ret = 0;

	ret = syscall0(SYSCALL_PAUSE);

	errno = syscall_errno(ret);

	return -1;
}

/*
 * A SIGTIMER timer dies with its notification, so arm a fresh one per call:
 * re-arming a fired id would be cancelled by that deletion.
 */
static int __alarm_timer_create(timer_t *timerid)
{
	struct sigevent evp;

	memset(&evp, 0, sizeof(evp));
	evp.sigev_notify = SIGEV_SIGNAL;
	evp.sigev_signo = SIGTIMER;

	return timer_create(CLOCK_REALTIME, &evp, timerid);
}

unsigned int alarm(unsigned int seconds)
{
	static timer_t timerid = -1;
	timer_t tid = (timer_t)-1, old = 0;
	struct itimerspec ts, ots;
	unsigned int remaining = 0;

	if (seconds != 0) {
		memset(&ts, 0, sizeof(ts));
		ts.it_value.tv_sec = seconds;

		if (__alarm_timer_create(&tid) != 0)
			return 0;

		if (timer_settime(tid, 0, &ts, NULL) != 0) {
			timer_delete(tid);
			return 0;
		}
	}

	old = __atomic_exchange_n(&timerid, tid, __ATOMIC_ACQ_REL);
	if (old == (timer_t)-1)
		return 0;

	/*
	 * What was left of the previous alarm (rounded up, as before); an id
	 * that already fired reports nothing, which is a remaining of 0 too.
	 */
	memset(&ots, 0, sizeof(ots));
	if (timer_gettime(old, &ots) == 0) {
		remaining = ots.it_value.tv_sec;
		if ((ots.it_value.tv_nsec >= 500000000L) ||
			((remaining == 0) && (ots.it_value.tv_nsec > 0)))
			++remaining;
	}

	/* cancel it; a notification that is already queued stays queued */
	timer_delete(old);

	return remaining;
}

static void __dead2 __sigreturn(void)
{
	for (;;)
		syscall0(SYSCALL_SIGRETURN);
}

/* Default signal handler */
static void __sigdefault(int signo,	siginfo_t *info, void *ctx)
{
	struct __pthread *self = __pthread_self;

	LMSG("recv %d - code %d val %p\n", signo,
		info->si_code, info->si_value.sival_ptr);

	/* SIGCANCEL is thread-wide */
	if (signo == SIGCANCEL) {
		/*
		 * pthread_join()/pthread_detach() wake a parked (detaching)
		 * thread with SIGCANCEL. The signal payload is only a hint:
		 * the kernel synthesizes it (ENOMEM -> 0xc) when the sigqueue
		 * node could not be allocated, which must not leak into the
		 * exit value. The authoritative value is the one this thread
		 * published in join_q.notification before parking.
		 */
		if (self->detaching)
			pthread_exit(pthread_aux(self)->join_q.notification);

		pthread_exit(info->si_value.sival_ptr);
	} else {
		exit(info->si_value.sival_int);
	}
}

extern void signal_entry(void (*sighandler)(int signo,
	siginfo_t *info, void *ctx), struct sigarguments *sa)
{
	int ori_errno = errno;

	if ((_sig_func_ptr)sighandler == SIG_DFL)
		sighandler = __sigdefault;

	sighandler(sa->info.si_signo, &sa->info, sa->ctx);

	errno = ori_errno;
	__sigreturn();
}
