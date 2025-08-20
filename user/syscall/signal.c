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

unsigned int alarm(unsigned int seconds)
{
	static timer_t timerid = -1;
	timer_t tid = 0;
	timer_t expected = -1;
	unsigned int ret = 0;
	struct sigevent evp;
	struct itimerspec ts, ots;

	tid = __atomic_load_n(&timerid, __ATOMIC_ACQUIRE);
	if (tid == (timer_t)-1) {
		memset(&evp, 0, sizeof(evp));
		evp.sigev_notify = SIGEV_SIGNAL;
		evp.sigev_signo = SIGTIMER;
		ret = timer_create(CLOCK_REALTIME, &evp, &tid);
		if (ret != 0)
			return 0;

		if (!__atomic_compare_exchange_n(&timerid, &expected, tid,
			false, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
			timer_delete(tid);
			tid = expected;
		}
	}

	memset(&ts, 0, sizeof(ts));
	ts.it_value.tv_sec = seconds;
	ret = timer_settime(tid, 0, &ts, &ots);
	if (ret != 0)
		return 0;

	ret = ots.it_value.tv_sec;
	if ((ots.it_value.tv_nsec >= 500000000L) ||
		(ret == 0 && ots.it_value.tv_nsec > 0))
		++ret;

	return ret;
}

static void __dead2 __sigreturn(void)
{
	for (;;)
		syscall0(SYSCALL_SIGRETURN);
}

/* Default signal handler */
static void __sigdefault(int signo,	siginfo_t *info, void *ctx)
{
	LMSG("recv %d - code %d val %p\n", signo,
		info->si_code, info->si_value.sival_ptr);

	/* SIGCANCEL is thread-wide */
	if (signo == SIGCANCEL)
		pthread_exit(info->si_value.sival_ptr);
	else
		exit(info->si_value.sival_int);
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
