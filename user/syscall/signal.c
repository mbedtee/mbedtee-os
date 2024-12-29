// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Signal functions
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <reent.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

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
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, signo);
	if (sigaction(signo, &act, &oact) < 0)
		return SIG_ERR;

	return oact.sa_handler;
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
	siginfo_t info = {0};

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
	unsigned int ret = 0;
	struct sigevent evp;
	struct itimerspec ts = {0}, ots;
	timer_t timerid = -1;

	evp.sigev_notify = SIGEV_SIGNAL;
	evp.sigev_signo = SIGTIMER;
	ret = timer_create(CLOCK_REALTIME, &evp, &timerid);
	if (ret != 0)
		return 0;

	ts.it_value.tv_sec = (time_t)seconds;
	ret = timer_settime(timerid, !TIMER_ABSTIME, &ts, &ots);
	if (ret != 0) {
		timer_delete(timerid);
		return 0;
	}

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
	if ((_sig_func_ptr)sighandler == SIG_DFL)
		sighandler = __sigdefault;

	sighandler(sa->signo, &sa->info, sa->ctx);

	__sigreturn();
}
