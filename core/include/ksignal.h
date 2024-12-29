/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * implementation for user-signal (kernel part)
 */

#ifndef _KSIGNAL_H
#define _KSIGNAL_H

#include <signal.h>
#include <list.h>
#include <spinlock.h>

#include <generated/autoconf.h>

struct thread;
struct process;

int sigenqueue(pid_t id, int signo, int sigcause,
	const union sigval value, bool threaddirected);

int sigdequeue(struct thread *t, sigset_t *mask, siginfo_t *info);

int sigt_init(struct thread *t);
int sigt_free(struct thread *t);
int sigp_init(struct process *proc);
int sigp_free(struct process *proc);

#if defined(CONFIG_SIGNAL)

/* Max. number of the queued signals for each process */
#define MAX_NUMOF_QUEUED (4096)

struct sigqueue {
	siginfo_t info;
	struct list_head node;
};

struct signal_proc {
	struct spinlock lock;

	/* current num of queued signals, process-wide, roughly */
	int nrqueued;

	/* global actions for all signals */
	struct sigaction act[NSIG];

	/* queued signals for whole process */
	sigset_t pending;
	struct list_head queue;
};

struct signal_thread {
	/* current signo under handling */
	uint8_t sighandling;
	/* last signo before SIGSTOP */
	uint8_t siglast;

	/* continuous cnt of signal handling */
	uint16_t continuouscnt;

	sigset_t mask; /* current runtime mask */
	sigset_t sigwait; /* set of sigwait, not mask */
	sigset_t savedmask;/* saved mask of during each sighandle() */

	/* queued signals for thread */
	sigset_t pending;
	struct list_head queue;
};

/*
 * thread has pending signal or not
 */
#define is_sigtpending(t) ((t)->sigt.pending & ~(t)->sigt.mask)

/*
 * thread and process have pending signal or not
 */
#define is_sigpending(t) (((t)->sigt.pending | (t)->proc->sigp.pending) & ~(t)->sigt.mask)

/*
 * thread is handling which signo
 */
#define sighandling(t) ((t)->sigt.sighandling)

#else

struct signal_proc {};
struct signal_thread {};

#define is_sigtpending(t) (false)
#define is_sigpending(t) (false)
#define sighandling(t) (0)

#endif

#endif
