// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * unwind backtrace @ userspace
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <sys/fcntl.h>

#include <syscall.h>
#include <unwind.h>
#include <backtrace.h>

#include <__pthread.h>

#include <pthread_mutexdep.h>

#if defined(__arm__)
typedef struct {_uw fnoffset; _uw content; } __EIT_entry;
__weak_symbol void __cxa_call_unexpected(_Unwind_Control_Block *ucbp) {}
__weak_symbol bool __cxa_begin_cleanup(_Unwind_Control_Block *ucbp) {return false; }
__weak_symbol int __cxa_type_match(_Unwind_Control_Block *ucbp, void *rttip,
	bool is_reference, void **matched_object)
{return false; }
#ifndef CONFIG_USER_BACKTRACE
__weak_symbol void *__gnu_Unwind_Find_exidx(void *pc, int *nrec) {return NULL; }
#endif
#endif

#ifdef CONFIG_USER_BACKTRACE

static int tracer_fd = -1;
DECLARE_RECURSIVE_PTHREAD_MUTEX(brslock);

static void __tprintf(const char *fmt, ...)
{
	va_list args;
	size_t l = 0;
	char tracer_buf[256];

	va_start(args, fmt);
	l = vsnprintf(tracer_buf, sizeof(tracer_buf), fmt, args);
	va_end(args);

	syscall3(SYSCALL_WRITE, tracer_fd, tracer_buf, l);
}

static _Unwind_Reason_Code __tracer(struct _Unwind_Context *ctx, void *d)
{
	int *depth = (int *)d;
	long offset = -1;
	static unsigned long lastlreg;
	unsigned long lreg = _Unwind_GetIP(ctx);
	char name_buf[128];

	if (*depth && lreg) {
		syscall3(SYSCALL_GET_FUNCNAME, lreg, name_buf, &offset);

		if ((offset == 0) && (*depth > 1))
			syscall3(SYSCALL_GET_FUNCNAME, lreg - sizeof(int),
					name_buf, &offset);

		if (strlen(name_buf)) {
			if (sizeof(long) == sizeof(int))
				__tprintf("#%d        <%08lx>                        (%s + 0x%lx)\n", *depth, lreg, name_buf, offset);
			else
				__tprintf("#%d        <%016lx>                (%s + 0x%lx)\n", *depth, lreg, name_buf, offset);
		} else {
			if (sizeof(long) == sizeof(int))
				__tprintf("#%d        <%08lx>\n", *depth, lreg);
			else
				__tprintf("#%d        <%016lx>\n", *depth, lreg);
		}
	}

	if (lastlreg == lreg)
		return _URC_END_OF_STACK;

	*depth += 1;
	lastlreg = lreg;

	return _URC_NO_REASON;
}

#if defined(__arm__)
void *__gnu_Unwind_Find_exidx(void *pc, int *nrec)
{
	int i = 0;
	struct __process *proc = __pthread_self->proc;
	struct unwind_info *unw = &proc->unwind;

	for (i = 0; i < MAX_UNWIND_TABLES; i++) {
		if ((pc >= unw->l_addr[i]) &&
			(pc < unw->l_addr[i] + unw->l_size[i])) {
			*nrec = unw->tabsize[i] / sizeof(__EIT_entry);
			return unw->tabs[i];
		}
	}

	return NULL;
}
#endif

void unwind_init(void)
{
#if !defined(__arm__)
	int i = 0;
	static int initflag;
	struct __process *proc = __pthread_self->proc;

	if (initflag == false) {
		initflag = true;
		for (i = 0; i < proc->unwind.nrtabs; i++)
			__register_frame(proc->unwind.tabs[i]);
	}
#endif
}

extern void backtrace(void)
{
	int depth = 0;

	__pthread_mutex_lock(&brslock);

	tracer_fd = syscall2(SYSCALL_OPEN, "/dev/uart0", O_RDWR);

	__tprintf("[INF %04u|%04u@CPU%02u]%s              (%04d):\n",
		gettid(), getpid(), sched_getcpu(), __func__, __LINE__);

	_Unwind_Backtrace(&__tracer, &depth);

	syscall1(SYSCALL_CLOSE, tracer_fd);

	__pthread_mutex_unlock(&brslock);

	_exit(-EFAULT);
}

#endif
