/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * syscall definitions
 */

#ifndef _SYSCALL_H
#define _SYSCALL_H

/*
 * 0 ~ 5 is reserved for the syscalls
 * which may change the regs-context holder
 */
#define SYSCALL_SCHED_YIELD             0
#define SYSCALL_SCHED_SUSPEND           1
#define SYSCALL_SIGRETURN               2
#define SYSCALL_PTHREAD_EXIT            3 /* thread termination */
#define SYSCALL_EXIT                    4 /* process termination */
#define SYSCALL_RESERVED                5

#define SYSCALL_OPEN                    6
#define SYSCALL_CLOSE                   7
#define SYSCALL_READ                    8
#define SYSCALL_WRITE                   9
#define SYSCALL_IOCTL                   10
#define SYSCALL_SBRK                    11
#define SYSCALL_MMAP                    12
#define SYSCALL_MUNMAP                  13
#define SYSCALL_POLL                    14
#define SYSCALL_RENAME                  15
#define SYSCALL_REMOVE                  16
#define SYSCALL_LSEEK                   17
#define SYSCALL_FSTAT                   18
#define SYSCALL_TRUNCATE                19
#define SYSCALL_READDIR                 20
#define SYSCALL_MKDIR                   21
#define SYSCALL_RMDIR                   22
#define SYSCALL_EXECVE                  23

#define SYSCALL_SCHED_SETSCHEDULER      24
#define SYSCALL_SCHED_GETSCHEDULER      25
#define SYSCALL_SCHED_SETPARAM          26
#define SYSCALL_SCHED_GETPARAM          27
#define SYSCALL_SCHED_SETAFFINITY       28
#define SYSCALL_SCHED_GETAFFINITY       29
#define SYSCALL_SCHED_GET_PRIORITY_MAX  30
#define SYSCALL_SCHED_GET_PRIORITY_MIN  31

#define SYSCALL_USLEEP                  32
#define SYSCALL_MSLEEP                  33

#define SYSCALL_PTHREAD_CREATE          34

#define SYSCALL_DUP                     35
#define SYSCALL_DUP2                    36

#define SYSCALL_WAIT_RDLOCK             37
#define SYSCALL_WAIT_WRLOCK             38
#define SYSCALL_WAKE_LOCK               39
#define SYSCALL_WAIT                    40
#define SYSCALL_WAKE                    41

#define SYSCALL_CLOCKGETTIME            42
#define SYSCALL_TIMER_CREATE            43
#define SYSCALL_TIMER_DELETE            44
#define SYSCALL_TIMER_SETTIME           45
#define SYSCALL_TIMER_GETTIME           46
#define SYSCALL_TIMER_GETOVERRUN        47

#define SYSCALL_MQ_OPEN                 48
#define SYSCALL_MQ_TIMEDSEND            49
#define SYSCALL_MQ_TIMEDRECEIVE         50
#define SYSCALL_MQ_GETSETATTR           51
#define SYSCALL_MQ_NOTIFY               52
#define SYSCALL_MQ_SENDFD               53
#define SYSCALL_MQ_RECEIVEFD            54

#define SYSCALL_PAUSE                   55
#define SYSCALL_SIGACTION               56
#define SYSCALL_SIGPROCMASK             57
#define SYSCALL_SIGQUEUE                58
#define SYSCALL_SIGPENDING              59
#define SYSCALL_SIGTIMEDWAIT            60
#define SYSCALL_SIGSUSPEND              61

#define SYSCALL_EPOLL_CREATE            62
#define SYSCALL_EPOLL_CTL               63
#define SYSCALL_EPOLL_WAIT              64

#define SYSCALL_SET_CONFIG              65
#define SYSCALL_GET_PROPERTY            66

#define SYSCALL_GET_FUNCNAME            67

#ifndef __ASSEMBLY__

#include <unistd.h>
#include <stddef.h>
#include <errno.h>

#define syscall_stdfd(x)    ((unsigned int)(x) <= STDERR_FILENO)

#define syscall_errno(x) ({const __typeof__(x) __x = (x); \
	(((__x >= 0) || (__x < -__ELASTERROR)) ? 0 : (-__x)); })

#define syscall_retval(x) ({const __typeof__(x) __x = (x); \
	(((__x >= 0) || (__x < -__ELASTERROR)) ? __x : (-1)); })

/*
 * for the syscalls which have less than 3 args
 */
long __syscall(long id, long arg1, long arg2, long arg3);

/*
 * for the syscalls which have more than 3 args
 */
static inline long syscall(long id, long arg1,
	long arg2, long arg3, long arg4, long arg5, long arg6)
{
    /* __builtin_apply_args not work, why? */
	long args[] = {arg1, arg2, arg3, arg4, arg5, arg6};

	return __syscall(id, (long)args, 0, 0);
}

#define syscall0(id)				__syscall(id, 0, 0, 0)
#define syscall1(id, a1)			__syscall(id, (long)(a1), 0, 0)
#define syscall2(id, a1, a2)		__syscall(id, (long)(a1), (long)(a2), 0)
#define syscall3(id, a1, a2, a3)	__syscall(id, (long)(a1), (long)(a2), (long)(a3))

#define syscall4(id, a1, a2, a3, a4) \
	syscall(id, (long)(a1), (long)(a2), (long)(a3), (long)(a4), 0, 0)
#define syscall5(id, a1, a2, a3, a4, a5) \
	syscall(id, (long)(a1), (long)(a2), (long)(a3), (long)(a4), (long)(a5), 0)
#define syscall6(id, a1, a2, a3, a4, a5, a6) \
	syscall(id, (long)(a1), (long)(a2), (long)(a3), (long)(a4), (long)(a5), (long)(a6))
#endif

#endif
