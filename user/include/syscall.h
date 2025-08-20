/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
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
#define SYSCALL_STAT                    19
#define SYSCALL_TRUNCATE                20
#define SYSCALL_READDIR                 21
#define SYSCALL_MKDIR                   22
#define SYSCALL_RMDIR                   23
#define SYSCALL_EXECVE                  24

#define SYSCALL_PREAD                   25
#define SYSCALL_PWRITE                  26

#define SYSCALL_SCHED_SETSCHEDULER      27
#define SYSCALL_SCHED_GETSCHEDULER      28
#define SYSCALL_SCHED_SETPARAM          29
#define SYSCALL_SCHED_GETPARAM          30
#define SYSCALL_SCHED_SETAFFINITY       31
#define SYSCALL_SCHED_GETAFFINITY       32
#define SYSCALL_SCHED_GET_PRIORITY_MAX  33
#define SYSCALL_SCHED_GET_PRIORITY_MIN  34

#define SYSCALL_USLEEP                  35
#define SYSCALL_MSLEEP                  36

#define SYSCALL_PTHREAD_CREATE          37

#define SYSCALL_DUP                     38
#define SYSCALL_DUP2                    39

#define SYSCALL_WAIT_RDLOCK             40
#define SYSCALL_WAIT_WRLOCK             41
#define SYSCALL_WAKE_LOCK               42
#define SYSCALL_WAIT                    43
#define SYSCALL_WAKE                    44

#define SYSCALL_CLOCKGETTIME            45
#define SYSCALL_TIMER_CREATE            46
#define SYSCALL_TIMER_DELETE            47
#define SYSCALL_TIMER_SETTIME           48
#define SYSCALL_TIMER_GETTIME           49
#define SYSCALL_TIMER_GETOVERRUN        50
#define SYSCALL_CLOCKGETRES             51

#define SYSCALL_PAUSE                   52
#define SYSCALL_SIGACTION               53
#define SYSCALL_SIGPROCMASK             54
#define SYSCALL_SIGQUEUE                55
#define SYSCALL_SIGPENDING              56
#define SYSCALL_SIGTIMEDWAIT            57
#define SYSCALL_SIGSUSPEND              58
#define SYSCALL_SIGALTSTACK             59

#define SYSCALL_EPOLL_CREATE            60
#define SYSCALL_EPOLL_CTL               61
#define SYSCALL_EPOLL_WAIT              62

#define SYSCALL_SELECT                  63
#define SYSCALL_PSELECT                 64

#define SYSCALL_FCNTL                   65
#define SYSCALL_PIPE                    66

#define SYSCALL_MQ_OPEN                 67
#define SYSCALL_MQ_UNLINK               68
#define SYSCALL_MQ_TIMEDSEND            69
#define SYSCALL_MQ_TIMEDRECEIVE         70
#define SYSCALL_MQ_GETSETATTR           71
#define SYSCALL_MQ_NOTIFY               72
#define SYSCALL_MQ_SENDFD               73
#define SYSCALL_MQ_RECEIVEFD            74

#define SYSCALL_POSIX_SPAWN             75
#define SYSCALL_WAITPID                 76
#define SYSCALL_EVENTFD2                77

#define SYSCALL_SEM_INIT                78
#define SYSCALL_SEM_DESTROY             79
#define SYSCALL_SEM_POST                80
#define SYSCALL_SEM_WAIT                81
#define SYSCALL_SEM_TRYWAIT             82
#define SYSCALL_SEM_TIMEDWAIT           83
#define SYSCALL_SEM_GETVALUE            84
#define SYSCALL_SEM_OPEN                85
#define SYSCALL_SEM_CLOSE               86
#define SYSCALL_SEM_UNLINK              87

#define SYSCALL_SET_CONFIG              88
#define SYSCALL_GET_PROPERTY            89
#define SYSCALL_GET_FUNCNAME            90
#define SYSCALL_GET_PROC_INFO           91

#if !defined(__ASSEMBLY__)

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

#endif

#endif
