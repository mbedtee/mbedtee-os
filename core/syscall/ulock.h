/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * syscall for user-mutex wait/wakeup
 */

#ifndef _SYSCALL_ULOCK_H
#define _SYSCALL_ULOCK_H

#ifdef __cplusplus
extern "C" {
#endif

long do_syscall_wait_rdlock(struct thread_ctx *regs);

long do_syscall_wait_wrlock(struct thread_ctx *regs);

long do_syscall_wake_lock(struct thread_ctx *regs);

#ifdef __cplusplus
}
#endif
#endif
