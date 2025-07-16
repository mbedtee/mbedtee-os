/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * kernel waitpid syscall interface
 */

#ifndef _SYS_WAITPID_H
#define _SYS_WAITPID_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ctx.h>
#include <errno.h>
#include <sys/types.h>

#if defined(CONFIG_WAITPID)
/*
 * Returns: pid on success, negative errno on failure.
 * If kstatus is non-NULL, it receives the child's raw exit code.
 */
pid_t kwaitpid(pid_t pid, int *kstatus, int options);
/* split-out syscall handlers */
long syscall_waitpid(struct thread_ctx *regs);
#else
static inline pid_t kwaitpid(pid_t pid, int *kstatus, int options) { return -ENOSYS; }
static inline long syscall_waitpid(struct thread_ctx *regs) { return -ENOSYS; }
#endif

#ifdef __cplusplus
}
#endif

#endif
