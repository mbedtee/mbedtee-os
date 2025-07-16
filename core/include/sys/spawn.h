/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * spawn syscall interface (kernel)
 */

#ifndef _SYS_SPAWN_H
#define _SYS_SPAWN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ctx.h>
#include <errno.h>
#include <spawn.h>

#if defined(CONFIG_SPAWN)
/* Implemented in core/syscall/spawn.c when CONFIG_SPAWN=y */
long syscall_posix_spawn(struct thread_ctx *regs);
/* In-kernel helper (used by kernel shell, etc). */
int kposix_spawn(pid_t *pid, const char *path,
	const posix_spawn_file_actions_t *file_actions,
	char *const argv[]);
#else
static inline int kposix_spawn(pid_t *pid, const char *path,
	const posix_spawn_file_actions_t *file_actions, char *const argv[]) { return -ENOSYS; }
static inline long syscall_posix_spawn(struct thread_ctx *regs) { return -ENOSYS; }
#endif

#ifdef __cplusplus
}
#endif

#endif
