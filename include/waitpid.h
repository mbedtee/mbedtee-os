/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * Minimal waitpid() interface.
 *
 * Notes:
 * - This is a minimal implementation intended for MbedTEE's spawn/pipeline use.
 * - The returned status is the child's raw _exit() value (not POSIX-encoded).
 * - Supported options: WNOHANG.
 * - Supported pid values:
 *   - pid > 0: wait for a specific child process id
 *   - pid == -1: wait for any child process
 */

#ifndef _WAITPID_H
#define _WAITPID_H

#include <sys/types.h>

/* Supported waitpid() options (minimal) */
#ifndef WNOHANG
#define WNOHANG 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

pid_t waitpid(pid_t pid, int *status, int options);

#ifdef __cplusplus
}
#endif

#endif
