/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 */

#ifndef _KSYSCALL_H
#define _KSYSCALL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ctx.h>

/*
 * General system-call entry @ kernel
 */
void *syscall_handler(struct thread_ctx *regs);

#ifdef __cplusplus
}
#endif
#endif
