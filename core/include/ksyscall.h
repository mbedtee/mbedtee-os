/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 */

#ifndef _KSYSCALL_H
#define _KSYSCALL_H

#include <ctx.h>

/*
 * General system-call entry @ kernel
 */
void *syscall_handler(struct thread_ctx *regs);

#endif
