/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * responds to the _sbrk() system call to resize the libc heap
 */

#ifndef _SBRK_H
#define _SBRK_H

int sbrk_init(struct process *proc);
long sbrk_incr(long incr);

#endif
