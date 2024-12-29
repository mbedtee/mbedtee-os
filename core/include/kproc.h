/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * basic kernel process struct
 */

#ifndef _KPROCESS_H
#define _KPROCESS_H

#include <mmu.h>

struct thread;
struct process;

/*
 * kernel process init
 *
 * one SoC have only one kernel process
 * and multiple user-processes
 */
int kproc_init(void);

/*
 * Returns the kernel process pointers
 */
struct process *kproc(void);
struct pt_struct *kpt(void);
struct thread *kthread(void);

#endif
