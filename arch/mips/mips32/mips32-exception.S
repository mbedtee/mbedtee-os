/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MIPS32 exception entry
 */

#include <mips32-asm.h>

.section ".asm.text", "ax"

.set push
.set noat
.set noreorder
.set nomips16

/*
 * exception_entry @ ebase + 0x180
 */
align_ebase

FUNC_START exception_entry
	save_thread_context
	jump exception_handler
	restore_thread_context
	eret
FUNC_END exception_entry

/*
 * schedule routine (yield to other thread).
 * Currently uses the IRQ sp
 */
FUNC_START schedule
	save_thread_context_sched
	jump sched_exec
	restore_thread_context
	eret
FUNC_END schedule

.set pop
