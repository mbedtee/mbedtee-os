/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * exception vectors for AArch32@ARMV7-A based
 */

#include "aarch32-ctx.h"

.align 5
.global exception_vectors
exception_vectors:
	b	. /* reset */
	b	_undefined_abort
	b	_syscall_handler
	b	_prefetch_abort
	b	_data_abort
	b	. /* reserved */
	b	_irq_handler
	b	. /* fiq */

_irq_handler:
	cpsid aif
	sub	lr, lr, #(BYTES_PER_LONG)
	save_thread_context
	bl irq_forward
	b exception_return

_prefetch_abort:
	cpsid aif
	sub lr, lr, #(BYTES_PER_LONG)
	save_thread_context
	bl prefetch_abort
 	b exception_return

_undefined_abort:
	cpsid aif
	save_thread_context
	bl undefined_abort
	b exception_return

_data_abort:
 	cpsid aif
	sub lr, lr, #(BYTES_PER_LONG * 2)
	prepare_abort_ksp
	beq _data_abort_might_sleep
	save_thread_context
	bl data_abort
	b exception_return

_data_abort_might_sleep:
	save_thread_context
	cps #(SYS_MODE)
	mov sp, r0
	bl data_abort
	cps #(SVC_MODE)
	mov sp, r0
	b exception_return

_syscall_handler:
	cpsid aif
	prepare_syscall_ksp
	save_thread_context
	cps #(SYS_MODE)
	mov sp, r0

	bl sys_handler

	cps #(SVC_MODE)
	mov sp, r0 /* r0 might be changed during sys_handler */

#ifdef CONFIG_REE_THREAD
exception_return:
	/*
	 * switch-world can only be done in the monitor mode,
	 * thus we switch to the monitor mode manually.
	 */
	add sp, sp, #(THREAD_CTX_SIZE)
	cps #(MON_MODE)
	sub sp, sp, #(THREAD_CTX_SIZE)
	b monitor_return
#else
exception_return:
	bl sched_sighandle
	restore_thread_context
	clrex
	movs pc, lr
#endif

/*
 * schedule routine (yield to other thread).
 * Must not use the current thread's stack
 */
FUNC_START schedule
	mrs r2, cpsr
	mov r3, lr
	cpsid aif
	cps #(IRQ_MODE)
	msr spsr_cxsf, r2
 	mov lr, r3
	save_thread_context
	bl sched_exec
	b exception_return
FUNC_END schedule
