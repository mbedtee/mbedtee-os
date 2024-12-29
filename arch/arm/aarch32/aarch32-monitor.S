/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch32@ARMV7-A SMC/FIQ routines for TEE/REE world switching
 */

#include "aarch32-ctx.h"

#define MONITOR_STACK_SIZE (2048)

.align 5
.global monitor_vectors
monitor_vectors:
monitor_reset:
	b   monitor_reset
monitor_undef:
	b   monitor_undef
	b   monitor_smc_handler
monitor_pref:
	b   monitor_pref
monitor_abort:
	b   monitor_abort
monitor_reserved:
	b   monitor_reserved
monitor_irq:
	b   monitor_irq
	b	monitor_fiq_handler

#ifdef CONFIG_REE_THREAD

.macro check_ns_flag rd
	mrc p15, 0, \rd, c13, c0, 4
	ldr \rd, [\rd, #(PERCPU_NS_FLAG)]
	cmp \rd, #1
.endm

/* restore secure world in MON mode */
.macro restore_s_context
	unset_nsbit r12

	ree_context_ptr r12
	bl save_precpu_ctx

	tee_context_ptr r12
	bl restore_precpu_ctx
.endm

/* restore ns world in MON mode */
.macro restore_ns_context
	tee_context_ptr r12
	bl save_precpu_ctx

	ree_context_ptr r12
	bl restore_precpu_ctx

	set_nsbit r12
.endm

/*
 * FIQ is routed to monitor mode
 * but the link value is following FIQ mode (lr + 4).
 */
monitor_fiq_handler:
	sub lr, lr, #(BYTES_PER_LONG)
	is_nsbit_unset r12
	beq fiq_called_from_s
	bne fiq_called_from_ns

monitor_smc_handler:
	is_nsbit_unset r12
	beq smc_called_from_s
	bne smc_called_from_ns

fiq_called_from_s:
	save_thread_context
	bl irq_handler
	b monitor_return

fiq_called_from_ns:
	save_thread_context
	restore_s_context
	bl irq_handler
	b monitor_return

/*
 * TEE2Monitor calls:
 *
 * r0 == 2: secondary_cpu_restart
 */
smc_called_from_s:
	cmp r0, #2
	beq secondary_cpu_restart
	b .

smc_called_from_ns:
	save_thread_context
	restore_s_context
	jump_smc_handler
	b monitor_return

.global monitor_return
monitor_return:
	check_ns_flag r12
	beq monitor_return_ns
monitor_return_s:
	/* call sighandle only for secure-world */
	bl sched_sighandle
	/* s/ns thread might be changed during sighandle, check again */
	check_ns_flag r12
	beq monitor_return_ns
	restore_thread_context
	clrex
	movs pc, lr

monitor_return_ns:
	restore_ns_context
	restore_thread_context
	clrex
	movs pc, lr

#else

/*
 * FIQ is routed to monitor mode
 * but the link value is following FIQ mode (lr + 4).
 */
monitor_fiq_handler:
	sub lr, lr, #(BYTES_PER_LONG)
	is_nsbit_unset r12
	beq fiq_called_from_s
	bne fiq_called_from_ns

monitor_smc_handler:
	is_nsbit_unset r12
	beq smc_called_from_s
	bne smc_called_from_ns

fiq_called_from_ns:
	push {r12, lr}
	push {r7}
	unset_nsbit r7
	ree_context_ptr r12
	set_nsbit r7
	pop {r7}
	bl save_thread_ctx
	unset_nsbit r7
	bl save_precpu_ctx

	tee_context_ptr r0
	add r12, r0, #(THREAD_CTX_SIZE)
	bl restore_precpu_ctx
	bl restore_thread_ctx

	tee_context_ptr r0
	bl irq_handler
	b monitor_return

smc_called_from_ns:
	push {r12, lr}
	push {r7}
	unset_nsbit r7
	ree_context_ptr r12
	set_nsbit r7
	pop {r7}
	bl save_thread_ctx
	unset_nsbit r7
	bl save_precpu_ctx

	tee_context_ptr r0
	add r12, r0, #(THREAD_CTX_SIZE)
	bl restore_precpu_ctx
	bl restore_thread_ctx

	tee_context_ptr r0
	jump_smc_handler
	b monitor_return

fiq_called_from_s:
	push {r12, lr}
	tee_context_ptr r12
	bl save_thread_ctx
	sub r0, r12, #(THREAD_CTX_SIZE)
	bl irq_handler
	b monitor_return

monitor_return:
	bl sched_sighandle
	bl restore_thread_ctx
	clrex
	movs pc, lr

/*
 * TEE2Monitor calls:
 */
smc_handling_for_s:
	cmp r0, #2
	beq secondary_cpu_restart
	b .

/*
 * r0 == 0: resume NS
 * r0 == others: TEE2Monitor calls
 *
 * r0 == 2: secondary_cpu_restart
 */
smc_called_from_s:
	cmp r0, #0
	bne smc_handling_for_s
	push {r12, lr}
	tee_context_ptr r12
	bl save_thread_ctx
	bl save_precpu_ctx

	ree_context_ptr r0
	add r12, r0, #(THREAD_CTX_SIZE)
	bl restore_precpu_ctx
	set_nsbit r12
	bl restore_thread_ctx
	clrex
	movs pc, lr
#endif

/* r0 holds the cpu-id */
FUNC_START _monitor_stack_init
	mov r1, #(MONITOR_STACK_SIZE)
	ldr r2, =__monitor_stack
	add	r2, r2, r1
	mla r2, r0, r1, r2
	mov sp, r2
	bx lr
FUNC_END _monitor_stack_init

	.bss
	.align 6
.global __monitor_stack
__monitor_stack:
	.fill MONITOR_STACK_SIZE * CONFIG_NR_CPUS, 1, 0
