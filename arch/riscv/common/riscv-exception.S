/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RISCV32/RISCV64 exception entry
 */

#include "riscv-asm.h"

/*
 * exception_entry, shall be at least aligned to 4 bytes
 */
.section ".head.text", "ax"

FUNC_START exception_entry
	save_thread_context
	call exception_handler
	mv sp, a0 /* a0 might be changed during syscall */
	restore_thread_context
	eret
FUNC_END exception_entry

/*
 * schedule routine (yield to other thread).
 * Currently uses the IRQ sp
 */
FUNC_START schedule
	save_thread_context_sched
	call sched_exec
	restore_thread_context
	eret
FUNC_END schedule

/*
 * exception_entry of m-mode, helps to
 * handle some requests from s-mode
 */
#if defined(CONFIG_RISCV_S_MODE)
FUNC_START exception_entry_mmode
	csrrw a5, mscratch, a5

	STR a6, (0 * BYTES_PER_LONG)(a5)
	STR a7, (1 * BYTES_PER_LONG)(a5)

	/* check if it's interrupt ? */
	csrr a6, mcause
	li a7, 1 << (__riscv_xlen - 1)
	and a7, a7, a6
	beq a7, zero, __mecall_exception
	li a7, (1 << (__riscv_xlen - 1)) - 1
	and a7, a7, a6

	li a6, 7  /* M-Timer */
	beq a6, a7, __mtimer_irq

	li a6, 3  /* M-IPI */
	beq a6, a7, __mipi_irq

	beqz zero, .

__mipi_irq:
	la a7, __ipibase
	LDR a7, (a7)
	csrr a6, mhartid
	slli a6, a6, 2
	add	a7, a7, a6
	sw zero, (a7)
	fence ow, ow
	csrs mip, 1 << 1 /* S-IPI */
	beqz zero, __mirq_done

__mtimer_irq:
	li a6, 1 << 7
	csrc mie, a6 /* M-Timer */
	li a6, 1 << 5
	csrs mip, a6 /* S-Timer */

__mirq_done:
	LDR a6, (0 * BYTES_PER_LONG)(a5)
	LDR a7, (1 * BYTES_PER_LONG)(a5)
	csrrw a5, mscratch, a5
	mret

__mecall_exception:
	csrrw a5, mscratch, a5
	csrr a7, mepc
	addi a7, a7, 4
	csrw mepc, a7
	li a7, ECALL_RDTIME
	beq a0, a7, __mecall_rdtime
	li a7, ECALL_WRTIME
	beq a0, a7, __mecall_wrtime
	li a7, ECALL_SENDIPI
	beq a0, a7, __mecall_sendipi
#	mret
	beqz zero, .

__mecall_rdtime:
	li a7, 0x7ff8
	add	a7, a7, a3
#if defined(CONFIG_64BIT)
	ld a0, (a7)
#else
1:	lw a1, 4(a7)
	lw a0, (a7)
	lw a2, 4(a7)
	bne a1, a2, 1b
#endif
	mret

__mecall_wrtime:
	csrr a7, mhartid
	slli a7, a7, 3
	add	a7, a7, a3
#if defined(CONFIG_64BIT)
	sd a1, (a7)
#else
	li a6, -1
	sw a6, 4(a7)
	sw a1, (a7)
	sw a2, 4(a7)
#endif
	li a6, 1 << 5 /* S-Timer */
	csrc mip, a6
	li a6, 1 << 7 /* M-Timer */
	csrs mie, a6
	mret

__mecall_sendipi:
	la a7, __ipibase
	LDR a6, (a7)
	beq a6, a3, 1f
	STR a3, (a7)
1:	slli a1, a1, 2
	add	a3, a3, a1
	li a7, 1
	sw a7, (a3)
	fence ow, orw
	mret

FUNC_END exception_entry_mmode

	.data
	.balign	BYTES_PER_LONG, 0
__ipibase:
	.fill 1, BYTES_PER_LONG, 0x2000000
#endif
