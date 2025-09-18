/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2022 Xing Loong <xing.xl.loong@gmail.com>
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

	li a6, MTIE  /* M-Timer */
	beq a6, a7, __mtimer_irq

	li a6, MSIE  /* M-IPI */
	beq a6, a7, __mipi_irq

	beqz zero, .

__mipi_irq:
	la a7, __plicsw
	LDR a7, (a7)
	bnez a7, __mipi_irq_plicsw
	la a7, __ipibase
	LDR a7, (a7)
	csrr a6, mhartid
	slli a6, a6, 2
	add	a7, a7, a6
	sw zero, (a7)
	fence ow, ow
	csrs mip, 1 << SSIE /* S-IPI */
	beqz zero, __mirq_done

__mipi_irq_plicsw:
	la a7, __ipibase
	LDR a7, (a7)
	csrr a6, mhartid
	slli a6, a6, 12          /* hartid * THRESHOLD_STRIDE */
	add a7, a7, a6
	lui a6, 0x200             /* THRESHOLD_BASE = 0x200000 */
	add a7, a7, a6            /* base + THRESHOLD_BASE + hartid*0x1000 */
	lw a6, 4(a7)              /* claim: read IRQ number */
	beqz a6, __mirq_done      /* spurious if no IRQ */
	sw a6, 4(a7)              /* complete: write back IRQ number */
	fence ow, ow
	csrs mip, 1 << SSIE       /* S-IPI */
	beqz zero, __mirq_done

__mtimer_irq:
	li a6, 1 << MTIE
	csrc mie, a6 /* M-Timer */
	li a6, 1 << STIE
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
	li a7, ECALL_APLIC_D
	beq a0, a7, __mecall_aplic_delegate
	li a7, ECALL_APLIC_MSI
	beq a0, a7, __mecall_aplic_msicfg
	li a7, ECALL_SET_PMP
	beq a0, a7, __mecall_set_pmp
	li a7, ECALL_CCTL_CMD
	beq a0, a7, __mecall_cctl_cmd
	beqz zero, .

__mecall_rdtime:
#if defined(CONFIG_64BIT)
	ld a0, (a3)
#else
1:	lw a1, 4(a3)
	lw a0, (a3)
	lw a2, 4(a3)
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
	li a6, 1 << STIE /* S-Timer */
	csrc mip, a6
	li a6, 1 << MTIE /* M-Timer */
	csrs mie, a6
	mret

__mecall_sendipi:
	csrs mie, 1 << MSIE /* enable M-IPI (mswi) */
	la a7, __ipibase
	LDR a6, (a7)
	beq a6, a3, 1f
	STR a3, (a7)
1:	la a7, __plicsw
	LDR a7, (a7)
	bnez a7, __mecall_sendipi_plicsw
	slli a1, a1, 2
	add	a3, a3, a1
	li a7, 1
	sw a7, (a3)
	fence ow, orw
	mret

__mecall_sendipi_plicsw:
	addi a6, a1, 1            /* a6 = hartid + 1 */
	li a7, 1
	sll a7, a7, a6            /* a7 = 1 << (hartid + 1) */
	li a6, 0x1000
	add a6, a3, a6            /* a6 = base + PENDING_BASE */
	sw a7, 0(a6)              /* write pending bit */
	fence ow, orw
	mret

__mecall_aplic_delegate:
	li a6, 1 << 10 /* sourcecfg D=1, Child=0 */
	li a5, 0
	add a1, a1, a2
1:  sw a6, (a1)
	addi a1, a1, BYTES_PER_INT
	addi a5, a5, 1
	blt	a5, a3, 1b
	mret

__mecall_aplic_msicfg:
	sw a2, (a1)
	sw a3, 4(a1)
	mret

/*
 * Set fine-grained PMP entries from S-mode via ecall.
 * a1 = dram_base (physical address of DRAM start)
 *
 * Using PMP TOR mode: pmpaddr[i-1] <= y < pmpaddr[i]
 * pmp0: 0 ~ dram_base (IO below DRAM, RW, Locked)
 * pmp1: dram_base ~ _start (DRAM below .text, RWX, Locked)
 * pmp2: _start ~ __TEXT_END (.text, RX, Locked)
 * pmp3: __TEXT_END ~ __RODATA_END (.rodata, R, Locked)
 * pmp4: rest (RWX, Locked)
 */
__mecall_set_pmp:
	/* pmp0: IO region below DRAM */
	beqz a1, 1f
	srli t1, a1, 2
	csrw pmpaddr0, t1
	li t2, 1 << 3 | 1 << 7 | 3 /* TOR | Locked | RW */
	j 2f
1:	csrw pmpaddr0, zero
	li t2, 0 /* OFF: no IO region below DRAM */

	/* pmp1: DRAM below .text */
2:	la t3, _start
	srli t1, t3, 2
	csrw pmpaddr1, t1
	li t3, 1 << 3 | 1 << 7 | 7 /* TOR | Locked | RWX */
	slli t3, t3, 8
	or t2, t2, t3

	/* pmp2: .text (RX) */
	la t1, __TEXT_END
	srli t1, t1, 2
	csrw pmpaddr2, t1
	li t3, 1 << 3 | 1 << 7 | 5 /* TOR | Locked | RX */
	slli t3, t3, 16
	or t2, t2, t3

	/* pmp3: .rodata (R) */
	la t1, __RODATA_END
	srli t1, t1, 2
	csrw pmpaddr3, t1
	li t3, 1 << 3 | 1 << 7 | 1 /* TOR | Locked | R */
	slli t3, t3, 24
	or t2, t2, t3

	/* pmp4: others (RWX) */
	li t1, -1
	csrw pmpaddr4, t1
#if defined(CONFIG_64BIT)
	li t3, 1 << 3 | 1 << 7 | 7 /* TOR | Locked | RWX */
	slli t3, t3, 32
	or t2, t2, t3
	csrw pmpcfg0, t2
#else
	csrw pmpcfg0, t2
	li t2, 1 << 3 | 1 << 7 | 7 /* TOR | Locked | RWX */
	csrw pmpcfg1, t2
#endif
	mret

/*
 * Andes CCTL command ecall handler
 * a1: CCTL command value to write to mcctlcommand (0x7cc)
 */
__mecall_cctl_cmd:
	csrw 0x7cc, a1
	mret

FUNC_END exception_entry_mmode

#endif

	.data
	.balign	BYTES_PER_LONG, 0
	.global __plicsw
__plicsw:
	.fill 1, BYTES_PER_LONG, 0
__ipibase:
	.fill 1, BYTES_PER_LONG, 0x2000000
