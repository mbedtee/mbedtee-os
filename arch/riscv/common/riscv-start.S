/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * startup entry
 */

#include <riscv-asm.h>

.section ".head.text", "ax"

/* Always start from M-Mode */
FUNC_START _start
	/* Mask all interrupts */
	csrw mie, zero
	csrw mip, zero
	csrw mstatus, zero

	call check_set_s_mode_delege

	/* a7 is hartid, assigned by M-Mode check_set_s_mode_delege() */
	call secondary_cpu_wait
	/* a7 is now logic-cpu-id */

	/*
	 * Setup percpu_data pointer
	 */
	call __gp_sp_exp_init

	fence.i

	call __bss_init

#if defined(CONFIG_MMU)
	call _mmu_init
#endif

	/* re-init the entries with virtual addresses */
	call __gp_sp_exp_init

	call main

__bss_init:
	bnez a7, 2f

	la t4, __bss_init_done
	lb t1, (t4)
	bnez t1, 2f

	li t1, 1
	sb t1, (t4)
	fence

	la t1, __BSS_START
	la t2, __BSS_END
	bge	t1, t2, 2f
	/* .bss always aligned to PAGE_SIZE,
	so we can handle it per 16/32 bytes */
1:  STR zero, (BYTES_PER_LONG * 0)(t1)
	STR zero, (BYTES_PER_LONG * 1)(t1)
	STR zero, (BYTES_PER_LONG * 2)(t1)
	STR zero, (BYTES_PER_LONG * 3)(t1)
	add t1, t1, (BYTES_PER_LONG * 4)
	blt	t1, t2, 1b

2:	ret

__gp_sp_exp_init:
	set_gp
	li t0, PERCPU_DATA_SIZE
	la t1, percpu_dt
	mul t2, a7, t0
	add	t2, t1, t2
	csrw CSR_SCRATCH, t2

	li t0, STACK_SIZE
	la t1, common_stack
	mul t2, t0, a7
	add	t2, t2, t1
	add	sp, t2, t0

	la t0, exception_entry
	csrw CSR_TVEC, t0
	ret

.macro set_supervisor_map hartreg, valreg
	sll \valreg, \valreg, \hartreg
	la a2, __supervisor_bmap
	/* atomic counter */
1:  lr.w a1, (a2)
	or a1, a1, \valreg
	sc.w.aq a3, a1, (a2)
	bnez a3, 1b
.endm

.macro set_machine_map hartreg
	li a4, 1
	sll a4, a4, \hartreg
	la a2, __machine_bmap
	/* atomic counter */
1:  lr.w a1, (a2)
	or a1, a1, a4
	sc.w.aq a3, a1, (a2)
	bnez a3, 1b
.endm

/* Always start from M-Mode */
check_set_s_mode_delege:
#if defined(CONFIG_RISCV_S_MODE)
#define MSCRATCH_SIZE (BYTES_PER_LONG * 8)
	csrr a7, mhartid
	la a1, exception_entry_mmode
	csrw mtvec, a1

	/* set mscratch for m-mode exception handling */
	li t0, MSCRATCH_SIZE
	la t1, __mscratch_data
	mul t2, a7, t0
	add	t2, t1, t2
	csrw mscratch, t2

	/*
	 * check if current hart has the supervisor mode,
	 * usually secondary harts have the supervisor mode
	 *
	 * the misa maybe not been implemented (zero), so set
	 * the S-Mode register to check if exception asserted
	 *
	 * beqz a0, means current hart does not have supervisor mode
	 */
	csr_writeable mtvec, sie, 0
	beqz a0, __mmode_harts_routine

	/* set the supervisor bitmap if supervisor mode present */
	set_supervisor_map a7, a0

	csrw sie, zero
	csrw sip, zero
	csrw sstatus, zero

	li t1, -1
	xori t2, t1, 1 << 9
	csrw medeleg, t2
	csrw mideleg, t1
	csrw mcounteren, t1

	csrs mie, 1 << 3 /* enable M-IPI (mswi) */

	set_pmp

	csrw satp, zero

	set_menvcfg

	set_mstateen0

	/* pass the misa value to supervisor mode software */
	csrr t0, misa
	la t1, __misa
	STR t0, (t1)

	/*
	 * MPP[12:11], 0-U 1-S 3-M
	 * SUM[18], MXR[19], SPP[8]
	 */
	la t2, __smode_start
	li t1, (1 << 11) | (3 << 18) | (1 << 8)
	csrw mstatus, t1
	csrw mepc, t2
	mret

__mmode_harts_routine:
	li t2, -1
	csrw mcounteren, t2
	csrw pmpaddr0, t2
	csrw pmpcfg0, 15

	la t0, cpu_power_id
	addi t1, a7, 1
	sw t1, (t0) /* release next-hart to bootup */
	fence rw, rw

	wfi
	beqz zero, .

__smode_start:
	la a1, exception_entry
	csrw stvec, a1

	/* check if sstc present */
	csr_writeable stvec, stimecmp, -1
	la t0, __sstc_supported
	sb a0, (t0)
#else
	csrr a7, mhartid

	/* set the supervisor bitmap if supervisor mode present */
	csr_writeable mtvec, sie, 0
	set_supervisor_map a7, a0
#endif
	set_machine_map a7
	ret
FUNC_END _start

#if defined(CONFIG_RISCV_S_MODE)
FUNC_START is_io_readable
	is_readable a0
	ret
FUNC_END is_io_readable

.data
.global __sstc_supported
__sstc_supported:
.byte 0

.data
.balign BYTES_PER_LONG, 0
.global __misa
__misa:
.fill 1, BYTES_PER_LONG, 0

.bss
.balign BYTES_PER_LONG, 0
__mscratch_data: /* +1 for E-Core, e.g. sifive_u */
.fill MSCRATCH_SIZE * (CONFIG_NR_CPUS + 1), 1, 0
#endif

.data
__bss_init_done:
.byte 0

.data
.balign BYTES_PER_INT, 0
.global __supervisor_bmap
__supervisor_bmap:
.word 0
.global __machine_bmap
__machine_bmap:
.word 0
