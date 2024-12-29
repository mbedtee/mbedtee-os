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

	/* a0 is hartid, assigned by M-Mode check_set_s_mode_delege() */
	la ra, 1f
	bnez a0, secondary_cpu_wait
	/* a0 is now logic-cpu-id */

	/*
	 * Setup percpu_data pointer
	 */
1:	call __gp_sp_exp_init

	fence.i

	call __bss_init

#if defined(CONFIG_MMU)
	call _mmu_init
#endif

	/* re-init the entries with virtual addresses */
	call __gp_sp_exp_init

	call main

__bss_init:
	bnez a0, 2f

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
	mul t2, a0, t0
	add	t2, t1, t2
	csrw CSR_SCRATCH, t2

	li t0, STACK_SIZE
	la t1, common_stack
	mul t2, t0, a0
	add	t2, t2, t1
	add	sp, t2, t0

	la t0, exception_entry
	csrw CSR_TVEC, t0
	ret

/* Always start from M-Mode */
check_set_s_mode_delege:
#if defined(CONFIG_RISCV_S_MODE)
#define MSCRATCH_SIZE (BYTES_PER_LONG * 8)

	la a1, exception_entry_mmode
	li s1, 1

	csrr a0, mhartid

	/* set mscratch for m-mode exception handling */
	li t0, MSCRATCH_SIZE
	la t1, __mscratch_data
	mul t2, a0, t0
	add	t2, t1, t2
	csrw mscratch, t2

	/* check if hart0 has supervisor mode,
	secondary harts must have supervisor mode */
	bnez a0, 2f
	la t0, 1f
	csrw mtvec, t0
	csrw mepc, zero

	/* the misa maybe not been impleemented (zero), so
	 set S-Mode register to trigger exception */
	csrw sie, zero

	.align 2
1:	csrw mtvec, a1
	csrr t1, mepc
	/* bnez t1, means hart0 does not have supervisor mode */
	bnez t1, __mmode_hart0_routine
	la t0, __hart0_supervisor_supported
	sb s1, (t0)

2:	csrw mtvec, a1
	csrw sie, zero
	csrw sip, zero
	csrw sstatus, zero

	/* pass the misa value to supervisor mode software */
	csrr t0, misa
	la t1, __misa
	STR t0, (t1)

	li t1, -1
	xori t2, t1, 1 << 9
	csrw medeleg, t2
	csrw mideleg, t1
	csrw mcounteren, t1

	csrw pmpaddr0, t1
	csrw pmpcfg0, 15

	sfence.vma
	csrw satp, zero

	/* check if the menvcfg exist or not */
	la a2, __mmode_check_menvcfg
	csrw mtvec, a2

#if defined(CONFIG_64BIT)
	li t2, (1 << 63) | (1 << 62) /* STCE / PBMTE */
	or t2, t2, 0xf0  /* CBZE / CBCFE / CBIE / without-FIOM */
	csrw menvcfg, t2
#else
	csrw mstatush, zero
	li t2, (1 << 31) | (1 << 30) /* STCE / PBMTE */
	csrw menvcfgh, t2
	li t2, 0xf0  /* CBZE / CBCFE / CBIE / without-FIOM */
	csrw menvcfg, t2
#endif

	/* check if the menvcfg exist or not */
	.align 2
__mmode_check_menvcfg:
	csrw mtvec, a1 /* resume m-mode exception entry */

	csrs mie, 1 << 3 /* enable M-IPI (mswi) */

	/*
	 * MPP[12:11], 0-U 1-S 3-M
	 * SUM[18], MXR[19], SPP[8]
	 */
	la t2, __smode_start
	li t1, (1 << 11) | (3 << 18) | (1 << 8)
	csrw mstatus, t1
	csrw mepc, t2
	mret

__mmode_hart0_routine:
	li t2, -1
	csrw mcounteren, t2
	csrw pmpaddr0, t2
	csrw pmpcfg0, 15

	la t0, cpu_hartid
	li t1, 1
	sw t1, (t0) /* release hart1 to bootup */
	fence rw, rw
	wfi
	beqz zero, .

__smode_start:
	li s1, 1
	li t1, -1
	la a1, exception_entry
	la a2, __smode_check_sstc
	csrw stvec, a2

	csrw stimecmp, t1
	la t0, __sstc_supported
	sb s1, (t0)

	.align 2
__smode_check_sstc:
	csrw stvec, a1 /* resume s-mode exception entry */
#else
	csrr a0, mhartid

	/* check if hart0 has supervisor mode,
	secondary harts must have supervisor mode */
	bnez a0, 2f
	la t0, 1f
	csrw mtvec, t0
	csrw mepc, zero

	/* the misa maybe not been impleemented, so
	 set S-Mode register to trigger exception */
	csrw sie, zero

	.align 2
1:	csrr t1, mepc
	/* bnez t1, means hart0 does not have supervisor mode */
	bnez t1, 2f
	la t0, __hart0_supervisor_supported
	li s1, 1
	sb s1, (t0)
2:
#endif
	ret

FUNC_END _start

#if defined(CONFIG_RISCV_S_MODE)
FUNC_START is_sswi_supported
	csrr a7, stvec
	la a6, __smode_check_sswi
	csrw stvec, a6
	la a5, __sswi_supported

	lw a0, (a0)
	li a4, 1
	sb a4, (a5)

	.align 2
__smode_check_sswi:
	csrw stvec, a7 /* resume s-mode exception entry */
	lb a0, (a5)
	ret
FUNC_END is_sswi_supported

	.data
.global __sswi_supported
__sswi_supported:
	.byte 0

	.data
.global __sstc_supported
__sstc_supported:
	.byte 0

	.bss
	.balign BYTES_PER_LONG, 0
__mscratch_data: /* +1 for E-Core, e.g. sifive_u */
	.fill MSCRATCH_SIZE * (CONFIG_NR_CPUS + 1), 1, 0
#endif

	.data
__bss_init_done:
	.byte 0

	.data
.global __hart0_supervisor_supported
__hart0_supervisor_supported:
	.byte 0

	.data
	.balign BYTES_PER_LONG, 0
.global __misa
__misa:
	.fill 1, BYTES_PER_LONG, 0
