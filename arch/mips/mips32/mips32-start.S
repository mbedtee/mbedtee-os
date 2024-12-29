/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MIPS32 startup entry
 */

#include <mips32-asm.h>

.set push
.set noat
.set noreorder
.set nomips16

.balign 32, 0
.section ".head.text", "ax"
FUNC_START _start
	/*
	 * kernel mode, interrupt disabled
	 * IM7-0 Masked, BEV = 0, EXL = 0
	 * Access to DSP ASE Allowed
	 * Disable reduced power mode
	 */
	mfc0	t0, C0_STATUS
	lui		t0, 0x0100
	mtc0	t0, C0_STATUS
	ehb

	/*
	 * Disable cache
	 */
	mfc0	t0, C0_CONFIG
	li      t1, ~0x7
	and     t0, t1
	ori		t0, 2
	mtc0	t0, C0_CONFIG
	ehb

	/*
	 * Setup Stack
	 */
	la		sp, common_stack
	addiu	sp, STACK_SIZE

	/*
	 * Exception base, 0x180
	 */
	la		t0, exception_entry
	mtc0	t0, C0_EBASE
	ehb

	bal		__cpu_init
	nop

#if defined(CONFIG_MMU)
	jump	_mmu_init
#endif

	bal		__bss_init
	nop

	set_gp

	jump 	main

__cpu_init:
	move	k0, ra

	/*
	 * Enable Config7 IHB [29]
	 */
	mfc0	t0, C0_CONFIG, 7
	li		t1, (1 << 29)
	or		t0, t1
	mtc0	t0, C0_CONFIG, 7
	ehb

	/*
	 * Clear C0_WATCHLO exception
	 */
	mtc0	zero, C0_WATCHLO, 0
	mtc0	zero, C0_WATCHLO, 1
	mtc0	zero, C0_WATCHLO, 2
	mtc0	zero, C0_WATCHLO, 3

	/*
	 * Clear C0_WATCHHI status
	 */
	li		t0, 7
	mtc0	t0, C0_WATCHHI, 0
 	mtc0	t0, C0_WATCHHI, 1
	mtc0	t0, C0_WATCHHI, 2
	mtc0	t0, C0_WATCHHI, 3

	/*
	 * Clear Cause register
	 */
	mtc0    zero, C0_CAUSE

	/*
	 * Clear Counter/Compare register
	 */
	mtc0    zero, C0_COUNT
 	mtc0    zero, C0_COMPARE

	/*
	 * Clear all ITag/DTag/Idata/Ddata Registers
	 */
	mtc0	zero, C0_TAGLO
	mtc0	zero, C0_TAGLO, 1
	mtc0	zero, C0_TAGLO, 2
	mtc0	zero, C0_TAGLO, 3
	mtc0	zero, C0_TAGLO, 4
	mtc0	zero, C0_TAGLO, 5
	mtc0	zero, C0_TAGHI
	mtc0	zero, C0_TAGHI, 1
	mtc0	zero, C0_TAGHI, 2
	mtc0	zero, C0_TAGHI, 5
	ehb

	/*
	 * Enable L2 cache
	 */
	mfc0	t0, C0_CONFIG, 2
	li 		t1, (1 << 12)
	not		t1
	and		t0, t1
	mtc0	t0, C0_CONFIG, 2
	ehb

	/*
	 * Init the caches
	 */
	jump	local_flush_icache_all
	jump	local_invalidate_dcache_l1
	jump	local_invalidate_dcache_l2

	/*
	 * Cacheable, Write-Back, Write-Allocate
	 */
	mfc0	t0, C0_CONFIG
	li      t1, ~0x7
	and     t0, t1
	ori		t0, 3
	mtc0	t0, C0_CONFIG
	ehb

	/*
	 * Init others
	 */
	mtc0	zero, C0_PAGEMASK
	mtc0	zero, C0_TLBHI
	mtc0	zero, C0_WIRED
	mtc0	zero, C0_BADVADDR
	mtc0	zero, C0_EPC
	mtc0	zero, C0_ERROREPC
	ehb

	/*
	 * clear shadow setting
	 */
	mtc0	zero, C0_STATUS, 1
	mtc0	zero, C0_STATUS, 2
	mtc0	zero, C0_STATUS, 3
	ehb

	/*
	 * Enable user-mode to read UL register
	 */
	li		t0, (1 << 29)
	mtc0    t0, C0_HWRENA

	li		t0, 0x007ffff0
	mtc0    t0, C0_CONTEXT, 1
	mtc0	zero, C0_CONTEXT, 2
	ehb

	jr		k0
	nop

.macro _bss_range rd
	bal 0f
	nop
	.word __BSS_START
	.word __BSS_END
0:	move	\rd, ra
.endm

__bss_init:
	move	v1, ra
	_bss_range v0
	lw		t0, (BYTES_PER_LONG * 0)(v0)
	lw		t1, (BYTES_PER_LONG * 1)(v0)
	addiu	t1, -(BYTES_PER_LONG)
1:	sw		zero, 0(t0)
	sltu	t2, t0, t1
	bnez	t2, 1b
	addiu	t0, BYTES_PER_LONG
	jr		v1
	nop

FUNC_END _start

.set pop
