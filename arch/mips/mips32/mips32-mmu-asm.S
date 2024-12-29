/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MIPS32 early MMU functions
 */

#include <cpu.h>
#include <regdef.h>
#include <mips32-asm.h>
#include <mips32-mmu.h>

.section ".asm.text", "ax"

.set	push
.set	noat
.set	noreorder
.set	nomips16

FUNC_START _mmu_init
	/* set asid to 0 */
	li	t1, 0
	mtc0 t1, C0_TLBHI
	ehb

	/* MIPS has fix-mapping-table */

	la t1, __memstart
	la t2, _start
	sw t2, 0(t1)
	sync
	jr ra
	nop
FUNC_END _mmu_init

	.data
	.balign BYTES_PER_LONG, 0
.global __memstart
__memstart:
	.word 0

.set	pop
