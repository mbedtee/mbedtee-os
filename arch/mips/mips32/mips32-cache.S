/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MIPS32 cache init
 */

#include <cpu.h>
#include <regdef.h>
#include <mips32-asm.h>

.section ".asm.text", "ax"

.set push
.set noat
.set noreorder
.set nomips16

FUNC_START local_flush_icache_all
	mfc0	t0, C0_CONFIG, 1

	/*
	 * Check if I-Cache is present
	 * Config1 [21:19]
	 */
	sll		t1, t0, 10
	srl		t1, 29
	beqz	t1, __icache_inv_out
	nop

	/*
	 * Clear ITagLo/ITaghi Registers
	 */
	mtc0	zero, C0_TAGLO
	mtc0	zero, C0_TAGHI

	/*
	 * Calculate I-Cache Line Size -> t1
	 * RD = RS << RT(4:0) (2 << t1)
	 */
	li		t2,	2
	sllv	t1, t2, t1

	/*
	 * Number of sets per way -> t2
	 * Config1 [24:22]
	 */
	sll		t2, t0, 7
	srl		t2, 29
	li		t3, 64
	sllv	t2, t3, t2

	/*
	 * Number of ways @ Config1 [18:16]
	 * Total number of Sets -> t3
	 */
	sll		t3, t0, 13
	srl		t3, 29
	add		t3, 1
	mul		t3, t2, t3

	/*
	 * Base of kseg0 segment
	 */
	lui		t4, 0x8000

	/*
	 * Index_Store_Tag_I
	 */
1:	cache	0x8, 0(t4)
	addiu	t3, -1
	bnez	t3, 1b
	addu	t4, t1

__icache_inv_out:
	jr	ra
	nop
FUNC_END local_flush_icache_all

FUNC_START local_invalidate_dcache_l1
	mfc0	t0, C0_CONFIG, 1

	/*
	 * Check if L1 D-Cache is present
	 * Config1 [12:10]
	 */
	sll		t1, t0, 19
	srl		t1, 29
	beqz	t1, __dcache_inv_out
	nop

	/*
	 * Clear ITagLo/DTagLo Registers
	 */
	mtc0	zero, C0_TAGLO
	mtc0	zero, C0_TAGLO, 2

	/*
	 * Calculate L1 D-Cache Line Size -> t1
	 * RD = RS << RT(4:0) (2 << t1)
	 */
	li		t2,	2
	sllv	t1, t2, t1

	/*
	 * Number of sets per way -> t2
	 * Config1 [15:13]
	 */
	sll		t2, t0, 16
	srl		t2, 29
	li		t3, 64
	sllv	t2, t3, t2

	/*
	 * Number of ways @ Config1 [9:7]
	 * Total number of Sets -> t3
	 */
	sll		t3, t0, 22
	srl		t3, 29
	add		t3, 1
	mul		t3, t2, t3

	/*
	 * Base of kseg0 segment
	 */
	lui		t4, 0x8000

	/*
	 * Index_Store_Tag_D
	 */
1:	cache	0x9, 0(t4)
	addiu	t3, -1
	bne		t3, zero, 1b
	addu	t4, t1

__dcache_inv_out:
	jr	ra
	nop
FUNC_END local_invalidate_dcache_l1

FUNC_START local_invalidate_dcache_l2
	mfc0	t0, C0_CONFIG, 2

	/*
	 * Check if L2 D-Cache is present
	 * Config2 [7:4]
	 */
	sll		t1, t0, 24
	srl		t1, 28
	beqz	t1, __l2_dcache_inv_out
	nop

	/*
	 * Calculate L2 D-Cache Line Size -> t1
	 * RD = RS << RT(4:0) (2 << t1)
	 */
	li		t2,	2
	sllv	t1, t2, t1

	/*
	 * Clear L23TagLo Registers
	 */
	mtc0	zero, C0_TAGLO, 4

	/*
	 * Number of sets per way -> t2
	 * Config2 [11:8]
	 */
	sll		t2, t0, 20
	srl		t2, 28
	li		t3, 64
	sllv	t2, t3, t2

	/*
	 * Number of ways @ Config2 [3:0]
	 * Total number of Sets -> t3
	 */
	sll		t3, t0, 28
	srl		t3, 28
	add		t3, 1
	mul		t3, t2, t3

	/*
	 * Base of kseg0 segment
	 */
	lui		t4, 0x8000

	/*
	 * Index_Store_Tag_D L2
	 */
1:	cache	0xB, 0(t4)
	addiu	t3, -1
	bne		t3, zero, 1b
	addu	t4, t1

__l2_dcache_inv_out:
	jr	ra
	nop
FUNC_END local_invalidate_dcache_l2

.set pop
