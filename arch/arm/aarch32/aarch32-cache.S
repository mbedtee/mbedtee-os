/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch32@ARMV7-A L1 and L2 Cache clean/invalidate by Set/Way
 */

#include <aarch32-asm.h>

/*
 * r1 - clean(0) or invalidate(1)
 * r2 - log2of(LineLen)
 * r3 - Ways - 1
 * r4 - leading-zeros of Ways
 * r5 - Sets
 * r10 - Cache level
 *
 * tmp use r6, r7
 */
dcache_clean_or_inv_set_way:
sets:
	mov	r6, r3
ways:
	/* orr set_idx << log2of(linelen), orr cache-level */
	orr	r7, r10, r5, lsl r2
	/* orr way_idx << leading-zeros of Ways */
	orr	r7, r7, r6, lsl r4
	cmp	r1, #0
	mcreq p15, 0, r7, c7, c14, 2
	mcrne p15, 0, r7, c7, c6, 2
	subs r6, r6, #1
	bge ways
	subs r5, r5, #1
	bge sets
	bx	lr

/* tmp use r1 ~ r7, r9, r10 */
clean_or_inv_dcache:
	mov r9, lr

	/* store Level to r0 */
	lsl r10, #1
	mcr	p15, 2, r10, c0, c0, 0
	isb

	/* store (line-len) to r2 */
	mrc p15, 1, r6, c0, c0, 0
	and r2, r6, #7
	add r2, #4

	/* store (Ways - 1) to r3 */
	mov r3, #0x3ff
	and r3, r3, r6, lsr #3

	/* store num of leading-zeros of Ways to r4 */
	clz	r4, r3

	/* store (Sets - 1) to r5 */
	mov r5, #0x7fff
	and r5, r5, r6, lsr #13

	bl dcache_clean_or_inv_set_way

	/* restore r0 */
	lsr	r10, #1

	dsb
	isb
	bx r9

FUNC_START flush_icache_all
	mov r3, #0
	mcr p15, 0, r3, c7, c1,	0 /* ICIALLUIS */
	mcr p15, 0, r3, c7, c1,	6 /* BPIALLIS */
	dsb ish
	bx lr
FUNC_END flush_icache_all

FUNC_START flush_cache_all
	push {r1-r10, lr}

	dsb

	mov r1, #0 /* cache clean */

	mrc	p15, 1, r8, c0, c0, 1 /* CLIDR */
	mov	r8, r8, lsr #24 /* LoU 26:24 */
	ands r8, r8, #7 /* LoU */
	beq __flush_finished

	mov r10, #0 /* start from level 1 */

__flush:
	bl clean_or_inv_dcache
	add r10, r10, #1
	cmp	r8, r10
	bgt __flush

__flush_finished:
	/*
	 * Invalidate Instruction cache (ICIALLUIS)
	 * Invalidate branch predictor buffer (BPIALLIS)
	 * Invalidate entire TLB (TLBIALLIS)
	 */
	mov r1, #0
	mcr p15, 0, r1, c7, c1,	0
	mcr p15, 0, r1, c7, c1,	6
	mcr p15, 0, r1, c8, c3, 0

	pop {r1-r10, pc}
FUNC_END flush_cache_all

FUNC_START invalidate_cache_all
	mov r11, lr

	dsb

	/*
	 * Invalidate Instruction cache (ICIALLUIS)
	 * Invalidate branch predictor buffer (BPIALLIS)
	 * Invalidate entire TLB (TLBIALLIS)
	 */
	mov r1, #0
	mcr p15, 0, r1, c7, c1,	0
	mcr p15, 0, r1, c7, c1,	6
	mcr p15, 0, r1, c8, c3, 0

	mov r1, #1 /* cache invalidate */
	mrc	p15, 1, r8, c0, c0, 1 /* CLIDR */
	mov	r8, r8, lsr #24 /* LoU 26:24 */
	ands r8, r8, #7 /* LoU */
	beq __inv_finish

	mov r10, #0 /* start from level 1 */

__inv:
	bl clean_or_inv_dcache
	add r10, r10, #1
	cmp	r8, r10
	bgt __inv

__inv_finish:
	bx r11
FUNC_END invalidate_cache_all

/*
 * level of unification inner shareable
 */
FUNC_START flush_cache_louis
	push {r1-r10, lr}

	dsb

	mov r1, #0 /* cache clean */

	mrc	p15, 1, r8, c0, c0, 1 /* CLIDR */
	mov	r8, r8, lsr #21 /* LoUIS 23:21 */
	ands r8, r8, #7 /* LoUIS */
	beq __louis_finished

	mov r10, #0 /* start from level 1 */

__louis:
	bl clean_or_inv_dcache
	add r10, r10, #1
	cmp	r8, r10
	bgt __louis

__louis_finished:
	/*
	 * Invalidate Instruction cache (ICIALLUIS)
	 * Invalidate branch predictor buffer (BPIALLIS)
	 * Invalidate entire TLB (TLBIALLIS)
	 */
	mov r1, #0
	mcr p15, 0, r1, c7, c1,	0
	mcr p15, 0, r1, c7, c1,	6
	mcr p15, 0, r1, c8, c3, 0

	pop {r1-r10, pc}
FUNC_END flush_cache_louis

FUNC_START invalidate_cache_l1
	mov r11, lr

	dsb nshst

	/*
	 * Invalidate Local Instruction cache (ICIALLU)
	 * Invalidate Local branch predictor buffer (BPIALL)
	 * Invalidate Local entire TLB (TLBIALL)
	 */
	mov r1, #0
	mcr p15, 0, r1, c7, c5,	0
	mcr p15, 0, r1, c7, c5,	6
	mcr p15, 0, r1, c8, c7, 0
	dsb nsh
	isb

	mov r1, #1 /* cache invalidate */
	mov r10, #0 /* level 1 */
	bl clean_or_inv_dcache

	bx r11
FUNC_END invalidate_cache_l1
