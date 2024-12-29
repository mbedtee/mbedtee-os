/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Cache clean/invalidate by Set/Way @ AArch64
 */

#include <aarch64-asm.h>

dcache_ops_setway:
	/* store Level to x12 */
	lsl x12, x12, #1
	msr csselr_el1, x12
	isb

	/* store log2of(LineLen) to x2 */
	mrs x6, ccsidr_el1
	and x2, x6, #7
	add x2, x2, #4

	/* store (Ways - 1) to x3 */
	mov x3, #0x3ff
	and x3, x3, x6, lsr #3

	/* store num of leading-zeros of Ways to x4 */
	clz	x4, x3

	/* store (Sets - 1) to x5 */
	mov x5, #0x7fff
	and x5, x5, x6, lsr #13

/*
 * x1 - clean(0) or invalidate(1)
 * x2 - log2of(LineLen)
 * x3 - Ways - 1
 * x4 - leading-zeros of Ways
 * x5 - Sets
 * x12 - Cache level
 *
 * x6, x7, x11 - temp reg for loops
 */
__loop_sets:
	mov	x6, x3
__loop_ways:
	/* orr set_idx << log2of(linelen), orr cache-level */
	lsl x7, x5, x2
	orr x7, x7, x12
	/* orr way_idx << leading-zeros of Ways */
	lsl x11, x6, x4
	orr x7, x11, x7
	cbnz x1, __inv_only
	/* flush and invalidate the cache (clean) */
	dc cisw, x7

__loops:
	subs x6, x6, #1
	bge __loop_ways
	subs x5, x5, #1
	bge __loop_sets
	b __loop_done

__inv_only:
	/* only invalidate the cache, no flush (invalidate)*/
	dc isw, x7
	b __loops

__loop_done:
	/* restore x12 */
	lsr	x12, x12, #1

	dsb nsh
	isb
	ret

FUNC_START flush_icache_all
	dsb ishst
	ic ialluis
	dsb ish
	isb
	ret
FUNC_END flush_icache_all

FUNC_START invalidate_tlb_all
	dsb ishst
	tlbi vmalle1is
	dsb ish
	isb
	ret
FUNC_END invalidate_tlb_all

FUNC_START flush_cache_all
	mov x15, lr

	dsb ishst

	mrs	x12, clidr_el1 /* CLIDR */
	mov	x9, x12, lsr #24 /* LoC 26:24 */
	ands x9, x9, #7 /* LoC */
	beq __flush_finished

	mov x12, #0 /* start from level 1 */
	mov x1, #0 /* cache clean */

__flush:
	bl dcache_ops_setway
	add x12, x12, #1
	cmp	x9, x12
	bgt __flush

__flush_finished:
	/*
	 * Invalidate All Instruction cache
	 * Invalidate entire TLB
	 */
	bl flush_icache_all
	bl invalidate_tlb_all
	dsb ish
	isb

	br x15
FUNC_END flush_cache_all

/*
 * level of unification inner shareable
 */
FUNC_START flush_cache_louis
	mov x15, lr

	dsb ishst

	mrs	x12, clidr_el1 /* CLIDR */
	mov	x9, x12, lsr #21 /* LoUIS 23:21 */
	ands x9, x9, #7 /* LoUIS */
	beq __louis_finished

	mov x12, #0 /* start from level 1 */
	mov x1, #0 /* cache clean */

__louis:
	bl dcache_ops_setway
	add x12, x12, #1
	cmp	x9, x12
	bgt __louis

__louis_finished:
	/*
	 * Invalidate All Instruction cache
	 * Invalidate entire TLB
	 */
	bl flush_icache_all
	bl invalidate_tlb_all
	dsb ish
	isb

	br x15
FUNC_END flush_cache_louis

FUNC_START invalidate_cache_all
	mov x15, lr

	dsb ishst

	/*
	 * Invalidate All Instruction cache
	 * Invalidate entire TLB
	 */
	bl flush_icache_all
	bl invalidate_tlb_all

	mrs	x12, clidr_el1 /* CLIDR */
	mov	x9, x12, lsr #24 /* LoC 26:24 */
	ands x9, x9, #7 /* LoC */
	beq __inv_finish

	mov x12, #0 /* start from level 1 */
	mov x1, #1 /* cache invalidate */

__inv:
	bl dcache_ops_setway
	add x12, x12, #1
	cmp	x9, x12
	bgt __inv

__inv_finish:
	dsb ish
	isb

	br x15
FUNC_END invalidate_cache_all

FUNC_START invalidate_cache_l1
	dsb nshst

	mov x15, lr

	mov x1, #1 /* cache invalidate */
	mov x12, #0 /* level 1 */
	bl dcache_ops_setway

	/*
	 * Invalidate local Instruction cache
	 * Invalidate local TLB
	 */
	dsb nshst
	ic iallu
	tlbi vmalle1
	dsb nsh
	isb

	br x15
FUNC_END invalidate_cache_l1
