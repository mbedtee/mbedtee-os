/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch64 EL1 startup entry
 */

#include "aarch64-mmu.h"
#include "aarch64-asm.h"

/*
 * x0 - logic cpu-id
 * x1 - Monitor rctx pointer
 * x2 - Monitor SMC SGI num
 */
.global cpu_setup
cpu_setup:
	msr daifset, #(0xF)
	bl __bss_init
	bl _tpidr_init
	bl _cpu_init
	bl _stack_init
#if defined(CONFIG_MMU)
	bl _mmu_init
#endif
	bl main

/*
 * percpu data pointer is stored at tpidr_el1
 * save rctx / smc-sgi to percpu_dt
 * (rctx / smc-sgi are shared by EL3 via x1/x2 registers)
 */
_tpidr_init:
	adr_l x10, percpu_dt
	ldr x11, =percpu_dt
	mov x9, #(PERCPU_DATA_SIZE)
	madd x12, x0, x9, x10
	madd x13, x0, x9, x11
	msr tpidr_el1, x13
	isb

	/* RCTX + SGI */
	sub x10, x11, x10
	add x1, x10, x1 /* phys_to_virt of RCTX */
	str x1, [x12, #(PERCPU_REE_CTX)]
	str x2, [x12, #(PERCPU_SMC_SGI)]
	dsb nsh
	ret

/* Init .bss to zero */
__bss_init:
	cbnz x0, 1f
	adr_l x9, __bss_init_done
	ldr w10, [x9]
	cbnz w10, 1f

	ldr w10, =1
	str w10, [x9]
	dsb nsh

	adr_l x11, __BSS_START
	adr_l x12, __BSS_END
2:  cmp	x11, x12
	bge	1f
	/* .bss always aligned to PAGE_SIZE,
	so we can handle it per 64 bytes */
	stp	xzr, xzr, [x11], #(BYTES_PER_LONG * 2)
	stp	xzr, xzr, [x11], #(BYTES_PER_LONG * 2)
	stp	xzr, xzr, [x11], #(BYTES_PER_LONG * 2)
	stp	xzr, xzr, [x11], #(BYTES_PER_LONG * 2)
	b	2b
1:  ret

/*
 * Setup EL1 Stack
 */
_stack_init:
	mov x1, #(STACK_SIZE)
	ldr	x2, =common_stack
	add	x2, x2, #(STACK_SIZE)
	madd x2, x0, x1, x2
	msr spsel, #1
	mov sp, x2
	msr spsel, #0
	mov sp, x2
	ret

/*
 * Invalidate I/D caches
 * Invalidate BP, Invalidate TLB
 */
_cpu_init:
	/*
	 * SCTLR
	 * disable MMU/cache/BP/AlignCheck, use Little EE
	 * [14] Does Not Trap DC ZVA instructions to EL1
	 * [6] Non-aligned access for several instructions
	 */
	ldr x1, =((1 << 14) | (1 << 6))
	msr sctlr_el1, x1
	isb

	/*
	 * ZEN, FPEN
	 * does not trap SVE/SIMD/FP
	 */
	ldr x1, =((3 << 16) | (3 << 20))
	msr cpacr_el1, x1
	isb

	/* Set VBAR */
	ldr	x1, =exception_vectors
	msr vbar_el1, x1
	isb

	mov x25, lr
	adr lr, 1f

	/*
	 * invalidate tlb, icache and dcache
	 */
	cbz  x0, invalidate_cache_all
	cbnz x0, invalidate_cache_l1

1:	br x25
	nop

	.data
	.align	2
__bss_init_done:
	.word 0
