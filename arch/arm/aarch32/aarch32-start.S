/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch32@ARMV7-A startup entry
 */

#include "aarch32-mmu.h"
#include "aarch32-asm.h"

.text
.section ".head.text", "ax"

.global _start
_start:
	msr cpsr_c, #(SYS_MODE | IRQ_MASK | FIQ_MASK)
	unset_nsbit r12
	mrc p15, 0, r0, c0, c0, 5 /* mpidr */
	ldr r12, =MPIDR_BITMASK
	and r0, r0, r12
	cmp	r0, #0
	blne secondary_cpu_wait

cpu_setup:
	bl __tpidr_init

	/*
	 * disable MMU, disable L1 cache,
	 * Invalidate I/D caches
	 * Invalidate BP, Invalidate TLB
	 */
	bl _cpu_init

	/*
	 * Set all .bss to 0
	 */
	bl __bss_init

	/*
	 * Early MMU init
	 */
#if defined(CONFIG_MMU)
	bl _mmu_init
#endif

	/*
	 * Setup stacks
	 */
	bl _stack_init

	bl main

/*
 * percpu data pointer is stored at tpidrprw (el1)
 */
__tpidr_init:
	mov r1, #(PERCPU_DATA_SIZE)
	ldr r2, =percpu_dt
	mla r2, r0, r1, r2
	mcr p15, 0, r2, c13, c0, 4
	bx lr

__bss_init:
	cmp	r0, #0
	bxne lr
	adr_l r4, __bss_init_done
	ldr r1, [r4]
	cmp	r1, #0
	bxne lr

	ldr r1, =1
	str r1, [r4]
	dsb nsh

	adr_l r1, __BSS_START
	adr_l r2, __BSS_END
1:  cmp	r1, r2
	bxge lr
	/* .bss always aligned to PAGE_SIZE,
	so we can handle it per 16 bytes */
	str	r0,	[r1], #(BYTES_PER_LONG)
	str	r0,	[r1], #(BYTES_PER_LONG)
	str	r0,	[r1], #(BYTES_PER_LONG)
	str	r0,	[r1], #(BYTES_PER_LONG)
	b 1b

_stack_init:
	/*
	 * Setup Monitor Stack
	 */
	cps #(MON_MODE)
	bl _monitor_stack_init

	/*
	 * Setup Other Stacks
	 */
	mov r1, #(STACK_SIZE)
	ldr r2, =common_stack
	add	r2, r2, r1
	mla r2, r0, r1, r2

	cps #(ABT_MODE)
	mov sp, r2
	cps #(UND_MODE)
	mov sp, r2
	cps #(IRQ_MODE)
	mov sp, r2
	cps #(SVC_MODE)
	mov sp, r2
	cps #(SYS_MODE)
	mov sp, r2
	bx lr

_cpu_init:
	/* Set VBAR */
	ldr	r1, =exception_vectors
	mcr	p15, 0, r1, c12, c0, 0

	/* Set MVBAR */
	ldr	r1, =monitor_vectors
	mcr	p15, 0, r1, c12, c0, 1

	/* Set SDER */
	ldr r1, =0
	mcr p15, 0, r1, c1, c1, 1

	/*
	 * SCTLR
	 * disable MMU/cache/BP/AlignCheck,  use Little EE
	 * [28] TRE TEX remap enabled. TEX[2:1] bits are ignored by the memory
	 * management hardware. The TEX[0], C and B bits, with the MMU remap
	 * registers, describe the memory region attributes.
	 * [21] Low interrupt latency configuration. Some performance features disabled.
	 */
	ldr r1, =((1 << 28) | (1 << 21))
	mcr p15, 0, r1, c1, c0, 0
	isb

	/*
	 * Set ACTLR
	 * SMP enables coherent requests to the processor
	 * Cortex-A15 BTB (IBE)
	 */
	ldr r1, =0x00000041
	mcr p15, 0, r1, c1, c0, 1
	isb

	/*
	 * invalidate icache and dcache
	 */
	mov r12, lr

	cmp r0, #0
	bleq invalidate_cache_all
	blne invalidate_cache_l1

	/*
	 * Set NSACR
	 * enable NS access to cp10/cp11 for floating-point extension
	 * FIQ mode and the FIQ Banked registers are accessible in Secure state only
	 */
	ldr r1, =(0xC00)
	orr r1, r1, #(1 << 19)
	mcr p15, 0, r1, c1, c1, 2
	isb

	/*
	 * Set SCR
	 * Set the FIQ bit so as to route FIQs to monitor mode
	 * The number of cycles required for data operations is forced to be independent of the data values
	 * Secure state instruction fetches from Non-secure memory are not permitted
	 * CPSR.F/A, SMC-enabled, Hyper-call-disabled
	 */
	ldr r1, =((1 << 2) | (1 << 6) | (1 << 9))
	mcr p15, 0, r1, c1, c1, 0
	isb

	bx r12

	.data
	.align	2
__bss_init_done:
	.word 0
