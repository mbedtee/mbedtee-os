/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch32@ARMV7-A early MMU functions
 */

#include "aarch32-mmu.h"
#include "aarch32-asm.h"
#include <generated/autoconf.h>

FUNC_START _mmu_init
	/* only CPU-0 setups the early pgtbl at the first time,
	secondary-cores or secondary-times calls __mmu_secondary_init */
	cmp r0, #0
	bne __mmu_secondary_init

	adr_l r1, __memstart
	ldr r2, [r1]
	cmp r2, #0
	bne __mmu_secondary_init

	adr_l r2, _start
	str r2, [r1]
	dsb nsh
	b __mmu_early_init

__mmu_common_setting:
	/*
	 * Set DACR to Client Memory
	 * Accesses are checked against the permission bits in the translation tables.
	 * Domain 0 -> Client memory -> for kernel
	 * Domain 1 -> Client memory -> for user
	 */
	ldr	r1, =((MMU_DOMAIN_CLIENT << (MMU_KERN_DOMAIN * 2)) | \
			(MMU_DOMAIN_CLIENT << (MMU_USER_DOMAIN * 2)))
	mcr p15, 0, r1, c3, c0, 0
	isb

	/*
	 * Set PRRR/NMRR because of TRE
	 * PRRR: Outer/Inner Shareable
	 * Region 7 -> Normal memory - outer-shareable for big.LITTLE,
	 *                            inner-shareable for single cluster arch.
	 * Region 0 -> Strongly-ordered memory - non-shareable
	 *
 	 * NMRR: Outer/Inner Cacheable
	 * Region 7 -> inner/outer write-back and write-allocate
	 * Region 0 -> Non-cacheable
	 */
#ifdef CONFIG_ARM_BIGLITTLE
	ldr	r1, =0x00088000 /* outer-shareable */
#else
	ldr	r1, =0x80088000 /* inner-shareable */
#endif
	mcr	p15, 0, r1, c10, c2, 0 /* PRRR */
	ldr r1, =0x40004000
	mcr	p15, 0, r1, c10, c2, 1 /* NMRR */
	isb

	/* set TTBCR.N */
	mov r6, #(MMU_TTBCR_VAL)
	mcr p15, 0, r6, c2, c0, 2
	isb

	/* set CONTEXTIDR/TTBR0 to 0 */
	mov r6, #0
	mcr p15, 0, r6, c13, c0, 1
	mcr p15, 0, r6, c2, c0, 0
	isb
	bx lr

/* r6 holds the flags */
__mmu_enable:
	/*
	 * Invalidate Local Instruction cache (ICIALLU)
	 * Invalidate Local branch predictor buffer (BPIALL)
	 * Invalidate Local entire TLB (TLBIALL)
	 */
	dsb nshst
	mov r7, #0
	mcr p15, 0, r7, c7, c5,	0
	mcr p15, 0, r7, c7, c5,	6
	mcr p15, 0, r7, c8, c7, 0
	dsb nsh
	isb

	dsb nshst
	mrc p15, 0, r7, c1, c0, 0
	orr r7, r7, r6
	mcr p15, 0, r7, c1, c0, 0
	isb

	clrex
	bx lr

__mmu_early_init:
	mov r12, lr

	bl __mmu_common_setting

	/* set TTBR1 for mapping the kernel memory space */
	adr_l r5, __kern_early_pgtbl
	mcr p15, 0, r5, c2, c0, 1
	isb

	/* Flags for the kernel memory mappings,
	client/normal-memory / cache / execute-able */
	ldr r6, =SECTION_MAP_FLAGS

	/* Get the gap of virt_to_phys */
	adr_l r8, _start /* Get the physical address */
	ldr r7, =_start /* Get the virtual address */
	sub r4, r7, r8

	/* Map the current kernel physical memory for code execution */
	mov r8, r8, lsr #(SECTION_SHIFT)
	add r7, r6, r8, lsl #(SECTION_SHIFT)
	str	r7, [r5, r8, lsl #2]

	/* Get the virtual address */
	ldr r7, =_start
	mov r10, r7, lsr #(SECTION_SHIFT)

	/* Map the whole kernel virtual memory space */
1:	add r7, r6, r8, lsl #(SECTION_SHIFT)
	str	r7, [r5, r10, lsl #2]
	add r8, r8, #1
	add r10, r10, #1
	/* continue mapping until touch the top */
	cmp	r10, #(PTDS_PER_KPT)
	blo	1b

	/* set SCTLR to turn on the MMU, without WXN */
	ldr r6, =(MMU_ENABLE_FLAGS & (~SCTLR_WXN_BIT))
	bl __mmu_enable

	/* preparation for clearing the physical mapping */
	adr_l r8, _start
	mov r8, r8, lsr #(SECTION_SHIFT)

	/* jump to phys_to_virt address space */
	cmp r4, #0
	beq 3f
	ldr r6, =2f
	bx r6

	/* clear the physical mapping */
2:  add r5, r5, r4
	ldr r7, =0
	str	r7, [r5, r8, lsl #2]

3:	add r12, r12, r4
	bx r12

__mmu_secondary_init:
	mov r12, lr

	bl __mmu_common_setting

	/* set TTBR1 for mapping the kernel memory space */
	adr_l r5, __kern_pgtbl
	orr r6, r5, #(MMU_TTBR_FLAGS)
	mcr p15, 0, r6, c2, c0, 1
	isb

	/* Get the gap of virt_to_phys */
	adr r8, __mmu_secondary_init
	ldr r7, =__mmu_secondary_init
	sub r4, r7, r8
	cmp r4, #0
	beq 3f

	/* switch to __kern_early_pgtbl for mmu disable->enable transition */
	adr_l r9, __kern_early_pgtbl
	mcr p15, 0, r9, c2, c0, 1
	isb

	/* use __kern_early_pgtbl to map the current kernel
	 physical memory for code execution */
	ldr r6, =SECTION_MAP_FLAGS
	mov r8, r8, lsr #(SECTION_SHIFT)
	add r7, r6, r8, lsl #(SECTION_SHIFT)
	str	r7, [r9, r8, lsl #2]

	/* set SCTLR to turn on the MMU, without WXN */
	ldr r6, =(MMU_ENABLE_FLAGS & (~SCTLR_WXN_BIT))
	bl __mmu_enable

	/* jump to phys_to_virt address space */
1:	ldr r6, =2f
	bx r6

	/* switch to __kern_pgtbl  */
2:	orr r6, r5, #(MMU_TTBR_FLAGS)
	mcr p15, 0, r6, c2, c0, 1
	isb

	/* set SCTLR to turn on the MMU, with WXN */
3:	ldr r6, =(MMU_ENABLE_FLAGS)
	bl __mmu_enable
	add r12, r12, r4
	bx r12

FUNC_END _mmu_init

	.data
	.align 2
.global __memstart
__memstart:
	.word 0

	.bss
	.align (PAGE_SHIFT + 2)
.global __kern_early_pgtbl
__kern_early_pgtbl:
	.fill PTDS_PER_KPT, BYTES_PER_LONG, 0
