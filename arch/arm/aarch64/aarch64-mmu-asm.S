/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch64 early MMU functions
 */

#include "aarch64-mmu.h"
#include "aarch64-asm.h"

FUNC_START _mmu_init
	/* only CPU-0 setups the early pgtbl at the first time,
	secondary-cores or secondary-times calls __mmu_secondary_init */
	cbnz x0, __mmu_secondary_init

	adr_l x1, __memstart
	ldr x2, [x1]
	cbnz x2, __mmu_secondary_init

	adr_l x2, _start
	str x2, [x1]
	dsb sy
	b __mmu_early_init

/* x6 holds the flags */
__mmu_enable:
	dsb nshst
	mrs x7, sctlr_el1
	orr x7, x7, x6
	msr sctlr_el1, x7
	isb
	dsb nshst
	ic iallu
	tlbi vmalle1
	dsb nsh
	isb
	clrex
	ret

__mmu_early_init:
	mov x25, lr

	/*
	 *	MT_NORMAL                   0
	 *	MT_DEVICE_nGnRnE            1
	 *
	 *	MAIR_ATTR_DEVICE_nGnRnE     (0x00UL)
	 *	MAIR_ATTR_NORMAL            (0xffUL)
	 */
	ldr x6, =MAIR_VAL
	msr mair_el1, x6
	isb

	/* set TTBR0 / TTBR1 */
	adr_l x15, __kern_tmp_pgtbl_ttbr0
	msr ttbr0_el1, x15
	adr_l x5, __kern_early_pgtbl
	msr ttbr1_el1, x5
	isb

	/* set TCR, TTBR0 / TTBR1 both have 512GB (depends on VA_BITS) address space */
	ldr x6, =TCR_VAL
	msr tcr_el1, x6

	/* Get the gap of virt_to_phys */
	adr_l x8, _start /* Get the physical address */
	ldr x7, =_start /* Get the virtual address */
	sub x4, x7, x8

	/* x8, x9 hold the PTD/PMD index of physical _start */
	mov x9, x8, lsr #(SECTION_SHIFT)
	mov x8, x8, lsr #(PTD_SHIFT)

	/* Map the current kernel physical memory for code execution */
	/* x11 holds the tmp PMDs */
	adr_l x11, __kern_tmp_ptd
	ldr x20, =(PTD_TYPE_TABLE)
	orr x20, x20, x11
	str	x20, [x15, x8, lsl #3] /* link PTD with PMDs */

	/* x20, x21 hold the PTD/PMD flags */
	ldr x21, =(SECTION_MAP_FLAGS)
	orr x7, x21, x9, lsl #(SECTION_SHIFT)
	and x10, x9, #(PMDS_PER_PTD - 1)
	str	x7, [x11, x10, lsl #3] /* set the PMD */

	/* x11 holds the PMDs */
	adr_l x11, __kern_early_ptd
	ldr x20, =(PTD_TYPE_TABLE)
	orr x20, x20, x11

	/* Get the virtual address */
	ldr x12, =_start
	ldr x7, =(-(1 << VA_BITS))
	sub	x12, x12, x7
	mov x12, x12, lsr #(SECTION_SHIFT) /* PMD index - start */

	/* Map the whole kernel virtual memory space - 1PTD -> 1G */
	mov x14, x12, lsr #(PTD_SHIFT - SECTION_SHIFT)
	str	x20, [x5, x14, lsl #3] /* link PTD with PMDs */
1:	orr x7, x21, x9, lsl #(SECTION_SHIFT)
	and x10, x12, #(PMDS_PER_PTD - 1)
	str	x7, [x11, x10, lsl #3] /* set the PMD */
	add x9, x9, #1
	add x12, x12, #1
	/* OS only reserved 1 PTD, so the mapping shall be within a PTD */
	cmp	x10, #(PMDS_PER_PTD - 1)
	blo	1b

	/* set SCTLR to turn on the MMU, without WXN */
	ldr x6, =(SCTLR_VAL & (~SCTLR_WXN))
	bl __mmu_enable

	/* jump to phys_to_virt address space */
	ldr x6, =2f
	br x6

	/* unset ttbr0, switch to use the ttbr1 */
2:	ldr x7, =0
	msr ttbr0_el1, x7
	isb

	add x25, x25, x4
	br x25

__mmu_secondary_init:
	mov x25, lr

	/*
	 *	MT_NORMAL                   0
	 *	MT_DEVICE_nGnRnE            1
	 *
	 *	MAIR_ATTR_DEVICE_nGnRnE     (0x00UL)
	 *	MAIR_ATTR_NORMAL            (0xffUL)
	 */
	ldr x6, =MAIR_VAL
	msr mair_el1, x6
	isb

	ldr x7, =0
	adr_l x5, __kern_pgtbl
	msr ttbr1_el1, x5
	msr ttbr0_el1, x7
	isb

	/* set TCR, TTBR0 / TTBR1 both have 512GB
	 (depends on VA_BITS) address space */
	ldr x6, =TCR_VAL
	msr tcr_el1, x6
	isb

	/* Get the gap of virt_to_phys */
	adr x8, 1f
	ldr x7, =1f
	sub x4, x7, x8
	cmp x4, #0
	beq 3f

	adr_l x15, __kern_tmp_pgtbl_ttbr0
	msr ttbr0_el1, x15
	isb

	/* set SCTLR to turn on the MMU, without WXN */
	ldr x6, =(SCTLR_VAL & (~SCTLR_WXN))
	bl __mmu_enable

	/* jump to phys_to_virt address space */
1:	ldr x6, =2f
	br x6

	/* unset ttbr0, switch to use the ttbr1 */
2:	ldr x7, =0
	msr ttbr0_el1, x7
	isb

	/* set SCTLR to turn on the MMU, with WXN */
3:	ldr x6, =(SCTLR_VAL)
	bl __mmu_enable
	add x25, x25, x4
	br x25

FUNC_END _mmu_init

	.data
	.align 3
.global __memstart
__memstart:
	.dword 0

	.bss
	.align PAGE_SHIFT
__kern_tmp_pgtbl_ttbr0:
	.fill PTDS_PER_PT, BYTES_PER_LONG, 0

	.bss
	.align PAGE_SHIFT
__kern_tmp_ptd:
	.fill PMDS_PER_PTD, BYTES_PER_LONG, 0

/*
 * only for early init, will be recycled as heap
 */
	.section ".bss.early"
	.align PAGE_SHIFT
.global __kern_early_pgtbl
__kern_early_pgtbl:
	.fill PTDS_PER_PT, BYTES_PER_LONG, 0

	.section ".bss.early"
	.align PAGE_SHIFT
__kern_early_ptd:
	.fill PMDS_PER_PTD, BYTES_PER_LONG, 0
