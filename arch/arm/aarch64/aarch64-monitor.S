/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * EL3 - Secure Monitor - Start
 */

#include "aarch64-monitor.h"

.text
.section ".head.text", "ax"

.global _start
_start:
	unset_nsbit x7
	/* FIQ IRQ ASYNC, DEBUG exceptions are all masked */
	msr daifset, #(0xF)
	ldr x1, =MPIDR_BITMASK
	mrs x0, mpidr_el1
	and x0, x0, x1
	adr lr, cpu_setup_el3
	cbnz x0, secondary_cpu_wait

cpu_setup_el3:
	bl _cpu_init_el3
	bl _stack_init_el3
#	bl _mmu_init_el3
	bl _tpidr_init_el3

	/* Switch to EL1 */
	adr x8, cpu_setup
	msr	elr_el3, x8
	ldr x8, =(SPSR_MODE_EL1T | SPSR_DAIF_MASK)
	msr spsr_el3, x8
	mrs x1, tpidr_el3 /* rctx */
	ldr x2, =SMC_SGI_ID
	eret

/*
 * Setup EL3 Stack
 */
_stack_init_el3:
	mov x1, #(BUFFER_SIZE)
	adr_l x2, __el3_buffer
	add	x2, x2, x1
	madd x2, x0, x1, x2
	mov sp, x2
	ret

/*
 * setup tpidr_el3 to store s/ns world ctx pointer
 */
_tpidr_init_el3:
	mov x1, #(BUFFER_SIZE)
	adr_l x2, __el3_buffer
	madd x2, x0, x1, x2
	msr tpidr_el3, x2
	isb
	ret

_cpu_init_el3:
	/*
	 * SCTLR
	 * disable MMU/cache/BP/AlignCheck,  use Little EE
	 * [6] Non-aligned access for several instructions
	 */
	mov x1, #(1 << 6)
	msr sctlr_el3, x1
	isb

	/* Set Monitor VBAR */
	adr_l x1, monitor_vectors
	msr vbar_el3, x1
	isb

	/*
	 * Set SCR
	 * 02: Set the FIQ bit so as to route FIQs to monitor mode
	 * 08: HVC instructions are enabled at EL3, EL2, and EL1
	 * 09: Secure state instruction fetches from Non-secure memory are not permitted
	 * 10: low EL is aarch64
	 * 11: Secure EL1 access Counter-timer Physical Secure timer register not to be trapped.
	 * 26: Enable Accesses at EL1 and EL2 to GCR_EL1, RGSR_EL1, TFSR_EL1, TFSR_EL2 or TFSRE0_EL1
	 */
	ldr x1, =((1 << 2) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 26))
	msr scr_el3, x1
	isb

	/* Set the GenericTimer Counter FRQ */
	adr_l x1, __cntfrq
	ldr x1, [x1]
	msr cntfrq_el0, x1
	isb

	/*
	 * trap nothing to el3
	 */
	ldr x1, =(1 << 8)
	msr cptr_el3, x1
	isb

	/*
	 * Set MDCR - Disable Secure self-hosted debugs
	 * SDD (1 << 16), SPD32 [15:14]
	 */
	ldr x1, =((1 << 16) | (2 << 14))
	msr mdcr_el3, x1
	isb

	/*
	 * Set CPUECTLR.SMPEN
	 * SMP enables coherent requests to the processors
	 */
	smp_enable

	mov x25, lr
	adr lr, 2f

	/*
	 * invalidate tlb, icache and dcache
	 */
	cbz  x0, invalidate_cache_all
	cbnz x0, invalidate_cache_l1

	/*
	 * SCTLR -- enable I/D caches for EL3
	 */
2:	mrs x1, sctlr_el3
	orr x1, x1, #(1 << 2)
	orr x1, x1, #(1 << 12)
	msr sctlr_el3, x1
	isb

	/*
	 * GIC SRE is enabled for EL3 (bit0)
	 * icc_sre_el2 / icc_sre_el1 access is enabled (bit3)
	 * FIQ(bit1)/IRQ(bit2) bypass is disabled
	 */
#if defined(CONFIG_ARM_GICV3)
	ldr x1, =((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3))
	msr icc_sre_el3, x1
	isb
#endif

	br x25


/* x6 holds the flags */
__mmu_enable_el3:
	dsb ishst
	mrs x7, sctlr_el3
	orr x7, x7, x6
	msr sctlr_el3, x7
	isb
	ret

__mmu_early_init_el3:
	mov x25, lr

	/*
	 *	MT_NORMAL                   0
	 *	MT_DEVICE_nGnRnE            1
	 *
	 *	MAIR_ATTR_DEVICE_nGnRnE     (0x00UL)
	 *	MAIR_ATTR_NORMAL            (0xffUL)
	 */
	ldr x6, =MAIR_VAL
	msr mair_el3, x6
	isb

	/* set TTBR0 */
	adr_l x5, __kern_pgtbl_el3
	msr ttbr0_el3, x5
	isb

	/* set TCR, TTBR0 has 512GB (depends on VA_BITS) address space */
	ldr x6, =TCR_VAL_EL3
	msr tcr_el3, x6
	isb

	/* The gap of virt_to_phys is 0 */
	adr_l x8, _start /* Get the physical address */
	/* x8 hold the phys PMD index of _start */
	mov x8, x8, lsr #(SECTION_SHIFT)

	/* x13 holds the PTD flags */
	adr_l x11, __kern_ptd_el3
	ldr x13, =(PTD_TYPE_TABLE)
	orr x13, x13, x11

	/* x14 hold the PMD flags */
	ldr x14, =(SECTION_MAP_FLAGS)

	/* Get the virtual address, virtual==phys */
	adr_l x12, _start
	mov x12, x12, lsr #(SECTION_SHIFT) /* PMD index - start */

	/* Map the whole kernel virtual memory space */
	mov x7, x12, lsr #(PTD_SHIFT - SECTION_SHIFT)
	str	x13, [x5, x7, lsl #3] /* PTD */

1:	orr x7, x14, x8, lsl #(SECTION_SHIFT)
	and x10, x12, #(PMDS_PER_PTD - 1)
	str	x7, [x11, x10, lsl #3] /* PMD */
	add x8, x8, #1
	add x12, x12, #1
	cmp	x10, #(PMDS_PER_PTD - 1) /* within a PTD */
	blo	1b

	/* set SCTLR to turn on the MMU, without WXN */
	ldr x6, =(SCTLR_VAL_EL3)
	bl __mmu_enable_el3
	br x25

__mmu_secondary_init_el3:
	mov x25, lr

	/*
	 *	MT_NORMAL                   0
	 *	MT_DEVICE_nGnRnE            1
	 *
	 *	MAIR_ATTR_DEVICE_nGnRnE     (0x00UL)
	 *	MAIR_ATTR_NORMAL            (0xffUL)
	 */
	ldr x6, =MAIR_VAL
	msr mair_el3, x6
	isb

	/* set TCR, TTBR0 has 512GB (depends on VA_BITS) address space */
	ldr x6, =TCR_VAL_EL3
	msr tcr_el3, x6

	/* set TTBR0 */
	adr_l x5, __kern_pgtbl_el3
	msr ttbr0_el3, x5
	isb

	/* set SCTLR to turn on the MMU, without WXN */
	ldr x6, =(SCTLR_VAL_EL3)
	bl __mmu_enable_el3
	br x25

_mmu_init_el3:
	/* only CPU-0 setups the early pgtbl at the first time,
	secondary-cores or secondary-times calls __mmu_secondary_init_el3 */

	cbnz x0, __mmu_secondary_init_el3
	b __mmu_early_init_el3

	.data
	.align	3
.global __cntfrq
__cntfrq:
	.dword 1000000000 /* Default 1 GHz */

	.bss
	.align 6
__el3_buffer:
	.fill BUFFER_SIZE * CONFIG_NR_CPUS, 1, 0

	.data
	.align PAGE_SHIFT
__kern_pgtbl_el3:
	.fill PTDS_PER_PT, BYTES_PER_LONG, 0

	.align PAGE_SHIFT
__kern_ptd_el3:
	.fill PMDS_PER_PTD, BYTES_PER_LONG, 0
