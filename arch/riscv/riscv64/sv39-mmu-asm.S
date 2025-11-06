/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * early MMU functions (Sv39)
 */

#include <cpu.h>

#include "riscv-asm.h"
#include "riscv-mmu.h"

FUNC_START _mmu_init
	/* only CPU-0 setups the early pgtbl at the first time,
	secondary-cores or secondary-times calls __mmu_secondary_init */
	bnez a7, __mmu_secondary_init

	la t1, __memstart
	LDR t2, 0(t1)
	bnez t2, __mmu_secondary_init

	la t2, _start
	STR t2, 0(t1)
	fence
	beqz zero, __mmu_early_init

__mmu_early_init:
	mv s11, ra

	li t0, SR_SUM | SR_MXR
	csrs CSR_STATUS, t0

	la s5, __kern_early_pgtbl

	/* Flags for the kernel memory mappings */
	li s6, SECTION_MAP_FLAGS

	/* Get the gap of virt_to_phys */
	la s8, _start /* Get the physical address */
	li s7, VA_OFFSET /* Get the virtual address */
	sub s4, s7, s8

	li t0, BYTES_PER_LONG

	/* s8, s9 hold the PTD/PMD index of physical _start */
	srli s9, s8, SECTION_SHIFT
	srli s8, s8, PTD_SHIFT

	/* Map the current kernel physical memory for code execution */
	/* s0 holds the tmp PMDs */
	la s0, __kern_tmp_ptd
	srli t3, s0, PPN_BIAS
	ori t3, t3, PTD_VALID
	mul t4, s8, t0
	add t4, s5, t4
	STR t3, 0(t4) /* link PTD with PMDs */

	slli t6, s9, SECTION_SHIFT - PPN_BIAS
	or t6, s6, t6
	andi t5, s9, (PMDS_PER_PTD - 1)
	mul t4, t5, t0
	add t4, s0, t4
	STR t6, 0(t4) /* set the PMD */

	/* s10 holds the PMDs */
	la s10, __kern_early_ptd
	srli t6, s10, PPN_BIAS
	ori t6, t6, PTD_VALID

	/* Get the virtual address */
	li s3, -(1 << (VA_BITS))
	sub	s3, s7, s3
	srli s3, s3, SECTION_SHIFT /* PMD index - start */

	li s2, (PMDS_PER_PTD - 1) /* PMD index - top */

	/* Map the whole kernel virtual memory space - 1PTD -> 1G */
	srli t3, s3, (PTD_SHIFT - SECTION_SHIFT)
	mul t3, t3, t0
	add t3, s5, t3
	STR t6, 0(t3) /* link PTD with PMDs */
1:	slli t6, s9, SECTION_SHIFT - PPN_BIAS
	or t6, s6, t6
	andi s1, s3, (PMDS_PER_PTD - 1)
	mul t4, s1, t0
	add t4, s10, t4
	STR t6, 0(t4) /* set the PMD */
	addi s9, s9, 1
	addi s3, s3, 1
	/* OS only reserved 1 PTD, so the mapping shall be within a PTD */
	blt	s1, s2, 1b

	/* set SATP to turn on the MMU */
	li t6, SATP_MODE
	srli t4, s5, PAGE_SHIFT
	or t6, t6, t4
	sfence.vma
	csrw satp, t6

	add ra, s11, s4
	fence.i
	ret

__mmu_secondary_init:
	mv s11, ra

	li t0, SR_SUM | SR_MXR
	csrs CSR_STATUS, t0

	la s5, __kern_pgtbl

	/* Get the gap of virt_to_phys */
	la s8, _start /* Get the physical address */
	li s7, VA_OFFSET /* Get the virtual address */
	sub s4, s7, s8
	beqz s4, 1f

	/* set SATP with __kern_early_pgtbl to turn on the MMU */
	la s10, __kern_early_pgtbl
	li t6, SATP_MODE
	srli t4, s10, PAGE_SHIFT
	or t5, t6, t4
	sfence.vma
	csrw satp, t5

	/* jump to phys_to_virt address space */
	la s6, 1f
	add s6, s6, s4
	jalr s6

	/* switch to __kern_pgtbl  */
1:	li t6, SATP_MODE
	srli t4, s5, PAGE_SHIFT
	or t5, t6, t4
	csrw satp, t5
	sfence.vma

	add ra, s11, s4
	fence.i
	ret

FUNC_END _mmu_init

	.data
	.balign	BYTES_PER_LONG, 0
.global __memstart
__memstart:
	.dword 0

	.bss
	.align PAGE_SHIFT
.global __kern_early_pgtbl
__kern_early_pgtbl:
	.fill PTDS_PER_PT, BYTES_PER_LONG, 0

	.bss
	.align PAGE_SHIFT
__kern_tmp_ptd:
	.fill PMDS_PER_PTD, BYTES_PER_LONG, 0

	.section ".bss"
	.align PAGE_SHIFT
__kern_early_ptd:
	.fill PMDS_PER_PTD, BYTES_PER_LONG, 0
