/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * early MMU functions (Sv32)
 */

#include <cpu.h>

#include "riscv-asm.h"
#include "riscv-mmu.h"

FUNC_START _mmu_init
	/* only CPU-0 setups the early pgtbl at the first time,
	secondary-cores or secondary-times calls __mmu_secondary_init */
	bnez a0, __mmu_secondary_init

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

	/* Map the current kernel physical memory for code execution */
	srli s8, s8, SECTION_SHIFT
	slli t6, s8, SECTION_SHIFT - PPN_BIAS
	or t6, s6, t6
	mul t4, s8, t0
	add t4, s5, t4
	STR t6, 0(t4)

	/* Get the virtual address */
	srli s10, s7, SECTION_SHIFT

	/* get the top */
	li s9, PTDS_PER_PT

	/* Map the whole kernel virtual memory space */
1:	slli t6, s8, SECTION_SHIFT - PPN_BIAS
	or t6, s6, t6
	mul t4, s10, t0
	add t4, s5, t4
	STR t6, 0(t4)
	addi s8, s8, 1
	addi s10, s10, 1
	/* continue mapping until touch the top */
	blt s10, s9, 1b

	/* set SATP to turn on the MMU */
	li t6, SATP_MODE
	srli t4, s5, PAGE_SHIFT
	or t6, t6, t4
	sfence.vma
	csrw satp, t6

	/* preparation for clearing the physical mapping */
	la s8, _start
	srli s8, s8, SECTION_SHIFT

	/* jump to phys_to_virt address space */
	beqz s4, 3f
	la s6, 2f
	add s6, s6, s4
	jalr s6

	/* clear the physical mapping */
2:  add s5, s5, s4
	mul t4, s8, t0
	add t4, s5, t4
	STR zero, 0(t4)

3:	add ra, s11, s4
	fence.i
	ret

__mmu_secondary_init:
	mv s11, ra

	li t0, SR_SUM | SR_MXR
	csrs CSR_STATUS, t0

	la s5, __kern_pgtbl
	la s9, __kern_early_pgtbl

	li t0, BYTES_PER_LONG
	li s6, SECTION_MAP_FLAGS

	/* Get the gap of virt_to_phys */
	la s8, _start /* Get the physical address */
	li s7, VA_OFFSET /* Get the virtual address */
	sub s4, s7, s8
	beqz s4, 1f

	/* use __kern_early_pgtbl to map the current kernel
	 physical memory for code execution */
	srli s8, s8, SECTION_SHIFT
	slli t6, s8, SECTION_SHIFT - PPN_BIAS
	or t6, s6, t6
	mul t4, s8, t0
	add t4, s9, t4
	STR t6, 0(t4)

	/* set SATP with __kern_early_pgtbl to turn on the MMU */
	li t6, SATP_MODE
	srli t4, s9, PAGE_SHIFT
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
	.word 0

	.bss
	.align PAGE_SHIFT
.global __kern_early_pgtbl
__kern_early_pgtbl:
	.fill PTDS_PER_PT, BYTES_PER_LONG, 0
