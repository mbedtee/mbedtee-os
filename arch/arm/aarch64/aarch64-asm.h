/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * ASM macros for AArch64
 */

#ifndef _AARCH64_ASM_H
#define _AARCH64_ASM_H

#include <cpu.h>
#include <map.h>
#include <generated/asm-offsets.h>

#define SCR_NS_BIT (1 << 0)

.macro is_nsbit_unset rt
	str \rt, [sp, #-8]!
	mrs \rt, scr_el3
	tst	\rt, #(SCR_NS_BIT)
	ldr \rt, [sp], #8
.endm

.macro set_nsbit rt
	mrs \rt, scr_el3
	orr	\rt, \rt, #(SCR_NS_BIT)
	msr scr_el3, \rt

	isb
.endm

.macro unset_nsbit rt
	mrs \rt, scr_el3
	bic	\rt, \rt, #(SCR_NS_BIT)
	msr scr_el3, \rt

	isb
.endm

.macro FUNC_START name
	.global \name
	.type \name, %function
\name :
.endm

.macro FUNC_END name
	.size \name, . -\name
.endm

/*
 * Calculate the relative address of the symbol
 * store the relative address to \xd
 *
 * symbol address in the physical memory
 */
.macro adr_l xd, sym
	adrp \xd, \sym
	add \xd, \xd, :lo12:\sym
.endm

.macro smp_enable
	/*
	 * Set CPUECTLR.SMPEN
	 * SMP enables coherent requests to the processors
	 */
	/* Only A53/A35/A57/A72/A73 have this reg */
	mrs x1, midr_el1
	and x1, x1, #(0xfff0)
	ldr x2, =(0xd030) /* == Cortex-A53 */
	cmp x1, x2

	beq 55f
	ldr x2, =(0xd040) /* == Cortex-A35 */
	cmp x1, x2

	beq 55f
	ldr x2, =(0xd070) /* == Cortex-A57 */
	cmp x1, x2

	beq 55f
	ldr x2, =(0xd080) /* == Cortex-A72 */
	cmp x1, x2

	beq 55f
	ldr x2, =(0xd090) /* == Cortex-A73 */
	cmp x1, x2

	beq 55f
	b 88f
55 :
	mrs x1, S3_1_C15_C2_1
	orr x1, x1, #(0x40)
	msr S3_1_C15_C2_1, x1
88 : isb
.endm

.macro smp_disable
	/*
	 * Clr CPUECTLR.SMPEN
	 * disable SMP coherent requests to the processors
	 */
	/* Only A53/A35/A57/A72/A73 have this reg */
	mrs x1, midr_el1
	and x1, x1, #(0xfff0)
	ldr x2, =(0xd030) /* == Cortex-A53 */
	cmp x1, x2

	beq 55f
	ldr x2, =(0xd040) /* == Cortex-A35 */
	cmp x1, x2

	beq 55f
	ldr x2, =(0xd070) /* == Cortex-A57 */
	cmp x1, x2

	beq 55f
	ldr x2, =(0xd080) /* == Cortex-A72 */
	cmp x1, x2

	beq 55f
	ldr x2, =(0xd090) /* == Cortex-A73 */
	cmp x1, x2

	beq 55f
	b 88f
55 :
	mrs x1, S3_1_C15_C2_1
	bic x1, x1, #(0x40)
	msr S3_1_C15_C2_1, x1
88 : isb
.endm

#endif
