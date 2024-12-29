/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * ASM macros for AArch32@ARMV7-A
 */

#ifndef _AARCH32_ASM_H
#define _AARCH32_ASM_H

#include <cpu.h>
#include <map.h>
#include <generated/asm-offsets.h>

#define SCR_NS_BIT			(1)

.macro is_nsbit_unset rt
	push	{\rt}
	mrc     p15, 0, \rt, c1, c1, 0

	tst		\rt, #(SCR_NS_BIT)
	pop		{\rt}
.endm

.macro set_nsbit rt
	mrc     p15, 0, \rt, c1, c1, 0

	orr		\rt, \rt, #(SCR_NS_BIT)
	mcr     p15, 0, \rt, c1, c1, 0

	isb
.endm

.macro unset_nsbit rt
	mrc     p15, 0, \rt, c1, c1, 0

	bic		\rt, \rt, #(SCR_NS_BIT)
	mcr     p15, 0, \rt, c1, c1, 0

	isb
.endm

.macro jump_smc_handler
#if defined(CONFIG_RPC)
	bl smc_handler
#else
	b .
#endif
.endm

.macro FUNC_START name
	.global \name
	.type \name, % function
\name :
.endm

.macro FUNC_END name
	.size \name, . -\name
.endm

/*
 * Calculate the relative address of the symbol
 * store the relative address to \rd
 *
 * symbol address in the physical memory
 */
.macro adr_l rd, sym
	movw \rd, #:lower16:\sym - .relative_pc\@
	movt \rd, #:upper16:\sym - .relative_pc\@
	.set .relative_pc\@, . + 8
	add \rd, \rd, pc
.endm

#endif
