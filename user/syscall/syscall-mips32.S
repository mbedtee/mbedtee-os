/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * syscall entry for MIPS32 based solutions
 */

.text
.global __syscall
.ent __syscall
__syscall:
.cfi_startproc /* to generate the unwind table @ .eh_frame */
	addiu	$sp, $sp, -4
	sw		$ra, 0($sp)

	.cfi_adjust_cfa_offset 4
	.cfi_rel_offset $ra, 0

	/* syscall-id is in a0 */
	syscall

	lw		$ra, 0($sp)
	addiu	$sp, $sp, 4

	jr $ra
	nop
.cfi_endproc
.end __syscall
