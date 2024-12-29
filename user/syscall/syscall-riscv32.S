/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * syscall entry for RISCV32 based solutions
 */

.text
.balign 4
.option norelax
.global __syscall
.type __syscall, %function
__syscall:
.cfi_startproc
	addi sp, sp, -4
	sw ra, 0(sp)

	.cfi_adjust_cfa_offset 4
	.cfi_rel_offset ra, 0

	/* syscall-id is in a0 */
	ecall

	lw ra, 0(sp)
	addi sp, sp, 4
	ret
.cfi_endproc
.size	__syscall, .-__syscall
