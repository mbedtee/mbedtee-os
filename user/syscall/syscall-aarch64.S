/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * syscall entry for AArch64 based solutions
 */

.text
.global __syscall
.type __syscall, %function
__syscall:
.cfi_startproc /* to generate the unwind table @ .eh_frame */
	str     x30, [sp, #-8]!

	.cfi_adjust_cfa_offset 8
	.cfi_rel_offset x30, 0

	svc 0

	ldr     x30, [sp], #8
	ret
.cfi_endproc
.size	__syscall, .-__syscall
