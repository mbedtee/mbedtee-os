/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * syscall entry for AArch32@ARMV7-A based solutions
 */

.text
.global __syscall
.type __syscall, %function
__syscall:
.fnstart /* Marks the start of a function with an unwind table entry.
 		to generate the unwind table @ .ARM.exidx .ARM.extab  */
.cfi_startproc
	push {lr}

	.save {lr}
	.cfi_adjust_cfa_offset 4
	.cfi_rel_offset lr, 0

	/* value is not used, svc-id is in r0 */
	svc 0

	pop {pc}
.cfi_endproc
.fnend /* Marks the end of a function with an unwind table entry. */
.size	__syscall, .-__syscall
