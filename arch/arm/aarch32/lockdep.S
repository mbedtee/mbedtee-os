/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch32 lock dependences (8-bits)
 */

#include <aarch32-asm.h>

FUNC_START arch_atomic_tryacquire
#	int arch_atomic_tryacquire(struct lockval *lv);
	dmb ishst
	mov	r2, #1
1:	ldrexb r1, [r0]
	cmp	r1, #0
	bne 2f
	strexb r1, r2, [r0]
	cmp	r1, #0
	bne 1b
	dmb ish
2:	mov r0, r1
	bx	lr
FUNC_END arch_atomic_tryacquire

FUNC_START arch_atomic_acquire
#	int arch_atomic_acquire(struct lockval *lv);
	dmb ishst
	mov	r2, #1
1:	ldrexb r1, [r0]
	cmp	r1, #0
	wfene
	bne 2f
	strexb r1, r2, [r0]
	cmp	r1, #0
	bne 1b
	dmb ish
2:	mov r0, r1
	bx	lr
FUNC_END arch_atomic_acquire

FUNC_START arch_atomic_release
#	void arch_atomic_release(struct lockval *lv);
	mov	r1, #0
	dmb ishst
	strb r1, [r0]
	dmb ish
	sev
	bx	lr
FUNC_END arch_atomic_release

FUNC_START arch_semaphore_acquire
#	int arch_semaphore_acquire(struct lockval *lv);
	dmb ishst
1:	ldrexb r1, [r0]
	cmp	r1, #0
	beq	__wait_sem_event
	/* Decrement the counter */
	sub	r1, #1
	strexb r2, r1, [r0]
	cmp	r2, #0
	bne	1b
	dmb ish
	mov r0, #0
	bx	lr

__wait_sem_event:
	mov r0, #1
	bx  lr
FUNC_END arch_semaphore_acquire

FUNC_START arch_semaphore_release
#	int arch_semaphore_release(struct lockval *lv, unsigned int *limit);
	dmb ishst
1:	ldrexb	r2, [r0]
	ldr 	r3, [r1]
	cmp     r2, r3
	bcs     __invalid_release
	add     r2, #1
	strexb  r3, r2, [r0]
	cmp     r3, #0
	bne     1b
	dmb ish
	mov     r0, #0
	bx      lr

__invalid_release:
	mov r0, #1
	bx	lr
FUNC_END arch_semaphore_release
