/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch64 lock dependences (8-bits)
 */

#include <aarch64-asm.h>

FUNC_START arch_atomic_tryacquire
#	int arch_atomic_tryacquire(struct lockval *lv);
	mov	w2, #1
	dmb ishst
1:	ldaxrb w1, [x0]
	cbnz w1, 2f
	stxrb w1, w2, [x0]
	cbnz w1, 1b
	dmb ish
2:	mov w0, w1
	ret
FUNC_END arch_atomic_tryacquire

FUNC_START arch_atomic_acquire
#	int arch_atomic_acquire(struct lockval *lv);
	mov	w2, #1
	dmb ishst
1:	ldaxrb w1, [x0]
	cbnz w1, 2f
	stxrb w1, w2, [x0]
	cbnz w1, 1b
	mov w0, w1
	dmb ish
	ret

2:  wfe
	mov w0, w1
	ret
FUNC_END arch_atomic_acquire

FUNC_START arch_atomic_release
#	void arch_atomic_release(struct lockval *lv);
	dmb ishst
	stlrb wzr, [x0]
	dmb ish
	sev
	ret
FUNC_END arch_atomic_release

FUNC_START arch_semaphore_acquire
#	int arch_semaphore_acquire(struct lockval *lv);

	dmb ishst
1:	ldaxrb w1, [x0]
	cbz	w1, __wait_sem_event
	/* Decrement the counter */
	sub	w1, w1, #1
	stxrb w2, w1, [x0]
	cbnz w2, 1b
	dmb ish
	mov w0, #0
	ret

__wait_sem_event:
	mov w0, #1
	ret
FUNC_END arch_semaphore_acquire

FUNC_START arch_semaphore_release
#	int arch_semaphore_release(struct lockval *lv, unsigned int *limit);

	dmb ishst
1:	ldaxrb	w2, [x0]
	ldr 	w3, [x1]
	cmp     w2, w3
	bcs     __invalid_release
	add     w2, w2, #1
	stxrb   w3, w2, [x0]
	cbnz    w3, 1b
	dmb ish
	mov     w0, #0
	ret

__invalid_release:
	mov w0, #1
	ret
FUNC_END arch_semaphore_release
