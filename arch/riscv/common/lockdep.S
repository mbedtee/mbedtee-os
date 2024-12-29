/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * lock dependences (32-bits)
 */

#include <riscv-asm.h>

FUNC_START arch_atomic_tryacquire
#   int arch_atomic_tryacquire(struct lockval *lv);
	li      a4, 1

1:	lr.w    a3, (a0)
	bnez    a3, 2f
	sc.w.aq a3, a4, (a0)
	bnez    a3, 1b

2: 	mv      a0, a3
	ret
FUNC_END arch_atomic_tryacquire

FUNC_START arch_atomic_acquire
#   int arch_atomic_acquire(struct lockval *lv);
 	li      a4, 1
1:	lr.w    a3, (a0)
	bnez    a3, 2f
	sc.w.aq a3, a4, (a0)
	bnez    a3, 1b

2: 	/* no wfe instruction in riscv */
	mv      a0, a3
	ret
FUNC_END arch_atomic_acquire

FUNC_START arch_atomic_release
#   void arch_atomic_release(struct lockval *lv);
	amoswap.w zero, zero, (a0)
	ret
FUNC_END arch_atomic_release

FUNC_START arch_semaphore_acquire
#   int arch_semaphore_acquire(struct lockval *lv);
1:	lr.w a1, (a0)
	beqz a1, __wait_sem_event
	/* Decrement the counter */
	addi a1, a1, -1
	sc.w.aq a2, a1, (a0)
	bnez a2, 1b
	mv a0, zero
	ret

__wait_sem_event:
	li a0, 1
	ret
FUNC_END arch_semaphore_acquire

FUNC_START arch_semaphore_release
#   int arch_semaphore_release(struct lockval *lv, unsigned char *limit);

1:	lr.w a2, (a0)
	lbu a3, (a1)
	bgeu a2, a3, __invalid_release
	addi a2, a2, 1
	sc.w.aq a3, a2, (a0)
	bnez a3, 1b
	mv a0, zero
	ret

__invalid_release:
	li a0, 1
	ret
FUNC_END arch_semaphore_release
