/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * lock dependences (32-bits)
 */

#include <mips32-asm.h>

.text
.set push
.set noat
.set noreorder
.set nomips16

FUNC_START arch_atomic_tryacquire
#	int arch_atomic_tryacquire(struct lockval *lv);
	ll		v0, 0(a0)
	bnez	v0, 1f
	li		v1, 1
	sc		v1, 0(a0)
	beqz	v1, 1f
	li		v0, 1
	sync
	move	v0, zero

1:	jr 		ra
	nop
FUNC_END arch_atomic_tryacquire

FUNC_START arch_atomic_acquire
#	int arch_atomic_acquire(struct lockval *lv);
	ll		v0, 0(a0)
	bnez	v0, 1f
	li		v1, 1
	sc		v1, 0(a0)
	beqz	v1, 1f
	li		v0, 1
	sync
	move	v0, zero

1:	jr 		ra
	nop
FUNC_END arch_atomic_acquire

FUNC_START arch_atomic_release
#	void arch_atomic_release(struct lockval *lv);
	sync
	jr		ra
	sw      zero, 0(a0)
FUNC_END arch_atomic_release

FUNC_START arch_semaphore_acquire
#	int arch_semaphore_acquire(struct lockval *lv);
1:	ll		v1, 0(a0)
	beqz	v1, __wait_sem_event
	/* Decrement the counter */
	addiu	v1, -1
	sc		v1, 0(a0)
	beqz	v1, 1b
	move	v0, zero
	sync
	jr		ra
	nop

__wait_sem_event:
	jr		ra
	li		v0, 1
FUNC_END arch_semaphore_acquire

FUNC_START arch_semaphore_release
#	int arch_semaphore_release(struct lockval *lv, unsigned int *limit);
1:	ll		v1, 0(a0)
	lw		v0, 0(a1)
	beq     v0, v1, __invalid_condi
	addiu	v1, 1
	sc		v1, 0(a0)
	beqz    v1, 1b
	move	v0, zero
	sync
	jr		ra
	nop

__invalid_condi:
	jr		ra
	li		v0, 1
FUNC_END arch_semaphore_release

#if 0 /* 8-bits implementation */
FUNC_START arch_atomic_tryacquire
#   int arch_atomic_tryacquire(struct lockval *lv);
    li      a1, -4
    li      a2, 1
    li      v1, 0xff
    and     a1, a0, a1
    andi    a0, a0, 3  /* e.g. a0 = 2 */
    sll     a0, a0, 3  /* e.g. a0 = 16 */
    sllv    v1, v1, a0 /* e.g. v1 = 0x00ff0000 */
    sllv    a2, a2, a0 /* e.g. a2 = 0x00010000 */
    sync

1:  ll      v0, 0(a1)
    and     a3, v0, v1 /* a3 = lock_val & 0x00ff0000 */
    bnez    a3, 2f
    or      a3, v0, a2 /* a3 = lock_val | 0x00010000 */
    sc      a3, 0(a1)
    beqz    a3, 1b
    nop
    sync
    move    v0, zero

2:  jr      ra
    nop
FUNC_END arch_atomic_tryacquire

FUNC_START arch_atomic_acquire
#   int arch_atomic_acquire(struct lockval *lv);
    li      a1, -4
    li      a2, 1
    li      v1, 0xff
    and     a1, a0, a1
    andi    a0, a0, 3  /* e.g. a0 = 2 */
    sll     a0, a0, 3  /* e.g. a0 = 16 */
    sllv    v1, v1, a0 /* e.g. v1 = 0x00ff0000 */
    sllv    a2, a2, a0 /* e.g. a2 = 0x00010000 */
    sync

1:  ll      v0, 0(a1)
    and     a3, v0, v1 /* a3 = lock_val & 0x00ff0000 */
    bnez    a3, 2f
    or      a3, v0, a2 /* a3 = lock_val | 0x00010000 */
    sc      a3, 0(a1)
    beqz    a3, 1b
    nop
    sync
    jr      ra
    move    v0, zero

2:  wait
    jr      ra
    nop
FUNC_END arch_atomic_acquire

FUNC_START arch_atomic_release
#   void arch_atomic_release(struct lockval *lv);
    sync
    jr      ra
    sb      zero, 0(a0)
FUNC_END arch_atomic_release

FUNC_START arch_semaphore_acquire
#   int arch_semaphore_acquire(struct lockval *lv);
    li      a1, -4
    li      a2, 1
    li      v1, 0xff
    and     a1, a0, a1
    andi    a0, a0, 3  /* e.g. a0 = 2 */
    sll     a0, a0, 3  /* e.g. a0 = 16 */
    sllv    v1, v1, a0 /* e.g. v1 = 0x00ff0000 */
    sllv    a2, a2, a0 /* e.g. a2 = 0x00010000 */
    sync

1:  ll      v0, 0(a1)
    and     a3, v0, v1 /* a3 = lock_val & 0x00ff0000 */
    beqz    a3, __wait_sem_event
    subu    a3, v0, a2 /* a3 = lock_val - 0x00010000 */
    sc      a3, 0(a1)
    beqz    a3, 1b
	nop
    sync
    jr      ra
    move    v0, zero

__wait_sem_event:
    jr      ra
    li      v0, 1
FUNC_END arch_semaphore_acquire

FUNC_START arch_semaphore_release
#   int arch_semaphore_release(struct lockval *lv, unsigned int *limit);
    li      t0, -4
    li      a2, 1
    li      v1, 0xff
    and     t0, a0, t0
    andi    a0, a0, 3  /* e.g. a0 = 2 */
    sll     a0, a0, 3  /* e.g. a0 = 16 */
    sllv    v1, v1, a0 /* e.g. v1 = 0x00ff0000 */
    sllv    a2, a2, a0 /* e.g. a2 = 0x00010000 */
    sync

1:  ll      v0, 0(t0)
    lw      t1, 0(a1)
    sllv    t1, t1, a0 /* e.g. limit << 16 */
    and     a3, v0, v1 /* a3 = lock_val & 0x00ff0000 */
    beq     a3, t1, __invalid_condi
    addu    a3, v0, a2 /* a3 = lock_val + 0x00010000 */
    sc      a3, 0(t0)
    beqz    a3, 1b
    nop
    sync
    jr      ra
    move    v0, zero

__invalid_condi:
    jr      ra
    li      v0, 1
FUNC_END arch_semaphore_release

#endif

.set pop
