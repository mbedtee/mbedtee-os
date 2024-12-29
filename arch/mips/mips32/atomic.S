/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * atomic operations
 */

#include <mips32-asm.h>

.text
.set push
.set noat
.set noreorder
.set nomips16

FUNC_START atomic_add_return
#	int atomic_add_return(struct atomic_num *v, int i);
	sync
1:	ll		v0, 0(a0)
	addu	v0, a1
	move 	v1, v0
	sc		v1, 0(a0)
	beqz	v1, 1b
	nop
	sync	/* for __ATOMIC_ACQUIRE */
	jr		ra
	nop
FUNC_END atomic_add_return

FUNC_START atomic_sub_return
#	int atomic_sub_return(struct atomic_num *v, int i);
	sync
1:	ll		v0, 0(a0)
	subu	v0, a1
	move 	v1, v0
	sc		v1, 0(a0)
	beqz	v1, 1b
	nop
	sync	/* for __ATOMIC_ACQUIRE */
	jr		ra
	nop
FUNC_END atomic_sub_return

FUNC_START atomic_set_return
#	int atomic_set_return(struct atomic_num *v, int i);
	sync
1:	ll		v0, 0(a0)
	move	v1, a1
	sc		v1, 0(a0)
	beqz	v1, 1b
	nop
	sync	/* for __ATOMIC_ACQUIRE */
	jr		ra
	nop
FUNC_END atomic_set_return

FUNC_START atomic_compare_set
#	int atomic_compare_set(struct atomic_num *v, int *expected, int i);
	sync
	lw      v1, 0(a1)
1:	ll		v0, 0(a0)
	bne     v1, v0, 2f
	move	a3, a2
	sc		a3, 0(a0)
	beqz	a3, 1b
	nop
	sync	/* for __ATOMIC_ACQUIRE */
	jr		ra
	li		v0, 1 	/* return true when success */

2:	sw		v0, 0(a1)
	jr		ra
	li		v0, 0 	/* return false when failure */
FUNC_END atomic_compare_set

FUNC_START atomic_orr
#	void atomic_orr(struct atomic_num *v, long i);
	sync
1:	ll		v0, 0(a0)
	or		v0, a1
	move 	v1, v0
	sc		v1, 0(a0)
	beqz	v1, 1b
	nop
	sync	/* for __ATOMIC_ACQUIRE */
	jr		ra
	nop
FUNC_END atomic_orr

FUNC_START atomic_bic
#	void atomic_bic(struct atomic_num *v, int i);
	sync
1:	ll		v0, 0(a0)
	not		v1, a1
	and		v0, v1
	move 	v1, v0
	sc		v1, 0(a0)
	beqz	v1, 1b
	nop
	sync	/* for __ATOMIC_ACQUIRE */
	jr		ra
	nop
FUNC_END atomic_bic

.set pop
