/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * atomic operations
 */

#include <riscv-asm.h>

FUNC_START atomic_add_return
#	int atomic_add_return(struct atomic_num *v, int i);

	/* Get atomic counter */
1:  lr.w a2, (a0)
	/* Add the counter */
	add a2, a2, a1
	sc.w.aq a3, a2, (a0)
	bnez a3, 1b

	mv a0, a2 /* return the new value */
	ret
FUNC_END atomic_add_return

FUNC_START atomic_sub_return
#	int atomic_sub_return(struct atomic_num *v, int i);

	/* Get atomic counter */
1:  lr.w a2, (a0)
	/* Sub the counter */
	sub a2, a2, a1
	sc.w.aq a3, a2, (a0)
	bnez a3, 1b

	mv a0, a2 /* return the new value */
	ret
FUNC_END atomic_sub_return

FUNC_START atomic_set_return
#	int atomic_set_return(struct atomic_num *v, int i);

	/* Get atomic counter */
1:	lr.w a2, (a0)
	sc.w.aq a3, a1, (a0)
	bnez a3, 1b

	mv a0, a2 	/* return the old value */
	ret
FUNC_END atomic_set_return

FUNC_START atomic_compare_set
#	int atomic_compare_set(struct atomic_num *v, int *expected, int i);

	lw a5, (a1)

	/* Get atomic counter */
1:	lr.w a3, (a0)
	bne a3, a5, 2f
	sc.w.aq a4, a2, (a0)
	bnez a4, 1b
	li a0, 1 /* return true when success */
	ret

2:	li a0, 0 /* return false when failure */
	sw a3, (a1)
	ret
FUNC_END atomic_compare_set

FUNC_START atomic_orr
#	void atomic_orr(struct atomic_num *v, int i);

	/* Get atomic counter */
1:  lr.w a2, (a0)
	/* orr the counter with i */
	or a2, a2, a1
	sc.w.aq a3, a2, (a0)
	bnez a3, 1b

	ret
FUNC_END atomic_orr

FUNC_START atomic_bic
#	void atomic_bic(struct atomic_num *v, int i);

	not	a1, a1

	/* Get atomic counter */
1:	lr.w a2, (a0)
	/* bic the counter with i */
	and	a2, a2, a1
	sc.w.aq a3, a2, (a0)
	bnez a3, 1b

	ret
FUNC_END atomic_bic
