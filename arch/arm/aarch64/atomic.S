/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * atomic operations
 */

#include <aarch64-asm.h>

FUNC_START atomic_add_return
#	int atomic_add_return(struct atomic_num *v, int i);

	/* Get atomic counter */
	dmb ishst
1:	ldaxr	w2, [x0]
	/* Add the counter */
	add 	w2, w2, w1
	stxr	w3, w2, [x0]
	cbnz 	w3, 1b
	dmb ish

	mov		w0, w2 /* return the new value */
	ret
FUNC_END atomic_add_return

FUNC_START atomic_sub_return
#	int atomic_sub_return(struct atomic_num *v, int i);

	/* Get atomic counter */
	dmb ishst
1:	ldaxr	w2, [x0]
	/* Sub the counter */
	sub 	w2, w2, w1
	stxr	w3, w2, [x0]
	cbnz 	w3, 1b
	dmb ish

	mov		w0, w2 /* return the new value */
	ret
FUNC_END atomic_sub_return

FUNC_START atomic_set_return
#	int atomic_set_return(struct atomic_num *v, int i);

	/* Get atomic counter */
	dmb ishst
1:	ldaxr w2, [x0]
	stxr w3, w1, [x0]
	cbnz w3, 1b
	dmb ish

	mov w0, w2 	/* return the old value */
	ret
FUNC_END atomic_set_return

FUNC_START atomic_compare_set
#	int atomic_compare_set(struct atomic_num *v, int *expected, int i);

	ldr w5, [x1]

	/* Get atomic counter */
	dmb ishst
1:	ldaxr w3, [x0]
	cmp w3, w5
	bne 2f
	stxr w4, w2, [x0]
	cbnz w4, 1b
	dmb ish
	mov w0, #1 /* return true when success */
	ret

2:	mov w0, #0 	/* return false when failure */
	str w3, [x1]
	ret
FUNC_END atomic_compare_set

FUNC_START atomic_orr
#	void atomic_orr(struct atomic_num *v, int i);

	/* Get atomic counter */
	dmb ishst
1:	ldaxr w2, [x0]
	/* orr the counter with i */
	orr w2, w2, w1
	stxr w3, w2, [x0]
	cbnz w3, 1b
	dmb ish

	ret
FUNC_END atomic_orr

FUNC_START atomic_bic
#	void atomic_bic(struct atomic_num *v, int i);

	/* Get atomic counter */
	dmb ishst
1:	ldaxr	w2, [x0]
	/* bic the counter with i */
	bic w2, w2, w1
	stxr w3, w2, [x0]
	cbnz w3, 1b
	dmb ish

	ret
FUNC_END atomic_bic
