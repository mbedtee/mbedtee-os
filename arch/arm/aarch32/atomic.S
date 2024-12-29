/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * atomic operations
 */

#include <aarch32-asm.h>

FUNC_START atomic_add_return
#	int atomic_add_return(struct atomic_num *v, int i);

	/* Get atomic counter */
	dmb		ishst
1:	ldrex	r2, [r0]
	/* Add the counter */
	add 	r2, r1
	strex	r3, r2, [r0]
	cmp 	r3, #0
	bne 	1b

	dmb		ish
	mov		r0, r2 /* return the new value */
	bx		lr
FUNC_END atomic_add_return

FUNC_START atomic_sub_return
#	int atomic_sub_return(struct atomic_num *v, int i);

	/* Get atomic counter */
	dmb		ishst
1:	ldrex	r2, [r0]
	/* Sub the counter */
	sub 	r2, r1
	strex	r3, r2, [r0]
	cmp 	r3, #0
	bne 	1b

	dmb		ish
	mov		r0, r2 /* return the new value */
	bx		lr
FUNC_END atomic_sub_return

FUNC_START atomic_set_return
#	int atomic_set_return(struct atomic_num *v, int i);

	/* Get atomic counter */
	dmb ishst
1:	ldrex r2, [r0]
	strex r3, r1, [r0]
	cmp r3, #0
	bne 1b

	dmb ish
	mov r0, r2 	/* return the old value */
	bx	lr
FUNC_END atomic_set_return

FUNC_START atomic_compare_set
#	int atomic_compare_set(struct atomic_num *v, int *expected, int i);
	push {r4, r5}

	ldr r5, [r1]
	/* Get atomic counter */
	dmb ishst
1:	ldrex r3, [r0]
	cmp r3, r5
	bne 3f
	strex r4, r2, [r0]
	cmp r4, #0
	bne 1b
	dmb ish
	mov r0, #1 /* return true when success */
2:	pop {r4, r5}
	bx	lr

3:	mov r0, #0 	/* return false when failure */
	str r3, [r1]
	b 2b
FUNC_END atomic_compare_set

FUNC_START atomic_orr
#	void atomic_orr(struct atomic_num *v, int i);

	/* Get atomic counter */
	dmb ishst
1:	ldrex r2, [r0]
	/* orr the counter with i */
	orr r2, r2, r1
	strex r3, r2, [r0]
	cmp r3, #0
	bne 1b

	dmb ish
	bx	lr
FUNC_END atomic_orr

FUNC_START atomic_bic
@	void atomic_bic(struct atomic_num *v, int i);

	/* Get atomic counter */
	dmb ishst
1:	ldrex	r2, [r0]
	/* bic the counter with i */
	bic r2, r2, r1
	strex r3, r2, [r0]
	cmp r3, #0
	bne 1b

	dmb ish
	bx	lr
FUNC_END atomic_bic
