/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * ID allocator
 */

#ifndef _IDA_H
#define _IDA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <bitops.h>
#include <barrier.h>
#include <atomic.h>
#include <spinlock.h>

struct ida {
	/* total number of IDs */
	unsigned int nbits;
	/*
	 * for ida_alloc() only, to record the last allocated/freed ID,
	 * increased 1 for next ida_alloc()
	 */
	unsigned int next;
	/* bit map of ID array */
	unsigned long *bitmap;
	struct spinlock lock;
};

int ida_init(struct ida *ida, unsigned int total);
int ida_set(struct ida *ida, unsigned int id);
int ida_alloc(struct ida *ida);
void ida_free(struct ida *ida, unsigned int id);
void ida_destroy(struct ida *ida);

/* allocate an unused id between which (start <= id < end) */
int ida_alloc_range(struct ida *ida, unsigned int start, unsigned int end);

static inline bool ida_isset(struct ida *ida, unsigned int id)
{
	unsigned int word = 0;
	unsigned long bits = 0;

	if (id >= ida->nbits)
		return false;

	word = id >> BIT_SHIFT_PER_LONG;
	bits = smp_load_acquire(&ida->bitmap[word]);

	return !!(bits & (1UL << (id & BIT_MASK_PER_LONG)));
}

/* allocate an unused id between which (min <= id < ida->nbits) */
static inline int ida_alloc_min(struct ida *ida, unsigned int min)
{
	return ida_alloc_range(ida, min, -1);
}

/* allocate an unused id between which (0 <= id < max) */
static inline int ida_alloc_max(struct ida *ida, unsigned int max)
{
	return ida_alloc_range(ida, 0, max);
}

#ifdef __cplusplus
}
#endif
#endif
