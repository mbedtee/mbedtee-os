/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * ID allocator
 */

#ifndef _IDA_H
#define _IDA_H

#include <bitops.h>
#include <barrier.h>
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
	if (id >= ida->nbits)
		return false;

	/* make sure the updates to ida->bitmap is visible */
	smp_mb();

	return bitmap_bit_isset(ida->bitmap, id);
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

#endif
