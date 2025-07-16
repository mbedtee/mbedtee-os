/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * buddy allocator
 */

#ifndef _BUDDY_H
#define _BUDDY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <list.h>
#include <kmath.h>
#include <stdint.h>
#include <stddef.h>
#include <spinlock.h>

/*
 * Get the buddy manager area size
 */
#define buddy_mgs(size, node_size) (((size) >> ((log2of(node_size)) - 1)) - 1)
#define buddy_order_mgs(order, node_order) ((1 << ((order) - (node_order) + 1)) - 1)

#define buddy_max_order(b) ((b)->manager[0].order)

#define buddy_is_idle(b) ((b)->curr_size == ((1UL << (b)->order) - (b)->resvd))

struct buddy_pool {
	/* heap start, virt-addr */
	void *start;

	size_t curr_size;

	struct {
		unsigned char order;
	} *manager; /* manager controls the child's order */

	/*
	 * reserved_size:
	 * e.g. (pool_struct_size or manager_size) in case of the manager stands inside the pool
	 * e.g. (0) in case of the manager stands outside the pool and no reserved node
	 */
	unsigned int resvd;

	/* pool total order */
	unsigned char order;

	/* min alloc size */
	unsigned char node_order;
};

/*
 * Initialize a buddy pool.
 * The size must be a power of 2.
 * The manager_area must be supplied by the caller.
 */
int buddy_init(struct buddy_pool *buddy,
		void *start, size_t size,
		void *manager_area, size_t node_size);

/*
 * Initialize a buddy pool.
 * The manager_area is managed internally by this function,
 * which reuses the start address as the manager_area.
 */
int buddy_init_ex(struct buddy_pool *buddy,
		void *start, size_t size, size_t node_size);


void *buddy_alloc_order(struct buddy_pool *buddy,
		unsigned int order);

static inline void *buddy_alloc(struct buddy_pool *buddy,
		size_t size)
{
	if (size == 0)
		return NULL;

	return buddy_alloc_order(buddy, log2of(roundup2pow(size)));
}

/*
 * Return the size freed (aligned to the next power of 2).
 */
size_t buddy_free(struct buddy_pool *buddy,
		const void *addr);

/*
 * Return the allocation size held at 'addr'.
 */
size_t buddy_sizeof(struct buddy_pool *buddy,
		const void *addr);

void buddy_reserve(struct buddy_pool *buddy,
		size_t size);

#ifdef __cplusplus
}
#endif
#endif
