// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * buddy allocator
 */

#include <defs.h>
#include <trace.h>
#include <buddy.h>
#include <kmath.h>
#include <errno.h>
#include <trace.h>

#define lchild_of(x) ((((x) + 1) << 1) - 1)
#define rchild_of(x) (((x) + 1) << 1)
#define parent_of(x) ((((x) + 1) >> 1) - 1)

int buddy_init(struct buddy_pool *buddy,
		void *start, size_t size,
		void *manager_area, size_t node_size)
{
	unsigned int i = 0;
	unsigned int child_order = 0;
	unsigned int mgr_size = 0;

	if ((!is_pow2(size)) || (!is_pow2(node_size))) {
		EMSG("size isn't power of 2\n");
		return -EINVAL;
	}

	if (size % node_size) {
		EMSG("size isn't aligned\n");
		return -EINVAL;
	}

	buddy->start = start;
	buddy->curr_size = size;
	buddy->manager = manager_area;
	buddy->node_order = log2of(node_size);
	buddy->order = log2of(size);
	buddy->resvd = 0;

	/* prepare the manager, using log2N */
	child_order = buddy->order + 1;
	mgr_size = buddy_order_mgs(buddy->order, buddy->node_order);
	for (i = 0; i < mgr_size; i++) {
		if (is_pow2(i + 1))
			child_order--;
		buddy->manager[i].order = child_order;
	}
	return 0;
}

int buddy_init_ex(struct buddy_pool *buddy,
		void *start, size_t size, size_t node_size)
{
	int ret = -ENOMEM;
	size_t mgr_size = 0;
	size_t unaligned_size = 0;
	size_t pool_size = roundup2pow(size);

	if (size <= node_size)
		return -EINVAL;

	mgr_size = buddy_mgs(pool_size, node_size);
	mgr_size = roundup(mgr_size, node_size);

	/* make sure the allocated address aligned to node_size */
	unaligned_size = roundup(pool_size - size, node_size);

	/* no space left */
	if (unaligned_size + mgr_size >= pool_size)
		return -EINVAL;

	ret = buddy_init(buddy, start - unaligned_size, pool_size,
				start, node_size);
	if (ret)
		return ret;

	buddy_reserve(buddy, unaligned_size + mgr_size);

	return 0;
}

void *buddy_alloc_order(struct buddy_pool *buddy,
		unsigned int order)
{
	unsigned int lchild_order = 0;
	unsigned int rchild_order = 0;
	unsigned long offset = 0;
	unsigned long i = 0;
	unsigned long mgr_size = 0;

	order = max(order, (unsigned int)buddy->node_order);

	if (order > buddy_max_order(buddy))
		return NULL;

	mgr_size = buddy_order_mgs(buddy->order, buddy->node_order);
	while ((i < mgr_size) && (buddy->manager[i].order >= order)) {
		if ((rchild_of(i) < mgr_size) &&
			(buddy->manager[lchild_of(i)].order >= order))
			i = lchild_of(i);
		else
			i = rchild_of(i);
	}

	i = parent_of(i);
	offset = ((i + 1) << order) - (1UL << buddy->order);

	if ((long)offset < 0)
		return NULL;

	buddy->manager[i].order = 0;
	buddy->curr_size -= (1UL << order);

	while (i) {
		i = parent_of(i);
		lchild_order = buddy->manager[lchild_of(i)].order;
		rchild_order = buddy->manager[rchild_of(i)].order;
		buddy->manager[i].order = max(lchild_order, rchild_order);
	}

	return buddy->start + offset;
}

size_t buddy_sizeof(struct buddy_pool *buddy,
		const void *addr)
{
	unsigned int order = 0;
	unsigned int i = 0;
	unsigned long offset = 0;

	if (!addr)
		return 0;

	offset = addr - buddy->start;

	/* assert(offset <= (1UL << buddy->order)); */

	/* start from the youngest child */
	order = buddy->node_order;
	i = ((offset + (1UL << buddy->order)) >> order) - 1;
	while (i && buddy->manager[i].order) {
		order++;
		i = parent_of(i);
	}

	return 1UL << order;
}

size_t buddy_free(struct buddy_pool *buddy,
		const void *addr)
{
	unsigned int order = 0;
	unsigned int lchild_order = 0;
	unsigned int rchild_order = 0;
	unsigned int i = 0;
	unsigned long offset = 0;
	size_t freedsize = 0;

	if (!addr)
		return 0;

	offset = addr - buddy->start;

	/* assert(offset <= (1UL << buddy->order)); */

	/* start from the youngest child */
	order = buddy->node_order;
	i = ((offset + (1UL << buddy->order)) >> order) - 1;
	while (i && buddy->manager[i].order) {
		order++;
		i = parent_of(i);
	}

	freedsize = 1UL << order;

	/*assert(offset == (i + 1) * freedsize - (1UL << buddy->order));*/

	buddy->manager[i].order = order;
	buddy->curr_size += freedsize;

	/* resume the parents */
	while (i) {
		i = parent_of(i);
		lchild_order = buddy->manager[lchild_of(i)].order;
		rchild_order = buddy->manager[rchild_of(i)].order;
		buddy->manager[i].order = max(lchild_order, rchild_order) +
			((lchild_order == order) && (rchild_order == order));
		order++;
	}

	return freedsize;
}

void buddy_reserve(struct buddy_pool *buddy, size_t size)
{
	unsigned int order = buddy_max_order(buddy);
	unsigned int node_order = buddy->node_order;

	size = roundup(size, (size_t)1 << node_order);

	while (order >= node_order) {
		if (size & (1UL << order))
			buddy_alloc_order(buddy, order);
		order--;
	}

	buddy->resvd += size;
}
