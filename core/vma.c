// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Virtual Memory Address Space management
 */

#include <vma.h>
#include <defs.h>
#include <page.h>
#include <errno.h>
#include <trace.h>
#include <buddy.h>
#include <kmath.h>
#include <rbtree.h>
#include <kmalloc.h>
#include <stdbool.h>

/*
 * level is 0/1/2/3, level step order is 7
 *
 * If node_size == 4K, then the vma space is max. to 1TB
 *
 * Pool Order: 12 -> 19   ->  26  -> 33 -> 40
 * Pool Size:  4K -> 512K ->  64M -> 8G -> 1T
 *
 * if node_size == 8K, then the vma space is max. to 2TB
 * Pool Order: 13 -> 20   -> 27   -> 34  -> 41
 * Pool Size:  8K -> 1M   -> 128M -> 16G -> 2T
 *
 * and so on...
 *
 * e.g. when 4K node_size applied:
 * Pool Level: 0 (0    < S <= 512K)
 * Pool Level: 1 (512K < S <= 64M)
 * Pool Level: 2 (64M  < S <= 8G)
 * Pool Level: 3 (8G   < S <= 1T)
 */

#define vm_order_level(vm, order) ( \
	(order <= vm->node_order + 7)  ? 0 : \
	(order <= vm->node_order + 14) ? 1 : \
	(order <= vm->node_order + 21) ? 2 : 3)

#define va_match_buddy(va, buddy) (((buddy)->start <= (va)) && \
	(((buddy)->start - 1 + (1UL << (buddy)->order)) > ((va) - 1)))

struct vma_pool {
	struct rb_node node;
	struct rb_node addrnode;
	struct buddy_pool buddy;
};

static void vma_rbadd_addr(struct vma_pool *p,
	struct rb_node **root)
{
	struct rb_node **ppn = root, *parent = NULL;
	struct vma_pool *tmp = NULL;
	void *addr = p->buddy.start;

	while (*ppn) {
		parent = *ppn;

		tmp = rb_entry_of(parent, struct vma_pool, addrnode);

		if (addr < tmp->buddy.start)
			ppn = &parent->left;
		else
			ppn = &parent->right;
	}

	rb_link_parent(&p->addrnode, ppn, parent);
	rb_insert(&p->addrnode, root);
}

static struct vma_pool *vma_rbfind(struct vma *vm,
	const void *va, unsigned int level)
{
	struct rb_node *n = vm->rbroota[level];
	struct vma_pool *pool = NULL;
	struct buddy_pool *buddy = NULL;

	while (n) {
		pool = rb_entry_of(n, struct vma_pool, addrnode);

		buddy = &pool->buddy;

		if (va_match_buddy(va, buddy))
			return pool;

		if (va < buddy->start)
			n = n->left;
		else
			n = n->right;
	}

	return NULL;
}

static void *vma_find_top_space
(
	struct vma *vm, int level
)
{
	if (vm->rbroot[level]) {
		IMSG("already allocated\n");
		return NULL; /* already allocated */
	}

	return vm->start;
}

static void vma_rbadd(struct vma_pool *p,
	struct rb_node **root, struct rb_node *from)
{
	struct vma_pool *tmp = NULL;
	struct rb_node **ppn = NULL, *parent = NULL;
	unsigned int order = buddy_max_order(&p->buddy);

	ppn = from ? &from : root;

	while (*ppn) {
		parent = *ppn;

		tmp = rb_entry_of(parent, struct vma_pool, node);

		if (order < buddy_max_order(&tmp->buddy))
			ppn = &parent->left;
		else
			ppn = &parent->right;
	}

	rb_link_parent(&p->node, ppn, parent);
	rb_insert(&p->node, root);
}

static inline void vma_rbtree_resort(struct vma_pool *p,
	unsigned int old_max_order, struct rb_node **root)
{
	unsigned int new_max_order = buddy_max_order(&p->buddy);
	struct rb_node *n = NULL;

	if (new_max_order > old_max_order) {
		n = rb_next(&p->node);
		if (n && new_max_order > buddy_max_order(
				&rb_entry_of(n, struct vma_pool, node)->buddy)) {
			rb_del(&p->node, root);
			vma_rbadd(p, root, NULL);
		}
	} else if (new_max_order < old_max_order) {
		n = rb_prev(&p->node);
		if (n && new_max_order < buddy_max_order(
				&rb_entry_of(n, struct vma_pool, node)->buddy)) {
			rb_del(&p->node, root);
			vma_rbadd(p, root, NULL);
		}
	}
}

static struct vma_pool *vma_pool_add
(
	struct vma *vm, unsigned int level
)
{
	void *mgr = NULL;
	void *pool_start = NULL;
	struct vma_pool *pool = NULL;
	struct rb_node *n = NULL, *match = NULL;
	unsigned int pool_order = vm->node_order + ((level + 1) * 7);
	unsigned int node_order = vm->node_order + (level * 7);

	if (pool_order >= vm->size_order && vm->size_order > node_order) {
		pool_order = min((unsigned int)vm->size_order, pool_order);
		pool_start = vma_find_top_space(vm, level);
	} else {
		if (level == ARRAY_SIZE(vm->rbroot) - 1)
			return NULL;
again:
		/* ask for help from upper level */
		n = vm->rbroot[level + 1];
		while (n) {
			pool = rb_entry_of(n, struct vma_pool, node);
			if (pool_order <= buddy_max_order(&pool->buddy)) {
				match = n;
				n = n->left;
			} else {
				n = n->right;
			}
		}

		if (match) {
			unsigned int old_order = 0;

			pool = rb_entry_of(match, struct vma_pool, node);
			old_order = buddy_max_order(&pool->buddy);
			pool_start = buddy_alloc_order(&pool->buddy, pool_order);
			vma_rbtree_resort(pool, old_order, &vm->rbroot[level + 1]);
		} else {
			pool = vma_pool_add(vm, level + 1);
			if (pool)
				goto again;
		}
	}

	if (!pool_start)
		return NULL;

	pool = kmalloc(sizeof(struct vma_pool));
	if (!pool)
		goto err;

	mgr = kmalloc(buddy_order_mgs(pool_order, node_order));
	if (!mgr)
		goto err;

	buddy_init(&pool->buddy, pool_start,
		1UL << pool_order, mgr, 1UL << node_order);

	vma_rbadd(pool, &vm->rbroot[level], rb_last(vm->rbroot[level]));
	vma_rbadd_addr(pool, &vm->rbroota[level]);
	return pool;

err:
	/* return the pool_start to upper level buddy */
	if (match) {
		struct vma_pool *parent = rb_entry_of(match, struct vma_pool, node);

		unsigned int old_order = buddy_max_order(&parent->buddy);

		buddy_free(&parent->buddy, pool_start);
		vma_rbtree_resort(parent, old_order, &vm->rbroot[level + 1]);
	}
	kfree(mgr);
	kfree(pool);
	return NULL;
}

static void vma_pool_remove(struct vma *vm,
	struct vma_pool *pool, unsigned int level)
{
	vm->last = NULL;

	rb_del(&pool->node, &vm->rbroot[level]);
	rb_del(&pool->addrnode, &vm->rbroota[level]);
	kfree(pool->buddy.manager);
	kfree(pool);
}

struct vma *vma_create
(
	unsigned long start, size_t size, size_t node_size
)
{
	struct vma *vm = NULL;

	if (start == 0 || size == 0)
		return NULL;

	if (!is_pow2(size) || !is_pow2(node_size)) {
		EMSG("size isn't power of 2\n");
		return NULL;
	}

	if (start % node_size != 0) {
		EMSG("start/pool_size isn't aligned\n");
		return NULL;
	}

	vm = kzalloc(sizeof(struct vma));
	if (!vm)
		return NULL;

	vm->start = (void *)start;
	vm->size_order = log2of(size);
	vm->node_order = log2of(node_size);
	spin_lock_init(&vm->lock);

	return vm;
}

void vma_destroy(struct vma *vm)
{
	int i = 0;
	struct vma_pool *pool = NULL;
	unsigned long flags = 0;

	if (vm) {
		spin_lock_irqsave(&vm->lock, flags);
		for (i = 0; i < ARRAY_SIZE(vm->rbroot); i++) {
			while ((pool = rb_first_entry_postorder(vm->rbroot[i],
					struct vma_pool, node)) != NULL) {
				vma_pool_remove(vm, pool, i);
			}
		}
		spin_unlock_irqrestore(&vm->lock, flags);
		kfree(vm);
	}
}

void *vma_alloc(struct vma *vm, size_t size)
{
	void *va = NULL;
	unsigned int order = 0, level = 0;
	unsigned long flags = 0;
	struct vma_pool *pool = NULL;
	struct rb_node *n = NULL, *match = NULL;

	if (!vm || size == 0)
		return NULL;

	size = roundup2pow(size);
	order = max(log2of(size), (unsigned int)vm->node_order);

	if (order > vm->size_order)
		return NULL;

	spin_lock_irqsave(&vm->lock, flags);

	/*
	 * e.g. when 4K node_size applied:
	 * Pool Level: 0 (0    < S <= 512K)
	 * Pool Level: 1 (512K < S <= 64M)
	 * Pool Level: 2 (64M  < S <= 8G)
	 * Pool Level: 3 (8G   < S <= 1T)
	 */

	level = vm_order_level(vm, order);

	n = vm->rbroot[level];
	while (n) {
		pool = rb_entry_of(n, struct vma_pool, node);
		if (order <= buddy_max_order(&pool->buddy)) {
			match = n;
			n = n->left;
		} else {
			n = n->right;
		}
	}

	pool = rb_entry(match, struct vma_pool, node);

again:
	if (pool) {
		unsigned int old_order = buddy_max_order(&pool->buddy);

		va = buddy_alloc_order(&pool->buddy, order);
		vma_rbtree_resort(pool, old_order, &vm->rbroot[level]);
	} else {
		pool = vma_pool_add(vm, level);
		if (pool)
			goto again;
	}

	spin_unlock_irqrestore(&vm->lock, flags);
	return va;
}

void vma_free(struct vma *vm, void *va)
{
	bool freed = false;
	unsigned int i = 0;
	unsigned long flags = 0;
	struct vma_pool *pool = NULL;
	struct buddy_pool *buddy = NULL;

	if (!vm || !va)
		return;

	spin_lock_irqsave(&vm->lock, flags);

	pool = vm->last;
	if (pool && va_match_buddy(va, &pool->buddy)) {
		unsigned int old_order = 0;

		buddy = &pool->buddy;
		old_order = buddy_max_order(buddy);
		buddy_free(buddy, va);
		freed = true;

		i = vm_order_level(vm, buddy->order);
		if (buddy->curr_size == (1UL << buddy->order)) {
			va = buddy->start; /* need to remove upper level ? */
			vma_pool_remove(vm, pool, i);
			i += 1;
		} else {
			vma_rbtree_resort(pool, old_order, &vm->rbroot[i]);
			i = -1;
		}
	}

	for (; i < ARRAY_SIZE(vm->rbroot); i++) {
		pool = vma_rbfind(vm, va, i);
		if (pool) {
			unsigned int old_order = 0;

			buddy = &pool->buddy;
			old_order = buddy_max_order(buddy);
			buddy_free(buddy, va);
			freed = true;

			if (i == 0)
				vm->last = pool;

			if (buddy->curr_size == (1UL << buddy->order)) {
				va = buddy->start; /* need to remove upper level ? */
				vma_pool_remove(vm, pool, i);
			} else {
				vma_rbtree_resort(pool, old_order, &vm->rbroot[i]);
				break;
			}
		}
	}

	spin_unlock_irqrestore(&vm->lock, flags);

	assert(freed);
}

/*
 * return the num of bytes held by 'addr' (aligned power of 2)
 */
size_t vma_sizeof(struct vma *vm, void *va)
{
	int i = 0;
	size_t size = 0;
	struct vma_pool *pool = NULL;
	unsigned long flags = 0;

	if (!vm || !va)
		return 0;

	spin_lock_irqsave(&vm->lock, flags);

	for (; i < ARRAY_SIZE(vm->rbroot); i++) {
		pool = vma_rbfind(vm, va, i);
		if (pool) {
			size = buddy_sizeof(&pool->buddy, va);
			break;
		}
	}

	spin_unlock_irqrestore(&vm->lock, flags);

	return size;
}

void vma_info(struct debugfs_file *d, struct vma *vm)
{
	int i = 0;
	unsigned long flags = 0;
	struct vma_pool *pool = NULL;

	BUILD_ERROR_ON(ARRAY_SIZE(vm->rbroot) != 4);

	spin_lock_irqsave(&vm->lock, flags);

	for (i = 0; i < ARRAY_SIZE(vm->rbroot); i++) {
		rb_for_each_entry(pool, vm->rbroot[i], node) {
			debugfs_printf(d, "l %d Start %p Size %lx, Free %lx, MaxOrder %d\n", i,
				pool->buddy.start, 1UL << pool->buddy.order,
				(long)pool->buddy.curr_size, (int)buddy_max_order(&pool->buddy));
		}
	}

	spin_unlock_irqrestore(&vm->lock, flags);
}
