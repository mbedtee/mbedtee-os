// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * kernel heaps operations on the contiguous physical pages
 */

#include <mem.h>
#include <errno.h>
#include <trace.h>
#include <kproc.h>
#include <device.h>
#include <string.h>
#include <buddy.h>
#include <kmalloc.h>
#include <timer.h>
#include <spinlock.h>
#include <tasklet.h>
#include <rbtree.h>
#include <page.h>
#include <kmath.h>
#include <workqueue.h>
#include <bitops.h>

#define POOL_TYPE_BUDDY  (1)
#define POOL_TYPE_BITMAP (2)

#define BUDDY_NODE_SIZE (64)

static unsigned long early_reserved[PAGE_SIZE/sizeof(long)]
	__section(".bss")
	__aligned(PAGE_SIZE) = {0};

#define BITMAP_NODE_SIZE (16)
#define NBITS_PER_PAGE (PAGE_SIZE / BITMAP_NODE_SIZE)
#define NBITS_RESVD_PER_PAGE ((sizeof(struct kmalloc_bitmap) + \
						BITMAP_NODE_SIZE - 1) / BITMAP_NODE_SIZE)
#define NBITS_USABLE_PER_PAGE (NBITS_PER_PAGE - NBITS_RESVD_PER_PAGE)

static void __shrink_pool(struct work *w);

struct kmalloc_desc {
	int nrpools;
	struct spinlock lock;
	size_t freesz;
	struct rb_node *rbroot;
};

struct kmalloc_buddy {
	struct rb_node node;
	unsigned short type;
	struct buddy_pool buddy;
};

struct kmalloc_bitmap {
	struct rb_node node;
	unsigned short type;
	unsigned short idx;
	unsigned short max;
	unsigned short nbits;
	unsigned long bmap[NBITS_PER_PAGE/BITS_PER_LONG];
};

static struct kmalloc_desc _buddy = {0};
static struct kmalloc_desc _bitmap = {0};

static DECLARE_DELAYED_WORK(_shrinkdw, __shrink_pool);

static inline struct kmalloc_desc *buddy(void)
{
	return &_buddy;
}
static inline struct kmalloc_desc *bmap(void)
{
	return &_bitmap;
}

static inline bool bmap_is_idle(struct kmalloc_bitmap *p)
{
	return ((p)->nbits == NBITS_USABLE_PER_PAGE);
}

static inline unsigned int bmap_nbitsof(const void *ptr)
{
	return *(unsigned int *)((uintptr_t)(ptr) - BITMAP_NODE_SIZE);
}

static inline unsigned int bmap_idxof(const void *ptr, void *start)
{
	return (((uintptr_t)(ptr) - (uintptr_t)(start)) / BITMAP_NODE_SIZE) - 1;
}

static inline unsigned int bmap_sizeof(size_t size)
{
	return (((size) + BITMAP_NODE_SIZE - 1) / BITMAP_NODE_SIZE) + 1;
}

static inline void *ptr2pool(const void *ptr)
{
	return (void *)((uintptr_t)(ptr) & PAGE_MASK);
}

static inline long buddy_single_alloc_max(void)
{
	struct kmalloc_desc *d = buddy();
	struct kmalloc_buddy *p = NULL;

	p = rb_last_entry(d->rbroot, struct kmalloc_buddy, node);

	return (p && buddy_max_order(&p->buddy)) ?
			1UL << buddy_max_order(&p->buddy) : 0;
}

static inline long bmap_single_alloc_max(void)
{
	struct kmalloc_desc *d = bmap();
	struct kmalloc_bitmap *p = NULL;

	p = rb_last_entry(d->rbroot, struct kmalloc_bitmap, node);

	return p ? p->max * BITMAP_NODE_SIZE : 0;
}

/* dynamic free a pool */
static inline void kmalloc_pool_free(void *p)
{
	pages_free_continuous(p);
}

static struct kmalloc_buddy *kmalloc_buddy_deploy(
	void *start, size_t node_size)
{
	size_t mgr_size = 0;
	size_t struct_size = 0;
	struct kmalloc_buddy *p  = NULL;

	mgr_size = buddy_mgs(PAGE_SIZE, node_size);
	mgr_size = roundup(mgr_size, node_size);

	struct_size = roundup(sizeof(*p), node_size);

	p = start;

	if (buddy_init(&p->buddy, start, PAGE_SIZE, p + 1, node_size))
		return NULL;

	buddy_reserve(&p->buddy, mgr_size + struct_size);

	p->type = POOL_TYPE_BUDDY;

	return p;
}

static struct kmalloc_bitmap *kmalloc_bmap_deploy(void *start)
{
	struct kmalloc_bitmap *p = NULL;

	p = start;
	memset(p, 0, sizeof(*p));
	p->type = POOL_TYPE_BITMAP;
	p->nbits = NBITS_USABLE_PER_PAGE;
	p->max = NBITS_USABLE_PER_PAGE;
	p->idx = NBITS_RESVD_PER_PAGE;
	bitmap_set(p->bmap, 0, p->idx);

	return p;
}

/* alloc/deploy a buddy or bitmap pool */
static void *kmalloc_pool_alloc(int type)
{
	void *start = NULL;

	start = pages_alloc_continuous(PG_RW | PG_POOL, 1);
	if (start == NULL)
		goto err;

	if (type == POOL_TYPE_BUDDY)
		kmalloc_buddy_deploy(start, BUDDY_NODE_SIZE);
	else
		kmalloc_bmap_deploy(start);

	return start;

err:
	pages_free_continuous(start);
	return NULL;
}

#define BUDDY_RBSIZE(b) (((unsigned int)buddy_max_order(b) << 16) + (b)->curr_size + 1)

static inline void __kmalloc_buddy_rbadd(
	struct kmalloc_buddy *p, struct rb_node **root)
{
	struct rb_node **ppn = root, *parent = NULL;
	struct kmalloc_buddy *tmp = NULL;
	unsigned int size = BUDDY_RBSIZE(&p->buddy);

	while (*ppn) {
		parent = *ppn;

		tmp = rb_entry_of(parent, struct kmalloc_buddy, node);
		if (size < BUDDY_RBSIZE(&tmp->buddy))
			ppn = &parent->left;
		else
			ppn = &parent->right;
	}

	rb_link_parent(&p->node, ppn, parent);
	rb_insert(&p->node, root);
}

static inline void __kfree_buddy_rbtree_sort(
	struct kmalloc_buddy *p, struct rb_node **root)
{
	struct kmalloc_buddy *nxt = NULL;
	struct rb_node *n = rb_next(&p->node);
	unsigned int size = BUDDY_RBSIZE(&p->buddy);

	if (n) {
		nxt = rb_entry_of(n, struct kmalloc_buddy, node);
		if (size > BUDDY_RBSIZE(&nxt->buddy)) {
			rb_del(&p->node, root);
			__kmalloc_buddy_rbadd(p, root);
		}
	}
}

static inline void __kmalloc_buddy_rbtree_sort(
	struct kmalloc_buddy *p, struct rb_node **root)
{
	struct kmalloc_buddy *prev = NULL;
	struct rb_node *n = rb_prev(&p->node);
	unsigned int size = BUDDY_RBSIZE(&p->buddy);

	if (n) {
		prev = rb_entry_of(n, struct kmalloc_buddy, node);
		if (size < BUDDY_RBSIZE(&prev->buddy)) {
			rb_del(&p->node, root);
			__kmalloc_buddy_rbadd(p, root);
		}
	}
}


/*
 * return the num of bytes held by 'addr' (aligned power of 2)
 */
static size_t kmalloc_sizeof(void *addr)
{
	size_t size = 0;
	struct kmalloc_buddy *p = NULL;
	unsigned long flags = 0;

	if (addr == NULL)
		return 0;

	if (((uintptr_t)addr & ~PAGE_MASK) == 0) {
		size = pages_sizeof(virt_to_page(addr));
		return size << PAGE_SHIFT;
	}

	p = ptr2pool(addr);

	if (p->type == POOL_TYPE_BUDDY) {
		spin_lock_irqsave(&buddy()->lock, flags);
		size = buddy_sizeof(&p->buddy, addr);
		spin_unlock_irqrestore(&buddy()->lock, flags);
	} else if (p->type == POOL_TYPE_BITMAP) {
		size = bmap_nbitsof(addr) * BITMAP_NODE_SIZE;
	}

	return size;
}

static size_t __shrink_buddy_pool(void)
{
	unsigned long flags = 0, num = 0;
	struct kmalloc_desc *d = buddy();
	struct kmalloc_buddy *pool = NULL, *idle = NULL;

	do {
		idle = NULL;

		if (d->freesz <= PAGE_SIZE * 2)
			break;

		spin_lock_irqsave(&d->lock, flags);

		pool = rb_last_entry(d->rbroot, struct kmalloc_buddy, node);
		if (pool && buddy_is_idle(&pool->buddy)) {
			rb_del(&pool->node, &d->rbroot);
			d->freesz -= pool->buddy.curr_size;
			d->nrpools--;
			idle = pool;
			num++;
		}

		spin_unlock_irqrestore(&d->lock, flags);

		kmalloc_pool_free(idle);
	} while (idle);

	return num;
}

static size_t __shrink_bmap_pool(void)
{
	unsigned long flags = 0, num = 0;
	struct kmalloc_desc *d = bmap();
	struct kmalloc_bitmap *pool = NULL, *idle = NULL;

	do {
		idle = NULL;

		if ((d->freesz * BITMAP_NODE_SIZE) <= PAGE_SIZE)
			break;

		spin_lock_irqsave(&d->lock, flags);

		pool = rb_last_entry(d->rbroot, struct kmalloc_bitmap, node);
		if (pool && bmap_is_idle(pool)) {
			rb_del(&pool->node, &d->rbroot);
			d->freesz -= pool->nbits;
			d->nrpools--;
			idle = pool;
			num++;
		}

		spin_unlock_irqrestore(&d->lock, flags);

		kmalloc_pool_free(idle);
	} while (idle);

	return num;
}

static void __shrink_pool(struct work *w)
{
	struct delayed_work *dw = container_of(w, struct delayed_work, w);

	__shrink_buddy_pool();
	__shrink_bmap_pool();

	__schedule_delayed_work(dw, MICROSECS_PER_SEC);
}

size_t kmalloc_release(unsigned int usecs)
{
	size_t num = 0;

	if (usecs == 0) {
		num += __shrink_buddy_pool();
		num += __shrink_bmap_pool();
	} else {
		__mod_delayed_work(&_shrinkdw, usecs);
	}

	return num;
}

static void *kmalloc_buddy(size_t size)
{
	unsigned int order = 0;
	void *addr = NULL;
	unsigned long flags = 0;
	struct kmalloc_desc *d = buddy();
	struct kmalloc_buddy *p = NULL;
	struct rb_node *n = NULL, *match = NULL;

	order = log2of(size);

	spin_lock_irqsave(&d->lock, flags);

	n = d->rbroot;
	while (n) {
		p = rb_entry_of(n, struct kmalloc_buddy, node);
		if (order <= buddy_max_order(&p->buddy)) {
			match = n;
			n = n->left;
		} else {
			n = n->right;
		}
	}

	p = rb_entry(match, struct kmalloc_buddy, node);

again:
	if (p) {
		addr = buddy_alloc_order(&p->buddy, order);
		d->freesz -= 1UL << max(order, (unsigned int)p->buddy.node_order);
		__kmalloc_buddy_rbtree_sort(p, &d->rbroot);
	}

	spin_unlock_irqrestore(&d->lock, flags);

	if ((addr == NULL) && (order < PAGE_SHIFT)) {
		p = kmalloc_pool_alloc(POOL_TYPE_BUDDY);
		if (p) {
			spin_lock_irqsave(&d->lock, flags);
			__kmalloc_buddy_rbadd(p, &d->rbroot);
			d->nrpools++;
			d->freesz += p->buddy.curr_size;
			goto again;
			spin_unlock_irqrestore(&d->lock, flags);
		}
	}

	return addr;
}

static void kfree_buddy(struct kmalloc_buddy *p,
	const void *addr)
{
	unsigned long flags = 0;
	struct kmalloc_desc *d = buddy();

	spin_lock_irqsave(&d->lock, flags);
	d->freesz += buddy_free(&p->buddy, addr);
	__kfree_buddy_rbtree_sort(p, &d->rbroot);
	spin_unlock_irqrestore(&d->lock, flags);
}

#define BMAP_RBSIZE(b) ((((unsigned int)((b)->max)) << 16) + (b)->nbits + 1)

static inline void __kmalloc_bmap_rbadd(
	struct kmalloc_bitmap *p, struct rb_node **root)
{
	struct rb_node **ppn = root, *parent = NULL;
	struct kmalloc_bitmap *tmp = NULL;
	unsigned int size = BMAP_RBSIZE(p);

	while (*ppn) {
		parent = *ppn;

		tmp = rb_entry_of(parent, struct kmalloc_bitmap, node);

		if (size < BMAP_RBSIZE(tmp))
			ppn = &parent->left;
		else
			ppn = &parent->right;
	}

	rb_link_parent(&p->node, ppn, parent);
	rb_insert(&p->node, root);
}

static inline void __kfree_bmap_rbtree_sort(struct kmalloc_bitmap *p,
	struct rb_node **root)
{
	struct kmalloc_bitmap *nxt = NULL;
	struct rb_node *n = rb_next(&p->node);
	unsigned int size = BMAP_RBSIZE(p);

	if (n) {
		nxt = rb_entry_of(n, struct kmalloc_bitmap, node);
		if (size > BMAP_RBSIZE(nxt)) {
			rb_del(&p->node, root);
			__kmalloc_bmap_rbadd(p, root);
		}
	}
}

static inline void __kmalloc_bmap_rbtree_sort(struct kmalloc_bitmap *p,
	struct rb_node **root)
{
	struct kmalloc_bitmap *prev = NULL;
	struct rb_node *n = rb_prev(&p->node);
	unsigned int size = BMAP_RBSIZE(p);

	if (n) {
		prev = rb_entry_of(n, struct kmalloc_bitmap, node);
		if (size < BMAP_RBSIZE(prev)) {
			rb_del(&p->node, root);
			__kmalloc_bmap_rbadd(p, root);
		}
	}
}

static inline void *kmalloc_bmap(unsigned int nbits)
{
	void *addr = NULL;
	unsigned int idx = 0, max = 0;
	unsigned long flags = 0;
	struct kmalloc_desc *d = bmap();
	struct kmalloc_bitmap *p = NULL;
	struct rb_node *n = NULL, *match = NULL;

	spin_lock_irqsave(&d->lock, flags);

	n = d->rbroot;
	while (n) {
		p = rb_entry_of(n, struct kmalloc_bitmap, node);
		if (nbits <= p->max) {
			match = n;
			n = n->left;
		} else {
			n = n->right;
		}
	}

	p = rb_entry(match, struct kmalloc_bitmap, node);

again:
	if (p) {
		idx = bitmap_next_zero_area(p->bmap, p->idx + p->max, p->idx, nbits);

		bitmap_set(p->bmap, idx, nbits);
		p->idx = bitmap_max_zero_area(p->bmap, NBITS_PER_PAGE, &max);
		p->max = max;
		p->nbits -= nbits;
		d->freesz -= nbits;

		addr = (void *)p + (idx * BITMAP_NODE_SIZE);
		*(unsigned int *)addr = nbits;
		addr = addr + BITMAP_NODE_SIZE;

		__kmalloc_bmap_rbtree_sort(p, &d->rbroot);
	}

	spin_unlock_irqrestore(&d->lock, flags);

	if (addr == NULL) {
		p = kmalloc_pool_alloc(POOL_TYPE_BITMAP);
		if (p) {
			spin_lock_irqsave(&d->lock, flags);
			d->nrpools++;
			d->freesz += p->max;
			__kmalloc_bmap_rbadd(p, &d->rbroot);
			goto again;
			spin_unlock_irqrestore(&d->lock, flags);
		}
	}

	return addr;
}

static void kfree_bmap(struct kmalloc_bitmap *p,
	const void *ptr)
{
	unsigned long flags = 0;
	struct kmalloc_desc *d = bmap();
	unsigned int nbits = 0, idx = 0, max = 0;

	spin_lock_irqsave(&d->lock, flags);

	nbits = bmap_nbitsof(ptr);
	idx = bmap_idxof(ptr, p);

	bitmap_clear(p->bmap, idx, nbits);

	p->idx = bitmap_max_zero_area(p->bmap, NBITS_PER_PAGE, &max);
	p->max = max;
	p->nbits += nbits;
	d->freesz += nbits;

	__kfree_bmap_rbtree_sort(p, &d->rbroot);

	spin_unlock_irqrestore(&d->lock, flags);
}

/*
 * allocate from the kmalloc pools or page pools
 */
void *kmalloc(size_t size)
{
	void *addr = NULL;
	size_t alignedsize = 0, nbits = 0;

	if (size == 0)
		return NULL;

	alignedsize = roundup2pow(size);
	nbits = bmap_sizeof(size);

	if (nbits >= NBITS_USABLE_PER_PAGE) {
		addr = pages_alloc_continuous(PG_RW,
				alignedsize >> PAGE_SHIFT);
	} else {
		if ((alignedsize < BUDDY_NODE_SIZE - 16) ||
			(alignedsize - size) > (alignedsize >> 2))
			addr = kmalloc_bmap(nbits);

		if (addr == NULL)
			addr = kmalloc_buddy(alignedsize);

		if ((addr == NULL) && ((size < 512)
			 || (size != alignedsize)))
			addr = kmalloc_bmap(nbits);
	}

	if (addr == NULL)
		LMSG("alloc failed %d\n", (int)size);

	return addr;
}

void kfree(const void *addr)
{
	struct kmalloc_buddy *p = NULL;

	if (addr == NULL)
		return;

	if (((uintptr_t)addr & ~PAGE_MASK) == 0) {
		pages_free_continuous((void *)addr);
		return;
	}

	p = ptr2pool(addr);

	if (p->type == POOL_TYPE_BUDDY)
		kfree_buddy(p, addr);
	else if (p->type == POOL_TYPE_BITMAP)
		kfree_bmap((struct kmalloc_bitmap *)p, addr);
}

void *kzalloc(size_t size)
{
	void *addr = kmalloc(size);

	if (addr)
		memset(addr, 0, size);

	return addr;
}

void *kcalloc(size_t n, size_t size)
{
	size_t total = n * size;
	void *addr = kmalloc(total);

	if (addr)
		memset(addr, 0, total);

	return addr;
}

void *krealloc(void *oldp, size_t size)
{
	size_t oldsize = 0;
	void *newp = NULL;

	if (oldp == NULL)
		return kmalloc(size);

	if (size == 0) {
		kfree(oldp);
		return NULL;
	}

	oldsize = kmalloc_sizeof(oldp);
	if (oldsize == 0)
		return NULL;

	IMSG("%p nsz:0x%lx osz:0x%lx\n", oldp,
		 (long)size, (long)oldsize);

	if (roundup2pow(size) == oldsize)
		return oldp;

	newp = kmalloc(size);
	if (newp == NULL)
		return NULL;

	memcpy(newp, oldp, min(oldsize, size));

	kfree(oldp);

	return newp;
}

static void kmalloc_buddy_add_default(void *start, size_t size)
{
	int i = 0;
	struct kmalloc_buddy *p = NULL;
	struct kmalloc_desc *d = buddy();
	unsigned long flags = 0;

	spin_lock_irqsave(&d->lock, flags);

	for (i = 0; i < size / PAGE_SIZE; i++) {
		p = kmalloc_buddy_deploy(start, BUDDY_NODE_SIZE);

		d->nrpools++;
		d->freesz += p->buddy.curr_size;
		p->buddy.curr_size--; /* never to be freed */
		start += PAGE_SIZE;

		__kmalloc_buddy_rbadd(p, &d->rbroot);
	}
	spin_unlock_irqrestore(&d->lock, flags);
}

static void kmalloc_bmap_add_default(void *start, size_t size)
{
	int i = 0;
	struct kmalloc_bitmap *p = NULL;
	struct kmalloc_desc *d = bmap();
	unsigned long flags = 0;

	spin_lock_irqsave(&d->lock, flags);
	for (i = 0; i < size / PAGE_SIZE; i++) {
		p = kmalloc_bmap_deploy(start);

		d->nrpools++;
		d->freesz += p->nbits;
		p->nbits--; /* never to be freed */
		start += PAGE_SIZE;

		__kmalloc_bmap_rbadd(p, &d->rbroot);
	}

	spin_unlock_irqrestore(&d->lock, flags);
}

int __init kmalloc_early_init(void)
{
	/*
	 * a small static pool, located @ bss
	 */
	void *start = early_reserved;
	size_t size = sizeof(early_reserved);

	kmalloc_buddy_add_default(start, size);

	return 0;
}

/*
 * 1. initialize the delayed work for dynamic shrinking
 * 2. initialize the smallest pools, reuse the .bss.early / .init sections
 */
int kmalloc_post_init(void)
{
	int ret = false;

	unsigned long start = __early_bss_start();
	unsigned long size = __early_bss_size();

	ret = __schedule_delayed_work(&_shrinkdw, MICROSECS_PER_SEC);

	assert(ret != false);

	if (size) {
		IMSG("Recycle .bss.early @ 0x%lx, 0x%lx\n", start, size);
		start = roundup(start, PAGE_SIZE);
		size = min(size - start + __early_bss_start(), size);
		kmalloc_bmap_add_default((void *)start, size);
	}

	start = __init_start();
	size = __init_size();

	if (size) {
		IMSG("Recycle .init @ 0x%lx, 0x%lx\n", start, size);

#if defined(CONFIG_MMU)
		unmap(kpt(), (void *)start, size);

		ret = map(kpt(), virt_to_phys(start), (void *)start, size, PG_RW);
		if (ret != 0)
			return ret;
#endif

		kmalloc_buddy_add_default((void *)start, size);
	}

	return 0;
}

void kmalloc_info(struct debugfs_file *d)
{
	debugfs_printf(d, "Buddy  Pools: %06d, Free 0x%08lx SingleAllocMax: 0x%lx\n",
			buddy()->nrpools, (long)buddy()->freesz, buddy_single_alloc_max());

	debugfs_printf(d, "Bitmap Pools: %06d, Free 0x%08lx SingleAllocMax: 0x%lx\n",
			bmap()->nrpools, (long)bmap()->freesz * BITMAP_NODE_SIZE,
			bmap_single_alloc_max());
}

strong_alias(kmalloc, malloc);
strong_alias(kfree, free);
