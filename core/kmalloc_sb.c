// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Slab + Buddy Allocator
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

/* pool type tag, stored at offset-0 of every pool-page header */
#define POOL_TYPE_BUDDY  (1)
#define POOL_TYPE_SLAB   (2)

#define BUDDY_NODE_SIZE  (64)

static unsigned long early_reserved[PAGE_SIZE/sizeof(long)]
	__section(".bss") __aligned(PAGE_SIZE);

#define SLAB_MAX_SIZE    (128)

static const unsigned short slab_sizes[] = {
	16, 32, 48, 64, 96, SLAB_MAX_SIZE
};

#define NR_SLAB_CLASSES  ARRAY_SIZE(slab_sizes)

/* shrink idle pools every 2 seconds */
#define SHRINK_INTERVAL_USECS  (2 * MICROSECS_PER_SEC)

/*
 * Warm reserve: keep at most this many completely-empty
 * partial pages per slab class.
 */
#define SLAB_MIN_PARTIAL  1

static void __shrink_pool(struct work *w);

struct kmalloc_buddy_desc {
	int nrpools;
	struct spinlock lock;
	size_t freesz;
	struct rb_node *rbroot;
};

struct kmalloc_buddy {
	unsigned short type;
	struct rb_node node;
	struct buddy_pool buddy;
};

struct kmalloc_slab {
	unsigned short type;
	unsigned short class_idx;
	unsigned short inuse;
	unsigned short total;
	void *freelist;
	struct list_head list;
};

/* read the pool type from a page-aligned pool address */
#define pool_typeof(pool) (*(unsigned short *)(pool))

/*
 * kfree()/kmalloc_sizeof() identify the pool type by reading
 * pool_typeof(ptr2pool(addr)), therefore 'type' must be the
 * first member of every pool-page header struct.
 */
_Static_assert(offsetof(struct kmalloc_buddy, type) == 0 &&
	offsetof(struct kmalloc_slab, type) == 0,
	"pool type must be at offset 0");

struct slab_class {
	struct spinlock lock;
	struct list_head partial;
	struct list_head full;
	unsigned short obj_size;
	unsigned int nr_partial;
	unsigned int nr_full;
	size_t freesz;
};

static struct kmalloc_buddy_desc _buddy;
static struct slab_class _slab_classes[NR_SLAB_CLASSES];

static DECLARE_DELAYED_WORK(_shrinkdw, __shrink_pool);

static inline struct kmalloc_buddy_desc *buddy(void)
{
	return &_buddy;
}

static inline void *ptr2pool(const void *ptr)
{
	return (void *)((uintptr_t)(ptr) & PAGE_MASK);
}

static inline int slab_classof(size_t size)
{
	if (size <= 16) return 0;
	if (size <= 32) return 1;
	if (size <= 48) return 2;
	if (size <= 64) return 3;
	if (size <= 96) return 4;
	return 5;
}

static inline long buddy_single_alloc_max(void)
{
	struct kmalloc_buddy_desc *d = buddy();
	struct kmalloc_buddy *p = NULL;

	p = rb_last_entry(d->rbroot, struct kmalloc_buddy, node);

	return (p && buddy_max_order(&p->buddy) != 0) ?
			1UL << buddy_max_order(&p->buddy) : 0;
}

static inline long slab_single_alloc_max(void)
{
	return SLAB_MAX_SIZE;
}

static struct kmalloc_buddy *kmalloc_buddy_deploy(
	void *start, size_t node_size)
{
	size_t mgr_size = 0;
	size_t struct_size = 0;
	struct kmalloc_buddy *p = NULL;

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

static struct kmalloc_slab *kmalloc_slab_deploy(void *start, int class_idx)
{
	struct kmalloc_slab *sp = start;
	unsigned short obj_size = slab_sizes[class_idx];
	unsigned int hdr_size = roundup(sizeof(struct kmalloc_slab), obj_size);
	unsigned int total = (PAGE_SIZE - hdr_size) / obj_size;
	char *base = (char *)start + hdr_size;
	int i = 0;

	sp->type = POOL_TYPE_SLAB;
	sp->class_idx = class_idx;
	sp->inuse = 0;
	sp->total = total;
	sp->freelist = NULL;
	INIT_LIST_HEAD(&sp->list);

	for (i = total - 1; i >= 0; i--) {
		void **obj = (void **)(base + i * obj_size);
		*obj = sp->freelist;
		sp->freelist = obj;
	}

	return sp;
}

static void kmalloc_slab_init(void)
{
	int i = 0;

	for (i = 0; i < NR_SLAB_CLASSES; i++) {
		struct slab_class *sc = &_slab_classes[i];

		INIT_LIST_HEAD(&sc->partial);
		INIT_LIST_HEAD(&sc->full);
		spin_lock_init(&sc->lock);
		sc->obj_size = slab_sizes[i];
		sc->nr_partial = 0;
		sc->nr_full = 0;
		sc->freesz = 0;
	}
}

/* alloc/deploy a buddy pool */
static void *kmalloc_buddy_pool_alloc(void)
{
	void *start = NULL;

	start = pages_alloc_continuous(PG_RW, 1);
	if (!start)
		return NULL;

	if (!kmalloc_buddy_deploy(start, BUDDY_NODE_SIZE)) {
		pages_free_continuous(start);
		return NULL;
	}

	return start;
}

#define BUDDY_RBKEY(b) (((unsigned int)buddy_max_order(b) << 16) + (b)->curr_size + 1)

static inline void __kmalloc_buddy_rbadd(
	struct kmalloc_buddy *p, struct rb_node **root)
{
	struct rb_node **ppn = root, *parent = NULL;
	struct kmalloc_buddy *tmp = NULL;
	unsigned int key = BUDDY_RBKEY(&p->buddy);

	while (*ppn) {
		parent = *ppn;

		tmp = rb_entry_of(parent, struct kmalloc_buddy, node);
		if (key < BUDDY_RBKEY(&tmp->buddy))
			ppn = &parent->left;
		else
			ppn = &parent->right;
	}

	rb_link_parent(&p->node, ppn, parent);
	rb_insert(&p->node, root);
}

/*
 * Re-sort a pool in the RB-tree when its key ordering
 * relative to its neighbor is actually violated.
 * alloc decreases the key (check predecessor),
 * free increases the key (check successor).
 */
static inline void __kmalloc_buddy_rb_resort(
	struct kmalloc_buddy *p, unsigned int old_key,
	struct rb_node **root)
{
	unsigned int new_key = BUDDY_RBKEY(&p->buddy);
	struct rb_node *n = NULL;

	if (new_key < old_key) {
		n = rb_prev(&p->node);
		if (n && new_key < BUDDY_RBKEY(
				&rb_entry_of(n, struct kmalloc_buddy,
				node)->buddy)) {
			rb_del(&p->node, root);
			__kmalloc_buddy_rbadd(p, root);
		}
	} else if (new_key > old_key) {
		n = rb_next(&p->node);
		if (n && new_key > BUDDY_RBKEY(
				&rb_entry_of(n, struct kmalloc_buddy,
				node)->buddy)) {
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
	unsigned long flags = 0;
	struct kmalloc_buddy *p = NULL;
	struct kmalloc_slab *sp = NULL;

	if (!addr)
		return 0;

	if (((uintptr_t)addr & ~PAGE_MASK) == 0) {
		size = pages_sizeof(virt_to_page(addr));
		return size << PAGE_SHIFT;
	}

	switch (pool_typeof(ptr2pool(addr))) {
	case POOL_TYPE_BUDDY:
		p = ptr2pool(addr);
		spin_lock_irqsave(&buddy()->lock, flags);
		size = buddy_sizeof(&p->buddy, addr);
		spin_unlock_irqrestore(&buddy()->lock, flags);
		break;
	case POOL_TYPE_SLAB:
		sp = ptr2pool(addr);
		size = slab_sizes[sp->class_idx];
		break;
	default:
		break;
	}

	return size;
}

static size_t __shrink_buddy_pool(void)
{
	unsigned long flags = 0, num = 0;
	struct kmalloc_buddy_desc *d = buddy();
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

		pages_free_continuous(idle);
	} while (idle);

	return num;
}

static size_t __shrink_slab_pool(void)
{
	unsigned long flags = 0, num = 0;
	int i = 0;

	for (i = 0; i < NR_SLAB_CLASSES; i++) {
		struct slab_class *sc = &_slab_classes[i];
		struct kmalloc_slab *idle = NULL;

		do {
			struct kmalloc_slab *sp = NULL;

			idle = NULL;

			if (sc->nr_partial <= SLAB_MIN_PARTIAL)
				break;

			spin_lock_irqsave(&sc->lock, flags);

			if (sc->nr_partial > SLAB_MIN_PARTIAL) {
				sp = list_last_entry(&sc->partial,
						struct kmalloc_slab, list);
				if (sp->inuse == 0) {
					list_del(&sp->list);
					sc->nr_partial--;
					sc->freesz -= sp->total;
					idle = sp;
					num++;
				}
			}

			spin_unlock_irqrestore(&sc->lock, flags);

			pages_free_continuous(idle);
		} while (idle);
	}

	return num;
}

static void __shrink_pool(struct work *w)
{
	struct delayed_work *dw = container_of(w, struct delayed_work, w);

	__shrink_buddy_pool();
	__shrink_slab_pool();

	__schedule_delayed_work(dw, SHRINK_INTERVAL_USECS);
}

size_t kmalloc_release(unsigned int usecs)
{
	size_t num = 0;

	if (usecs == 0) {
		num += __shrink_buddy_pool();
		num += __shrink_slab_pool();
	} else {
		__mod_delayed_work(&_shrinkdw, usecs);
	}

	return num;
}

static void *kmalloc_buddy(size_t size)
{
	unsigned int order = 0;
	unsigned int old_key = 0;
	void *addr = NULL;
	unsigned long flags = 0;
	struct kmalloc_buddy_desc *d = buddy();
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
		old_key = BUDDY_RBKEY(&p->buddy);
		addr = buddy_alloc_order(&p->buddy, order);
		d->freesz -= 1UL << max(order, (unsigned int)p->buddy.node_order);
		__kmalloc_buddy_rb_resort(p, old_key, &d->rbroot);
	}

	spin_unlock_irqrestore(&d->lock, flags);

	if (!addr && (order < PAGE_SHIFT)) {
		p = kmalloc_buddy_pool_alloc();
		if (p) {
			spin_lock_irqsave(&d->lock, flags);
			__kmalloc_buddy_rbadd(p, &d->rbroot);
			d->nrpools++;
			d->freesz += p->buddy.curr_size;
			goto again;
		}
	}

	return addr;
}

static void kfree_buddy(struct kmalloc_buddy *p,
	const void *addr)
{
	unsigned long flags = 0;
	unsigned int old_key = 0;
	struct kmalloc_buddy_desc *d = buddy();

	spin_lock_irqsave(&d->lock, flags);
	old_key = BUDDY_RBKEY(&p->buddy);
	d->freesz += buddy_free(&p->buddy, addr);
	__kmalloc_buddy_rb_resort(p, old_key, &d->rbroot);
	spin_unlock_irqrestore(&d->lock, flags);
}

static void *kmalloc_slab(int class_idx)
{
	struct slab_class *sc = &_slab_classes[class_idx];
	struct kmalloc_slab *sp = NULL;
	void *start = NULL, *obj = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&sc->lock, flags);

	if (list_empty(&sc->partial)) {
		spin_unlock_irqrestore(&sc->lock, flags);

		start = pages_alloc_continuous(PG_RW, 1);
		if (!start)
			return NULL;

		sp = kmalloc_slab_deploy(start, class_idx);

		spin_lock_irqsave(&sc->lock, flags);
		list_add(&sp->list, &sc->partial);
		sc->nr_partial++;
		sc->freesz += sp->total;
	}

	sp = list_first_entry(&sc->partial, struct kmalloc_slab, list);

	obj = sp->freelist;
	sp->freelist = *(void **)obj;
	sp->inuse++;
	sc->freesz--;

	if (sp->inuse == sp->total) {
		list_move(&sp->list, &sc->full);
		sc->nr_partial--;
		sc->nr_full++;
	}

	spin_unlock_irqrestore(&sc->lock, flags);

	return obj;
}

/*
 * Slab free: return object, move between full/partial.
 * Partial list sorted by occupancy: fullest at head, sparsest at tail.
 * Empty slabs reclaimed immediately when enough spares remain.
 */
static void kfree_slab(const void *addr)
{
	struct kmalloc_slab *sp = ptr2pool(addr);
	struct slab_class *sc = &_slab_classes[sp->class_idx];
	unsigned long flags = 0;
	bool was_full = false;
	bool do_free = false;
	void *obj = (void *)addr;

	spin_lock_irqsave(&sc->lock, flags);

	was_full = (sp->inuse == sp->total);

	*(void **)obj = sp->freelist;
	sp->freelist = obj;
	sp->inuse--;
	sc->freesz++;

	if (was_full) {
		/* Was full, now has 1 free slot - move to partial head (fullest) */
		list_move(&sp->list, &sc->partial);
		sc->nr_full--;
		sc->nr_partial++;
	} else if (sp->inuse == 0) {
		/* Empty - reclaim immediately if enough spare pages remain */
		if (sc->nr_partial > SLAB_MIN_PARTIAL) {
			list_del(&sp->list);
			sc->nr_partial--;
			sc->freesz -= sp->total;
			do_free = true;
		} else {
			list_move_tail(&sp->list, &sc->partial);
		}
	} else if (sp->inuse * 2 < sp->total) {
		/* Below half-full: demote to tail to favor fuller pages */
		list_move_tail(&sp->list, &sc->partial);
	}

	spin_unlock_irqrestore(&sc->lock, flags);

	if (do_free)
		pages_free_continuous(sp);
}

/*
 * allocate from the slab / buddy / page pools
 */
void *kmalloc(size_t size)
{
	void *addr = NULL;
	size_t alignedsize = 0;

	if (size == 0)
		return NULL;

	if (size <= SLAB_MAX_SIZE) {
		addr = kmalloc_slab(slab_classof(size));
		if (addr)
			return addr;
	}

	alignedsize = roundup2pow(size);

	if (alignedsize >= PAGE_SIZE) {
		addr = pages_alloc_continuous(PG_RW,
				alignedsize >> PAGE_SHIFT);
	} else {
		addr = kmalloc_buddy(alignedsize);
	}

	if (!addr)
		LMSG("alloc failed %ld\n", (long)size);

	return addr;
}

void kfree(const void *addr)
{
	if (!addr)
		return;

	if (((uintptr_t)addr & ~PAGE_MASK) == 0) {
		pages_free_continuous((void *)addr);
		return;
	}

	switch (pool_typeof(ptr2pool(addr))) {
	case POOL_TYPE_BUDDY:
		kfree_buddy(ptr2pool(addr), addr);
		break;
	case POOL_TYPE_SLAB:
		kfree_slab(addr);
		break;
	default:
		break;
	}
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
	size_t total = 0;
	void *addr = NULL;

	if (n != 0 && size > (size_t)-1 / n)
		return NULL;

	total = n * size;
	addr = kmalloc(total);

	if (addr)
		memset(addr, 0, total);

	return addr;
}

void *krealloc(void *oldp, size_t size)
{
	size_t oldsize = 0;
	void *newp = NULL;

	if (!oldp)
		return kmalloc(size);

	if (size == 0) {
		kfree(oldp);
		return NULL;
	}

	oldsize = kmalloc_sizeof(oldp);
	if (oldsize == 0)
		return NULL;

	DMSG("%p nsz:0x%lx osz:0x%lx\n", oldp,
		 (long)size, (long)oldsize);

	if (size <= oldsize)
		return oldp;

	newp = kmalloc(size);
	if (!newp)
		return NULL;

	memcpy(newp, oldp, oldsize);

	kfree(oldp);

	return newp;
}

static void kmalloc_buddy_add_default(void *start, size_t size)
{
	int i = 0;
	struct kmalloc_buddy *p = NULL;
	struct kmalloc_buddy_desc *d = buddy();
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

int __init kmalloc_early_init(void)
{
	/*
	 * a small static pool, located @ bss
	 */
	void *start = early_reserved;
	size_t size = sizeof(early_reserved);

	kmalloc_slab_init();
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

	ret = __schedule_delayed_work(&_shrinkdw, SHRINK_INTERVAL_USECS);

	assert(ret);

	if (size != 0) {
		IMSG("Recycle .bss.early @ 0x%lx, 0x%lx\n", start, size);
		start = roundup(start, PAGE_SIZE);
		size = min(size - start + __early_bss_start(), size);
		kmalloc_buddy_add_default((void *)start, size);
	}

	start = __init_start();
	size = __init_size();

	if (size != 0) {
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
	int i = 0;
	size_t slab_free_total = 0;
	unsigned int slab_nr_pages = 0;

	debugfs_printf(d, "Buddy Pools: %06d, Free 0x%08lx SingleAllocMax: 0x%lx\n",
			buddy()->nrpools, (long)buddy()->freesz, buddy_single_alloc_max());

	for (i = 0; i < NR_SLAB_CLASSES; i++) {
		struct slab_class *sc = &_slab_classes[i];

		slab_free_total += sc->freesz * sc->obj_size;
		slab_nr_pages += sc->nr_partial + sc->nr_full;
	}

	debugfs_printf(d, "Slab  Pools: %06d, Free 0x%08lx SingleAllocMax: 0x%lx\n",
			slab_nr_pages, (long)slab_free_total, slab_single_alloc_max());
}

strong_alias(kmalloc, malloc);
strong_alias(kfree, free);
strong_alias(kcalloc, calloc);
strong_alias(krealloc, realloc);
