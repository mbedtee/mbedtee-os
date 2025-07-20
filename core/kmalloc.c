// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Pure Slab Allocator (O(1) Multi-list approach)
 */

#include <mem.h>
#include <errno.h>
#include <trace.h>
#include <kproc.h>
#include <device.h>
#include <string.h>
#include <kmalloc.h>
#include <timer.h>
#include <spinlock.h>
#include <tasklet.h>
#include <list.h>
#include <page.h>
#include <kmath.h>
#include <workqueue.h>
#include <bitops.h>

#define POOL_TYPE_SLAB    (1)
#define POOL_FLAG_STATIC  (1 << 15)

#define pool_is_slab(sp)   (((sp)->type & ~POOL_FLAG_STATIC) == POOL_TYPE_SLAB)
#define pool_is_static(sp) ((sp)->type & POOL_FLAG_STATIC)

/* Define slab classes up to 1024 */
#define SLAB_MAX_SIZE    (1024)
static const unsigned short slab_sizes[] = {
	16, 32, 48, 64, 96, 128, 192, 256, 384, 512, SLAB_MAX_SIZE
};

#define NR_SLAB_CLASSES        ARRAY_SIZE(slab_sizes)
#define NR_SLAB_RECYCLE_CLASSES 8  /* classes <= 256, for recycled .init/.bss.early */
#define NR_SLAB_EARLY_PAGES  8 /* pre-reserved for early boot */
static long early_reserved[(NR_SLAB_EARLY_PAGES * PAGE_SIZE)/sizeof(long)]
	__section(".bss") __aligned(PAGE_SIZE);

#define SHRINK_INTERVAL_USECS  (2 * MICROSECS_PER_SEC)
#define SLAB_MIN_PARTIAL  1

struct kmalloc_slab {
	unsigned short type;       /* POOL_TYPE_SLAB | optional POOL_FLAG_STATIC */
	unsigned short class_idx;
	unsigned short inuse;
	unsigned short total;
	void *freelist;
	struct list_head list;
};

struct slab_class {
	struct spinlock lock;
	struct list_head partial;
	struct list_head full;
	unsigned short obj_size;
	unsigned int nr_partial;
	unsigned int nr_full;
	size_t freesz;
};

static struct slab_class _slab_classes[NR_SLAB_CLASSES];
static void __shrink_pool(struct work *w);
static DECLARE_DELAYED_WORK(_shrinkdw, __shrink_pool);

static inline void *ptr2pool(const void *ptr)
{
	return (void *)((uintptr_t)(ptr) & PAGE_MASK);
}

static inline int slab_classof(size_t size)
{
	/*
	 * Map ceiling(size/16) index -> slab class index.
	 * slab_sizes[] = {16,32,48,64,96,128,192,256,384,512,1024}
	 * idx = ceil(size/16) = (size + 15) >> 4
	 * idx range: [1..64] covers sizes [1..1024].
	 */
	static const uint8_t class_map[65] = {
		[0]       = 0,  /* size==0: class 0 (16B) */
		[1]       = 0,  /* 1..16   -> class 0 (16B)  */
		[2]       = 1,  /* 17..32  -> class 1 (32B)  */
		[3]       = 2,  /* 33..48  -> class 2 (48B)  */
		[4]       = 3,  /* 49..64  -> class 3 (64B)  */
		[5]  = 4, [6]  = 4,  /* 65..96  -> class 4 (96B)  */
		[7]  = 5, [8]  = 5,  /* 97..128 -> class 5 (128B) */
		[9]  = 6, [10] = 6, [11] = 6, [12] = 6, /* 129..192 -> class 6 (192B) */
		[13] = 7, [14] = 7, [15] = 7, [16] = 7, /* 193..256 -> class 7 (256B) */
		[17] = 8, [18] = 8, [19] = 8, [20] = 8, /* 257..320 -> class 8 (384B) */
		[21] = 8, [22] = 8, [23] = 8, [24] = 8, /* 321..384 -> class 8 (384B) */
		[25] = 9, [26] = 9, [27] = 9, [28] = 9, /* 385..448 -> class 9 (512B) */
		[29] = 9, [30] = 9, [31] = 9, [32] = 9, /* 449..512 -> class 9 (512B) */
		[33] = 10, [34] = 10, [35] = 10, [36] = 10, /* 513..576 -> class 10 (1024B) */
		[37] = 10, [38] = 10, [39] = 10, [40] = 10,
		[41] = 10, [42] = 10, [43] = 10, [44] = 10,
		[45] = 10, [46] = 10, [47] = 10, [48] = 10,
		[49] = 10, [50] = 10, [51] = 10, [52] = 10,
		[53] = 10, [54] = 10, [55] = 10, [56] = 10,
		[57] = 10, [58] = 10, [59] = 10, [60] = 10,
		[61] = 10, [62] = 10, [63] = 10, [64] = 10, /* ..1024 -> class 10 (1024B) */
	};
	unsigned int idx = (unsigned int)((size + 15) >> 4);

	if (likely(idx <= 64))
		return class_map[idx];
	return 11;
}

static inline long slab_single_alloc_max(void)
{
	return SLAB_MAX_SIZE;
}

static struct kmalloc_slab *kmalloc_slab_deploy(void *start, int class_idx, bool is_static)
{
	struct kmalloc_slab *sp = start;
	unsigned short obj_size = slab_sizes[class_idx];
	unsigned int hdr_size = roundup(sizeof(struct kmalloc_slab), obj_size);
	unsigned int total = (PAGE_SIZE - hdr_size) / obj_size;
	char *base = (char *)start + hdr_size;
	int i = 0;

	sp->type = POOL_TYPE_SLAB | (is_static ? POOL_FLAG_STATIC : 0);
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

static size_t kmalloc_sizeof(void *addr)
{
	struct kmalloc_slab *sp = NULL;
	size_t size = 0;

	if (!addr)
		return 0;

	if (((uintptr_t)addr & ~PAGE_MASK) == 0) {
		size = pages_sizeof(virt_to_page(addr));
		return size << PAGE_SHIFT;
	}

	sp = ptr2pool(addr);
	if (pool_is_slab(sp))
		size = slab_sizes[sp->class_idx];

	return size;
}

static size_t __shrink_slab_pool(void)
{
	unsigned long flags = 0, num = 0;
	int i = 0;

	for (i = 0; i < NR_SLAB_CLASSES; i++) {
		struct slab_class *sc = &_slab_classes[i];
		struct kmalloc_slab *idle = NULL;

		do {
			struct kmalloc_slab *sp = NULL, *tmp = NULL;

			idle = NULL;

			if (sc->nr_partial <= SLAB_MIN_PARTIAL)
				break;

			spin_lock_irqsave(&sc->lock, flags);

			list_for_each_entry_safe(sp, tmp, &sc->partial, list) {
				if (sp->inuse == 0 && sc->nr_partial > SLAB_MIN_PARTIAL) {
					/* Do not free static memory back to page allocator */
					if (pool_is_static(sp))
						continue;

					list_del(&sp->list);
					sc->nr_partial--;
					sc->freesz -= sp->total;
					idle = sp;
					num++;
					break;
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

	__shrink_slab_pool();

	__schedule_delayed_work(dw, SHRINK_INTERVAL_USECS);
}

size_t kmalloc_release(unsigned int usecs)
{
	size_t num = 0;

	if (usecs == 0)
		num += __shrink_slab_pool();
	else
		__mod_delayed_work(&_shrinkdw, usecs);

	return num;
}

struct kmalloc_slab *kmalloc_slab_expand(int class_idx)
{
	int i = 0;
	void *heappage = NULL, *n = early_reserved;
	static bool reserved_done = false;
	static struct spinlock early_l = {{0}};
	unsigned long flags = 0;
	struct kmalloc_slab *ks = NULL;

	while (!reserved_done && (i < NR_SLAB_EARLY_PAGES)) {
		spin_lock_irqsave(&early_l, flags);

		if (*(long *)n == 0)
			ks = kmalloc_slab_deploy(n, class_idx, true);

		n += PAGE_SIZE;
		if (++i == NR_SLAB_EARLY_PAGES)
			reserved_done = true;

		spin_unlock_irqrestore(&early_l, flags);

		if (ks)
			return ks;
	}

	heappage = pages_alloc_continuous(PG_RW, 1);
	if (!heappage)
		return NULL;

	return kmalloc_slab_deploy(heappage, class_idx, false);
}

static void *kmalloc_slab(int class_idx)
{
	struct slab_class *sc = &_slab_classes[class_idx];
	struct kmalloc_slab *sp = NULL;
	void *obj = NULL;
	unsigned long flags = 0;

	spin_lock_irqsave(&sc->lock, flags);

	if (list_empty(&sc->partial)) {
		spin_unlock_irqrestore(&sc->lock, flags);

		sp = kmalloc_slab_expand(class_idx);
		if (!sp)
			return NULL;

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
		if (!pool_is_static(sp) && sc->nr_partial > SLAB_MIN_PARTIAL) {
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

	/* Fallback to page allocator for large sizes or slab exhaustion */
	alignedsize = roundup(size, PAGE_SIZE);
	addr = pages_alloc_continuous(PG_RW, alignedsize >> PAGE_SHIFT);

	if (!addr)
		LMSG("alloc failed %ld\n", (long)size);

	return addr;
}

void kfree(const void *addr)
{
	struct kmalloc_slab *sp = NULL;

	if (!addr)
		return;

	if (((uintptr_t)addr & ~PAGE_MASK) == 0) {
		pages_free_continuous((void *)addr);
		return;
	}

	sp = ptr2pool(addr);
	if (pool_is_slab(sp)) {
		kfree_slab(addr);
	} else {
		EMSG("invalid kfree %p type %x\n", addr, sp->type);
		backtrace();
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

static void kmalloc_slab_add_default(void *start, size_t size, int nr_classes)
{
	int i = 0;
	struct kmalloc_slab *sp = NULL;
	struct slab_class *sc = NULL;
	unsigned long flags = 0;
	void *end = start + size;
	int class_idx = 0;

	for (i = 2; start < end; i++) {
		/*
		 * Distribute pages across slab classes round-robin.
		 * For early_reserved (NR_SLAB_CLASSES pages), every class gets 1 page.
		 * For recycled regions, only small classes are used to avoid waste.
		 */
		class_idx = i % nr_classes;
		sc = &_slab_classes[class_idx];

		spin_lock_irqsave(&sc->lock, flags);
		sp = kmalloc_slab_deploy(start, class_idx, true);
		list_add(&sp->list, &sc->partial);
		sc->nr_partial++;
		sc->freesz += sp->total;
		spin_unlock_irqrestore(&sc->lock, flags);

		start += PAGE_SIZE;
	}
}

int __init kmalloc_early_init(void)
{
	kmalloc_slab_init();
	return 0;
}

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
		kmalloc_slab_add_default((void *)start, size, NR_SLAB_RECYCLE_CLASSES);
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

		kmalloc_slab_add_default((void *)start, size, NR_SLAB_RECYCLE_CLASSES);
	}

	return 0;
}

void kmalloc_info(struct debugfs_file *d)
{
	int i = 0;
	size_t slab_free_total = 0;
	unsigned int slab_nr_pages = 0;

	for (i = 0; i < NR_SLAB_CLASSES; i++) {
		struct slab_class *sc = &_slab_classes[i];

		slab_free_total += sc->freesz * sc->obj_size;
		slab_nr_pages += sc->nr_partial + sc->nr_full;
	}

	debugfs_printf(d, "Slab Pools: %06d, Free 0x%08lx SingleAllocMax: 0x%lx\n",
			slab_nr_pages, (long)slab_free_total, slab_single_alloc_max());
}

strong_alias(kmalloc, malloc);
strong_alias(kfree, free);
strong_alias(kcalloc, calloc);
strong_alias(krealloc, realloc);