// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * page operations
 */

#include <trace.h>
#include <spinlock.h>
#include <kmalloc.h>
#include <kmath.h>
#include <page.h>
#include <buddy.h>
#include <device.h>
#include <errno.h>
#include <thread.h>

static LIST_HEAD(pools);

struct page_pool {
	struct list_head node;
	unsigned long pa;
	size_t size;
	struct page *pages;
	struct buddy_pool buddy;
	struct spinlock lock;
};

int page_pool_add(unsigned long pa, unsigned long size)
{
	int ret = -ENOMEM;
	void *mgr = NULL;
	struct page *pages = NULL;
	size_t n = 0, nr_pages = 0, mgrsize = 0;
	size_t structsz = sizeof(struct page);
	struct page_pool *pool = NULL;

	if (size <= PAGE_SIZE)
		return 0;

	if (pa & ~PAGE_MASK)
		return -EINVAL;

	pool = kzalloc(sizeof(struct page_pool));
	if (!pool)
		return -ENOMEM;

	nr_pages = size >> PAGE_SHIFT;
	n = roundup2pow(nr_pages);

	/*
	 * | pages | mgr |
	 * |   PA-RESVD  |  PA-pages-for-allocation  |
	 */
	pages = phys_to_virt(pa);
	mgr = pages + nr_pages;

	memset(pages, 0, structsz * nr_pages);

	ret = buddy_init(&pool->buddy, pages - (n - nr_pages),
				structsz * n, mgr, structsz);
	if (ret != 0)
		goto out;

	mgrsize = (nr_pages * structsz) + buddy_mgs(structsz * n, structsz);
	mgrsize = roundup(mgrsize, PAGE_SIZE) >> PAGE_SHIFT;
	buddy_reserve(&pool->buddy, (n - nr_pages + mgrsize) * structsz);

	pool->pa = pa;
	pool->size = size;
	pool->pages = pages;
	spin_lock_init(&pool->lock);
	list_add_tail(&pool->node, &pools);

	return 0;

out:
	kfree(pool);
	return ret;
}

unsigned long page_to_phys(struct page *p)
{
	struct page_pool *pool = NULL;
	size_t nr_pages = 0;
	size_t idx = 0;

	list_for_each_entry(pool, &pools, node) {
		nr_pages = pool->size >> PAGE_SHIFT;
		if (p < pool->pages)
			continue;

		idx = p - pool->pages;
		if (idx < nr_pages)
			return pool->pa + ((unsigned long)idx << PAGE_SHIFT);
	}

	EMSG("page %p\n", p);
	assert(0);
	return 0;
}

struct page *phys_to_page(unsigned long pa)
{
	struct page_pool *pool = NULL;
	unsigned long offset = 0;

	list_for_each_entry(pool, &pools, node) {
		if (pa < pool->pa)
			continue;

		offset = pa - pool->pa;
		if (offset < pool->size)
			return pool->pages + (offset >> PAGE_SHIFT);
	}

	EMSG("pa %lx\n", pa);
	assert(0);
	return NULL;
}

/*
 * get the kernel virtual address of page
 */
void *page_address(struct page *p)
{
	if (p && atomic_read(&p->refc) != 0)
		return phys_to_virt(page_to_phys(p));

	return NULL;
}

static struct page_pool *find_page_pool(struct page *p)
{
	struct page_pool *pool = NULL;
	struct buddy_pool *buddy = NULL;

	list_for_each_entry(pool, &pools, node) {
		buddy = &pool->buddy;
		if ((void *)p >= buddy->start &&
			(void *)p < buddy->start + (1ul << buddy->order))
			return pool;
	}

	return NULL;
}

/*
 * return the num of pages held by 'p' (aligned power of 2)
 */
size_t pages_sizeof(struct page *p)
{
	size_t num = 0;
	struct page_pool *pool = NULL;
	unsigned long flags = 0;

	if (p) {
		if (atomic_read(&p->refc) <= 0)
			EMSG("%p refc error %d\n", p, atomic_read(&p->refc));

		assert(atomic_read(&p->refc) > 0);

		pool = find_page_pool(p);
		if (pool) {
			spin_lock_irqsave(&pool->lock, flags);
			num = buddy_sizeof(&pool->buddy, p) / sizeof(struct page);
			spin_unlock_irqrestore(&pool->lock, flags);
		}
	}

	return num;
}

/*
 * allocate 'num' of continuous pages
 * return the first page struct.
 */
static struct page *pages_alloc(unsigned long num)
{
	struct page *p = NULL;
	struct page_pool *pool = NULL;
	unsigned long lflags = 0;

again:
	list_for_each_entry(pool, &pools, node) {
		spin_lock_irqsave(&pool->lock, lflags);
		p = buddy_alloc(&pool->buddy, num * sizeof(struct page));
		spin_unlock_irqrestore(&pool->lock, lflags);
		if (p) {
			if (atomic_read(&p->refc) != 0)
				EMSG("%p refc error %d\n", p, atomic_read(&p->refc));
			assert(atomic_read(&p->refc) == 0);
			atomic_set(&p->refc, 1);
			break;
		}
	}

	if (!p && (kmalloc_release(0) >= num))
		goto again;

	return p;
}

/*
 * free all the pages which start from p
 */
static void pages_free(struct page *p)
{
	struct page_pool *pool = NULL;
	unsigned long flags = 0;

	if (p) {
		if (atomic_read(&p->refc) <= 0)
			EMSG("%p refc error %d\n", p, atomic_read(&p->refc));

		assert(atomic_read(&p->refc) > 0);

		pool = find_page_pool(p);
		assert(pool != NULL);

		if (atomic_sub_return(&p->refc, 1) == 0) {
			spin_lock_irqsave(&pool->lock, flags);
			buddy_free(&pool->buddy, p);
			spin_unlock_irqrestore(&pool->lock, flags);
		}
	}
}

/*
 * allocate one page
 */
struct page *page_alloc(void)
{
	return pages_alloc(1);
}

/*
 * allocate batch pages.
 * reduce lock operations by trying multiple buddy allocs
 * while holding the same pool lock.
 */
int pages_batch_alloc(struct page **pages, size_t num)
{
	int ret = -ENOMEM;
	size_t i = 0, cnt = 0;
	unsigned long lflags = 0;
	struct page *p = NULL;
	struct page_pool *pool = NULL;

again:
	list_for_each_entry(pool, &pools, node) {
		spin_lock_irqsave(&pool->lock, lflags);
		while (cnt < num) {
			p = buddy_alloc(&pool->buddy, sizeof(struct page));
			if (!p)
				break;
			atomic_set(&p->refc, 1);
			pages[cnt++] = p;
		}
		spin_unlock_irqrestore(&pool->lock, lflags);

		if (cnt == num)
			return 0;
	}

	if ((cnt < num) && (kmalloc_release(0) >= (num - cnt)))
		goto again;

	for (i = 0; i < cnt; i++) {
		pages_free(pages[i]);
		pages[i] = NULL;
	}

	return ret;
}

/*
 * free one page
 */
void page_free(struct page *p)
{
	pages_free(p);
}

/*
 * increase the page reference count
 */
void page_get(struct page *p)
{
	atomic_inc(&p->refc);
}

/*
 * decrease the page reference count
 * free it if reference count equal to zero
 */
void page_put(struct page *p)
{
	pages_free(p);
}

/*
 * allocate 'num' of contiguous pages, 'num' shall be power of 2
 * return the kernel virtual address
 */
void *pages_alloc_continuous(unsigned long flags, unsigned long num)
{
	void *va = NULL;
	struct page *p = NULL;

	if (num == 0 || flags == 0)
		return NULL;

	p = pages_alloc(roundup2pow(num));
	if (!p)
		return NULL;

	va = phys_to_virt(page_to_phys(p));

	if (flags & PG_ZERO)
		memset(va, 0, num << PAGE_SHIFT);

	return va;
}

/*
 * free contiguous pages, start from 'va'
 */
void pages_free_continuous(void *va)
{
	if (va) {
		struct page *p = phys_to_page(virt_to_phys(va));

		pages_free(p);
	}
}

size_t nr_free_pages(void)
{
	size_t nrpages = 0;
	struct page_pool *pool = NULL;

	/*
	 * make sure the stores to "pool->buddy" is done
	 */
	smp_rmb();

	list_for_each_entry(pool, &pools, node)
		nrpages += pool->buddy.curr_size >> pool->buddy.node_order;

	return nrpages;
}

size_t nr_continuous_free_pages(void)
{
	int max = 0;
	size_t nrpages = 0, ret = 0;
	struct page_pool *pool = NULL;

	/*
	 * make sure the stores to "pool->buddy" is done
	 */
	smp_rmb();

	list_for_each_entry(pool, &pools, node) {
		max = buddy_max_order(&pool->buddy);
		if (max != 0) {
			nrpages = 1UL << (max - pool->buddy.node_order);
			if (nrpages > ret)
				ret = nrpages;
		}
	}

	return ret;
}

void page_info(struct debugfs_file *d)
{
	struct page_pool *pool = NULL;
	struct buddy_pool *buddy = NULL;
	unsigned int i = 0, max = 0, shift = 0;

	list_for_each_entry(pool, &pools, node) {
		buddy = &pool->buddy;
		shift = buddy->node_order;

		debugfs_printf(d, "\npage pool %d info: size 0x%lx\n",
			i++, (unsigned long)pool->size);
		debugfs_printf(d, "page phys: 0x%lx, va: %p\n",
			pool->pa, phys_to_virt(pool->pa));

		max = buddy_max_order(buddy);
		debugfs_printf(d, "page cnt: %ld/%ld (singleAllocMax: %ld)\n",
			(unsigned long)buddy->curr_size >> shift,
			(unsigned long)pool->size >> PAGE_SHIFT,
			max ? (1UL << (max - shift)) : 0UL);

		debugfs_printf(d, "\n");
	}
}
