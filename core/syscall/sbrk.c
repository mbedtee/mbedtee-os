// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * responds to the _sbrk() system call to resize the libc heap
 */

#include <trace.h>
#include <string.h>
#include <kmalloc.h>
#include <page.h>
#include <page_scatter.h>
#include <mmu.h>
#include <mem.h>
#include <errno.h>
#include <spinlock.h>
#include <thread.h>

static void sbrk_pages_free(struct list_head *head,
	unsigned long va, unsigned long size, void *pt)
{
	unsigned long nr_pages = size >> PAGE_SHIFT;

	if (list_empty(head) || (nr_pages == 0))
		return;

	pages_list_unmap(head, pt, (void *)va, nr_pages);
	pages_list_free(head, nr_pages);
}

static int sbrk_pages_alloc(struct list_head *head,
	unsigned long va, unsigned long size, void *pt)
{
	int ret = 0;
	size_t nr_pages = size >> PAGE_SHIFT;
	struct list_head *curr = head->prev;

	ret = pages_list_alloc(head, nr_pages);
	if (ret != 0)
		return ret;

	ret = pages_list_map(curr, pt, (void *)va, nr_pages, PG_RW);
	if (ret != 0)
		pages_list_free(head, nr_pages);

	return ret;
}

int sbrk_init(struct process *proc)
{
	if ((!proc) || (!proc->c->heap_size))
		return -EINVAL;

	INIT_LIST_HEAD(&proc->heap_pages);
	proc->heap_residue = 0;
	proc->heap_current = USER_HEAP_VA(proc);

	return 0;
}

long sbrk_incr(long incr)
{
	long ret = -EINVAL;
	long size = 0, algnsize = 0;
	struct process *p = current->proc;

	if (!p)
		return -ENOENT;

	if (incr == 0)
		return p->heap_current;

	mutex_lock(&p->mlock);

	if (incr > 0) {
		if ((p->heap_current - USER_HEAP_VA(p) + incr) >
				min(p->c->heap_size, USER_HEAP_SIZE)) {
			EMSG("heap size limitation for %s - 0x%lx\n",
				p->c->name, (long)p->c->heap_size);
			ret = -ENOMEM;
			goto out;
		}

		if (p->heap_residue >= incr) {
			p->heap_residue -= incr;
		} else {
			size = incr - p->heap_residue;
			algnsize = roundup(size, PAGE_SIZE);
			ret = sbrk_pages_alloc(&p->heap_pages,
				p->heap_current + p->heap_residue, algnsize, p->pt);
			if (ret != 0)
				goto out;
			p->heap_residue = algnsize - size;
		}
	} else {
		DMSG("incr = -0x%lx\n", -incr);

		size = -incr + p->heap_residue;
		algnsize = rounddown(size, PAGE_SIZE);
		sbrk_pages_free(&p->heap_pages,
				p->heap_current + p->heap_residue - algnsize,
				algnsize, p->pt);

		p->heap_residue = size - algnsize;
	}

	ret = p->heap_current;
	p->heap_current += incr;

out:
	mutex_unlock(&p->mlock);
	return ret;
}

static void sbrk_destroy(struct process *p)
{
	if (!p || !p->heap_current)
		return;

	/* free all the heap pages */
	sbrk_pages_free(&p->heap_pages, USER_HEAP_VA(p),
		p->heap_current + p->heap_residue - USER_HEAP_VA(p), p->pt);
	struct scatter_page *sp = NULL;

	list_for_each_entry(sp, &p->heap_pages, node) {
		IMSG("pid%d %p, pos:%lx residue %lx\n", p->id, sp,
			p->heap_current, p->heap_residue);
	}

	assert(list_empty(&p->heap_pages));

	p->heap_residue = 0;
	p->heap_current = 0;
}
DECLARE_CLEANUP(sbrk_destroy);
