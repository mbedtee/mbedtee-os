// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * GlobalPlatform ShareMemory
 */

#include <sched.h>
#include <thread.h>
#include <mmu.h>
#include <kmalloc.h>
#include <vma.h>
#include <trace.h>
#include <prng.h>

#include <rpc_callee.h>

static LIST_HEAD(rpc_gpshms);
static DECLARE_SEMA(shms_sema, 1);

struct rpc_gpshm {
	uint64_t id;
	size_t cnt;
	off_t offset;
	unsigned long *pages;
	void *va;
	int refc;
	struct process *proc;
	struct list_head node;
};

static inline void rpc_gpshm_lock(void)
{
	down(&shms_sema);
}

static inline void rpc_gpshm_unlock(void)
{
	up(&shms_sema);
}

static struct rpc_gpshm *rpc_gpshm_of(uint64_t id)
{
	struct rpc_gpshm *n = NULL, *ret = NULL;

	if (id == 0)
		return NULL;

	list_for_each_entry(n, &rpc_gpshms, node) {
		if (n->id == id) {
			ret = n;
			break;
		}
	}
	return ret;
}

static void rpc_gpshm_free(struct rpc_gpshm *n)
{
	list_del(&n->node);
	kfree(n->pages);
	kfree(n);
}

static uint64_t rpc_shmid_get(void)
{
	uint64_t id = 0;

	do {
		prng(&id, sizeof(id));
		id <<= 16;
		id |= current_id;
	} while (rpc_gpshm_of(id) != NULL);

	return id;
}

int rpc_gpshm_register(struct rpc_memref *mr)
{
	int ret = -1, i = 0;
	size_t pt_size = 0;
	unsigned long *rpages = NULL, *lpages = NULL;
	struct rpc_gpshm *n = NULL;

	if (mr->pages & (~PAGE_MASK))
		return -EFAULT;

	if ((mr->cnt == 0) || (mr->cnt >
		(USER_VM4REE_SIZE / 2 / PAGE_SIZE)))
		return -EINVAL;

	pt_size = mr->cnt * sizeof(unsigned long);

	/* map the page table */
	rpages = phys_to_virt(mr->pages);

	lpages = kmalloc(pt_size);
	if (lpages == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(lpages, rpages, pt_size);

	for (i = 0; i < mr->cnt; i++) {
		if (lpages[i] & (~PAGE_MASK)) {
			ret = -EFAULT;
			goto out;
		}

		if (mem_in_secure(lpages[i])) {
			ret = -EACCES;
			goto out;
		}
	}

	n = kzalloc(sizeof(*n));
	if (n == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	n->cnt = mr->cnt;
	n->offset = mr->offset;
	n->pages = lpages;
	n->refc = 1;

	rpc_gpshm_lock();
	mr->id = n->id = rpc_shmid_get();
	list_add_tail(&n->node, &rpc_gpshms);
	rpc_gpshm_unlock();

	ret = 0;

out:
	if (ret < 0)
		kfree(lpages);
	return ret;
}

int rpc_gpshm_unregister(struct rpc_memref *mr)
{
	int ret = -1;
	struct rpc_gpshm *n = NULL;

	rpc_gpshm_lock();

	n = rpc_gpshm_of(mr->id);
	if (n == NULL) {
		ret = 0;
		goto out;
	}

	if (--n->refc != 0) {
		ret = 0;
		goto out;
	}

	if (n->proc) {
		unmap(n->proc->pt, n->va, n->cnt << PAGE_SHIFT);
		vma_free(n->proc->vm4ree, n->va);
	}

	rpc_gpshm_free(n);
	ret = 0;

out:
	rpc_gpshm_unlock();
	return ret;
}

static int __rpc_gpshm_map(struct rpc_gpshm *n,
	struct process *proc, unsigned long flags)
{
	int i = 0, ret = -1;
	size_t shm_size = n->cnt << PAGE_SHIFT;
	void *shm_va = NULL;

	if (flags & PG_EXEC)
		return -ENOEXEC;

	if (n->proc && n->va) {
		if (n->proc != proc)
			return -EBUSY;
		return 0;
	}

	shm_va = vma_alloc(proc->vm4ree, shm_size);
	if (!shm_va)
		return -ENOMEM;

	for (i = 0; i < n->cnt; i++) {
		ret = map(proc->pt, n->pages[i],
				shm_va + (PAGE_SIZE * i),
				PAGE_SIZE, flags);
		if (ret != 0)
			break;
	}

	if (ret != 0) {
		unmap(proc->pt, shm_va, i * PAGE_SIZE);
		goto out;
	}

	n->proc = proc;
	n->va = shm_va;
	return 0;

out:
	vma_free(proc->vm4ree, shm_va);
	return ret;
}

void *rpc_gpshm_map(struct process *proc,
	struct rpc_memref *mr, unsigned long flags)
{
	int ret = -1;
	struct rpc_gpshm *n = NULL;
	void *va = NULL;

	rpc_gpshm_lock();

	n = rpc_gpshm_of(mr->id);
	if (n == NULL) {
		n = ERR_PTR(-EINVAL);
		goto out;
	}

	ret = __rpc_gpshm_map(n, proc, flags);
	if (ret != 0) {
		n = ERR_PTR(ret);
		goto out;
	}

	if (mr->offset >= n->cnt * PAGE_SIZE ||
		(mr->size > n->cnt * PAGE_SIZE) ||
		(mr->offset + mr->size > n->cnt * PAGE_SIZE)) {
		n = ERR_PTR(-EINVAL);
		goto out;
	}

	n->refc += 1;

	va = n->va + n->offset + mr->offset;

out:
	rpc_gpshm_unlock();
	if (IS_ERR_PTR(n))
		return n;
	return va;
}

int rpc_gpshm_unmap(uint64_t id)
{
	int ret = -1;
	struct rpc_gpshm *n = NULL;

	rpc_gpshm_lock();

	n = rpc_gpshm_of(id);
	if (n == NULL) {
		ret = -EINVAL;
		goto out;
	}

	if (n->proc && (--n->refc == 0)) {
		unmap(n->proc->pt, n->va, n->cnt << PAGE_SHIFT);
		vma_free(n->proc->vm4ree, n->va);

		n->proc = NULL;
		n->va = NULL;

		rpc_gpshm_free(n);
	}

	ret = 0;

out:
	rpc_gpshm_unlock();
	return ret;
}

/*
 * callback for each process cleanup
 * to avoid resource leaking
 */
static void rpc_gpshm_cleanup(struct process *p)
{
	struct rpc_gpshm *n = NULL, *_n = NULL;

	rpc_gpshm_lock();
	list_for_each_entry_safe(n, _n, &rpc_gpshms, node) {
		if (n->proc == p) {
			n->proc = NULL;
			n->va = NULL;

			assert(n->refc > 0);

			if (--n->refc == 0)
				rpc_gpshm_free(n);
		}
	}
	rpc_gpshm_unlock();
}
DECLARE_CLEANUP(rpc_gpshm_cleanup);

/*
 * resource message information for debug purpose
 */
void rpc_gpshm_info(struct debugfs_file *d)
{
	struct rpc_gpshm *n = NULL;

	rpc_gpshm_lock();
	list_for_each_entry(n, &rpc_gpshms, node) {
		debugfs_printf(d, "\nshm %llx info:\n", (long long)n->id);
		debugfs_printf(d, "pages ptr: %p, cnt %d\n",
					n->pages, (int)n->cnt);
		debugfs_printf(d, "owner proc: %p va: %p refc: %d\n",
					n->proc, n->va, n->refc);
	}
	rpc_gpshm_unlock();
}
