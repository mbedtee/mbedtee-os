// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * mmap
 */

#include <errno.h>
#include <trace.h>
#include <device.h>
#include <thread.h>
#include <uaccess.h>
#include <kmalloc.h>
#include <fs.h>
#include <vma.h>

#include <sys/mmap.h>

static inline void vm_lock(struct process *proc, 	unsigned long *flags)
{
	spin_lock_irqsave(&proc->slock, *flags);
}

static inline void vm_unlock(struct process *proc,	unsigned long flags)
{
	spin_unlock_irqrestore(&proc->slock, flags);
}

static void vm_unmap(struct process *proc,
	struct vm_struct *vm)
{
	int i = 0;
	int nrpages = vm->length >> PAGE_SHIFT;
	void *va = vm->va;
	unsigned long pa = 0;
	struct page *p = NULL;

	for (i = 0; i < nrpages; i++) {
		pa = user_virt_to_phys_pt(vm->pt, va);

		if (pa != 0) {
			p = phys_to_page(pa);

			page_unmap(p, vm->pt, va);
		}

		va += PAGE_SIZE;
	}
}

static void vm_put(struct process *proc, struct vm_struct *vm)
{
	if (vm && atomic_dec_return(&vm->refc) == 0) {
		vm_unmap(proc, vm);
		vm->vm_ops->munmap(vm);
		vma_free(proc->vm, vm->va);
		fdesc_put(vm->fdesc);
		kfree(vm);
	}
}

static struct vm_struct *vm_get(struct process *proc, void *addr)
{
	struct vm_struct *vm = NULL, *ret = NULL;
	unsigned long flags = 0;

	vm_lock(proc, &flags);

	list_for_each_entry(vm, &proc->mmaps, node) {
		if (vm->va <= addr &&
			addr <= vm->va + vm->length - 1) {
			ret = vm;
			atomic_inc(&vm->refc);
			break;
		}
	}

	vm_unlock(proc, flags);
	return ret;
}

int vm_fault(struct process *proc, void *addr, int flags)
{
	int ret = -1, retry = 0;
	struct vm_fault vf = {0};
	struct vm_struct *vm = NULL;

	if (flags & PG_EXEC)
		return -EACCES;

	vm = vm_get(proc, addr);
	if (!vm) {
		ret = -EFAULT;
		goto out;
	}

	if (((flags & PG_RW) > (vm->prot & PG_RW))) {
		ret = -EACCES;
		goto out;
	}

	vf.offset = vm->offset + (addr - vm->va);
	ret = vm->vm_ops->fault(vm, &vf);
	if (ret == 0) {
		ret = page_map(vf.page, vm->pt, addr, vm->prot);
		while (ret == -ENOMEM && ++retry < 50) {
			DMSG("oops OOM, retrying %d\n", retry);
			msleep(20);
			ret = page_map(vf.page, vm->pt, addr, vm->prot);
		}
	}
	if (ret == -ENOMEM)
		EMSG("oops OOM, retried %d\n", retry);

out:
	vm_put(proc, vm);
	return ret;
}

void *vm_mmap(void *addr, size_t length, int prot,
		int flags, int fd, off_t offset)
{
	void *va = NULL;
	long kprot = 0, ret = 0, oflags = 0;
	struct file_desc *d = NULL;
	struct vm_struct *vm = NULL;
	struct process *proc = current->proc;
	unsigned long lflags = 0;

	if (!page_aligned(offset) || length == 0)
		return ERR_PTR(-EINVAL);

	if (addr && !page_aligned(addr))
		return ERR_PTR(-EINVAL);

	if (addr && !access_ok(addr, length))
		return ERR_PTR(-EFAULT);

	d = fdesc_get(fd);
	if (!d)
		return ERR_PTR(-EBADF);

	oflags = d->file->flags;

	if (((oflags & O_ACCMODE) == O_WRONLY) ||
		((oflags & O_ACCMODE) == O_RDONLY &&
		(prot & PROT_WRITE))) {
		ret = -EACCES;
		goto out;
	}

	if (!d->file->fops->mmap) {
		ret = -ENXIO;
		goto out;
	}

	switch (prot) {
	case PROT_READ:
		kprot = PG_RO;
		break;

	case PROT_WRITE:
	case PROT_READ | PROT_WRITE:
		kprot = PG_RW;
		break;

	default:
		ret = -EINVAL;
		goto out;
	}

	vm = kzalloc(sizeof(struct vm_struct));
	if (!vm) {
		ret = -ENOMEM;
		goto out;
	}

	length = roundup(length, PAGE_SIZE);
	va = vma_alloc(proc->vm, length);
	if (!va) {
		ret = -ENOMEM;
		goto out;
	}

	vm->va = va;
	vm->pt = proc->pt;
	vm->length = length;
	vm->prot = kprot;
	vm->offset = offset;
	vm->fdesc = d;
	atomic_set(&vm->refc, 1);

	ret = d->file->fops->mmap(d->file, vm);
	if (ret != 0)
		goto out;

	vm_lock(proc, &lflags);
	list_add_tail(&vm->node, &proc->mmaps);
	vm_unlock(proc, lflags);

	return va;

out:
	vma_free(proc->vm, va);
	kfree(vm);
	fdesc_put(d);
	return ERR_PTR(ret);
}

int vm_munmap(void *addr, size_t length)
{
	int ret = -EINVAL;
	struct vm_struct *vm = NULL;
	struct process *proc = current->proc;
	unsigned long flags = 0;

	if (!access_ok(addr, length))
		return -EFAULT;

	vm_lock(proc, &flags);
	list_for_each_entry(vm, &proc->mmaps, node) {
		if (vm->va == addr) {
			list_del(&vm->node);
			ret = 0;
			break;
		}
	}
	vm_unlock(proc, flags);

	if (ret == 0)
		vm_put(proc, vm);

	return ret;
}

/*
 * callback for each process cleanup
 * to avoid resource leaking
 */
static void vm_cleanup(struct process *proc)
{
	struct file_desc *d = NULL;
	struct vm_struct *vm = NULL;
	unsigned long flags = 0;

	vm_lock(proc, &flags);

	while ((vm = list_first_entry_or_null(&proc->mmaps,
				struct vm_struct, node)) != NULL) {
		list_del(&vm->node);
		vm_unlock(proc, flags);

		d = vm->fdesc;
		LMSG("vmunmap %s%s on %s@%d - va=%p fd=%d refc=%d\n",
			d->file->fs->mnt.path, d->file->path,
			d->proc->c->name, d->proc->id,
			vm->va, d->fd, d->refc);

		assert(atomic_read(&vm->refc) == 1);

		vm_put(proc, vm);

		vm_lock(proc, &flags);
	}

	vm_unlock(proc, flags);
}
DECLARE_CLEANUP_HIGH(vm_cleanup);
