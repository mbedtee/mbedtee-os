// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
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

static struct vm_struct *vm_lookup(struct process *proc, void *addr)
{
	struct vm_struct *vm = NULL, *ret = NULL;

	list_for_each_entry(vm, &proc->mmaps, node) {
		if (vm->va <= addr &&
			addr <= vm->va + vm->length - 1) {
			ret = vm;
			break;
		}
	}

	return ret;
}

int vm_fault(struct process *proc, void *addr, int flags)
{
	int ret = -1, retry = 0;
	struct vm_fault vf = {0};
	struct vm_struct *vm = NULL;

	if (flags & PG_EXEC)
		return -EACCES;

	mutex_lock(&proc->mlock);

	vm = vm_lookup(proc, addr);
	if (vm == NULL) {
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
		while (ret == -ENOMEM && ++retry < 30) {
			msleep(20);
			ret = page_map(vf.page, vm->pt, addr, vm->prot);
		}
	}
	if (ret == -ENOMEM)
		EMSG("oops OOM, retried %d\n", retry);

out:
	mutex_unlock(&proc->mlock);
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

	if (!page_aligned(offset) || !length)
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

	if (d->file->fops->mmap == NULL) {
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
	if (vm == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	length = roundup(length, PAGE_SIZE);
	va = vma_alloc(proc->vm, length);
	if (va == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	vm->va = va;
	vm->pt = proc->pt;
	vm->length = length;
	vm->prot = kprot;
	vm->offset = offset;
	vm->fdesc = d;

	mutex_lock(&proc->mlock);

	ret = d->file->fops->mmap(d->file, vm);
	if (ret != 0) {
		mutex_unlock(&proc->mlock);
		goto out;
	}

	list_add_tail(&vm->node, &proc->mmaps);
	mutex_unlock(&proc->mlock);

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

	if (!access_ok(addr, length))
		return -EFAULT;

	mutex_lock(&proc->mlock);
	list_for_each_entry(vm, &proc->mmaps, node) {
		if (vm->va == addr) {
			list_del(&vm->node);
			vm_unmap(proc, vm);
			ret = 0;
			break;
		}
	}
	mutex_unlock(&proc->mlock);

	if (ret == 0) {
		vm->vm_ops->munmap(vm);
		vma_free(proc->vm, addr);
		fdesc_put(vm->fdesc);
		kfree(vm);
	}

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

	mutex_lock(&proc->mlock);

	while ((vm = list_first_entry_or_null(&proc->mmaps,
				struct vm_struct, node)) != NULL) {
		list_del(&vm->node);
		vm_unmap(proc, vm);
		mutex_unlock(&proc->mlock);

		d = vm->fdesc;
		LMSG("vmunmap %s%s on %s@%d - va=%p fd=%d refc=%d\n",
			d->file->fs->mnt.path, d->file->path,
			d->proc->c->name, d->proc->id,
			vm->va, d->fd, d->refc);

		vm->vm_ops->munmap(vm);
		vma_free(proc->vm, vm->va);
		fdesc_put(vm->fdesc);
		kfree(vm);

		mutex_lock(&proc->mlock);
	}

	mutex_unlock(&proc->mlock);
}
DECLARE_CLEANUP_HIGH(vm_cleanup);
