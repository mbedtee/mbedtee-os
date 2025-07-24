// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * SHM (POSIX shared memory) based on tmpfs
 */

#include <of.h>
#include <fs.h>
#include <vma.h>
#include <trace.h>
#include <init.h>
#include <uaccess.h>
#include <strmisc.h>
#include <kmalloc.h>
#include <page_scatter.h>

#include <tfs.h>

/*
 * shm file node based on tmpfs
 * lifecycle: create -> unlink
 */
struct shm_fnode {
	struct tfs_node node; /* tfs node */
	struct list_head pages; /* page list */
	size_t filesize;	/* real size */
	size_t nr_pages; /* page aligned size */
};

/*
 * shm file information
 * lifecycle: open -> close
 */
struct shm_finfo {
	struct file *f;

	struct tfs_node *n; /* tfs node */
};

#define shm_fnode_of(n) container_of(n, struct shm_fnode, node)

static void shm_trunc_node(struct shm_fnode *fn)
{
	pages_list_free(&fn->pages, fn->nr_pages);
	fn->filesize = 0;
	fn->nr_pages = 0;
}

static struct tfs_node *shm_alloc_node(
	struct tfs *fs)
{
	struct shm_fnode *fn = kzalloc(sizeof(*fn));

	if (!fn)
		return NULL;

	INIT_LIST_HEAD(&fn->pages);

	return &fn->node;
}

static void shm_free_node(struct tfs_node *n)
{
	struct shm_fnode *fn = shm_fnode_of(n);

	shm_trunc_node(fn);
	kfree(fn);
}

static int shm_openfile(struct tfs *fs,
	struct shm_finfo *fi, int isdir, struct file *f)
{
	int ret = -1;
	int flags = f->flags;
	struct tfs_node *n = fi->n;
	int wrflag = flags & O_ACCMODE;

	tfs_lock_node(n);

	if (flags & O_EXCL) {
		ret = -EEXIST;
		goto out;
	}

	if (n->attr & TFS_ATTR_DIR) {
		if (flags & (O_ACCMODE | O_CREAT)) {
			ret = -EISDIR;
			goto out;
		}

		if (flags & (O_TRUNC | O_APPEND)) {
			ret = -EISDIR;
			goto out;
		}
		f->flags |= O_DIRECTORY;
	} else if (isdir | (flags & O_DIRECTORY)) {
		ret = -ENOTDIR;
		goto out;
	}

	ret = tfs_security_check(fs, n);
	if (ret != 0)
		goto out;

	if (wrflag != 0 && (flags & O_TRUNC)) {
		shm_trunc_node(shm_fnode_of(n));
		tfs_update_time(NULL, &n->mtime, &n->ctime);
	}

	fi->f = f;

out:
	tfs_unlock_node(n);
	return ret;
}

static int shm_mkfile(struct tfs *fs,
	struct shm_finfo *fi, int isdir,
	struct file *f, mode_t mode)
{
	int ret = -1;
	int flags = f->flags;
	struct tfs_node *n = NULL;

	if (!(flags & O_CREAT))
		return -ENOENT;

	if (isdir)
		return -EISDIR;

	if (flags & O_DIRECTORY)
		return -ENOTDIR;

	ret = tfs_make_node(fs, f->path, &n, false);
	if (ret != 0)
		return ret;

	n->refc++;

	fi->n = n;
	fi->f = f;

	return ret;
}

static int shm_do_open(struct file *f, mode_t mode, void *arg)
{
	int ret = -1;
	struct shm_finfo *fi = NULL;
	struct tfs *fs = file2tfs(f);
	int isdir = fspath_isdir(f->path);

	fi = kzalloc(sizeof(struct shm_finfo));
	if (!fi)
		return -ENOMEM;

	tfs_lock(fs);

	fi->n = tfs_get_node(fs, f->path);

	if (fi->n) {
		ret = shm_openfile(fs, fi, isdir, f);
		if (ret != 0) {
			tfs_put_node(fs, fi->n);
			goto out;
		}
	} else {
		ret = shm_mkfile(fs, fi, isdir, f, mode);
		if (ret != 0)
			goto out;
	}

	f->priv = fi;
	ret = 0;

out:
	tfs_unlock(fs);
	if (ret != 0)
		kfree(fi);
	return ret;
}

static int shm_close(struct file *f)
{
	struct shm_finfo *fi = f->priv;
	struct tfs_node *n = fi->n;
	struct tfs *fs = file2tfs(f);

	kfree(fi);

	tfs_lock(fs);
	tfs_put_node(fs, n);
	tfs_unlock(fs);

	return 0;
}

static ssize_t shm_read(struct file *f, void *buf, size_t cnt)
{
	struct shm_finfo *fi = f->priv;
	struct tfs_node *n = fi->n;
	struct shm_fnode *fn = shm_fnode_of(n);
	struct scatter_page *sp = NULL;
	off_t rd_off = 0, pgoff = 0;
	size_t rd_bytes = 0, unalign = 0, remain = 0, cp_bytes = 0;
	void *va = NULL;

	if (cnt == 0)
		return 0;

	if (!buf)
		return -EINVAL;

	tfs_lock_node(n);

	if (fn->filesize <= (size_t)f->pos)
		goto out;

	remain = min(fn->filesize - (size_t)f->pos, cnt);
	if (remain == 0)
		goto out;

	list_for_each_entry(sp, &fn->pages, node) {
		pgoff += PAGE_SIZE;
		if (pgoff <= f->pos)
			continue;

		unalign = f->pos % PAGE_SIZE;
		rd_bytes = min((size_t)PAGE_SIZE - unalign, remain);

		va = page_address(sp->page);

		cp_bytes = copy_to_user(buf + rd_off, va + unalign, rd_bytes);

		if (cp_bytes != 0) {
			if (rd_off == 0)
				rd_off = -EFAULT;
			goto out;
		}

		remain -= rd_bytes;
		rd_off += rd_bytes;
		f->pos += rd_bytes;

		if (remain == 0)
			break;
	}

out:
	if (rd_off > 0)
		tfs_update_time(&n->atime, NULL, NULL);
	tfs_unlock_node(n);
	return rd_off;
}

static ssize_t shm_write(struct file *f, const void *buf, size_t cnt)
{
	ssize_t ret = -1;
	struct shm_finfo *fi = f->priv;
	struct tfs_node *n = fi->n;
	struct shm_fnode *fn = shm_fnode_of(n);
	struct scatter_page *sp = NULL;
	off_t wr_off = 0, pgoff = 0;
	size_t wr_bytes = 0, cp_bytes = 0;
	size_t unalign = 0, remain = 0;
	size_t newpages = 0, total = 0;
	void *va = NULL;

	if (cnt == 0)
		return 0;

	if (!buf)
		return -EINVAL;

	tfs_lock_node(n);

	if (f->flags & O_APPEND)
		f->pos = fn->filesize;

	/* allocate pages to cover [0, f->pos + cnt] */
	total = roundup(f->pos + cnt, PAGE_SIZE) >> PAGE_SHIFT;
	if (total > fn->nr_pages) {
		newpages = total - fn->nr_pages;
		ret = pages_list_alloc(&fn->pages, newpages);
		if (ret != 0) {
			tfs_unlock_node(n);
			return ret;
		}
		fn->nr_pages += newpages;
	}

	remain = cnt;

	list_for_each_entry(sp, &fn->pages, node) {
		pgoff += PAGE_SIZE;
		if (pgoff <= f->pos)
			continue;

		unalign = f->pos % PAGE_SIZE;
		wr_bytes = min((size_t)PAGE_SIZE - unalign, remain);

		va = page_address(sp->page);

		cp_bytes = copy_from_user(va + unalign, buf + wr_off, wr_bytes);

		if (cp_bytes != 0) {
			if (wr_off == 0)
				wr_off = -EFAULT;
			goto out;
		}

		remain -= wr_bytes;
		wr_off += wr_bytes;
		f->pos += wr_bytes;

		if (remain == 0)
			break;
	}

out:
	if (wr_off > 0) {
		if (fn->filesize < f->pos)
			fn->filesize = f->pos;
		tfs_update_time(NULL, &n->mtime, &n->ctime);
	} else {
		if (newpages != 0)
			pages_list_free(&fn->pages, newpages);
	}
	tfs_unlock_node(n);
	return wr_off;
}

static void shm_munmap(struct vm_struct *vm)
{
	vm->private_data = NULL;
	vm->vm_ops = NULL;
}

static int shm_fault(struct vm_struct *vm,
	struct vm_fault *vf)
{
	struct tfs_node *n = NULL;
	struct shm_fnode *fn = NULL;
	struct scatter_page *sp = NULL;
	struct page *p = NULL;
	off_t pos = 0;

	if (!vm->vm_ops || !vm->private_data)
		return -EFAULT;

	n = vm->private_data;
	fn = shm_fnode_of(n);

	tfs_lock_node(n);

	if (vf->offset < (fn->nr_pages << PAGE_SHIFT)) {
		if (vf->offset > (fn->nr_pages << (PAGE_SHIFT - 1))) {
			pos = (fn->nr_pages << PAGE_SHIFT);
			list_for_each_entry_reverse(sp, &fn->pages, node) {
				pos -= PAGE_SIZE;
				if (pos == vf->offset) {
					p = sp->page;
					break;
				}
			}
		} else {
			list_for_each_entry(sp, &fn->pages, node) {
				if (pos == vf->offset) {
					p = sp->page;
					break;
				}
				pos += PAGE_SIZE;
			}
		}
	}

	vf->page = p;

	tfs_unlock_node(n);

	return p ? 0 : -EFAULT;
}

static const struct vm_operations shm_vm_ops = {
	.fault = shm_fault,
	.munmap = shm_munmap,
};

static int shm_mmap(struct file *f, struct vm_struct *vm)
{
	struct shm_finfo *fi = f->priv;

	vm->vm_ops = &shm_vm_ops;
	vm->private_data = fi->n;

	return 0;
}

static off_t shm_seekdir(struct file *f, off_t off, int whence)
{
	int ret = -EINVAL;
	struct tfs *fs = file2tfs(f);
	struct shm_finfo *fi = f->priv;

	tfs_lock(fs);
	ret = tfs_seekdir(fs, fi->n, &f->pos, off, whence);
	tfs_unlock(fs);

	return ret;
}

static off_t shm_lseek(struct file *f, off_t off, int whence)
{
	off_t ret = -1;
	struct shm_finfo *fi = f->priv;
	struct tfs_node *n = fi->n;
	struct shm_fnode *fn = shm_fnode_of(n);

	if (n->attr & TFS_ATTR_DIR)
		return shm_seekdir(f, off, whence);

	tfs_lock_node(n);

	if (!(n->attr & TFS_ATTR_ARC)) {
		ret = -EBADF;
		goto out;
	}

	if (whence == SEEK_CUR) {
		off += f->pos;
	} else if (whence == SEEK_END) {
		off += fn->filesize;
	} else if (whence != SEEK_SET) {
		ret = -EINVAL;
		goto out;
	}

	if ((ret = off) < 0) {
		ret = -EINVAL;
		goto out;
	}

	f->pos = ret;

out:
	tfs_unlock_node(n);
	return ret;
}

static int shm_ftruncate(struct file *f, off_t length)
{
	int ret = -1;
	struct shm_finfo *fi = f->priv;
	struct tfs_node *n = fi->n;
	struct shm_fnode *fn = shm_fnode_of(n);
	size_t needed = 0;

	if (n->attr & TFS_ATTR_DIR)
		return -EISDIR;

	if (length < 0)
		return -EFBIG;

	tfs_lock_node(n);

	needed = roundup(length, PAGE_SIZE) >> PAGE_SHIFT;

	if (length <= fn->filesize) {
		/* shrink pages */
		fn->filesize = length;
		if (fn->nr_pages > needed) {
			pages_list_free(&fn->pages, fn->nr_pages - needed);
			fn->nr_pages = needed;
		}
	} else {
		/* extend pages */
		if (needed > fn->nr_pages) {
			ret = pages_list_alloc(&fn->pages,
					needed - fn->nr_pages);
			if (ret != 0)
				goto out;
			fn->nr_pages = needed;
		}
		fn->filesize = length;
	}

	tfs_update_time(NULL, &n->mtime, &n->ctime);
	ret = 0;

out:
	tfs_unlock_node(n);
	return ret;
}

static int shm_fstat(struct file *f, struct stat *st)
{
	struct shm_finfo *fi = f->priv;
	struct tfs_node *n = fi->n;
	struct shm_fnode *fn = shm_fnode_of(n);

	if (!st)
		return -EINVAL;

	tfs_lock_node(n);

	if (n->attr & TFS_ATTR_DIR) {
		st->st_mode = S_IFDIR;
		st->st_blocks = 1;
		st->st_size = sizeof(struct tfs_node);
		st->st_blksize = st->st_size;
	} else {
		st->st_mode = S_IFREG;
		st->st_blocks = fn->nr_pages;
		st->st_size = fn->filesize;
		st->st_blksize = PAGE_SIZE;
	}

	st->st_atime = n->atime;
	st->st_mtime = n->mtime;
	st->st_ctime = n->ctime;

	tfs_unlock_node(n);
	return 0;
}

static int shm_rename(struct file_system *pfs,
	const char *oldpath, const char *newpath)
{
	int ret = -1;
	struct tfs *fs = pfs->priv;

	tfs_lock(fs);
	ret = tfs_rename(fs, oldpath, newpath);
	tfs_unlock(fs);

	return ret;
}

static int shm_do_unlink(struct file_system *pfs, const char *path)
{
	int ret = -1;
	struct tfs *fs = pfs->priv;

	tfs_lock(fs);
	ret = tfs_unlink(fs, path);
	tfs_unlock(fs);

	return ret;
}

static ssize_t shm_readdir(struct file *f, struct dirent *d, size_t count)
{
	ssize_t rdbytes = -1;
	struct tfs *fs = file2tfs(f);
	struct shm_finfo *fi = f->priv;

	if (!d)
		return -EINVAL;

	tfs_lock(fs);
	rdbytes = tfs_readdir(fs, fi->n, &f->pos, d, count);
	tfs_unlock(fs);

	return rdbytes;
}

static int shm_mkdir(struct file_system *pfs, const char *path, mode_t mode)
{
	int ret = -1;
	struct tfs_node *n = NULL;
	struct tfs *fs = pfs->priv;

	tfs_lock(fs);
	ret = tfs_make_node(fs, path, &n, true);
	tfs_unlock(fs);

	return ret;
}

static int shm_rmdir(struct file_system *pfs, const char *path)
{
	int ret = -1;
	struct tfs *fs = pfs->priv;

	tfs_lock(fs);
	ret = tfs_rmdir(fs, path);
	tfs_unlock(fs);

	return ret;
}

static const struct file_operations shm_fops = {
	.open = shm_do_open,
	.close = shm_close,
	.read = shm_read,
	.write = shm_write,
	.mmap = shm_mmap,

	.lseek = shm_lseek,
	.ftruncate = shm_ftruncate,
	.fstat = shm_fstat,
	.rename = shm_rename,
	.unlink = shm_do_unlink,

	.readdir = shm_readdir,
	.mkdir = shm_mkdir,
	.rmdir = shm_rmdir,
};

/* based on the tmpfs */
static struct tfs shm_tfs = {
	.alloc = shm_alloc_node,
	.free = shm_free_node,
	.security_check = tfs_check,
};

static struct file_system shm_fs = {
	/* based on the tmpfs */
	.name = "shm",
	.mnt = {"/shm", 0, 0},
	.mount = tfs_mount,
	.umount = tfs_umount,
	.getpath = tfs_getpath,
	.putpath = tfs_putpath,

	.fops = &shm_fops,

	/* independent tmpfs instance */
	.priv = &shm_tfs,
};

static void __init shm_init(void)
{
	assert(fs_mount(&shm_fs) == 0);
}

MODULE_INIT_CORE(shm_init);
