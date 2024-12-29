// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
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
	int hole; /* seek hole pages beyond file size */

	off_t pos; /* current file position */

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

	if (fn == NULL)
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

static inline int shm_calc_seekhole(size_t filesize, size_t off)
{
	size_t ext = 0, hole = 0;

	ext = roundup(filesize, 1 << PAGE_SHIFT);
	if (off > ext) {
		ext = roundup(off - ext, 1 << PAGE_SHIFT);
		hole = ext >> PAGE_SHIFT;
	}
	return hole;
}

/*
 * free the superfluous seek holes
 */
static inline void shm_free_seekhole(struct shm_finfo *fi)
{
	size_t size = 0, nr = 0;
	struct shm_fnode *fn = shm_fnode_of(fi->n);

	size = max(fn->filesize, (size_t)fi->pos);
	size = roundup(size, PAGE_SIZE);
	nr = size >> PAGE_SHIFT;

	if (fn->nr_pages > nr) {
		pages_list_free(&fn->pages, fn->nr_pages - nr);
		fn->nr_pages = nr;
	}
}

static int shm_openfile(struct tfs *fs,
	struct shm_finfo *fi, int isdir, struct file *f)
{
	int ret = -1;
	int flags =  f->flags;
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

	if (wrflag && (flags & O_TRUNC)) {
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
	if (fi == NULL)
		return -ENOMEM;

	tfs_lock(fs);

	fi->n = tfs_get_node(fs, f->path);

	if (fi->n != NULL) {
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

	if (n->attr & TFS_ATTR_ARC) {
		tfs_lock_node(n);
		fi->pos = 0;
		shm_free_seekhole(fi);
		tfs_unlock_node(n);
	}

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
	off_t rd_off = 0, pos = 0;
	size_t rd_bytes = 0, unalign = 0, remain = 0, cp_bytes = 0;
	void *va = NULL;

	if (cnt == 0)
		return 0;

	if (buf == NULL)
		return -EINVAL;

	tfs_lock_node(n);

	if (fn->filesize <= (size_t)fi->pos)
		goto out;

	remain = min(fn->filesize - (size_t)fi->pos, cnt);
	if (remain == 0)
		goto out;

	list_for_each_entry(sp, &fn->pages, node) {
		pos += PAGE_SIZE;
		if (pos <= fi->pos)
			continue;

		unalign = fi->pos % PAGE_SIZE;
		rd_bytes = min((size_t)PAGE_SIZE - unalign, remain);

		va = page_address(sp->page);

		cp_bytes = copy_to_user(buf + rd_off, va + unalign, rd_bytes);

		if (cp_bytes) {
			if (rd_off == 0)
				rd_off = -EFAULT;
			goto out;
		}

		remain -= rd_bytes;
		rd_off += rd_bytes;
		fi->pos += rd_bytes;

		if (remain == 0)
			break;
	}

out:
	if (rd_off > 0)
		tfs_update_time(&n->mtime, NULL, NULL);
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
	off_t wr_off = 0, pos = 0;
	size_t wr_bytes = 0, cp_bytes = 0;
	size_t unalign = 0, remain = 0, newpages = 0;
	void *va = NULL;

	if (cnt == 0)
		return 0;

	if (buf == NULL)
		return -EINVAL;

	tfs_lock_node(n);

	if (f->flags & O_APPEND) {
		fi->pos = fn->filesize;
		shm_free_seekhole(fi);
		fi->hole = 0;
	}

	/* allocate new pages */
	remain = max(fn->filesize, (size_t)fi->pos);
	remain = roundup(remain, PAGE_SIZE) - fi->pos;
	if (cnt > remain) {
		newpages = roundup(cnt - remain, PAGE_SIZE) >> PAGE_SHIFT;
		ret = pages_list_alloc(&fn->pages, newpages);
		if (ret != 0) {
			tfs_unlock_node(n);
			return ret;
		}
		fn->nr_pages += newpages;
	}

	remain = cnt;

	list_for_each_entry(sp, &fn->pages, node) {
		pos += PAGE_SIZE;
		if (pos <= fi->pos)
			continue;

		unalign = fi->pos % PAGE_SIZE;
		wr_bytes = min((size_t)PAGE_SIZE - unalign, remain);

		va = page_address(sp->page);

		cp_bytes = copy_from_user(va + unalign, buf + wr_off, wr_bytes);

		if (cp_bytes) {
			if (wr_off == 0)
				wr_off = -EFAULT;
			goto out;
		}

		remain -= wr_bytes;
		wr_off += wr_bytes;
		fi->pos += wr_bytes;

		if (remain == 0)
			break;
	}

out:
	if (wr_off > 0) {
		if (fn->filesize < fi->pos)
			fn->filesize = fi->pos;
		fi->hole = 0;
		tfs_update_time(NULL, &n->mtime, &n->ctime);
	} else {
		if (newpages)
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
	struct tfs_node *n = vm->private_data;
	struct shm_fnode *fn = shm_fnode_of(n);
	struct scatter_page *sp = NULL;
	struct page *p = NULL;
	off_t pos = 0;

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
	ret = tfs_seekdir(fs, fi->n, &fi->pos, off, whence);
	tfs_unlock(fs);

	return ret;
}

static off_t shm_seekfile(struct shm_finfo *fi, off_t off)
{
	int wrflag = 0, hole = 0;
	struct shm_fnode *fn = shm_fnode_of(fi->n);
	off_t ret = -1;

	if (off < 0)
		return -EINVAL;

	/* extend cluster chain */
	wrflag = fi->f->flags & O_ACCMODE;
	if (off > fn->filesize) {
		if (wrflag) {
			hole = shm_calc_seekhole(fn->filesize, off);
			if (hole > fi->hole) {
				ret = pages_list_alloc(&fn->pages, hole - fi->hole);
				if (ret != 0)
					goto out;
				fn->nr_pages += hole - fi->hole;
			}
		} else {
			off = fn->filesize;
		}
	}

	fi->pos = off;
	ret = off;

	/* refresh the ceiling of the seek hole */
	if (fi->pos > fn->filesize)
		fi->hole = max(hole, fi->hole);

	/* shrink the superfluous seek holes */
	if (hole < fi->hole) {
		shm_free_seekhole(fi);
		fi->hole = hole;
	}

out:
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

	if (whence == SEEK_CUR)
		off += fi->pos;
	else if (whence == SEEK_END)
		off += (off_t)fn->filesize;
	else if (whence != SEEK_SET) {
		ret = -EINVAL;
		goto out;
	}

	ret = shm_seekfile(fi, off);

out:
	tfs_unlock_node(n);
	return ret;
}

static int shm_truncate(struct file *f, off_t length)
{
	int ret = -1;
	off_t off = 0, seek = 0;
	struct shm_finfo *fi = f->priv;
	struct tfs_node *n = fi->n;
	struct shm_fnode *fn = shm_fnode_of(n);

	if (n->attr & TFS_ATTR_DIR)
		return -EISDIR;

	if (length < 0)
		return -EFBIG;

	tfs_lock_node(n);

	if (length <= fn->filesize) {
		/* shrink pages */
		fn->filesize = length;
		shm_free_seekhole(fi);
	} else {
		/* extend pages */
		off = fi->pos;
		seek = shm_seekfile(fi, length);
		fi->pos = off;
		if (seek < 0) {
			ret = seek;
			goto out;
		}
		fn->filesize = length;
	}

	fi->hole = shm_calc_seekhole(length, fi->pos);
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

	if (st == NULL)
		return -EINVAL;

	tfs_lock_node(n);

	st->st_size = fn->filesize;
	st->st_blksize = PAGE_SIZE;

	if (n->attr & TFS_ATTR_DIR) {
		st->st_mode = S_IFDIR;
		st->st_blocks = 0;
	} else {
		st->st_mode = S_IFREG;
		st->st_blocks = fn->nr_pages;
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
	int ret = -1, name_l = 0;
	struct tfs_node *oldn = NULL;
	struct tfs_node *n = NULL, *dir = NULL;
	struct tfs *fs = pfs->priv;
	char *newname, *namebuf = NULL;
	char npath[FS_PATH_MAX];

	if (!newpath || !oldpath)
		return -EINVAL;

	tfs_lock(fs);

	oldn = tfs_get_node(fs, oldpath);
	if (oldn == NULL) {
		ret = -ENOENT;
		goto out;
	}

	n = tfs_get_node(fs, newpath);
	if (n != NULL) {
		ret = -EEXIST;
		goto out;
	}

	strlcpy(npath, newpath, sizeof(npath));
	dir = tfs_get_node(fs, dirname(npath));
	if (dir == NULL) {
		ret = -ENOENT;
		goto out;
	}

	/*
	 * usually used on the judgement:
	 * 'rename to a subdirectory of itself'
	 */
	n = dir;
	while (n != fs->root) {
		if (n == oldn) {
			ret = -EINVAL;
			goto out;
		}
		n = n->parent;
	}

	if (!(dir->attr & TFS_ATTR_DIR)) {
		ret = -ENOTDIR;
		goto out;
	}

	if (fspath_isdir(newpath) && !(oldn->attr & TFS_ATTR_DIR)) {
		ret = -ENOTDIR;
		goto out;
	}

	/* mount point not to be renamed */
	if (oldn->attr & TFS_ATTR_VOL) {
		ret = -EBUSY;
		goto out;
	}

	if ((oldn->attr & TFS_ATTR_DIR) &&
		(oldn->attr & TFS_ATTR_RO)) {
		ret = -EACCES;
		goto out;
	}

	newname = basename(newpath);
	name_l = strlen(newname) + 1;
	namebuf = kmalloc(name_l);
	if (namebuf == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	strlcpy(namebuf, newname, name_l);

	kfree(oldn->name);
	oldn->name = namebuf;
	oldn->parent->refc--;
	oldn->parent->sub_nodes--;
	oldn->parent = dir;
	dir->refc++;
	dir->sub_nodes++;
	list_move_tail(&oldn->node, &dir->nodes);

	tfs_update_time(NULL, NULL, &oldn->ctime);

	ret = 0;

out:
	tfs_put_node(fs, dir);
	tfs_put_node(fs, oldn);
	tfs_unlock(fs);
	return ret;
}

static int shm_do_unlink(struct file_system *pfs, const char *path)
{
	int ret = -1;
	struct tfs_node *n = NULL;
	struct tfs *fs = pfs->priv;

	if (!path)
		return -EINVAL;

	tfs_lock(fs);

	n = tfs_get_node(fs, path);
	if (n == NULL) {
		ret = -ENOENT;
		goto out;
	}

	if (n->attr & TFS_ATTR_DIR) {
		ret = -EISDIR;
		goto out;
	}

	if (fspath_isdir(path)) {
		ret = -ENOTDIR;
		goto out;
	}

	ret = tfs_security_check(fs, n);
	if (ret != 0)
		goto out;

	list_del(&n->node);

	tfs_put_node(fs, n);

out:
	tfs_put_node(fs, n);
	tfs_unlock(fs);
	return ret;
}

static ssize_t shm_readdir(struct file *f, struct dirent *d, size_t count)
{
	ssize_t rdbytes = -1;
	struct tfs *fs = file2tfs(f);
	struct shm_finfo *fi = f->priv;

	if (d == NULL)
		return -EINVAL;

	tfs_lock(fs);
	rdbytes = tfs_readdir(fs, fi->n, &fi->pos, d, count);
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
	struct tfs_node *n = NULL;
	struct tfs *fs = pfs->priv;

	if (!path)
		return -EINVAL;

	tfs_lock(fs);

	n = tfs_get_node(fs, path);
	if (n == NULL) {
		ret = -ENOENT;
		goto out;
	}

	if (!(n->attr & TFS_ATTR_DIR)) {
		ret = -ENOTDIR;
		goto out;
	}

	/* check current DIR empty or not */
	if (!list_empty(&n->nodes)) {
		ret = -ENOTEMPTY;
		goto out;
	}

	/* mount point is not removable */
	if (n->attr & TFS_ATTR_VOL) {
		ret = -EBUSY;
		goto out;
	}

	ret = tfs_security_check(fs, n);
	if (ret != 0)
		goto out;

	tfs_put_node(fs, n);

out:
	tfs_put_node(fs, n);
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
	.ftruncate = shm_truncate,
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

static struct file_system shm_root = {
	/* based on the tmpfs */
	.name = "shmfs",
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
	assert(fs_mount(&shm_root) == 0);
}

MODULE_INIT_CORE(shm_init);
