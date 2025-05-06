// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * FS framework
 */

#include <fs.h>
#include <fatfs.h>
#include <thread.h>
#include <kmalloc.h>

static SPIN_LOCK(__fslock);
static LIST_HEAD(__fslist);

/*
 * if the fs_getpath assigns own folder for this proc,
 * then create this folder to match the assigned prefix
 */
void fs_create(const char *name)
{
	unsigned long l = 0;
	char path[FS_PATH_MAX];
	struct file_system *fs = NULL, *_fs  = NULL;

	list_for_each_entry_safe(fs, _fs, &__fslist, node) {
		if (fs->getpath != fs_getpath)
			continue;
		l = snprintf(path, sizeof(path), "%s/%s", fs->mnt.path, name);
		if (l >= sizeof(path))
			continue;
		sys_mkdir(path, 0700);
	}
}

int fs_mount(struct file_system *fs)
{
	int ret = -1;
	unsigned long flags = 0;

	if (fs->mount) {
		sys_mkdir(fs->mnt.path, 0700);

		ret = fs->mount(fs);
		if (ret != 0) {
			EMSG("mount %s @ %s failed\n",
				fs->name, fs->mnt.path);
			return ret;
		}
	}

	spin_lock_irqsave(&__fslock, flags);
	list_add_tail(&fs->node, &__fslist);
	spin_unlock_irqrestore(&__fslock, flags);

	/* See fs_create() */
	if ((IS_ENABLED(CONFIG_USER)) &&
		(fs->getpath == fs_getpath))
		process_handle_fs(fs->mnt.path);

	return 0;
}

int fs_umount(struct file_system *fs)
{
	int ret = -EINVAL;
	unsigned long flags = 0;
	const char *path = NULL;
	int (*umount)(struct file_system *fs) = NULL;

	if (fs) {
		spin_lock_irqsave(&__fslock, flags);
		if (fs->refc == 0) {
			path = fs->mnt.path;
			list_del(&fs->node);
			umount = fs->umount;
			ret = 0;
		} else {
			ret = -EBUSY;
		}
		spin_unlock_irqrestore(&__fslock, flags);

		if (umount)
			umount(fs);
		if (ret == 0)
			sys_rmdir(path);
	}

	return ret;
}

static struct file_system *fs_of(const char *path)
{
	int curlen = 0, lastlen = 0, pathlen = 0, bias = 0;
	struct file_system *fs = NULL, *ret = NULL;

	if (!path)
		return NULL;

	if (*path != '/')
		bias = 1;

	pathlen = strlen(path);
	list_for_each_entry(fs, &__fslist, node) {
		curlen = strlen(fs->mnt.path) - bias;
		if (curlen && !memcmp(path, fs->mnt.path + bias, curlen)) {
			if (curlen > lastlen) {
				lastlen = curlen;
				ret = fs;
				if (pathlen == curlen)
					break;
			}
		}
	}

	if (ret == NULL && bias)
		ret = list_first_entry_or_null(&__fslist,
				struct file_system, node);

	return ret;
}

struct file_system *fs_get(const char *path)
{
	unsigned long flags = 0;
	struct file_system *fs = NULL;

	if (!path)
		return NULL;

	spin_lock_irqsave(&__fslock, flags);
	fs = fs_of(path);
	if (fs)
		fs->refc++;
	spin_unlock_irqrestore(&__fslock, flags);

	return fs;
}

void fs_put(struct file_system *fs)
{
	unsigned long flags = 0;

	if (fs) {
		spin_lock_irqsave(&__fslock, flags);
		assert(fs->refc > 0);
		fs->refc--;
		spin_unlock_irqrestore(&__fslock, flags);
	}
}

int fs_getpath(struct file_path *p)
{
	char *prefix = NULL, *dst = NULL, *s = NULL;
	int ret = -1, mnt_len = 0, prefix_len = 0;
	struct process *proc = current->proc;
	struct file_system *fs = p->fs;

	FMSG("alloc_path %s\n\n", p->path);

	/*
	 * rule is: /mnt/prefix/file_dir_name
	 * add prefix for each TA, each TA
	 * access only to its own space
	 */
	ret = strlen(p->path) + 1;
	if (!proc->c->privilege) {
		prefix = proc->c->name;
		prefix_len = strlen(prefix);
		mnt_len = strlen(fs->mnt.path);

		ret = 1 + prefix_len + 1 + ret + 1;
	}

	if (ret >= FS_PATH_MAX)
		return -ENAMETOOLONG;

	dst = kmalloc(ret);
	if (dst == NULL)
		return -ENOMEM;

	s = dst;
	if (mnt_len) {
		/* skip root slash */
		if (mnt_len != 1) {
			memcpy(s, fs->mnt.path, mnt_len);
			s += mnt_len;
		}
		*s++ = '/';

		memcpy(s, prefix, prefix_len);
		s += prefix_len;

		if (p->path[0] != '/')
			mnt_len -= 1;
		if (p->path[mnt_len] != '/')
			*s++ = '/';
	}

	strcpy(s, p->path + mnt_len);

	FMSG("relpath %s\n", dst);
	p->path = dst;
	return 0;
}

void fs_putpath(struct file_path *p)
{
	kfree(p->path);
}

/*
 * suspend all sub-file-systems
 */
void fs_suspend(void)
{
	struct file_system *fs = NULL;

	/*
	 * suspend the all sub file-systems
	 * no race condition at this moment
	 */
	list_for_each_entry_reverse(fs, &__fslist, node) {
		if (fs->suspend)
			fs->suspend(fs);
	}
}

/*
 * resume all sub-file-systems
 */
void fs_resume(void)
{
	struct file_system *fs = NULL;

	/*
	 * resume the all sub file-systems
	 * no race condition at this moment
	 */
	list_for_each_entry(fs, &__fslist, node) {
		if (fs->resume)
			fs->resume(fs);
	}
}

static int fs_debugfs_info(struct debugfs_file *d)
{
	unsigned long flags = 0;
	struct file_system *fs = NULL;

	spin_lock_irqsave(&__fslock, flags);
	list_for_each_entry(fs, &__fslist, node) {
		debugfs_printf(d, "%s  type %s   on %s", fs->name, fs->type, fs->mnt.path);
		if (fs->mnt.addr) {
			debugfs_printf(d, "\t%p %lx", fs->mnt.addr, (long)fs->mnt.size);
			if (fs->getfree)
				debugfs_printf(d, " %lx", (long)fs->getfree(fs));
		}
		debugfs_printf(d, "\n");
	}
	spin_unlock_irqrestore(&__fslock, flags);

	return 0;
}

static const struct debugfs_fops fs_debugfs_ops = {
	.read = fs_debugfs_info,
	.write = NULL,
};

static void __init fs_debugfs_init(void)
{
	debugfs_create("/mount", &fs_debugfs_ops);
}
MODULE_INIT(fs_debugfs_init);
