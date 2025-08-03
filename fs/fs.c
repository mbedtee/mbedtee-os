// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
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
	struct file_system *fs = NULL, *_fs = NULL;

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
	struct file_system *curr = NULL;

	/* Check for duplicate mount point */
	spin_lock_irqsave(&__fslock, flags);
	list_for_each_entry(curr, &__fslist, node) {
		if (strcmp(curr->mnt.path, fs->mnt.path) == 0) {
			spin_unlock_irqrestore(&__fslock, flags);
			return -EEXIST;
		}
	}
	spin_unlock_irqrestore(&__fslock, flags);

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
	/* Double check */
	list_for_each_entry(curr, &__fslist, node) {
		if (strcmp(curr->mnt.path, fs->mnt.path) == 0) {
			spin_unlock_irqrestore(&__fslock, flags);
			/* Rollback mount */
			if (fs->umount)
				fs->umount(fs);
			return -EEXIST;
		}
	}
	list_add_tail(&fs->node, &__fslist);
	spin_unlock_irqrestore(&__fslock, flags);

	/* See fs_create() todo */
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
	struct file_system *fs = NULL, *best_match = NULL;
	size_t best_len = 0;
	bool is_absolute = false;

	if (!path)
		return NULL;

	is_absolute = (*path == '/');

	list_for_each_entry(fs, &__fslist, node) {
		const char *mnt = fs->mnt.path;
		size_t mnt_len = strlen(mnt);
		size_t cmp_len = mnt_len;

		/*
		 * For relative path (e.g. "etc/init"), skip the leading '/'
		 * of the mount point (e.g. compare with "etc" of "/etc")
		 */
		if (!is_absolute) {
			if (mnt_len > 0 && mnt[0] == '/') {
				mnt++;
				cmp_len--;
			}
		}

		if (cmp_len == 0)
			continue;

		/* Check if path starts with the mount point */
		if (strncmp(path, mnt, cmp_len) == 0) {
			/*
			 * Boundary check to avoid partial match (e.g. /data vs /data2)
			 * Match if:
			 * 1. End of path string
			 * 2. Next char is separator '/'
			 * 3. Mount point itself ends with separator (e.g. root "/")
			 */
			char next = path[cmp_len];

			if (next == '\0' || next == '/' || mnt[cmp_len - 1] == '/') {
				/*
				 * Longest Prefix Match:
				 * If we have both "/" and "/data" mounted,
				 * path "/data/file" should match "/data" (len=5), not "/" (len=1).
				 */
				if (cmp_len > best_len) {
					best_len = cmp_len;
					best_match = fs;
				}
			}
		}
	}

	/* Fallback for relative paths to root fs */
	if (!best_match && !is_absolute)
		best_match = list_first_entry_or_null(&__fslist,
				struct file_system, node);

	return best_match;
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
	char *dst = NULL, *ptr = NULL, *end = NULL;
	struct process *proc = current->proc;
	struct file_system *fs = p->fs;
	size_t mnt_len = strlen(fs->mnt.path);
	size_t prefix_len = 0;
	size_t alloc_len = 0;
	const char *suffix = NULL;

	FMSG("alloc_path %s\n", p->path);

	if (!proc->c->privilege)
		prefix_len = strlen(proc->c->name);

	/*
	 * Calculate suffix: the path relative to the mount point.
	 * For "/ree/file" on mount "/ree", suffix is "/file".
	 */
	suffix = p->path + mnt_len;
	if (p->path[0] != '/' && mnt_len > 0)
		suffix--;

	/* Calculate allocation size conservatively */
	alloc_len = strlen(p->path) + prefix_len + mnt_len + 4;
	if (alloc_len >= FS_PATH_MAX)
		return -ENAMETOOLONG;

	dst = kmalloc(alloc_len);
	if (!dst)
		return -ENOMEM;

	ptr = dst;
	end = dst + alloc_len;

	/* 1. Mount point (e.g. "/ree" or "/") */
	ptr += strlcpy(ptr, fs->mnt.path, end - ptr);

	/* 2. Prefix for non-privileged processes */
	if (prefix_len) {
		/* Add separator between mount point and prefix if needed */
		if (ptr > dst && *(ptr - 1) != '/' && ptr < end)
			*ptr++ = '/';
		ptr += strlcpy(ptr, proc->c->name, end - ptr);
	}

	/* 3. Suffix - normalize to avoid double slashes */
	if (ptr > dst && *(ptr - 1) != '/' && suffix[0] != '/' && suffix[0] != '\0') {
		if (ptr < end)
			*ptr++ = '/';
	} else if (ptr > dst && *(ptr - 1) == '/' && suffix[0] == '/') {
		suffix++;
	}
	strlcpy(ptr, suffix, end - ptr);

	FMSG("relpath %s\n\n", dst);
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
	size_t totalsz = 0, idlesz = 0;

	spin_lock_irqsave(&__fslock, flags);
	list_for_each_entry(fs, &__fslist, node) {
		debugfs_printf(d, "%s\ttype %s\ton %s", fs->name,
			fs->type, fs->mnt.path);
		if (strlen(fs->mnt.path) < 4)
			debugfs_printf(d, "\t");

		if (fs->getsize) {
			fs->getsize(fs, &totalsz, &idlesz);
			debugfs_printf(d, "   %08lx %08lx",
				(unsigned long)totalsz, (unsigned long)idlesz);
		}

		if (fs->mnt.addr)
			debugfs_printf(d, " %p", fs->mnt.addr);

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
