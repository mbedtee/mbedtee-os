// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * REEFS (TEE to access REE file system)
 */

#include <fs.h>
#include <init.h>
#include <trace.h>
#include <errno.h>
#include <fcntl.h>
#include <prng.h>
#include <ktime.h>
#include <thread.h>
#include <list.h>
#include <kmalloc.h>
#include <string.h>

#include <mbedtee_memcmp.h>
#include <mbedcrypto.h>

#include <reefs_rpc.h>
#include <otp_huk.h>

#include "reefs_rpmb.h"

#define REEFS_MAX_FILE_SIZE (1024 * 1024 * 1024) /* 1GB */
#define REEFS_MAX_HOLE_SIZE (1024 * 1024) /* 1MB */

/*
 * (AES-128-GCM encrypted with host-key-iv inside TEE)
 *
 * reefs-file-struct =
 * 104 bytes header-aad {length + version + times + aad(uuid) +
 * 16 bytes header-tag + 16 bytes key + 16 bytes iv} +
 * 16 bytes block0-tag + block0-payload +
 * 16 bytes block1-tag + block1-payload + ...
 * 16 bytes blockN-tag + blockN-payload
 *
 * (app's uuid is enforced-added to aad)
 * (payload-aad = app-uuid + payload offset)
 *
 * struct reefs_hdr is defined in reefs_rpmb.h
 */

struct reefs_block {
	/* GCM tag of block payload */
	unsigned char tag[16];
	unsigned char payload[0x800];
};

struct reefs_inode {
	struct list_head node;
	struct mutex lock;
	char *path;
	int reefd;
	int refcnt;
	int dirty;
	int rpmb_dirty;
	int unlinked;
	struct reefs_hdr hdr;
	struct mbedcrypto_aes_gcm_ctx gcm_ctx;
};

struct reefs_fdesc {
	struct reefs_inode *inode;
	/* file descriptor in REEFS */
	int reefd;
	/* file type, REG or DIR ? */
	int type;
	/* file header struct */
	struct reefs_hdr hdr;
};

struct reefs {
	struct mutex mlock;
	struct list_head inodes;
};

#define reefs_pos(x) ({                                           \
	off_t __b = sizeof(((struct reefs_block *)0)->payload);       \
	off_t __p = ((off_t)(x)) / __b * sizeof(struct reefs_block);  \
	__p + sizeof(struct reefs_hdr);                              })

#define reefs_len(x) ({                                           \
	size_t __b = sizeof(((struct reefs_block *)0)->payload);      \
	size_t __p = roundup((size_t)(x), __b);                       \
	__p = __p / __b * sizeof(struct reefs_block);                 \
	__p + sizeof(struct reefs_hdr);                              })

static unsigned char reefs_root_key[16];
static unsigned char reefs_root_iv[16];

static int reefs_generate_keys(void)
{
	int ret = -1;
	uint8_t huk[32];
	const unsigned char salt[] = "mbedtee-reefs-salt";
	ret = otp_get_huk(huk, sizeof(huk));
	if (ret != 0) {
		EMSG("Failed to get HUK from OTP! (ret=%d)\n", ret);
		return ret;
	}

	ret = mbedcrypto_hkdf_derive(salt, sizeof(salt), huk, sizeof(huk),
			(const unsigned char *)"REEFS-KEY", 9, reefs_root_key, 16);
	if (ret != 0) {
		EMSG("Failed to derive REEFS key (ret=%d)\n", ret);
		memset(huk, 0, sizeof(huk));
		return -EPERM;
	}

	ret = mbedcrypto_hkdf_derive(salt, sizeof(salt), huk, sizeof(huk),
			(const unsigned char *)"REEFS-IV", 8, reefs_root_iv, 16);
	if (ret != 0) {
		EMSG("Failed to derive REEFS IV (ret=%d)\n", ret);
		memset(huk, 0, sizeof(huk));
		return -EPERM;
	}

	/*
	 * Zero HUK after use to prevent sensitive
	 * key material from remaining in memory
	 */
	memset(huk, 0, sizeof(huk));

	return 0;
}

static inline int reefs_lock(struct reefs *fs)
{
	return mutex_lock_interruptible(&fs->mlock);
}

static inline void reefs_unlock(struct reefs *fs)
{
	mutex_unlock(&fs->mlock);
}

static inline int reefs_inode_lock(struct reefs_inode *inode)
{
	return mutex_lock_interruptible(&inode->lock);
}

static inline void reefs_inode_unlock(struct reefs_inode *inode)
{
	mutex_unlock(&inode->lock);
}

static inline struct reefs *file2reefs(struct file *f)
{
	return f->fs->priv;
}

/*
 * Update file timestamps.
 * Similar to Linux VFS touch_atime/update_time.
 */
static void reefs_update_time(uint64_t *atime,
	uint64_t *mtime, uint64_t *ctime)
{
	time_t tsec = 0;

	get_systime(&tsec, NULL);

	if (atime)
		*atime = tsec;
	if (mtime)
		*mtime = tsec;
	if (ctime)
		*ctime = tsec;
}

static void reefs_fill_hdr(struct reefs_hdr *hdr,
	uint64_t len, uint64_t version)
{
	struct process *proc = current->proc;

	hdr->length = len;
	hdr->version = version;

	reefs_update_time(&hdr->atime, &hdr->mtime, &hdr->ctime);

	prng(hdr->key, sizeof(hdr->key));
	prng(hdr->iv, sizeof(hdr->iv));

	if (proc->c->privilege)
		prng(hdr->aad, sizeof(hdr->aad));
	else
		memcpy(hdr->aad, &proc->c->uuid, sizeof(hdr->aad));
}

static int reefs_crypt_hdr(struct reefs_hdr *hdr, int mode)
{
	int ret = -1;
	size_t olen = 0;
	void *aad = NULL;
	unsigned char tag[16];
	struct mbedcrypto_aes_gcm_ctx gcm;
	struct process *proc = current->proc;

	ret = mbedcrypto_aes_gcm_setkey(&gcm, reefs_root_key, 128);
	if (ret != 0)
		goto out;

	ret = mbedcrypto_aes_gcm_start(&gcm, mode, reefs_root_iv, 16);
	if (ret != 0)
		goto out;

	aad = proc->c->privilege ? &hdr->aad : (void *)&proc->c->uuid;
	ret = mbedcrypto_aes_gcm_update_aad(&gcm, aad, sizeof(TEE_UUID));
	ret |= mbedcrypto_aes_gcm_update_aad(&gcm, (void *)&hdr->length,
			sizeof(hdr->length) + sizeof(hdr->version) + sizeof(hdr->atime) +
			sizeof(hdr->mtime) + sizeof(hdr->ctime));
	if (ret != 0)
		goto out;

	ret = mbedcrypto_aes_gcm_update(&gcm, hdr->key, sizeof(hdr->key) + sizeof(hdr->iv),
				hdr->key, &olen);
	if (ret != 0)
		goto out;

	ret = mbedcrypto_aes_gcm_final(&gcm, tag, sizeof(hdr->tag));
	if (ret != 0)
		goto out;

	if (mode == MBEDCRYPTO_AES_DECRYPT) {
		if (mbedtee_memcmp(tag, hdr->tag, sizeof(hdr->tag)) != 0) {
			/* Clear sensitive fields on auth failure */
			memset(hdr->key, 0, sizeof(hdr->key));
			memset(hdr->iv, 0, sizeof(hdr->iv));
			ret = -EBADMSG;
			goto out;
		}
	} else {
		memcpy(hdr->tag, tag, sizeof(hdr->tag));
	}

out:
	mbedcrypto_aes_gcm_cleanup(&gcm);
	return ret;
}

static int reefs_create_hdr(struct file *f, struct reefs_hdr *hdr, mode_t mode)
{
	int ret = -1, fd = -1;
	int flags = (f->flags & ~O_ACCMODE) | O_RDWR | O_CREAT | O_TRUNC | O_EXCL;
	struct reefs_hdr ehdr = {0};

	fd = reefs_rpc_open(f->path, flags);
	if (fd < 0)
		return fd;

	reefs_fill_hdr(hdr, 0, 0);

	/* Encrypt to temporary buffer to preserve plaintext hdr for caller */
	memcpy(&ehdr, hdr, sizeof(ehdr));
	ret = reefs_crypt_hdr(&ehdr, MBEDCRYPTO_AES_ENCRYPT);
	if (ret != 0)
		goto out;

	ret = reefs_rpc_pwrite(fd, &ehdr, sizeof(struct reefs_hdr), 0);
	if (ret != sizeof(struct reefs_hdr)) {
		EMSG("pwrite ret=%d expect=%d\n", ret,
			(int)sizeof(struct reefs_hdr));
		ret = (ret < 0) ? ret : -EIO;
		goto out;
	}
	ret = 0;

out:
	memset(&ehdr, 0, sizeof(ehdr));
	if (ret < 0) {
		reefs_rpc_close(fd);
		reefs_rpc_unlink(f->path);
		return ret;
	}
	return fd;
}

static int reefs_update_hdr(int fd, struct reefs_hdr *hdr)
{
	int ret = -1;
	struct reefs_hdr nhdr = {0};

	memcpy(&nhdr, hdr, sizeof(nhdr));

	nhdr.version++;

	ret = reefs_crypt_hdr(&nhdr, MBEDCRYPTO_AES_ENCRYPT);
	if (ret != 0)
		return ret;

	ret = reefs_rpc_pwrite(fd, &nhdr, sizeof(struct reefs_hdr), 0);
	if (ret != sizeof(struct reefs_hdr)) {
		EMSG("pwrite ret=%d expect=%d\n", ret,
			(int)sizeof(struct reefs_hdr));
		return (ret < 0) ? ret : -EIO;
	}

	hdr->version = nhdr.version;

	return 0;
}

static ssize_t reefs_read_hdr(int fd, struct reefs_hdr *hdr)
{
	ssize_t ret = -1;
	ssize_t rdbytes = -1;

	rdbytes = reefs_rpc_pread(fd, hdr, sizeof(*hdr), 0);
	if (rdbytes != sizeof(*hdr)) {
		EMSG("pread ret=%d expect=%d\n", (int)rdbytes,
			(int)sizeof(struct reefs_hdr));
		return (rdbytes < 0) ? rdbytes : -EIO;
	}

	ret = reefs_crypt_hdr(hdr, MBEDCRYPTO_AES_DECRYPT);
	if (ret != 0) {
		EMSG("read_hdr: decrypt failed %zd\n", ret);
		return ret;
	}

	return rdbytes;
}

static int reefs_truncate_header(int fd, struct reefs_hdr *hdr)
{
	int ret = -1;

	hdr->length = 0;
	reefs_update_time(NULL, &hdr->mtime, &hdr->ctime);

	ret = reefs_update_hdr(fd, hdr);
	if (ret != 0)
		return ret;

	return reefs_rpc_ftruncate(fd, sizeof(struct reefs_hdr));
}

/*
 * Flush inode header to REE file only (no RPMB sync).
 * Used during write for crash consistency without the
 * overhead of RPMB anti-rollback update on every write.
 */
static int reefs_flush_hdr(struct reefs_inode *inode)
{
	int ret = 0;

	if (inode->dirty) {
		ret = reefs_update_hdr(inode->reefd, &inode->hdr);
		if (ret == 0) {
			inode->dirty = 0;
			inode->rpmb_dirty = 1;
		} else {
			EMSG("flush_hdr: update_hdr failed %d\n", ret);
		}
	}
	return ret;
}

/*
 * Full flush: update REE header + sync to RPMB.
 * Used on close/fsync for anti-rollback protection.
 */
static int reefs_flush_inode(struct reefs_inode *inode)
{
	int ret = 0;

	if (inode->dirty) {
		ret = reefs_update_hdr(inode->reefd, &inode->hdr);
		if (ret == 0) {
			inode->dirty = 0;
			inode->rpmb_dirty = 0;
			if (!inode->unlinked)
				reefs_rpmb_store_hdr(inode->path, &inode->hdr);
		} else {
			EMSG("flush_inode: update_hdr failed %d\n", ret);
		}
	} else if (inode->rpmb_dirty) {
		inode->rpmb_dirty = 0;
		if (!inode->unlinked)
			reefs_rpmb_store_hdr(inode->path, &inode->hdr);
	}
	return ret;
}

static struct reefs_inode *reefs_get_inode(
	struct reefs *fs, const char *path)
{
	struct reefs_inode *inode = NULL;

	list_for_each_entry(inode, &fs->inodes, node) {
		if (strcmp(inode->path, path) == 0) {
			inode->refcnt++;
			return inode;
		}
	}
	return NULL;
}

static struct reefs_inode *reefs_alloc_inode(
	struct reefs *fs, const char *path,
	int reefd, struct reefs_hdr *hdr)
{
	int ret = 0;
	struct reefs_inode *inode = kzalloc(sizeof(*inode));

	if (!inode)
		return NULL;

	inode->path = kmalloc(strlen(path) + 1);
	if (!inode->path) {
		kfree(inode);
		return NULL;
	}
	strcpy(inode->path, path);

	inode->reefd = reefd;
	memcpy(&inode->hdr, hdr, sizeof(*hdr));
	inode->refcnt = 1;

	mutex_init(&inode->lock);

	ret = mbedcrypto_aes_gcm_setkey(&inode->gcm_ctx,
			hdr->key, 128);
	if (ret != 0) {
		mutex_destroy(&inode->lock);
		mbedcrypto_aes_gcm_cleanup(&inode->gcm_ctx);
		kfree(inode->path);
		kfree(inode);
		return NULL;
	}

	list_add_tail(&inode->node, &fs->inodes);
	return inode;
}

static void reefs_put_inode(struct reefs *fs,
	struct reefs_inode *inode)
{
	if (--inode->refcnt == 0) {
		reefs_flush_inode(inode);
		reefs_rpc_close(inode->reefd);
		if (!inode->unlinked)
			list_del(&inode->node);
		mbedcrypto_aes_gcm_cleanup(&inode->gcm_ctx);
		mutex_destroy(&inode->lock);
		kfree(inode->path);
		kfree(inode);
	}
}

static int reefs_crypt_block(off_t pos,
	struct reefs_inode *inode,
	struct reefs_block *block, int mode)
{
	int ret = -1;
	size_t olen = 0;
	void *aad = NULL;
	unsigned char tag[16];
	struct process *proc = current->proc;
	struct reefs_hdr *hdr = &inode->hdr;

	ret = mbedcrypto_aes_gcm_start(&inode->gcm_ctx, mode, hdr->iv, 16);
	if (ret != 0)
		return ret;

	aad = proc->c->privilege ? &hdr->aad : (void *)&proc->c->uuid;
	ret = mbedcrypto_aes_gcm_update_aad(&inode->gcm_ctx, aad, sizeof(TEE_UUID));
	ret |= mbedcrypto_aes_gcm_update_aad(&inode->gcm_ctx, (void *)&pos, sizeof(pos));
	if (ret != 0)
		return ret;

	ret = mbedcrypto_aes_gcm_update(&inode->gcm_ctx, block->payload,
				 sizeof(block->payload), block->payload, &olen);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_aes_gcm_final(&inode->gcm_ctx,
				  tag, sizeof(block->tag));
	if (ret != 0)
		return ret;

	if (mode == MBEDCRYPTO_AES_DECRYPT) {
		if (mbedtee_memcmp(tag, block->tag, sizeof(block->tag)) != 0)
			return -EBADMSG;
	} else {
		memcpy(block->tag, tag, sizeof(block->tag));
	}

	return 0;
}

/*
 * read and decrypt a block
 * return number of bytes or errno
 */
static ssize_t reefs_read_block(struct reefs_fdesc *fdesc,
	off_t pos, struct reefs_block *block)
{
	ssize_t ret = -1;
	ssize_t rdbytes = 0;
	int fd = -1;

	if (!fdesc->inode)
		return -EINVAL;

	fd = fdesc->inode->reefd;

	rdbytes = reefs_rpc_pread(fd, block, sizeof(struct reefs_block), pos);
	if (rdbytes != sizeof(struct reefs_block)) {
		EMSG("pread ret=%d expect=%d\n", (int)rdbytes,
			(int)sizeof(struct reefs_block));
		return (rdbytes < 0) ? rdbytes : -EIO;
	}

	ret = reefs_crypt_block(pos, fdesc->inode, block, MBEDCRYPTO_AES_DECRYPT);
	if (ret != 0)
		return ret;

	return rdbytes;
}

/*
 * encrypt and write a block
 * return number of bytes or errno
 */
static int reefs_write_block(struct reefs_fdesc *fdesc,
	off_t pos, struct reefs_block *block)
{
	int ret = -1;
	int fd = -1;

	if (!fdesc->inode)
		return -EINVAL;

	fd = fdesc->inode->reefd;

	ret = reefs_crypt_block(pos, fdesc->inode, block, MBEDCRYPTO_AES_ENCRYPT);
	if (ret != 0)
		return ret;

	ret = reefs_rpc_pwrite(fd, block, sizeof(struct reefs_block), pos);
	if (ret != sizeof(struct reefs_block)) {
		EMSG("pwrite ret=%d expect=%d\n", ret,
			(int)sizeof(struct reefs_block));
		return (ret < 0) ? ret : -EIO;
	}

	return ret;
}

static int reefs_openfile(struct reefs *fs, struct file *f, mode_t mode)
{
	int ret = -1, fd = -1;
	int flags = f->flags;
	/*
	 * Always open with O_RDWR on REE side because reefs needs to:
	 * 1. Read the encrypted header even for write-only opens
	 * 2. Update metadata (mtime, etc.) even for read-only opens
	 */
	int wrflag = O_RDWR;
	struct reefs_fdesc *fdesc = NULL;
	struct reefs_hdr hdr = {0};
	struct reefs_inode *inode = NULL;

	inode = reefs_get_inode(fs, f->path);
	if (inode) {
		if (flags & O_EXCL) {
			reefs_put_inode(fs, inode);
			return -EEXIST;
		}
		if (wrflag && (flags & O_TRUNC)) {
			ret = reefs_truncate_header(inode->reefd, &inode->hdr);
			if (ret < 0) {
				reefs_put_inode(fs, inode);
				return ret;
			}
			inode->dirty = 0;
		}
	} else {
		int retry = 0;
retry_open:
		ret = reefs_rpc_open(f->path, wrflag);
		if (ret < 0) {
			if (ret == -EISDIR)
				return ret;

			if ((flags & O_CREAT) == 0)
				return ret;

			ret = reefs_create_hdr(f, &hdr, mode);
			if (ret < 0) {
				if (ret == -EEXIST && (flags & O_EXCL) == 0 && retry++ < 3)
					goto retry_open;
				return ret;
			}

			fd = ret;
		} else {
			fd = ret;

			if (flags & O_EXCL) {
				ret = -EEXIST;
				goto close_fd;
			}

			ret = reefs_read_hdr(fd, &hdr);
			if (ret < 0) {
				/*
				 * If it's a directory, return EISDIR to let caller
				 * retry with opendir.
				 */
				if (ret == -EISDIR)
					goto close_fd;

				/*
				 * REE header read/decrypt failed.
				 * Try to recover from RPMB backup.
				 */
				if (reefs_rpmb_load_hdr(f->path, &hdr) < 0) {
					DMSG("REEFS header recovery failed for %s\n", f->path);
					goto close_fd;
				}
				WMSG("REEFS recovered header from RPMB: %s\n", f->path);
				/*
				 * Recovered header - write it back to REE file.
				 * Re-encrypt with incremented version.
				 */
				ret = reefs_update_hdr(fd, &hdr);
				if (ret < 0)
					goto close_fd;
			} else {
				/*
				 * Normal path: verify REE header against
				 * RPMB for anti-rollback protection.
				 */
				ret = reefs_rpmb_verify_hdr(f->path, &hdr);
				if (ret < 0)
					goto close_fd;
			}

			if (wrflag && (flags & O_TRUNC)) {
				ret = reefs_truncate_header(fd, &hdr);
				if (ret < 0)
					goto close_fd;
			}
		}

		inode = reefs_alloc_inode(fs, f->path, fd, &hdr);
		if (!inode) {
			ret = -ENOMEM;
			goto close_fd;
		}
	}

	fdesc = kzalloc(sizeof(struct reefs_fdesc));
	if (!fdesc) {
		reefs_put_inode(fs, inode);
		return -ENOMEM;
	}

	fdesc->inode = inode;
	fdesc->type = DT_REG;
	f->priv = fdesc;
	return 0;

close_fd:
	reefs_rpc_close(fd);
	return ret;
}

static int reefs_opendir(struct reefs *fs, struct file *f, mode_t mode)
{
	int ret = -1, fd = -1;
	int flags = f->flags;
	struct reefs_fdesc *fdesc = NULL;
	struct reefs_stat rsp = {0};

	fd = reefs_rpc_opendir(f->path);
	if (fd < 0) {
		ret = fd;
		goto out;
	}

	if (flags & (O_ACCMODE | O_CREAT)) {
		ret = -EISDIR;
		goto out;
	}

	if (flags & (O_TRUNC | O_APPEND)) {
		ret = -EISDIR;
		goto out;
	}

	fdesc = kzalloc(sizeof(struct reefs_fdesc));
	if (!fdesc) {
		ret = -ENOMEM;
		goto out;
	}

	if (reefs_rpc_fstat(fd, &rsp, REEFS_O_DIRECTORY) == 0) {
		fdesc->hdr.atime = rsp.rst_atime;
		fdesc->hdr.mtime = rsp.rst_mtime;
		fdesc->hdr.ctime = rsp.rst_ctime;
		fdesc->hdr.length = rsp.rst_size;
	} else {
		reefs_update_time(NULL, &fdesc->hdr.mtime, NULL);
	}

	fdesc->reefd = fd;
	fdesc->type = DT_DIR;
	f->flags |= O_DIRECTORY;
	f->priv = fdesc;
	ret = 0;

out:
	if (ret < 0 && fd >= 0)
		reefs_rpc_closedir(fd);
	return ret;
}

static int reefs_open(struct file *f, mode_t mode, void *arg)
{
	int ret = -1;
	struct reefs *fs = file2reefs(f);

	ret = reefs_lock(fs);
	if (ret != 0)
		return ret;

	if ((f->flags & O_DIRECTORY) || fspath_isdir(f->path))
		ret = reefs_opendir(fs, f, mode);
	else {
		ret = reefs_openfile(fs, f, mode);
		if (ret == -EISDIR)
			ret = reefs_opendir(fs, f, mode);
	}

	reefs_unlock(fs);
	return ret;
}

static int reefs_close(struct file *f)
{
	struct reefs *fs = file2reefs(f);
	struct reefs_fdesc *fdesc = f->priv;

	if (!fdesc)
		return -EBADF;

	if (reefs_lock(fs) != 0)
		return -EINTR;

	f->priv = NULL;
	if (fdesc->type == DT_DIR)
		reefs_rpc_closedir(fdesc->reefd);
	else if (fdesc->inode)
		reefs_put_inode(fs, fdesc->inode);

	reefs_unlock(fs);

	kfree(fdesc);

	return 0;
}

static ssize_t reefs_read(struct file *f, void *buf, size_t cnt)
{
	ssize_t ret = -1, residue = 0;
	size_t offset = 0, rdbytes = 0, fpos = 0;
	struct reefs_fdesc *fdesc = f->priv;
	struct reefs_hdr *hdr = NULL;
	struct reefs_block *block = NULL;

	if (cnt == 0)
		return 0;

	if (!fdesc)
		return -EBADF;

	if (fdesc->type == DT_DIR)
		return -EISDIR;

	if (!fdesc->inode)
		return -EBADF;

	if (!buf)
		return -EINVAL;

	block = kmalloc(sizeof(struct reefs_block));
	if (!block)
		return -ENOMEM;

	if (reefs_inode_lock(fdesc->inode) != 0) {
		kfree(block);
		return -EINTR;
	}

	hdr = &fdesc->inode->hdr;

	if ((uint64_t)f->pos >= hdr->length) {
		ret = 0;  /* EOF - return 0, not error */
		goto out;
	}

	cnt = min(hdr->length - (uint64_t)f->pos, (uint64_t)cnt);

	while (offset < cnt) {
		if (fpos == 0) {
			/* convert TEE pos to REE file pos */
			fpos = reefs_pos(f->pos);
			residue = f->pos % sizeof(block->payload);
		} else {
			fpos += sizeof(struct reefs_block);
			residue = 0;
		}
		ret = reefs_read_block(fdesc, fpos, block);
		if (ret < 0) {
			if (offset != 0)
				ret = offset;
			goto out;
		}
		rdbytes = min(cnt - offset, sizeof(block->payload) - residue);
		memcpy(buf + offset, &block->payload[residue], rdbytes);
		offset += rdbytes;
		f->pos += rdbytes;
	}

	ret = offset;

out:
	/*
	 * Note: We intentionally do NOT update atime on read.
	 * Reasons:
	 * 1. Reduces flash wear (no header write on every read)
	 * 2. Avoids issues when TEE/REE time is not synchronized
	 * 3. atime has little practical value for secure storage
	 * 4. Similar to Linux 'noatime' mount option commonly used on flash
	 *
	 * mtime/ctime are still updated on write operations.
	 */
	reefs_inode_unlock(fdesc->inode);
	/* Clear sensitive data before freeing */
	memset(block, 0, sizeof(struct reefs_block));
	kfree(block);
	return ret;
}

static int reefs_fill_seekhole(
	struct reefs_fdesc *fdesc,
	struct reefs_block *block,
	off_t start, off_t end)
{
	int ret = -1;
	off_t len = 0, pos = 0;

	if (!fdesc->inode)
		return -EINVAL;

	pos = reefs_len(start);
	len = reefs_len(end);

	while (pos < len) {
		memset(&block->payload, 0, sizeof(block->payload));
		ret = reefs_write_block(fdesc, pos, block);
		if (ret < 0)
			return ret;
		pos += sizeof(struct reefs_block);
	}

	return 0;
}

static ssize_t reefs_write(struct file *f, const void *buf, size_t cnt)
{
	ssize_t ret = -1;
	size_t residue = 0, block_len = 0;
	size_t offset = 0, wrbytes = 0, fpos = 0;
	struct reefs_fdesc *fdesc = f->priv;
	struct reefs_hdr *hdr = NULL;
	struct reefs_block *block = NULL;

	if (cnt == 0)
		return 0;

	if (!fdesc)
		return -EBADF;

	if (fdesc->type == DT_DIR)
		return -EISDIR;

	if (!fdesc->inode)
		return -EBADF;

	if (!buf)
		return -EINVAL;

	if (cnt > REEFS_MAX_FILE_SIZE)
		return -EFBIG;

	block = kmalloc(sizeof(struct reefs_block));
	if (!block)
		return -ENOMEM;

	if (reefs_inode_lock(fdesc->inode) != 0) {
		kfree(block);
		return -EINTR;
	}

	hdr = &fdesc->inode->hdr;

	if (f->flags & O_APPEND)
		f->pos = hdr->length;

	if ((uint64_t)f->pos + cnt > REEFS_MAX_FILE_SIZE) {
		ret = -EFBIG;
		goto out;
	}

	/* fill the seek hole */
	if ((uint64_t)f->pos > hdr->length) {
		if ((uint64_t)f->pos - hdr->length > REEFS_MAX_HOLE_SIZE) {
			ret = -EFBIG;
			goto out;
		}
		ret = reefs_fill_seekhole(fdesc, block, hdr->length, f->pos);
		if (ret < 0)
			goto out;
	}

	block_len = sizeof(block->payload);

	while (offset < cnt) {
		if (fpos == 0) {
			/* convert TEE pos to REE file pos */
			fpos = reefs_pos(f->pos);
			residue = f->pos % block_len;
		} else {
			fpos += sizeof(struct reefs_block);
			residue = 0;
		}

		wrbytes = min(cnt - offset, block_len - residue);

		/*
		 * If we are not overwriting the whole block, we must read the
		 * existing block first, unless we are creating a new block
		 * past the current EOF.
		 */
		if (residue > 0 ||
		    (wrbytes < block_len &&
		     (f->pos + offset - residue) < hdr->length)) {
			ret = reefs_read_block(fdesc, fpos, block);
			if (ret < 0)
				goto out;
		} else {
			/* New block or full overwrite, just zero the buffer */
			if (wrbytes < block_len)
				memset(block->payload, 0, sizeof(block->payload));
		}

		memcpy(&block->payload[residue], buf + offset, wrbytes);

		ret = reefs_write_block(fdesc, fpos, block);
		if (ret < 0)
			goto out;
		offset += wrbytes;
	}

	if ((uint64_t)f->pos + offset > hdr->length) {
		hdr->length = f->pos + offset;
		fdesc->inode->dirty = 1;
	}

	reefs_update_time(NULL, &hdr->mtime, &hdr->ctime);

	fdesc->inode->dirty = 1;
	if (f->flags & O_SYNC) {
		ret = reefs_flush_hdr(fdesc->inode);
		if (ret < 0)
			goto out;
	}

	f->pos += offset;
	ret = offset;

out:
	reefs_inode_unlock(fdesc->inode);
	/* Clear sensitive data before freeing */
	memset(block, 0, sizeof(struct reefs_block));
	kfree(block);
	return ret;
}

static off_t reefs_lseek(struct file *f, off_t offset, int whence)
{
	off_t ret = -1, target = 0;
	struct reefs_fdesc *fdesc = f->priv;
	struct reefs_hdr *hdr = NULL;

	if (!fdesc)
		return -EBADF;

	if (fdesc->type == DT_DIR) {
		if (whence == SEEK_SET)
			target = offset;
		else if (whence == SEEK_CUR)
			target = f->pos + offset;
		else
			return -EINVAL;

		if (target < 0)
			return -EINVAL;

		ret = reefs_rpc_seekdir(fdesc->reefd, target);
		if (ret == 0) {
			f->pos = target;
			return target;
		}
		return ret;
	}

	if (!fdesc->inode)
		return -EBADF;

	if (reefs_inode_lock(fdesc->inode) != 0)
		return -EINTR;

	hdr = &fdesc->inode->hdr;

	if (whence == SEEK_CUR) {
		if (offset > 0 && f->pos > REEFS_MAX_FILE_SIZE - offset) {
			ret = -EFBIG;
			goto out;
		}
		if (offset < 0 && f->pos < -offset) {
			ret = -EINVAL;
			goto out;
		}
		target = f->pos + offset;
	} else if (whence == SEEK_SET)
		target = offset;
	else if (whence == SEEK_END)
		target = hdr->length + offset;
	else {
		ret = -EINVAL;
		goto out;
	}

	if (target < 0) {
		ret = -EINVAL;
		goto out;
	}

	if (target > REEFS_MAX_FILE_SIZE) {
		ret = -EFBIG;
		goto out;
	}

	f->pos = target;
	ret = target;

out:
	reefs_inode_unlock(fdesc->inode);
	return ret;
}

static int reefs_ftruncate(struct file *f, off_t length)
{
	off_t ret = -1, len = 0;
	struct reefs_fdesc *fdesc = f->priv;
	struct reefs_hdr *hdr = NULL;
	struct reefs_block *block = NULL;
	int fd = -1;

	if (length < 0)
		return -EFBIG;

	if (length > REEFS_MAX_FILE_SIZE)
		return -EFBIG;

	if (!fdesc)
		return -EBADF;

	if (fdesc->type == DT_DIR)
		return -EISDIR;

	if (!fdesc->inode)
		return -EBADF;

	if (reefs_inode_lock(fdesc->inode) != 0)
		return -EINTR;

	hdr = &fdesc->inode->hdr;
	fd = fdesc->inode->reefd;

	if (hdr->length == (uint64_t)length) {
		reefs_inode_unlock(fdesc->inode);
		return 0;
	}

	if (hdr->length > (uint64_t)length) {
		/* convert TEE len to REE file len */
		len = reefs_len(length);
		ret = reefs_rpc_ftruncate(fd, len);
	} else {
		block = kmalloc(sizeof(struct reefs_block));
		if (block)
			ret = reefs_fill_seekhole(fdesc, block, hdr->length, length);
		else
			ret = -ENOMEM;
	}
	if (ret < 0)
		goto out;

	hdr->length = length;
	reefs_update_time(NULL, &hdr->mtime, &hdr->ctime);

	fdesc->inode->dirty = 1;
	ret = 0;

out:
	reefs_inode_unlock(fdesc->inode);
	kfree(block);
	return ret;
}

static int reefs_fstat(struct file *f, struct stat *st)
{
	int ret = 0;
	struct reefs_fdesc *fdesc = f->priv;
	struct reefs_hdr *hdr = NULL;

	if (!fdesc)
		return -EBADF;

	if (!st)
		return -EINVAL;

	if (fdesc->type == DT_DIR) {
		struct reefs_stat rsp = {0};

		st->st_mode = S_IFDIR;
		st->st_blocks = 1;

		ret = reefs_rpc_fstat(fdesc->reefd, &rsp, REEFS_O_DIRECTORY);
		if (ret == 0) {
			st->st_size = rsp.rst_size;
			st->st_atime = rsp.rst_atime;
			st->st_mtime = rsp.rst_mtime;
			st->st_ctime = rsp.rst_ctime;
			st->st_blksize = rsp.rst_size;
		}
	} else {
		if (!fdesc->inode)
			return -EBADF;

		if (reefs_inode_lock(fdesc->inode) != 0)
			return -EINTR;

		hdr = &fdesc->inode->hdr;

		st->st_size = hdr->length;
		st->st_blksize = sizeof(((struct reefs_block *)0)->payload);
		st->st_blocks = hdr->length / st->st_blksize;
		if (hdr->length % st->st_blksize)
			st->st_blocks++;

		st->st_mode = S_IFREG;

		st->st_atime = hdr->atime;
		st->st_mtime = hdr->mtime;
		st->st_ctime = hdr->ctime;

		reefs_inode_unlock(fdesc->inode);
	}

	return ret;
}

static int reefs_rename(struct file_system *pfs,
	const char *oldpath, const char *newpath)
{
	int ret = -1;
	struct reefs *fs = pfs->priv;
	struct reefs_inode *inode = NULL;
	size_t oldlen = 0, newlen = 0;
	size_t real_oldlen = 0, real_newlen = 0;
	size_t match_count = 0;
	size_t suffix_len = 0;
	struct reefs_rename_node {
		struct reefs_inode *inode;
		char *newpath;
	} *nodes = NULL;
	char *p = NULL;
	size_t i = 0;

	if (!newpath || !oldpath)
		return -EINVAL;

	oldlen = strlen(oldpath);
	newlen = strlen(newpath);

	real_oldlen = oldlen;
	while (real_oldlen > 1 && oldpath[real_oldlen - 1] == '/')
		real_oldlen--;

	real_newlen = newlen;
	while (real_newlen > 1 && newpath[real_newlen - 1] == '/')
		real_newlen--;

	if (reefs_lock(fs) != 0)
		return -EINTR;

	/* First pass: count matching inodes */
	list_for_each_entry(inode, &fs->inodes, node) {
		if (strncmp(inode->path, oldpath, real_oldlen) != 0)
			continue;

		if (inode->path[real_oldlen] == '\0')
			match_count++;
		else if (inode->path[real_oldlen] == '/')
			match_count++;
	}

	if (match_count == 0) {
		/*
		 * Source file not in cache.
		 * Perform RPC rename and invalidate destination inode if cached.
		 */
		ret = reefs_rpc_rename(oldpath, newpath);
		if (ret == 0) {
			reefs_rpmb_rename(oldpath, newpath);

			inode = reefs_get_inode(fs, newpath);
			if (inode) {
				inode->unlinked = 1;
				list_del(&inode->node);
				reefs_put_inode(fs, inode);
			}
		}
		reefs_unlock(fs);
		return ret;
	}

	/* Allocate contiguous arrays to reduce allocation overhead */
	nodes = kzalloc(match_count * sizeof(*nodes));
	if (!nodes) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	/*
	 * We cannot allocate a single large buffer for all paths because
	 * kfree() expects a pointer returned by kmalloc().
	 * So we must allocate each path individually.
	 * Reverting to individual allocations but keeping the array structure.
	 */

	/* Second pass: fill nodes and allocate new paths */
	i = 0;
	list_for_each_entry(inode, &fs->inodes, node) {
		p = NULL;
		if (strncmp(inode->path, oldpath, real_oldlen) != 0)
			continue;

		if (inode->path[real_oldlen] == '\0') {
			p = kmalloc(real_newlen + 1);
			if (p) {
				memcpy(p, newpath, real_newlen);
				p[real_newlen] = '\0';
			}
		} else if (inode->path[real_oldlen] == '/') {
			suffix_len = strlen(inode->path) - real_oldlen;
			p = kmalloc(real_newlen + suffix_len + 1);
			if (p) {
				memcpy(p, newpath, real_newlen);
				strcpy(p + real_newlen, inode->path + real_oldlen);
			}
		}

		if (p) {
			nodes[i].inode = inode;
			nodes[i].newpath = p;
			i++;
		} else {
			/* Allocation failed, cleanup and exit */
			ret = -ENOMEM;
			goto out_free_nodes;
		}
	}

	/* Perform RPC rename */
	ret = reefs_rpc_rename(oldpath, newpath);
	if (ret != 0)
		goto out_free_nodes;

	/* Rename RPMB mirror */
	reefs_rpmb_rename(oldpath, newpath);

	/*
	 * If newpath overwrote an existing active inode, unlink it.
	 * Must do this BEFORE updating source inode paths, otherwise
	 * reefs_get_inode(newpath) would find the renamed source inode
	 * instead of the overwritten destination inode.
	 */
	inode = reefs_get_inode(fs, newpath);
	if (inode) {
		inode->unlinked = 1;
		list_del(&inode->node);
		reefs_put_inode(fs, inode); /* drop the get reference */
	}

	/* Apply updates: transfer ownership of path buffers to inodes */
	for (i = 0; i < match_count; i++) {
		kfree(nodes[i].inode->path);
		nodes[i].inode->path = nodes[i].newpath;
		nodes[i].newpath = NULL; /* ownership moved */
	}

	ret = 0;

out_free_nodes:
	for (i = 0; i < match_count; i++)
		kfree(nodes[i].newpath);
	kfree(nodes);
out_unlock:
	reefs_unlock(fs);
	return ret;
}

static int reefs_unlink(struct file_system *pfs, const char *path)
{
	int ret = -1;
	struct reefs *fs = pfs->priv;
	struct reefs_inode *inode = NULL;

	if (!path)
		return -EINVAL;

	if (reefs_lock(fs) != 0)
		return -EINTR;

	ret = reefs_rpc_unlink(path);
	if (ret == 0 || ret == -ENOENT) {
		/* Unlink RPMB mirror */
		reefs_rpmb_unlink(path);

		inode = reefs_get_inode(fs, path);
		if (inode) {
			inode->unlinked = 1;
			list_del(&inode->node);
			/* drop the get reference */
			reefs_put_inode(fs, inode);
		}
	}

	reefs_unlock(fs);

	return ret;
}

static ssize_t reefs_readdir(struct file *f,
	struct dirent *d, size_t cnt)
{
	unsigned char *rbuf = NULL;
	ssize_t ret = 0, str_len = 0;
	ssize_t rdbytes = 0, lastdoff = f->pos;
	struct reefs_fdesc *fdesc = f->priv;
	struct reefs_dirent *r = NULL;
	size_t buf_size = 1024;

	if (!fdesc)
		return -EBADF;

	if (fdesc->type != DT_DIR)
		return -ENOTDIR;

	if (!d && cnt != 0)
		return -EINVAL;

	rbuf = kmalloc(buf_size);
	if (!rbuf)
		return -ENOMEM;

	while (cnt != 0) {
		r = (struct reefs_dirent *)rbuf;
		rdbytes = min(buf_size, cnt);
		rdbytes = reefs_rpc_readdir(fdesc->reefd, r, rdbytes);
		if (rdbytes <= 0) {
			if (ret == 0 && rdbytes < 0)
				ret = rdbytes;
			goto out;
		}

		/* EOF ? */
		if (rdbytes < (min(buf_size, cnt) >> 1))
			cnt = 0;
		else
			cnt -= rdbytes;

		while (rdbytes) {
			d->d_reclen = r->d_reclen;
			str_len = strnlen(r->d_name, rdbytes) + 1;

			if (d->d_reclen == 0 ||
				(size_t)str_len > d->d_reclen ||
				d->d_reclen > rdbytes) {
				if (ret == 0)
					ret = -E2BIG;
				goto out;
			}

			f->pos = lastdoff;
			lastdoff = r->d_off;
			d->d_off = r->d_off;
			d->d_type = r->d_type;

			memcpy(d->d_name, r->d_name, str_len);

			ret += d->d_reclen;
			rdbytes -= d->d_reclen;
			r = (void *)r + d->d_reclen;
			d = (void *)d + d->d_reclen;
		}
	}

out:
	kfree(rbuf);
	return ret;
}

static int reefs_mkdir(struct file_system *pfs,
	const char *path, mode_t mode)
{
	if (!path)
		return -EINVAL;

	return reefs_rpc_mkdir(path, mode);
}

static int reefs_rmdir(struct file_system *pfs, const char *path)
{
	if (!path)
		return -EINVAL;

	return reefs_rpc_rmdir(path);
}

static const struct file_operations reefs_fops = {
	.open = reefs_open,
	.close = reefs_close,
	.read = reefs_read,
	.write = reefs_write,
	.mmap = NULL,
	.ioctl = NULL,
	.poll = NULL,

	.lseek = reefs_lseek,
	.ftruncate = reefs_ftruncate,
	.fstat = reefs_fstat,
	.rename = reefs_rename,
	.unlink = reefs_unlink,

	.mkdir = reefs_mkdir,
	.readdir = reefs_readdir,
	.rmdir = reefs_rmdir,
};

int reefs_mount(struct file_system *pfs)
{
	struct reefs *fs = NULL;

	fs = kzalloc(sizeof(struct reefs));
	if (!fs)
		return -ENOMEM;

	mutex_init(&fs->mlock);
	INIT_LIST_HEAD(&fs->inodes);
	pfs->fops = &reefs_fops;
	pfs->priv = fs;
	pfs->type = "reefs";

	/* Initialize RPMB anti-rollback protection */
	reefs_rpmb_init();

	return 0;
}

int reefs_umount(struct file_system *pfs)
{
	struct reefs *fs = pfs->priv;
	struct reefs_inode *inode, *next;

	pfs->fops = NULL;
	pfs->priv = NULL;

	list_for_each_entry_safe(inode, next, &fs->inodes, node) {
		EMSG("reefs_umount: inode %s still active (ref=%d)\n",
			inode->path, inode->refcnt);
		reefs_rpc_close(inode->reefd);
		list_del(&inode->node);
		mbedcrypto_aes_gcm_cleanup(&inode->gcm_ctx);
		mutex_destroy(&inode->lock);
		kfree(inode->path);
		kfree(inode);
	}

	mutex_destroy(&fs->mlock);

	kfree(fs);
	return 0;
}

static struct file_system reefs_fs = {
	.name = "reefs",
	.mnt = {"/ree", 0, 0},
	.mount = reefs_mount,
	.umount = reefs_umount,
	.getpath = fs_getpath,
	.putpath = fs_putpath,
};

static void __reefs_init(struct work *w)
{
	struct delayed_work *dw = NULL;
	dw = container_of(w, struct delayed_work, w);

	if (rpc_test_callee()) {
		if (reefs_generate_keys() == 0)
			fs_mount(&reefs_fs);
		kfree(dw);
	} else {
		schedule_delayed_work(dw, 200000);
	}
}

static void __init reefs_init(void)
{
	struct delayed_work *dw = NULL;

#if defined(CONFIG_ARM)
	if (!is_security_extn_ena())
		return;
#endif

	dw = kmalloc(sizeof(*dw));
	if (!dw)
		return;

	INIT_DELAYED_WORK(dw, __reefs_init);
	schedule_delayed_work(dw, 500000);
}

MODULE_INIT_LATE(reefs_init);
