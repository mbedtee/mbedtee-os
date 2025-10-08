// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
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

#include <mbedtls/gcm.h>

#include <reefs_rpc.h>

/*
 * (AES-128-GCM encrypted with host-key-iv inside TEE)
 *
 * reefs-file-struct =
 * 56 bytes header-aad (length + version + times + aad(uuid)) +
 * 16 bytes header-tag + 16 bytes key + 16 bytes iv +
 * 16 bytes block0-tag + block0-payload +
 * 16 bytes block1-tag + block1-payload + ...
 * 16 bytes blockN-tag + blockN-payload
 *
 * (app's uuid is enforced-added to aad) (payload-aad = app-uuid + payload offset)
 */
struct reefs_hdr {
	/* total-payloads-len */
	uint64_t length;
	/* current file version for anti-rollback */
	uint64_t version;

	uint64_t atime; /* time of last access */
	uint64_t mtime; /* time of last modification */
	uint64_t ctime; /* time of last status change */

	/* GCM aad (APP uuid) */
	unsigned char aad[16];

	/* GCM tag of key-iv */
	unsigned char tag[16];
	/* key for payload */
	unsigned char key[16];
	/* iv for payload */
	unsigned char iv[16];
};

struct reefs_block {
	/* GCM tag of block payload */
	unsigned char tag[16];
	unsigned char payload[4096 - 64];
};

struct reefs_fdesc {
	/* file descriptor in REEFS */
	int reefd;
	/* file type, REG or DIR ? */
	int type;
	/* file header struct */
	struct reefs_hdr hdr;
};

struct reefs {
	struct mutex mlock;
};

static const unsigned char reefs_root_key[16] = {
	0xc8, 0xef, 0xa2, 0xf0, 0xbb, 0x56, 0xa7, 0xef,
	0x44, 0x88, 0xd3, 0x21, 0x50, 0x4d, 0xab, 0x87
};
static const unsigned char reefs_root_iv[16] = {
	0x23, 0x24, 0xe7, 0x4b, 0xae, 0x33, 0xc3, 0x4a,
	0x74, 0xe7, 0x08, 0xf4, 0xa5, 0xd4, 0x73, 0xe1
};

#define reefs_pos(x) ({                                           \
	off_t __b = sizeof(((struct reefs_block *)0)->payload);      \
	off_t __p = ((off_t)(x)) / __b * sizeof(struct reefs_block);\
	__p + sizeof(struct reefs_hdr);                              })

#define reefs_len(x) ({                                           \
	size_t __b = sizeof(((struct reefs_block *)0)->payload);     \
	size_t __p = roundup((size_t)(x), __b);                       \
	__p = __p / __b * sizeof(struct reefs_block);                 \
	__p + sizeof(struct reefs_hdr);                              })

static inline void reefs_lock(struct reefs *fs)
{
	mutex_lock(&fs->mlock);
}

static inline void reefs_unlock(struct reefs *fs)
{
	mutex_unlock(&fs->mlock);
}

static inline struct reefs *file2reefs(struct file *f)
{
	return (struct reefs *)f->fs->priv;
}

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

static inline int reefs_retof(int mbedret)
{
	switch (mbedret) {
	case 0:
		return 0;
	case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
		return -ENOMEM;
	case MBEDTLS_ERR_CIPHER_AUTH_FAILED:
		return -EBADMSG;
	default:
		return -EINVAL;
	}
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
	mbedtls_gcm_context gcm;
	struct process *proc = current->proc;

	mbedtls_gcm_init(&gcm);

	ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, reefs_root_key, 128);
	if (ret != 0)
		goto out;

	ret = mbedtls_gcm_starts(&gcm, mode, reefs_root_iv, 16);
	if (ret != 0)
		goto out;

	aad = proc->c->privilege ? &hdr->aad : (void *)&proc->c->uuid;
	ret = mbedtls_gcm_update_ad(&gcm, aad, sizeof(TEE_UUID));
	ret |= mbedtls_gcm_update_ad(&gcm, (void *)&hdr->length,
			sizeof(hdr->length) + sizeof(hdr->version) + sizeof(hdr->atime) +
			sizeof(hdr->mtime) + sizeof(hdr->ctime));
	if (ret != 0)
		goto out;

	ret = mbedtls_gcm_update(&gcm, hdr->key, sizeof(hdr->key) + sizeof(hdr->iv),
				hdr->key, sizeof(hdr->key) + sizeof(hdr->iv), &olen);
	if (ret != 0)
		goto out;

	ret = mbedtls_gcm_finish(&gcm, NULL, 0, &olen, tag, sizeof(hdr->tag));
	if (ret != 0)
		goto out;

	if (mode == MBEDTLS_GCM_DECRYPT) {
		if (memcmp(tag, hdr->tag, sizeof(hdr->tag)) != 0) {
			ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
			goto out;
		}
	} else {
		memcpy(hdr->tag, tag, sizeof(hdr->tag));
	}

out:
	mbedtls_gcm_free(&gcm);
	return reefs_retof(ret);
}

static int reefs_create_hdr(struct file *f, struct reefs_hdr *hdr, mode_t mode)
{
	int ret = -1, fd = -1;

	fd = reefs_rpc_create(f->path, mode);
	if (fd < 0)
		return fd;

	reefs_fill_hdr(hdr, 0, 0);

	ret = reefs_crypt_hdr(hdr, MBEDTLS_GCM_ENCRYPT);
	if (ret != 0)
		goto out;

	ret = reefs_rpc_write(fd, hdr, sizeof(struct reefs_hdr));

out:
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

	ret = reefs_rpc_lseek(fd, 0, SEEK_SET);
	if (ret < 0)
		return ret;

	memcpy(&nhdr, hdr, sizeof(nhdr));

	nhdr.version++;

	ret = reefs_crypt_hdr(&nhdr, MBEDTLS_GCM_ENCRYPT);
	if (ret != 0)
		return ret;

	ret = reefs_rpc_write(fd, &nhdr, sizeof(struct reefs_hdr));
	if (ret < 0)
		return ret;

	hdr->version = nhdr.version;

	return ret;
}

static ssize_t reefs_read_hdr(int fd, struct reefs_hdr *hdr)
{
	ssize_t ret = -1;
	ssize_t rdbytes = -1;

	rdbytes = reefs_rpc_read(fd, hdr, sizeof(*hdr));
	if (rdbytes < 0)
		return rdbytes;

	ret = reefs_crypt_hdr(hdr, MBEDTLS_GCM_DECRYPT);
	if (ret != 0)
		return ret;

	return rdbytes;
}

static int reefs_crypt_block(off_t pos,
	struct reefs_hdr *hdr,
	struct reefs_block *block, int mode)
{
	int ret = -1;
	size_t olen = 0;
	void *aad = NULL;
	unsigned char tag[16];
	mbedtls_gcm_context gcm;
	struct process *proc = current->proc;

	mbedtls_gcm_init(&gcm);

	ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, hdr->key, 128);
	if (ret != 0)
		goto out;

	ret = mbedtls_gcm_starts(&gcm, mode, hdr->iv, 16);
	if (ret != 0)
		goto out;

	aad = proc->c->privilege ? &hdr->aad : (void *)&proc->c->uuid;
	ret = mbedtls_gcm_update_ad(&gcm, aad, sizeof(TEE_UUID));
	ret |= mbedtls_gcm_update_ad(&gcm, (void *)&pos, sizeof(pos));
	if (ret != 0)
		goto out;

	ret = mbedtls_gcm_update(&gcm, block->payload, sizeof(block->payload),
				block->payload, sizeof(block->payload), &olen);
	if (ret != 0)
		goto out;

	ret = mbedtls_gcm_finish(&gcm, NULL, 0, &olen, tag, sizeof(block->tag));
	if (ret != 0)
		goto out;

	if (mode == MBEDTLS_GCM_DECRYPT) {
		if (memcmp(tag, block->tag, sizeof(block->tag)) != 0) {
			ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
			goto out;
		}
	} else {
		memcpy(block->tag, tag, sizeof(block->tag));
	}

out:
	mbedtls_gcm_free(&gcm);
	return reefs_retof(ret);
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

	rdbytes = reefs_rpc_read(fdesc->reefd, block, sizeof(struct reefs_block));
	if (rdbytes < 0)
		return rdbytes;

	ret = reefs_crypt_block(pos, &fdesc->hdr, block, MBEDTLS_GCM_DECRYPT);
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

	ret = reefs_crypt_block(pos, &fdesc->hdr, block, MBEDTLS_GCM_ENCRYPT);
	if (ret != 0)
		return ret;

	return reefs_rpc_write(fdesc->reefd, block, sizeof(struct reefs_block));
}

static int reefs_openfile(struct reefs *fs, struct file *f, mode_t mode)
{
	int ret = -1, fd = -1;
	int flags = f->flags;
	int wrflag = flags & O_ACCMODE;
	struct reefs_fdesc *fdesc = NULL;
	struct reefs_hdr hdr = {0};

	ret = reefs_rpc_open(f->path, wrflag);
	if (ret < 0) {
		if (ret == -EISDIR)
			goto out;

		if ((flags & O_CREAT) == 0) {
			FMSG("ret %d\n", ret);
			goto out;
		}

		ret = reefs_create_hdr(f, &hdr, mode);
		if (ret < 0)
			goto out;

		fd = ret;
	} else {
		fd = ret;

		if (flags & O_EXCL) {
			ret = -EEXIST;
			goto out;
		}

		ret = reefs_read_hdr(fd, &hdr);
		if (ret < 0)
			goto out;

		if (wrflag && (flags & O_TRUNC)) {
			f->pos = hdr.length = 0;
			reefs_update_time(NULL, &hdr.mtime, &hdr.ctime);
			ret = reefs_update_hdr(fd, &hdr);
			if (ret > 0)
				ret = reefs_rpc_ftruncate(fd, sizeof(hdr));
		}

		if (ret < 0)
			goto out;
	}

	fdesc = kzalloc(sizeof(struct reefs_fdesc));
	if (fdesc == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	fdesc->reefd = fd;
	fdesc->type = DT_REG;
	memcpy(&fdesc->hdr, &hdr, sizeof(hdr));
	f->priv = fdesc;
	ret = 0;

out:
	if (ret < 0 && fd >= 0)
		reefs_rpc_close(fd);

	return ret;
}

static int reefs_opendir(struct reefs *fs, struct file *f, mode_t mode)
{
	int ret = -1, fd = -1;
	int flags = f->flags;
	struct reefs_fdesc *fdesc = NULL;

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
	if (fdesc == NULL) {
		ret = -ENOMEM;
		goto out;
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

	reefs_lock(fs);

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

	if (fdesc == NULL)
		return -EBADF;

	reefs_lock(fs);
	f->priv = NULL;
	if (fdesc->type == DT_DIR)
		reefs_rpc_closedir(fdesc->reefd);
	else
		reefs_rpc_close(fdesc->reefd);
	reefs_unlock(fs);

	kfree(fdesc);

	return 0;
}

static ssize_t reefs_read(struct file *f, void *buf, size_t cnt)
{
	ssize_t ret = -1, residue = 0;
	size_t offset = 0, rdbytes = 0, pos = 0;
	struct reefs *fs = file2reefs(f);
	struct reefs_fdesc *fdesc = f->priv;
	struct reefs_hdr *hdr = NULL;
	struct reefs_block *block = NULL;

	if (cnt == 0)
		return 0;

	if (fdesc == NULL)
		return -EBADF;

	if (buf == NULL)
		return -EINVAL;

	block = kmalloc(sizeof(struct reefs_block));
	if (block == NULL)
		return -ENOMEM;

	reefs_lock(fs);

	hdr = &fdesc->hdr;

	if ((uint64_t)f->pos >= hdr->length)
		goto out;

	cnt = min(hdr->length - (uint64_t)f->pos, (uint64_t)cnt);

	while (offset < cnt) {
		if (pos == 0) {
			/* convert TEE pos to REE file pos */
			pos = reefs_pos(f->pos);
			ret = reefs_rpc_lseek(fdesc->reefd, pos, SEEK_SET);
			if (ret < 0)
				goto out;
			residue = f->pos % sizeof(block->payload);
		} else {
			pos += sizeof(struct reefs_block);
			residue = 0;
		}
		ret = reefs_read_block(fdesc, pos, block);
		if (ret < 0) {
			if (offset != 0)
				ret = offset;
			reefs_rpc_lseek(fdesc->reefd, pos, SEEK_SET);
			goto out;
		}
		rdbytes = min(cnt - offset, sizeof(block->payload) - residue);
		memcpy(buf + offset, &block->payload[residue], rdbytes);
		offset += rdbytes;
		f->pos += rdbytes;
	}

	ret = offset;

out:
	if (ret > 0) {
		reefs_update_time(&hdr->atime, NULL, NULL);
		reefs_update_hdr(fdesc->reefd, hdr);
	}
	reefs_unlock(fs);
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

	pos = reefs_len(start);
	len = reefs_len(end);

	ret = reefs_rpc_lseek(fdesc->reefd, pos, SEEK_SET);
	if (ret < 0)
		return ret;

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
	size_t offset = 0, wrbytes = 0, pos = 0;
	struct reefs *fs = file2reefs(f);
	struct reefs_fdesc *fdesc = f->priv;
	struct reefs_hdr hdr = {0};
	struct reefs_block *block = NULL;

	if (cnt == 0)
		return 0;

	if (fdesc == NULL)
		return -EBADF;

	if (buf == NULL)
		return -EINVAL;

	block = kmalloc(sizeof(struct reefs_block));
	if (block == NULL)
		return -ENOMEM;

	reefs_lock(fs);

	memcpy(&hdr, &fdesc->hdr, sizeof(hdr));

	if (f->flags & O_APPEND) {
		ret = reefs_rpc_lseek(fdesc->reefd, 0, SEEK_END);
		f->pos = hdr.length;
	}

	/* fill the seek hole */
	if ((uint64_t)f->pos > hdr.length) {
		ret = reefs_fill_seekhole(fdesc, block, hdr.length, f->pos);
		if (ret < 0)
			goto out;
	}

	block_len = sizeof(block->payload);

	while (offset < cnt) {
		if (pos == 0) {
			/* convert TEE pos to REE file pos */
			pos = reefs_pos(f->pos);
			ret = reefs_rpc_lseek(fdesc->reefd, pos, SEEK_SET);
			if (ret < 0)
				goto out;
			residue = f->pos % block_len;
		} else {
			pos += sizeof(struct reefs_block);
			residue = 0;
		}

		if (residue) {
			ret = reefs_read_block(fdesc, pos, block);
			if (ret < 0)
				goto out;
			ret = reefs_rpc_lseek(fdesc->reefd, pos, SEEK_SET);
			if (ret < 0)
				goto out;
		}

		wrbytes = min(cnt - offset, block_len - residue);

		memcpy(&block->payload[residue], buf + offset, wrbytes);

		residue = block_len - residue - wrbytes;
		if (residue != 0)
			memset(&block->payload[block_len - residue], 0, residue);

		ret = reefs_write_block(fdesc, pos, block);
		if (ret < 0)
			goto out;
		offset += wrbytes;
	}

	if ((uint64_t)f->pos + offset > hdr.length)
		hdr.length = f->pos + offset;

	reefs_update_time(NULL, &hdr.mtime, &hdr.ctime);
	ret = reefs_update_hdr(fdesc->reefd, &hdr);
	if (ret < 0)
		goto out;

	memcpy(&fdesc->hdr, &hdr, sizeof(hdr));

	f->pos += offset;
	ret = offset;

out:
	reefs_unlock(fs);
	kfree(block);
	return ret;
}

static off_t reefs_lseek(struct file *f, off_t offset, int whence)
{
	off_t ret = -1;
	struct reefs *fs = file2reefs(f);
	struct reefs_fdesc *fdesc = f->priv;

	if (fdesc == NULL)
		return -EBADF;

	reefs_lock(fs);

	if (whence == SEEK_CUR)
		ret = f->pos + offset;
	else if (whence == SEEK_SET)
		ret = offset;
	else if (whence == SEEK_END) {
		ret = (fdesc->type != DT_DIR) ?
			fdesc->hdr.length + offset : -EINVAL;
	} else {
		ret = -EINVAL;
		goto out;
	}

	if (ret >= 0) {
		if (fdesc->type != DT_DIR)
			f->pos = ret;
		else
			reefs_rpc_seekdir(fdesc->reefd, ret);
	} else
		ret = -EINVAL;

out:
	reefs_unlock(fs);
	return ret;
}

static int reefs_ftruncate(struct file *f, off_t length)
{
	off_t ret = -1, len = 0;
	struct reefs *fs = file2reefs(f);
	struct reefs_fdesc *fdesc = f->priv;
	struct reefs_hdr hdr = {0};
	struct reefs_block *block = NULL;

	if (length < 0)
		return -EFBIG;

	if (fdesc == NULL)
		return -EBADF;

	reefs_lock(fs);

	memcpy(&hdr, &fdesc->hdr, sizeof(hdr));

	if (hdr.length == (uint64_t)length) {
		ret = 0;
		goto out;
	}

	if (hdr.length > (uint64_t)length) {
		/* convert TEE len to REE file len */
		len = reefs_len(length);
		ret = reefs_rpc_ftruncate(fdesc->reefd, len);
	} else {
		block = kmalloc(sizeof(struct reefs_block));
		if (block != NULL)
			ret = reefs_fill_seekhole(fdesc, block, hdr.length, length);
		else
			ret = -ENOMEM;
	}
	if (ret < 0)
		goto out;

	hdr.length = length;
	reefs_update_time(NULL, &hdr.mtime, &hdr.ctime);
	ret = reefs_update_hdr(fdesc->reefd, &hdr);
	if (ret < 0)
		goto out;

	memcpy(&fdesc->hdr, &hdr, sizeof(hdr));

	ret = 0;

out:
	reefs_unlock(fs);
	kfree(block);
	return ret;
}

static int reefs_fstat(struct file *f, struct stat *st)
{
	struct reefs *fs = file2reefs(f);
	struct reefs_fdesc *fdesc = f->priv;
	struct reefs_hdr *hdr = NULL;

	if (fdesc == NULL)
		return -EBADF;

	if (st == NULL)
		return -EINVAL;

	reefs_lock(fs);

	hdr = &fdesc->hdr;
	st->st_size = hdr->length;
	st->st_blksize = sizeof(((struct reefs_block *)0)->payload);
	st->st_blocks = hdr->length / st->st_blksize;
	if (hdr->length % st->st_blksize)
		st->st_blocks++;

	if (fdesc->type == DT_DIR)
		st->st_mode = S_IFDIR;
	else
		st->st_mode = S_IFREG;

	st->st_atime = hdr->atime;
	st->st_mtime = hdr->mtime;
	st->st_ctime = hdr->ctime;

	reefs_unlock(fs);
	return 0;
}

static int reefs_rename(struct file_system *pfs,
	const char *oldpath, const char *newpath)
{
	int ret = -1;
	struct reefs *fs = pfs->priv;

	if (!newpath || !oldpath)
		return -EINVAL;

	reefs_lock(fs);
	ret = reefs_rpc_rename(oldpath, newpath);
	reefs_unlock(fs);

	return ret;
}

static int reefs_unlink(struct file_system *pfs, const char *path)
{
	int ret = -1;
	struct reefs *fs = pfs->priv;

	if (!path)
		return -EINVAL;

	reefs_lock(fs);
	ret = reefs_rpc_unlink(path);
	reefs_unlock(fs);

	return ret;
}

static ssize_t reefs_readdir(struct file *f,
	struct dirent *d, size_t cnt)
{
	unsigned char rbuf[960];
	ssize_t ret = 0, str_len = 0;
	ssize_t rdbytes = 0, lastdoff = f->pos;
	struct reefs *fs = file2reefs(f);
	struct reefs_fdesc *fdesc = f->priv;
	struct reefs_dirent *r = (struct reefs_dirent *)rbuf;

	if (fdesc == NULL)
		return -EBADF;

	if (d == NULL && cnt != 0)
		return -EINVAL;

	reefs_lock(fs);

	while (cnt) {
		r = (struct reefs_dirent *)rbuf;
		rdbytes = min(sizeof(rbuf), cnt);
		rdbytes = reefs_rpc_readdir(fdesc->reefd, r, rdbytes);
		if (rdbytes <= 0) {
			if (rdbytes == 0)
				rdbytes = EOF;
			if (ret == 0)
				ret = rdbytes;
			goto out;
		}

		/* EOF ? */
		if (rdbytes < (min(sizeof(rbuf), cnt) >> 1))
			cnt = 0;
		else
			cnt -= rdbytes;

		while (rdbytes) {
			d->d_reclen = r->d_reclen;
			str_len = strnlen(r->d_name, rdbytes) + 1;

			if ((size_t)str_len > d->d_reclen ||
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
	reefs_unlock(fs);
	return ret;
}

static int reefs_mkdir(struct file_system *pfs,
	const char *path, mode_t mode)
{
	int ret = -1;
	struct reefs *fs = pfs->priv;

	if (path == NULL)
		return -EINVAL;

	reefs_lock(fs);
	ret = reefs_rpc_mkdir(path, mode);
	reefs_unlock(fs);

	return ret;
}

static int reefs_rmdir(struct file_system *pfs, const char *path)
{
	int ret = -1;
	struct reefs *fs = pfs->priv;

	if (path == NULL)
		return -EINVAL;

	reefs_lock(fs);
	ret = reefs_rpc_rmdir(path);
	reefs_unlock(fs);
	return ret;
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
	if (fs == NULL)
		return -ENOMEM;

	mutex_init(&fs->mlock);
	pfs->fops = &reefs_fops;
	pfs->priv = fs;
	pfs->type = "reefs";

	return 0;
}

int reefs_umount(struct file_system *pfs)
{
	struct reefs *fs = pfs->priv;

	pfs->fops = NULL;
	pfs->priv = NULL;

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

	fs_mount(&reefs_fs);

	kfree(dw);
}

static void __init reefs_init(void)
{
#if defined(CONFIG_ARM)
	if (!is_security_extn_ena())
		return;
#endif

	struct delayed_work *dw = kmalloc(sizeof(*dw));

	INIT_DELAYED_WORK(dw, __reefs_init);
	schedule_delayed_work(dw, 200000);
}

MODULE_INIT_LATE(reefs_init);
