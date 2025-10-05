// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * REEFS Anti-Rollback Protection via RPMB
 */

#include <fs.h>
#include <file.h>
#include <errno.h>
#include <fcntl.h>
#include <trace.h>
#include <string.h>

#include "reefs_rpmb.h"

#if defined(CONFIG_REEFS_ANTIROLLBACK_RPMB)

#define RPMB_PATH_MAX FS_NAME_MAX

/*
 * Build RPMB mirror path from REEFS path
 * REEFS file: /ree/TA/file
 * RPMB mirror: /rpmb/TA/file.reefs.hdr (stores reefs_hdr)
 *
 * RPMB FS uses flat namespace with '/' in filename,
 * so no need to create parent directories.
 */
static int reefs_rpmb_path(char *out, size_t outlen, const char *reefs_path)
{
	int ret = 0;

	while (*reefs_path == '/')
		reefs_path++;

	ret = snprintf(out, outlen, "/rpmb/%s.reefs.hdr", reefs_path);
	if (ret < 0 || (size_t)ret >= outlen)
		return -ENAMETOOLONG;

	DMSG("rpmbfs_path %s\n", out);

	return 0;
}

/*
 * Initialize RPMB protection
 */
int reefs_rpmb_init(void)
{
	IMSG("REEFS RPMB anti-rollback initialized\n");
	return 0;
}

/*
 * Load header from RPMB for recovery.
 * Called when REE header is corrupted or unreadable.
 */
int reefs_rpmb_load_hdr(const char *path, struct reefs_hdr *hdr)
{
	char rpmb_path[RPMB_PATH_MAX];
	int fd = 0, ret = 0;
	ssize_t n = 0;

	ret = reefs_rpmb_path(rpmb_path, sizeof(rpmb_path), path);
	if (ret < 0)
		return ret;

	fd = sys_open(rpmb_path, O_RDONLY);
	if (fd < 0)
		return fd;

	n = sys_read(fd, hdr, sizeof(struct reefs_hdr));
	sys_close(fd);

	if (n != sizeof(struct reefs_hdr)) {
		EMSG("RPMB load failed for %s: %zd\n", rpmb_path, n);
		return (n < 0) ? n : -EIO;
	}

	IMSG("RPMB header loaded for recovery: %s\n", path);
	return 0;
}

/*
 * Write header to RPMB using pre-built rpmb_path.
 * Opens without O_TRUNC so that if sys_write fails (e.g. ENOMEM),
 * the old RPMB record is preserved rather than destroyed.
 */
static int reefs_rpmb_write_hdr(const char *rpmb_path,
	const struct reefs_hdr *hdr)
{
	int fd = 0;
	ssize_t n = 0;

	fd = sys_open(rpmb_path, O_WRONLY | O_CREAT, 0600);
	if (fd < 0) {
		EMSG("RPMB open failed for %s: %d\n", rpmb_path, fd);
		return fd;
	}

	n = sys_write(fd, hdr, sizeof(struct reefs_hdr));

	sys_close(fd);

	if (n != sizeof(struct reefs_hdr)) {
		EMSG("RPMB write failed for %s: %zd\n", rpmb_path, n);
		return (n < 0) ? n : -EIO;
	}

	return 0;
}

/*
 * Store full header to RPMB after successful write.
 * This enables both anti-rollback protection and potential recovery.
 */
int reefs_rpmb_store_hdr(const char *path, const struct reefs_hdr *hdr)
{
	char rpmb_path[RPMB_PATH_MAX];
	int ret = 0;

	ret = reefs_rpmb_path(rpmb_path, sizeof(rpmb_path), path);
	if (ret < 0)
		return ret;

	return reefs_rpmb_write_hdr(rpmb_path, hdr);
}

/*
 * Verify REE header against RPMB mirror
 * Returns 0 if OK, -EBADMSG if rollback detected
 */
int reefs_rpmb_verify_hdr(const char *path, const struct reefs_hdr *hdr)
{
	char rpmb_path[RPMB_PATH_MAX];
	struct reefs_hdr rpmb_hdr;
	int fd = 0, ret = 0;
	ssize_t n = 0;

	ret = reefs_rpmb_path(rpmb_path, sizeof(rpmb_path), path);
	if (ret < 0)
		return ret;

	fd = sys_open(rpmb_path, O_RDONLY);
	if (fd < 0) {
		if (fd == -ENOENT) {
			/*
			 * No RPMB record exists - this is a new file or
			 * first access after enabling RPMB protection.
			 * Store current header as baseline.
			 */
			return reefs_rpmb_write_hdr(rpmb_path, hdr);
		}
		return fd;
	}

	n = sys_read(fd, &rpmb_hdr, sizeof(rpmb_hdr));

	sys_close(fd);

	if (n < 0) {
		EMSG("RPMB read error for %s: %zd\n", rpmb_path, n);
		return n;
	}

	if (n != sizeof(rpmb_hdr)) {
		/*
		 * Short read: RPMB record is corrupted (partial write
		 * from a previous non-atomic failure).  Unlink the
		 * corrupted record and re-establish baseline from
		 * current REE header.
		 */
		EMSG("RPMB record corrupted for %s (read %zd != %zu),"
			" rebuilding\n", rpmb_path, n, sizeof(rpmb_hdr));
		return reefs_rpmb_write_hdr(rpmb_path, hdr);
	}

	/* Anti-rollback check: REE version must not be less than RPMB version */
	if (hdr->version < rpmb_hdr.version) {
		EMSG("REEFS rollback detected: %s version %llu < RPMB %llu\n",
			path, (unsigned long long)hdr->version,
			(unsigned long long)rpmb_hdr.version);
		return -EBADMSG;
	}

	/*
	 * If REE version is greater, update RPMB record.
	 * This handles the case where file was legitimately updated
	 * but RPMB wasn't synced (e.g., crash recovery).
	 */
	if (hdr->version > rpmb_hdr.version) {
		DMSG("REEFS version advanced: %s version %llu > RPMB %llu, syncing\n",
			path, (unsigned long long)hdr->version,
			(unsigned long long)rpmb_hdr.version);
		return reefs_rpmb_write_hdr(rpmb_path, hdr);
	}

	return 0;
}

/*
 * Unlink RPMB mirror on file deletion
 */
int reefs_rpmb_unlink(const char *path)
{
	int ret = 0;
	char rpmb_path[RPMB_PATH_MAX];

	ret = reefs_rpmb_path(rpmb_path, sizeof(rpmb_path), path);
	if (ret < 0)
		return ret;

	ret = sys_unlink(rpmb_path);
	if (ret < 0 && ret != -ENOENT) {
		EMSG("RPMB unlink failed for %s: %d\n", rpmb_path, ret);
		return ret;
	}

	return 0;
}

/*
 * Rename RPMB mirror
 */
int reefs_rpmb_rename(const char *oldpath, const char *newpath)
{
	int ret = 0;
	char old_rpmb[RPMB_PATH_MAX];
	char new_rpmb[RPMB_PATH_MAX];

	ret = reefs_rpmb_path(old_rpmb, sizeof(old_rpmb), oldpath);
	if (ret < 0)
		return ret;

	ret = reefs_rpmb_path(new_rpmb, sizeof(new_rpmb), newpath);
	if (ret < 0)
		return ret;

	ret = sys_rename(old_rpmb, new_rpmb);
	if (ret < 0 && ret != -ENOENT) {
		EMSG("RPMB rename failed %s -> %s: %d\n", old_rpmb, new_rpmb, ret);
		return ret;
	}

	return 0;
}

#endif
