// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * mbedtest_misc.c -- Shared utility helpers (cleanup, mkpath, I/O).
 */

#include "mbedtest.h"
#include "mbedtest_internal.h"
#include <mmap.h>
#include <semaphore.h>

/* ---- Shared test buffers (only altstack, defined once) ---- */
char mbedtest_altstack_buf[SIGSTKSZ];

/*
 * test_retry_cleanup -- shared retry helper for unlink/rmdir.
 *
 * Retries fn(path) for up to 60 seconds (20 ms apart) unless
 * the error is one of ok_err1/ok_err2 (pass -1 if unused).
 * Logs on final failure but does not abort the test.
 */
static void test_retry_cleanup(int (*fn)(const char *),
			       const char *path,
			       const char *opname,
			       int ok_err1, int ok_err2)
{
	int ret = -1, err = 0, retry = 0;

	if (!path)
		return;

	do {
		ret = fn(path);
		err = errno;
		if (ret != 0 && err != ok_err1 && err != ok_err2) {
			if (++retry > 3000) {
				TERR("%s %s failed %d\n", opname, path, err);
				break;
			}
			usleep(20000);
		}
	} while (ret != 0 && err != ok_err1 && err != ok_err2);
}

/*
 * test_unlink: retry-backed unlink, ignores ENOENT.
 */
void test_unlink(const char *path)
{
	test_retry_cleanup(unlink, path, "unlink", ENOENT, -1);
}

/*
 * test_rmdir: retry-backed rmdir, ignores ENOENT/ENOTEMPTY.
 */
void test_rmdir(const char *path)
{
	test_retry_cleanup(rmdir, path, "rmdir", ENOENT, ENOTEMPTY);
}

/*
 * test_shm_unlink: retry-backed shm_unlink, ignores ENOENT.
 */
void test_shm_unlink(const char *path)
{
	test_retry_cleanup(shm_unlink, path, "shm_unlink", ENOENT, -1);
}

/*
 * test_mq_unlink: retry-backed mq_unlink, ignores ENOENT.
 */
void test_mq_unlink(const char *path)
{
	test_retry_cleanup(mq_unlink, path, "mq_unlink", ENOENT, -1);
}

/*
 * test_sem_unlink: retry-backed sem_unlink, ignores ENOENT.
 */
void test_sem_unlink(const char *path)
{
	test_retry_cleanup(sem_unlink, path, "sem_unlink", ENOENT, -1);
}

/*
 * test_mkpath: format a unique path from dir/suffix, pid and random seed.
 * Returns snprintf length on success, -1 on overflow or null arguments.
 */
int test_mkpath(char *buf, size_t buflen,
		const char *dir, const char *suffix)
{
	int len;

	if (!buf || buflen == 0 || !dir || !suffix)
		return -1;

	len = snprintf(buf, buflen, "%s/%s_%d_%x",
		       dir, suffix, (int)getpid(),
		       (unsigned)test_rand());

	if (len < 0 || (size_t)len >= buflen)
		return -1;

	return len;
}

/*
 * test_write_full: write len bytes, retrying on EINTR.
 * Returns len on success, -1 on any other error (errno set).
 */
ssize_t test_write_full(int fd, const void *buf, size_t len)
{
	size_t off = 0;
	ssize_t n = -1;
	int err = 0;
	const unsigned char *p = buf;

	errno = 0;
	while (off < len) {
		n = write(fd, p + off, len - off);
		err = errno;
		if (n > 0) {
			off += n;
			continue;
		}
		if (n == 0) {
			errno = ENOSPC;
			return -1;
		}
		if (err == EINTR)
			continue;
		return -1;
	}

	return off;
}

/*
 * test_read_full: read up to len bytes, retrying on EINTR.
 * Returns bytes read (may be < len on EOF), -1 on error.
 */
ssize_t test_read_full(int fd, void *buf, size_t len)
{
	size_t off = 0;
	ssize_t n = 0;
	int err = 0;
	unsigned char *p = buf;

	errno = 0;
	while (off < len) {
		n = read(fd, p + off, len - off);
		err = errno;
		if (n == 0)
			break;

		if (n < 0) {
			if (err == EINTR)
				continue;
			return -1;
		}
		off += n;
	}

	return off;
}
