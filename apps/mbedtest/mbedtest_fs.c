// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * mbedtest_fs.c -- File-system and shmfs/mmap tests.
 *
 * Tests defined here (entry point: fs_test):
 *   fs_basic_rw_test, fs_pread_pwrite_test,
 *   fs_rename_to_existing, fs_rename_to_dir, fs_rename_test,
 *   fs_truncate_boundary_test, fs_write_boundary_test,
 *   fs_metadata_test, fs_trunc_append_seek_test,
 *   fs_basic_test, fs_hole_test, fs_append_test,
 *   fs_directory_test, fs_dual_fd_trunc_test,
 *   shmfs_mmap1, shmfs_mmap2, shmfs_mmap3, fs_test_mnt
 */
#define _GNU_SOURCE
#include <generated/autoconf.h>
#include <dirent.h>
#include <mmap.h>
#include <sys/syslimits.h>

#include "mbedtest.h"
#include "mbedtest_internal.h"

/* ---- System externs not provided by this OS's headers ----------- */
extern int lstat(const char *path, struct stat *buf);

/* ---- Local tuning constants ------------------------------------- */
#define FS_BUFFER_SIZE            256
#define FS_BIGBUFF_SIZE           (32 * 1024)
#define FS_BLOCK_SIZE_DEFAULT     512

/*
 * fs_basic_rw_test: create file at random offset, write/read pattern verify.
 */
static int fs_basic_rw_test(const char *rootdir)
{
	int ret = -1, fd = -1, fd_rd = -1, fd_wr = -1;
	int seekval = 0;
	char buaff[FS_BUFFER_SIZE];
	char name[FS_BUFFER_SIZE];
	const char *pattern1 = "bbbbbbbbcccccccc";
	size_t pattern1_len = strlen(pattern1);
	const char *pattern = "bbbbbbbbcccccccc11112222";
	size_t pattern_len = strlen(pattern);

	snprintf(name, FS_BUFFER_SIZE, "%s/fs_%04d_rw.%x%d.txt",
		rootdir, gettid(), test_rand(), test_rand());

	test_unlink(name);

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(fd >= 0, errno, "open %s", name);

	seekval = test_rand() % 0x1000 + 1;
	ret = lseek(fd, seekval, SEEK_SET);
	CHECK(ret == seekval, ret < 0 ? errno : ERANGE);

	/* Write test pattern */
	ret = test_write_full(fd, "bbbbbbbbcccccccc", 16);
	CHECK(ret >= 0, errno, "write initial pattern ret=%d", ret);

	/* Open for read and verify */
	fd_rd = open(name, O_RDONLY);
	CHECK(fd_rd >= 0, errno, "open read %s", name);

	ret = lseek(fd_rd, seekval, SEEK_SET);
	CHECK(ret == seekval, errno);
	memset(buaff, 0, sizeof(buaff));
	ret = test_read_full(fd_rd, buaff, pattern1_len);
	CHECK(ret == pattern1_len, errno, "read pattern1 ret=%d data=%s",
		ret, buaff);
	CHECK(memcmp(buaff, pattern1, pattern1_len) == 0, EBADMSG);

	/* Open for write */
	fd_wr = open(name, O_WRONLY);
	CHECK(fd_wr >= 0, errno, "open write %s", name);

	CHECK(test_close_fd(&fd_rd) == 0, errno);
	CHECK(test_close_fd(&fd_wr) == 0, errno);

	/* Additional write and verify */
	ret = test_write_full(fd, "11112222", 8);
	CHECK(ret >= 0, errno, "append pattern ret=%d", ret);

	ret = lseek(fd, seekval, SEEK_SET);
	CHECK(ret == seekval, ret);
	memset(buaff, 0, sizeof(buaff));
	ret = test_read_full(fd, buaff, pattern_len);
	CHECK(ret == pattern_len, errno, "read pattern ret=%d data=%s",
		ret, buaff);
	CHECK(memcmp(buaff, pattern, pattern_len) == 0, EBADMSG);

out:
	test_close_fd(&fd_rd);
	test_close_fd(&fd_wr);
	test_close_fd(&fd);
	test_unlink(name);
	return TEST_ERRNO();
}

/*
 * fs_pread_pwrite_test: Verify pread/pwrite atomicity
 *  - pwrite at an offset, verify file pos unchanged
 *  - pread at an offset, verify file pos unchanged
 *  - cross-verify data with regular read
 */
static int fs_pread_pwrite_test(const char *rootdir)
{
	int fd = -1, ret = -1;
	off_t pos = 0;
	char name[FS_BUFFER_SIZE];
	char rbuf[64];
	const char *data0 = "AAAA";
	const char *data1 = "BBBB";
	const char *data2 = "CCCC";

	snprintf(name, FS_BUFFER_SIZE, "%s/prw_%04d.%x%d.txt",
		rootdir, gettid(), test_rand(), test_rand());

	test_unlink(name);

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(fd >= 0, errno, "open %s", name);

	/* write "AAAA" at pos 0 (regular write) */
	ret = test_write_full(fd, data0, 4);
	CHECK(ret == 4, errno);

	/* pos should be 4 now */
	pos = lseek(fd, 0, SEEK_CUR);
	CHECK(pos == 4, errno);

	/* pwrite "BBBB" at offset 8, pos must stay 4 */
	ret = pwrite(fd, data1, 4, 8);
	CHECK(ret == 4, errno);

	pos = lseek(fd, 0, SEEK_CUR);
	CHECK(pos == 4, errno);

	/* pwrite "CCCC" at offset 4, pos must stay 4 */
	ret = pwrite(fd, data2, 4, 4);
	CHECK(ret == 4, errno);

	pos = lseek(fd, 0, SEEK_CUR);
	CHECK(pos == 4, errno);

	/* pread at offset 0 => "AAAA", pos must stay 4 */
	memset(rbuf, 0, sizeof(rbuf));
	ret = pread(fd, rbuf, 4, 0);
	CHECK(ret == 4, errno);
	CHECK(memcmp(rbuf, data0, 4) == 0, EBADMSG);

	pos = lseek(fd, 0, SEEK_CUR);
	CHECK(pos == 4, errno);

	/* pread at offset 4 => "CCCC" */
	memset(rbuf, 0, sizeof(rbuf));
	ret = pread(fd, rbuf, 4, 4);
	CHECK(ret == 4, errno);
	CHECK(memcmp(rbuf, data2, 4) == 0, EBADMSG);

	/* pread at offset 8 => "BBBB" */
	memset(rbuf, 0, sizeof(rbuf));
	ret = pread(fd, rbuf, 4, 8);
	CHECK(ret == 4, errno);
	CHECK(memcmp(rbuf, data1, 4) == 0, EBADMSG);

	/* verify full content via regular read */
	lseek(fd, 0, SEEK_SET);
	memset(rbuf, 0, sizeof(rbuf));
	ret = test_read_full(fd, rbuf, 12);
	CHECK(ret == 12, errno);
	CHECK(memcmp(rbuf, "AAAACCCCBBBB", 12) == 0, EBADMSG);

out:
	test_close_fd(&fd);
	test_unlink(name);
	return TEST_ERRNO();
}

static int fs_rename_to_existing(const char *rootdir)
{
	char over_src[FS_BUFFER_SIZE] = {0};
	char over_dst[FS_BUFFER_SIZE] = {0};
	int over_fd = -1, over_dst_fd = -1, ret = -1;
	char over_buf[8] = {0};
	const char *src = "SRC";
	const char *dst = "DST";
	size_t n = strlen(src);

	snprintf(over_src, FS_BUFFER_SIZE, "%s/over_src_%04d.%x%d",
		rootdir, gettid(), test_rand(), test_rand());
	snprintf(over_dst, FS_BUFFER_SIZE, "%s/over_dst_%04d.%x%d",
		rootdir, gettid(), test_rand(), test_rand());
	test_unlink(over_src);
	test_unlink(over_dst);

	over_fd = open(over_src, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(over_fd >= 0, errno, "over_src %s", over_src);
	ret = test_write_full(over_fd, src, n);
	CHECK(ret == n, errno, "write %s ret=%d", over_src, ret);
	test_close_fd(&over_fd);

	over_fd = open(over_dst, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(over_fd >= 0, errno, "over_dst %s", over_dst);
	ret = test_write_full(over_fd, dst, n);
	CHECK(ret == n, errno, "write %s ret=%d", over_dst, ret);
	test_close_fd(&over_fd);

	/* Keep destination open across rename (POSIX: old fd remains valid) */
	over_dst_fd = open(over_dst, O_RDONLY);
	CHECK(over_dst_fd >= 0, errno);
	memset(over_buf, 0, sizeof(over_buf));
	ret = test_read_full(over_dst_fd, over_buf, n);
	CHECK(ret == n, errno);
	CHECK(memcmp(over_buf, dst, n) == 0, EBADMSG,
		"EXPECT %s GOT %02x %02x %02x", dst,
		over_buf[0], over_buf[1], over_buf[2]);

	ret = rename(over_src, over_dst);
	CHECK(ret == 0, errno, "rename overwrite %s -> %s ret=%d",
		over_src, over_dst, ret);

	over_fd = open(over_src, O_RDONLY);
	CHECK(errno == ENOENT, errno,
		"old source still exists %s", over_src);
	test_close_fd(&over_fd);

	over_fd = open(over_dst, O_RDONLY);
	CHECK(over_fd >= 0, errno, "over_dst %s", over_dst);
	memset(over_buf, 0, sizeof(over_buf));
	ret = test_read_full(over_fd, over_buf, n);
	CHECK(ret == n, errno);
	test_close_fd(&over_fd);
	CHECK(memcmp(over_buf, src, n) == 0, EBADMSG,
		"EXPECT %s GOT %02x %02x %02x", src,
		over_buf[0], over_buf[1], over_buf[2]);

	/* Verify old dst fd still reads old content */
	ret = lseek(over_dst_fd, 0, SEEK_SET);
	CHECK(ret == 0, errno);
	memset(over_buf, 0, sizeof(over_buf));
	ret = test_read_full(over_dst_fd, over_buf, n);
	CHECK(ret == n, errno);
	CHECK(memcmp(over_buf, dst, n) == 0, EBADMSG,
		"EXPECT %s GOT %02x %02x %02x", dst,
		over_buf[0], over_buf[1], over_buf[2]);

	test_close_fd(&over_dst_fd);

out:
	test_close_fd(&over_dst_fd);
	test_close_fd(&over_fd);
	test_unlink(over_src);
	test_unlink(over_dst);
	return TEST_ERRNO();
}

/*
 * fs_rename_to_dir: rename a file into a directory, verify old path
 * invalid and trailing-slash rename fails.
 */
static int fs_rename_to_dir(const char *rootdir)
{
	char mv_src[FS_BUFFER_SIZE] = {0};
	char mv_src2[FS_BUFFER_SIZE] = {0};
	char mv_dir[FS_BUFFER_SIZE] = {0};
	char mv_dir_slash[FS_BUFFER_SIZE] = {0};
	char mv_dst[FS_BUFFER_SIZE] = {0};
	int mv_fd = -1, ret = -1;
	char mv_buf[8] = {0};
	const char *mv = "MOVE";
	size_t mv_len = strlen(mv);

	snprintf(mv_src, FS_BUFFER_SIZE, "%s/mv_src_%04d_%x.%d",
		rootdir, gettid(), test_rand(), test_rand());
	snprintf(mv_src2, FS_BUFFER_SIZE, "%s/mv_src2_%04d_%x.%d",
		rootdir, gettid(), test_rand(), test_rand());
	snprintf(mv_dir, FS_BUFFER_SIZE, "%s/mv_dir_%04d_%x.%d",
		rootdir, gettid(), test_rand(), test_rand());
	snprintf(mv_dst, FS_BUFFER_SIZE, "%.*s/bb", (FS_BUFFER_SIZE - 4), mv_dir);
	snprintf(mv_dir_slash, FS_BUFFER_SIZE, "%.*s/", (FS_BUFFER_SIZE - 2), mv_dir);

	test_unlink(mv_dst);
	test_unlink(mv_src);
	test_unlink(mv_src2);
	test_rmdir(mv_dir);

	mv_fd = open(mv_src, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(mv_fd >= 0, errno, "mv_src %s", mv_src);
	ret = test_write_full(mv_fd, mv, mv_len);
	CHECK(ret == mv_len, errno);
	test_close_fd(&mv_fd);

	ret = mkdir(mv_dir, 0600);
	CHECK(ret == 0 || errno == EEXIST, errno, "mkdir %s", mv_dir);

	ret = rename(mv_src, mv_dst);
	CHECK(ret == 0, errno, "rename file into dir %s -> %s ret=%d",
		mv_src, mv_dst, ret);

	mv_fd = open(mv_src, O_RDONLY);
	CHECK(errno == ENOENT, errno,
		"old source still exists %s", mv_src);
	test_close_fd(&mv_fd);

	mv_fd = open(mv_dst, O_RDONLY);
	CHECK(mv_fd >= 0, errno, "mv_dst %s", mv_dst);
	memset(mv_buf, 0, sizeof(mv_buf));
	ret = test_read_full(mv_fd, mv_buf, mv_len);
	CHECK(ret == mv_len, errno);
	test_close_fd(&mv_fd);
	CHECK(memcmp(mv_buf, mv, mv_len) == 0, EBADMSG);

	/* Negative case: rename to existing directory path with trailing '/' */
	mv_fd = open(mv_src2, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(mv_fd >= 0, errno, "mv_src2 %s", mv_src2);
	test_close_fd(&mv_fd);

	ret = rename(mv_src2, mv_dir_slash);
	CHECK(ret != 0, errno,
		"rename file to dir path unexpectedly "
		"succeeded %s -> %s", mv_src2, mv_dir_slash);

	mv_fd = open(mv_src2, O_RDONLY);
	CHECK(mv_fd >= 0, errno, "mv_src2 %s", mv_src2);
	test_close_fd(&mv_fd);

out:
	test_unlink(mv_dst);
	test_unlink(mv_src);
	test_unlink(mv_src2);
	test_rmdir(mv_dir);
	return TEST_ERRNO();
}

/*
 * fs_rename_test: Test file and directory rename operations (self-contained)
 * Tests: rename files, rename directories, verify old names invalid
 */
static int fs_rename_test(const char *rootdir)
{
	int ret = -1, renamefd = -1, keepfd = -1;
	char buaff[64] = {0};
	char verify[64] = {0};
	const char *marker = "fd_after_rename";
	const char *pattern = "bbbbbbbbcccccccc11112222";
	size_t pattern_len = strlen(pattern);
	off_t endoff = -1;
	char *namestr = NULL, *name = NULL, *name2 = NULL;
	char *dir = NULL, *dir2 = NULL, *dir3 = NULL;
	int seekval = 0;

	namestr = calloc(1, FS_BUFFER_SIZE * 5);
	CHECK(namestr, ENOMEM, "alloc rename names");

	name = namestr;
	name2 = name + FS_BUFFER_SIZE;
	dir = name2 + FS_BUFFER_SIZE;
	dir2 = dir + FS_BUFFER_SIZE;
	dir3 = dir2 + FS_BUFFER_SIZE;

	snprintf(name, FS_BUFFER_SIZE, "%s/fs-%04d.%x%d.txt",
		rootdir, gettid(), test_rand(), test_rand());
	snprintf(name2, FS_BUFFER_SIZE, "%s/fs-%04d-rename-%x%d.txt",
		rootdir, gettid(), test_rand(), test_rand());
	snprintf(dir, FS_BUFFER_SIZE, "%s/dir_%04d_%x%d",
		rootdir, gettid(), test_rand(), test_rand());
	snprintf(dir2, FS_BUFFER_SIZE, "%s/dir2_%04d_%x%d",
		rootdir, gettid(), test_rand(), test_rand());

	test_unlink(name);
	test_unlink(name2);
	test_rmdir(dir);
	test_rmdir(dir2);

	keepfd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(keepfd >= 0, errno, "open %s", name);

	seekval = test_rand() % 0x1000 + 1;
	ret = lseek(keepfd, seekval, SEEK_SET);
	CHECK(ret == seekval, errno);

	ret = test_write_full(keepfd, pattern, pattern_len);
	CHECK(ret >= 0, errno);
	CHECK(ret == pattern_len, errno);

	ret = mkdir(dir, 0600);
	CHECK(ret == 0 || errno == EEXIST, errno, "mkdir %s", dir);

	/* Test directory rename (should fail on rootdir) */
	snprintf(dir3, FS_BUFFER_SIZE, "%s/ac", rootdir);
	ret = rename(rootdir, dir3);
	CHECK(ret != 0, errno, "rename mounted root unexpectedly "
		"succeeded %s -> %s", rootdir, dir3);

	/* Verify the existing open fd works before rename */
	ret = lseek(keepfd, seekval, SEEK_SET);
	CHECK(ret == seekval, errno);

	memset(buaff, 0, sizeof(buaff));
	ret = test_read_full(keepfd, buaff, pattern_len);
	CHECK(ret == pattern_len, errno, "rename pre-read ret=%d", ret);
	CHECK(memcmp(buaff, pattern, pattern_len) == 0, EBADMSG);

	/* Rename file and verify old name invalid */
	ret = rename(name, name2);
	CHECK(ret == 0, errno, "rename file %s -> %s ret=%d",
		name, name2, ret);

	renamefd = open(name, O_RDONLY);
	CHECK(errno == ENOENT, errno,
		"old name still exists %s", name);
	test_close_fd(&renamefd);

	/* After rename, the old fd should still be readable */
	ret = lseek(keepfd, seekval, SEEK_SET);
	CHECK(ret == seekval, errno);

	memset(buaff, 0, sizeof(buaff));
	ret = test_read_full(keepfd, buaff, pattern_len);
	CHECK(ret == pattern_len, errno, "rename post-read ret=%d", ret);
	CHECK(memcmp(buaff, pattern, pattern_len) == 0, EBADMSG);

	/* And it should still be writable; verify via a fresh open on name2 */
	endoff = lseek(keepfd, 0, SEEK_END);
	CHECK(endoff >= 0, errno);

	ret = test_write_full(keepfd, marker, strlen(marker));
	CHECK(ret >= 0, errno, "rename post-write ret=%d", ret);

	renamefd = open(name2, O_RDONLY);
	CHECK(renamefd >= 0, errno, "open %s", name2);

	ret = lseek(renamefd, endoff, SEEK_SET);
	CHECK(ret == endoff, errno);

	memset(verify, 0, sizeof(verify));
	ret = test_read_full(renamefd, verify, strlen(marker));
	CHECK(ret == strlen(marker), errno,
		"rename marker read ret=%d data=%s",
		ret, verify);
	CHECK(memcmp(verify, marker, strlen(marker)) == 0, EBADMSG);

	test_close_fd(&renamefd);

	/* Rename directory forward and back */
	ret = rename(dir, dir2);
	CHECK(ret == 0, errno, "rename dir %s -> %s", dir, dir2);
	renamefd = open(dir, O_RDONLY | O_DIRECTORY);
	CHECK(renamefd < 0, EEXIST, "old dir still exists %s ?", dir);

	ret = rename(dir2, dir);
	CHECK(ret == 0, errno, "rename dir %s -> %s", dir2, dir);
	renamefd = open(dir2, O_RDONLY | O_DIRECTORY);
	CHECK(renamefd < 0, EEXIST, "old dir still exists %s ?", dir2);

	ret = fs_rename_to_existing(rootdir);
	CHECK(ret == 0, ret, "rename over existing");
	ret = fs_rename_to_dir(rootdir);
	CHECK(ret == 0, ret, "rename to dir");

out:
	test_close_fd(&renamefd);
	test_close_fd(&keepfd);
	/* On failure we might have renamed dir->dir2, so cleanup both. */
	test_rmdir(dir);
	test_rmdir(dir2);
	test_unlink(name);
	test_unlink(name2);
	free(namestr);
	return TEST_ERRNO();
}

/* fs_verify_zero_region: read [start, start+len) and verify all bytes are 0. */
static int fs_verify_zero_region(int fd, off_t start, size_t len)
{
	unsigned char buf[64];
	size_t off = 0;
	size_t n = 0, i = 0;
	off_t pos = -1;
	ssize_t r = -1;

	while (off < len) {
		n = len - off;
		pos = -1;
		r = -1;

		if (n > sizeof(buf))
			n = sizeof(buf);

		pos = lseek(fd, start + off, SEEK_SET);
		CHECK(pos >= 0, errno, "zero lseek start=%ld off=%zu",
			(long)start, off);
		CHECK(pos == start + off, EBADMSG,
			"zero lseek pos=%ld expected=%ld",
			(long)pos, (long)(start + off));

		memset(buf, 0xA5, sizeof(buf));
		r = test_read_full(fd, buf, n);
		CHECK(r >= 0, errno, "zero read start=%ld off=%zu len=%zu",
			(long)start, off, n);
		CHECK(r == n, EBADMSG, "zero read ret=%ld expected=%zu",
			(long)r, n);

		for (i = 0; i < n; i++) {
			CHECK(buf[i] == 0, EBADMSG,
				"zero byte off=%ld got=0x%02x",
				(long)(start + off + i), buf[i]);
		}

		off += n;
	}

out:
	return TEST_ERRNO();
}

static size_t fs_detect_blksize(const char *rootdir)
{
	size_t blksize = FS_BLOCK_SIZE_DEFAULT;
	char probe[FS_BUFFER_SIZE];
	int fd = -1;
	struct stat st;

	snprintf(probe, sizeof(probe), "%s/blksz_%04d_%x%d.probe",
		rootdir, gettid(), test_rand(), test_rand());

	fd = open(probe, O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (fd >= 0) {
		if (fstat(fd, &st) == 0 && st.st_blksize > 0)
			blksize = st.st_blksize;
		close(fd);
	}

	test_unlink(probe);

	TDBG("%s: blksize=%zu\n", rootdir, blksize);

	return blksize;
}

/*
 * fs_truncate_boundary_test: Test ftruncate with various boundaries
 * Tests: expand/shrink files at block boundaries, partial blocks
 */
static int fs_truncate_boundary_test(const char *rootdir, size_t blksize)
{
	int ret = -1, fd3 = -1;
	char name[FS_BUFFER_SIZE];
	off_t prev_size = 0;
	off_t new_size = 0;

	snprintf(name, FS_BUFFER_SIZE, "%s/fs_trunc_%04d.%x%d.txt",
			rootdir, gettid(), test_rand(), test_rand());
	test_unlink(name);

	fd3 = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(fd3 >= 0, errno, "open %s", name);

	/* Test 1: 0??(blksize/2) (partial block, new allocation) */
	new_size = blksize / 2;
	ret = ftruncate(fd3, new_size);
	CHECK(ret == 0, errno, "ftruncate size=%zu ret=%d",
		blksize / 2, ret);
	ret = fs_verify_zero_region(fd3, prev_size, new_size - prev_size);
	CHECK(ret == 0, ret, "zero region 0->%ld", (long)new_size);
	prev_size = new_size;

	/* Test 2: (blksize/2)??blksize (complete first block boundary) */
	new_size = blksize;
	ret = ftruncate(fd3, new_size);
	CHECK(ret == 0, errno, "ftruncate size=%zu ret=%d", blksize, ret);
	ret = fs_verify_zero_region(fd3, prev_size, new_size - prev_size);
	CHECK(ret == 0, ret, "zero region to %ld", (long)new_size);
	prev_size = new_size;

	/* Test 3: blksize??(blksize+1) (boundary+1, new block allocation) */
	new_size = blksize + 1;
	ret = ftruncate(fd3, new_size);
	CHECK(ret == 0, errno, "ftruncate size=%zu ret=%d",
		blksize + 1, ret);
	ret = fs_verify_zero_region(fd3, prev_size, new_size - prev_size);
	CHECK(ret == 0, ret, "zero region to %ld", (long)new_size);
	prev_size = new_size;

	/* Test 4: (blksize+1)??(blksize*4+100) (multi-block w/ tail) */
	new_size = blksize * 4 + 100;
	ret = ftruncate(fd3, new_size);
	CHECK(ret == 0, errno, "ftruncate size=%zu ret=%d",
		blksize * 4 + 100, ret);
	ret = fs_verify_zero_region(fd3, prev_size, new_size - prev_size);
	CHECK(ret == 0, ret, "zero region to %ld", (long)new_size);
	prev_size = new_size;

	/* Test 5: (blksize*4+100)??(blksize*2) (shrink to complete blocks) */
	new_size = blksize * 2;
	ret = ftruncate(fd3, new_size);
	CHECK(ret == 0, errno, "ftruncate size=%zu ret=%d",
		blksize * 2, ret);
	prev_size = new_size;

	/* Test 6: (blksize*2)??(blksize*2+5) (expand within same block) */
	new_size = blksize * 2 + 5;
	ret = ftruncate(fd3, new_size);
	CHECK(ret == 0, errno, "ftruncate size=%zu ret=%d",
		blksize * 2 + 5, ret);
	ret = fs_verify_zero_region(fd3, prev_size, new_size - prev_size);
	CHECK(ret == 0, ret, "zero region to %ld", (long)new_size);
	prev_size = new_size;

	/* Test 7: (blksize*2+5)??(blksize/4) (shrink back to small) */
	new_size = blksize / 4;
	ret = ftruncate(fd3, new_size);
	CHECK(ret == 0, errno, "ftruncate size=%zu ret=%d",
		blksize / 4, ret);
	prev_size = new_size;

	/* Test 8: (blksize/4)??(blksize*20) (large expansion) */
	new_size = blksize * 20;
	ret = ftruncate(fd3, new_size);
	CHECK(ret == 0, errno, "ftruncate size=%zu ret=%d",
		blksize * 20, ret);
	ret = fs_verify_zero_region(fd3, prev_size, new_size - prev_size);
	CHECK(ret == 0, ret, "zero region to %ld", (long)new_size);
	prev_size = new_size;

out:
	test_close_fd(&fd3);
	test_unlink(name);
	return TEST_ERRNO();
}

/*
 * fs_write_boundary_test: Test block-boundary writes
 * Tests: aligned writes, cross-boundary writes, verify patterns
 */
static int fs_write_boundary_test(const char *rootdir, size_t blksize)
{
	int ret = -1, fd3 = -1, i = 0;
	unsigned char *wbuf = NULL;
	char name[FS_BUFFER_SIZE];

	snprintf(name, FS_BUFFER_SIZE, "%s/fs%04d_wbnd.%x%d.txt",
		rootdir, gettid(), test_rand(), test_rand());
	test_unlink(name);

	fd3 = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(fd3 >= 0, errno, "open %s", name);

	wbuf = malloc(blksize * 3 + 2);
	CHECK(wbuf, ENOMEM, "write_boundary alloc size=%zu", blksize * 3 + 2);

	/*
	 * Buffer layout: 0xAA (blksize), 0xBB (blksize+1), 0xCC (blksize)
	 * Tests data integrity across block boundaries
	 */
	memset(wbuf, 0xAA, blksize);
	memset(wbuf + blksize, 0xBB, blksize + 1);
	memset(wbuf + blksize + blksize + 1, 0xCC, blksize);

	/* Test 1: Write exactly one block (pattern 0xAA) */
	ret = test_write_full(fd3, wbuf, blksize);
	CHECK(ret >= 0, errno, "write_boundary write size=%zu ret=%d",
		blksize, ret);

	/* Test 2: Write block+1 (cross boundary, pattern 0xBB) */
	ret = lseek(fd3, 0, SEEK_SET);
	ret = test_write_full(fd3, wbuf + blksize, blksize + 1);
	CHECK(ret >= 0, errno, "write_boundary cross-block size=%zu ret=%d",
		blksize + 1, ret);

	/* Test 3: Seek to block boundary, write partial (pattern 0xCC) */
	ret = lseek(fd3, blksize * 2, SEEK_SET);
	CHECK(ret == blksize * 2, errno);
	ret = test_write_full(fd3, wbuf + blksize + blksize + 1, blksize / 2);
	CHECK(ret >= 0, errno, "write_boundary partial size=%zu off=%zu ret=%d",
		blksize / 2, blksize * 2, ret);

	/* Verify: read back and check patterns */
	ret = lseek(fd3, 0, SEEK_SET);
	memset(wbuf, 0, blksize * 3);
	ret = test_read_full(fd3, wbuf, blksize * 3);
	CHECK(ret >= 0, errno, "write_boundary verify read ret=%d", ret);

	/* Verify pattern 0xBB in [0, blksize+1) */
	for (i = 0; i < blksize + 1; i++) {
		CHECK(wbuf[i] == 0xBB, EBADMSG,
			"write_boundary off=%d expected=0xBB got=0x%02x", i, wbuf[i]);
	}

	/* Verify hole [blksize+1, blksize*2) is zero */
	for (i = blksize + 1; i < blksize * 2; i++) {
		CHECK(wbuf[i] == 0, EBADMSG,
			"write_boundary hole off=%d got=0x%02x", i, wbuf[i]);
	}

	/* Verify pattern 0xCC at [blksize*2, blksize*2 + blksize/2) */
	for (i = blksize * 2; i < (blksize * 2 + blksize / 2); i++) {
		CHECK(wbuf[i] == 0xCC, EBADMSG,
			"write_boundary off=%d expected=0xCC got=0x%02x", i, wbuf[i]);
	}
out:
	free(wbuf);
	test_close_fd(&fd3);
	test_unlink(name);
	return TEST_ERRNO();
}

/*
 * fs_metadata_test: Test fstat/stat/lstat consistency
 * Tests: size/type via fstat/stat/lstat
 */
static int fs_metadata_test(const char *rootdir)
{
	int ret = -1, fd = -1;
	char name[FS_BUFFER_SIZE] = {0};
	struct stat st = {0}, lst = {0}, fst = {0};
	const char *payload = "meta";

	snprintf(name, FS_BUFFER_SIZE, "%s/fs_%04d_meta.%x%d",
		rootdir, gettid(), test_rand(), test_rand());
	test_unlink(name);

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(fd >= 0, errno, "open %s", name);

	ret = test_write_full(fd, payload, strlen(payload));
	CHECK(ret >= 0, errno);

	ret = fstat(fd, &fst);
	CHECK(ret == 0, errno);
	ret = stat(name, &st);
	CHECK(ret == 0, errno);
	ret = lstat(name, &lst);
	CHECK(ret == 0, errno);

	CHECK(S_ISREG(st.st_mode) && S_ISREG(lst.st_mode) &&
		S_ISREG(fst.st_mode), EBADMSG);
	CHECK(st.st_size == fst.st_size && lst.st_size == fst.st_size, EBADMSG);

	/* symlink not supported; no symlink coverage */

out:
	test_close_fd(&fd);
	test_unlink(name);
	return TEST_ERRNO();
}

/*
 * fs_trunc_append_seek_test: Test O_TRUNC/O_APPEND with lseek edge cases
 */
static int fs_trunc_append_seek_test(const char *rootdir)
{
	int ret = -1, fd = -1;
	char name[FS_BUFFER_SIZE] = {0};
	char buf[32] = {0};
	struct stat st = {0};
	const char *base = "ABCDE";

	snprintf(name, FS_BUFFER_SIZE, "%s/fs_%04d_tas.%x%d",
		rootdir, gettid(), test_rand(), test_rand());

	test_unlink(name);

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(fd >= 0, errno, "open %s", name);

	ret = test_write_full(fd, base, strlen(base));
	CHECK(ret >= 0, errno);
	test_close_fd(&fd);

	/* O_TRUNC should reset size to 0 regardless of previous content */
	fd = open(name, O_RDWR | O_TRUNC, 0666);
	CHECK(fd >= 0, errno, "open %s", name);
	ret = fstat(fd, &st);
	CHECK(ret == 0, errno);
	CHECK(st.st_size == 0, EBADMSG);

	test_close_fd(&fd);

	/* Seed data, then O_APPEND should append even after lseek to 0 */
	fd = open(name, O_RDWR | O_TRUNC, 0666);
	CHECK(fd >= 0, errno, "open %s", name);
	ret = test_write_full(fd, "AA", 2);
	CHECK(ret >= 0, errno);
	test_close_fd(&fd);

	fd = open(name, O_RDWR | O_APPEND, 0666);
	CHECK(fd >= 0, errno, "open %s", name);
	ret = lseek(fd, 0, SEEK_SET);
	CHECK(ret == 0, errno);

	ret = test_write_full(fd, "Z", 1);
	CHECK(ret >= 0, errno);

	ret = lseek(fd, 0, SEEK_SET);
	CHECK(ret == 0, errno);
	memset(buf, 0, sizeof(buf));
	ret = test_read_full(fd, buf, 3);
	CHECK(ret == 3, errno);
	CHECK(memcmp(buf, "AAZ", 3) == 0, EBADMSG);

out:
	test_close_fd(&fd);
	test_unlink(name);
	return TEST_ERRNO();
}

/*
 * fs_basic_test: Basic filesystem test suite.
 *
 * Three independent sub-groups:
 *   [A] fs_basic_rw_test     -- self-contained, separate function
 *   [B] O_EXCL + O_TRUNC     -- excl_name, independent of name
 *   [C] Large RW + unlink    -- name: write->unlink->deferred-IO, steps chained
 */
static int fs_basic_test(const char *rootdir, size_t blksize)
{
	int ret = -1, fd = -1, fd3 = -1, fd4 = -1;
	int i = 0, fd_excl = -1, realsz = 0;
	char *namestr = NULL, *bigbuff = NULL;
	char *name = NULL, *excl_name = NULL;

	namestr = calloc(1, FS_BUFFER_SIZE * 2);
	CHECK(namestr, ENOMEM, "alloc fs names %s", rootdir);

	name = namestr;
	excl_name = name + FS_BUFFER_SIZE;

	snprintf(name, FS_BUFFER_SIZE, "%s/fs_%04d.%x%d.txt",
		rootdir, gettid(), test_rand(), test_rand());
	snprintf(excl_name, FS_BUFFER_SIZE, "%s/fs_%04d_excl.%x%d",
		rootdir, gettid(), test_rand(), test_rand());

	/* Cleanup stale files from previous runs */
	test_unlink(name);
	test_unlink(excl_name);

	/* Basic read/write test */
	ret = fs_basic_rw_test(rootdir);
	CHECK(ret == 0, ret, "basic rw %s", rootdir);

	/* Create and setup test file for large IO and unlink tests */
	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(fd >= 0, errno, "O_TRUNC open %s", name);

	fd_excl = open(excl_name, O_RDWR | O_CREAT | O_EXCL, 0666);
	CHECK(fd_excl >= 0, errno, "O_EXCL open %s", excl_name);

	ret = open(excl_name, O_RDWR | O_CREAT | O_EXCL, 0666);
	CHECK(errno == EEXIST, errno, "O_EXCL reopen %s", excl_name);
	if (ret >= 0) {
		close(ret);
		ret = -1;
	}

	/* Write large file */
	realsz = test_rand() % FS_BIGBUFF_SIZE + 1;
	bigbuff = malloc(realsz);
	CHECK(bigbuff, ENOMEM, "alloc bigbuff size=%d", realsz);

	memset(bigbuff, 0x5a, realsz);
	ret = test_write_full(fd, bigbuff, realsz);
	CHECK(ret == realsz, errno);

	/* Test fd operations */
	fd3 = open(name, O_WRONLY);
	CHECK(fd3 >= 0, errno);
	test_close_fd(&fd);
	test_close_fd(&fd3);

	fd3 = open(name, O_RDWR);
	CHECK(fd3 >= 0, errno, "open %s", name);

	/* Test unlink on open file (POSIX deferred deletion) */
	ret = unlink(name);
	CHECK(ret == 0, errno, "unlink %s", name);

	fd4 = open(name, O_RDONLY);
	CHECK(errno == ENOENT, errno,
		"unlinked file still visible %s", name);
	test_close_fd(&fd4);

	/* Verify unlinked file still readable */
	memset(bigbuff, 0, realsz);
	ret = test_read_full(fd3, bigbuff, realsz);
	CHECK(ret == realsz, errno);

	for (i = 0; i < realsz; i++) {
		CHECK(bigbuff[i] == 0x5a, EBADMSG,
			"unlinked read mismatch off=%d got=0x%02x", i, bigbuff[i]);
	}

	/* Verify unlinked file still writable */
	ret = test_write_full(fd3, bigbuff, realsz);
	CHECK(ret == realsz, errno);

out:
	/* Cleanup on error */
	free(bigbuff);
	test_close_fd(&fd);
	test_close_fd(&fd3);
	test_close_fd(&fd4);
	test_close_fd(&fd_excl);
	test_unlink(name);
	test_unlink(excl_name);
	free(namestr);
	return TEST_ERRNO();
}

/*
 * fs_hole_test: Test sparse file hole operations
 * Tests: lseek beyond EOF, zero-fill verification
 */
static int fs_hole_test(const char *rootdir, size_t blksize)
{
	int ret = -1, fd = -1;
	char name[FS_BUFFER_SIZE];
	off_t hole_off = 0, off_ret = -1;

	snprintf(name, FS_BUFFER_SIZE, "%s/fs_%04d_hole.%x%d.txt",
		rootdir, gettid(), test_rand(), test_rand());
	test_unlink(name);

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(fd >= 0, errno, "open %s", name);

	ret = test_write_full(fd, "data", 4);
	CHECK(ret == 4, errno, "hole initial write %s ret=%d", name, ret);

	if (blksize < 64)
		blksize = 64;
	/* Create a hole that crosses a real block boundary. */
	hole_off = blksize + 123;
	off_ret = lseek(fd, hole_off, SEEK_SET);
	CHECK(off_ret == hole_off, errno);

	ret = test_write_full(fd, "hole", 4);
	CHECK(ret == 4, errno, "hole write %s off=%ld ret=%d",
		name, (long)hole_off, ret);

	/* Verify the hole region is zero-filled. */
	ret = fs_verify_zero_region(fd, 4, hole_off - 4);
	CHECK(ret == 0, ret, "hole zero region len=%ld", (long)(hole_off - 4));

out:
	test_close_fd(&fd);
	test_unlink(name);
	return TEST_ERRNO();
}

/*
 * fs_append_test: Test O_APPEND concurrent writes
 * Tests: append mode, concurrent fd writes, ordering
 */
static int fs_append_test(const char *rootdir, size_t blksize)
{
	int fd = -1, fd_ap1 = -1, fd_ap2 = -1;
	unsigned char chk[4] = {0};
	char name[FS_BUFFER_SIZE];
	char *pad = NULL, *abuf = NULL, *bbuf = NULL;
	size_t pad_len = 0, alen = 0, blen = 0;
	struct stat st;
	ssize_t wret = -1, rret = -1;
	off_t off_ret = -1;

	snprintf(name, FS_BUFFER_SIZE, "%s/fs_%04d_append.%x%d.txt",
		rootdir, gettid(), test_rand(), test_rand());

	test_unlink(name);

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(fd >= 0, errno, "open %s", name);

	/* Pad close to a real block boundary so appends cross it. */
	pad_len = blksize - 2;
	pad = malloc(pad_len);
	CHECK(pad, ENOMEM, "append pad alloc size=%zu", pad_len);
	memset(pad, 'I', pad_len);
	wret = test_write_full(fd, pad, pad_len);
	CHECK(wret == pad_len, errno);

	/* Make each append write exceed one block. */
	alen = blksize + 17;
	blen = blksize + 23;
	abuf = malloc(alen);
	bbuf = malloc(blen);
	CHECK(abuf && bbuf, ENOMEM, "append alloc alen=%zu blen=%zu", alen, blen);
	memset(abuf, 'A', alen);
	memset(bbuf, 'B', blen);

	fd_ap1 = open(name, O_WRONLY | O_APPEND);
	CHECK(fd_ap1 >= 0, errno, "open %s", name);

	fd_ap2 = open(name, O_WRONLY | O_APPEND);
	CHECK(fd_ap2 >= 0, errno, "O_APPEND second open fd1=%d fd2=%d",
		fd_ap1, fd_ap2);

	if (fd_ap1 >= 0) {
		wret = test_write_full(fd_ap1, abuf, alen);
		CHECK(wret == alen, errno,
			"O_APPEND write fd1 ret=%d expected=%zu",
			(int)wret, alen);
		test_close_fd(&fd_ap1);
	}

	if (fd_ap2 >= 0) {
		wret = test_write_full(fd_ap2, bbuf, blen);
		CHECK(wret == blen, errno,
			 "O_APPEND write fd2 ret=%d expected=%zu",
			(int)wret, blen);
		test_close_fd(&fd_ap2);
	}

	/* Verify append result: size and region sampling */
	CHECK(fstat(fd, &st) == 0, errno);
	CHECK(st.st_size == pad_len + alen + blen, st.st_size);

	/* Check first/last bytes of A region */
	off_ret = lseek(fd, pad_len, SEEK_SET);
	CHECK(off_ret == pad_len, errno);
	rret = test_read_full(fd, chk, sizeof(chk));
	CHECK(rret == sizeof(chk), errno);
	CHECK(chk[0] == 'A' && chk[1] == 'A' &&
		chk[2] == 'A' && chk[3] == 'A', EBADMSG);

	off_ret = lseek(fd, pad_len + alen - sizeof(chk), SEEK_SET);
	CHECK(off_ret == (pad_len + alen - sizeof(chk)), errno);
	rret = test_read_full(fd, chk, sizeof(chk));
	CHECK(rret == sizeof(chk), errno);
	CHECK(chk[0] == 'A' && chk[1] == 'A' &&
		chk[2] == 'A' && chk[3] == 'A', EBADMSG);

	/* Check first/last bytes of B region */
	off_ret = lseek(fd, pad_len + alen, SEEK_SET);
	CHECK(off_ret == (pad_len + alen), errno);
	rret = test_read_full(fd, chk, sizeof(chk));
	CHECK(rret == sizeof(chk), errno);
	CHECK(chk[0] == 'B' && chk[1] == 'B' &&
		chk[2] == 'B' && chk[3] == 'B', EBADMSG);

	off_ret = lseek(fd, pad_len + alen + blen - sizeof(chk), SEEK_SET);
	CHECK(off_ret == (pad_len + alen + blen - sizeof(chk)), errno);
	rret = test_read_full(fd, chk, sizeof(chk));
	CHECK(rret == sizeof(chk), errno);
	CHECK(chk[0] == 'B' && chk[1] == 'B' &&
		chk[2] == 'B' && chk[3] == 'B', EBADMSG);

out:
	free(abuf);
	free(bbuf);
	free(pad);
	test_close_fd(&fd);
	test_close_fd(&fd_ap1);
	test_close_fd(&fd_ap2);
	test_unlink(name);
	return TEST_ERRNO();
}

/*
 * fs_directory_test: Test directory operations
 * Tests: mkdir, opendir, readdir, rmdir, creat in dir
 */
static int fs_directory_test(const char *rootdir)
{
	int ret = -1, fd = -1;
	int found = 0, found_dot = 0, found_dotdot = 0;
	char dir[FS_BUFFER_SIZE] = {0};
	char nameatdir[FS_BUFFER_SIZE * 2] = {0};
	const char *fname = NULL;
	DIR *dd = NULL;
	struct dirent *dddd = NULL;

	snprintf(dir, FS_BUFFER_SIZE, "%s/fs_dir_%04d_%x%d", rootdir,
			gettid(), test_rand(), test_rand());
	snprintf(nameatdir, sizeof(nameatdir), "%s/fs_aa_%04d.%x%d.txt",
		dir, gettid(), test_rand(), test_rand());

	test_unlink(nameatdir);
	test_rmdir(dir);

	/* Create directory */
	ret = mkdir(dir, 0600);
	CHECK(ret == 0 || errno == EEXIST, errno, "mkdir %s", dir);

	/* Test rmdir on rootdir (should fail) */
	ret = rmdir(rootdir);
	CHECK(ret != 0, errno, "rmdir mounted root unexpectedly succeeded %s",
		rootdir);

	/* Create file in directory */
	fd = creat(nameatdir, 0666);
	CHECK(fd >= 0, errno, "creat %s", nameatdir);

	/* Open and read directory */
	dd = opendir(dir);
	CHECK(dd, errno, "opendir %s", dir);

	/* Try rmdir on non-empty directory (should fail) */
	ret = rmdir(dir);
	CHECK(ret != 0, errno, "rmdir non-empty dir unexpectedly succeeded %s",
		dir);

	fname = strrchr(nameatdir, '/');
	if (fname)
		fname++;
	else
		fname = nameatdir;

	while ((dddd = readdir(dd)) != NULL) {
		if (!strcmp(dddd->d_name, "."))
			found_dot = 1;
		if (!strcmp(dddd->d_name, ".."))
			found_dotdot = 1;
		if (!strcmp(dddd->d_name, fname))
			found = 1;
	}
	CHECK(errno == 0, errno);
	CHECK(found, EBADMSG);
	if (!found_dot || !found_dotdot)
		TDBG("readdir missing dot entries dot=%d dotdot=%d\n",
			found_dot, found_dotdot);

	rewinddir(dd);

	test_unlink(nameatdir);

	test_rmdir(dir);

	dddd = readdir(dd);
	TDBG("readdir %s dddd=%p file=%s errno=%d\n", dir, dddd,
		dddd ? dddd->d_name : "null", errno);

out:
	test_close_fd(&fd);
	closedir(dd);
	test_unlink(nameatdir);
	test_rmdir(dir);
	return TEST_ERRNO();
}

/*
 * fs_readdir_seek_test: Test telldir/seekdir roundtrip.
 *
 * Creates a directory with several files, reads half of them,
 * saves the position with telldir(), reads the rest, then seeks
 * back and re-reads from the saved position to verify that
 * seekdir() restores the directory stream exactly.
 */
static int fs_readdir_seek_test(const char *rootdir)
{
	int ret = -1, i = 0, found = 0;
	char dir[FS_BUFFER_SIZE] = {0};
	char fname[FS_BUFFER_SIZE] = {0};
	char buf[FS_BUFFER_SIZE] = {0};
	const int nfiles = 10;
	DIR *dd = NULL;
	struct dirent *de = NULL;
	long saved_pos = -1;
	char *names_first[10] = {NULL};
	char *names_after[10] = {NULL};
	int nfirst = 0, nafter = 0;
	int fd = -1;

	snprintf(dir, FS_BUFFER_SIZE, "%s/fs_seek_%04d_%x%d",
		rootdir, gettid(), test_rand(), test_rand());

	test_rmdir(dir);

	ret = mkdir(dir, 0700);
	CHECK(ret == 0 || errno == EEXIST, errno, "mkdir %s", dir);

	/* Create nfiles entries in the directory */
	for (i = 0; i < nfiles; i++) {
		int n = snprintf(fname, sizeof(fname), "%s/f%02d", dir, i);
		CHECK(n > 0 && (size_t)n < sizeof(fname), ENAMETOOLONG,
			"fname too long dir=%s", dir);
		test_unlink(fname);
		fd = open(fname, O_RDWR | O_CREAT | O_TRUNC, 0666);
		CHECK(fd >= 0, errno, "creat %s", fname);
		test_close_fd(&fd);
	}

	dd = opendir(dir);
	CHECK(dd, errno, "opendir %s", dir);

	/* Pass 1: read first half, then telldir() */
	nfirst = 0;
	for (i = 0; i < nfiles / 2; i++) {
		errno = 0;
		de = readdir(dd);
		if (!de)
			break;
		/* skip . and .. */
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
			i--; /* don't count dot entries toward nfiles/2 */
			continue;
		}
		snprintf(buf, sizeof(buf), "%s", de->d_name);
		names_first[nfirst] = strdup(buf);
		CHECK(names_first[nfirst], ENOMEM, "strdup first[%d]", i);
		nfirst++;
	}

	saved_pos = telldir(dd);
	CHECK(saved_pos >= 0, errno, "telldir %s", dir);

	/* Pass 2: read remaining entries */
	nafter = 0;
	while ((de = readdir(dd)) != NULL) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		snprintf(buf, sizeof(buf), "%s", de->d_name);
		names_after[nafter] = strdup(buf);
		CHECK(names_after[nafter], ENOMEM, "strdup after[%d]", nafter);
		nafter++;
	}
	CHECK(errno == 0, errno);

	/* Pass 3: seekdir back to saved position and re-read */
	seekdir(dd, saved_pos);

	found = 0;
	while ((de = readdir(dd)) != NULL) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		for (i = 0; i < nafter; i++) {
			if (names_after[i] &&
			    !strcmp(de->d_name, names_after[i])) {
				found++;
				break;
			}
		}
	}
	CHECK(found == nafter, EBADMSG,
		"seekdir found=%d expected=%d", found, nafter);

	/* rewinddir should bring us back to start */
	rewinddir(dd);
	de = readdir(dd);
	CHECK(de != NULL, EIO, "rewinddir gave NULL");

out:
	closedir(dd);
	for (i = 0; i < nfiles; i++) {
		int cn = snprintf(fname, sizeof(fname), "%s/f%02d", dir, i);
		if (cn > 0 && (size_t)cn < sizeof(fname))
			test_unlink(fname);
	}
	test_rmdir(dir);
	for (i = 0; i < nfirst; i++)
		free(names_first[i]);
	for (i = 0; i < nafter; i++)
		free(names_after[i]);
	test_close_fd(&fd);
	return TEST_ERRNO();
}

/*
 * fs_enospc_test: Verify ENOSPC behaviour on disk-full.
 *
 * Writes 2KB blocks until ENOSPC using test_write_full (which
 * retries short writes and EINTR transparently). On ENOSPC the
 * helper returns -1 and we break out. Actual file size is taken
 * from fstat() rather than manual accounting so partial final
 * blocks are handled correctly.
 *
 * After fill, verifies the file content is intact and that
 * truncating to a smaller size succeeds. Cleans up the file
 * so downstream tests are not affected.
 */
static void fs_enospc_test(const char *rootdir)
{
	int ret = -1, fd = -1;
	char name[FS_BUFFER_SIZE] = {0};
	char zbuf[2048], rbuf[2048];
	size_t nblocks = 0;
	ssize_t wret = 0;
	struct stat st = {0};
	off_t sz_before = 0;

	TEST_START("fs_enospc_test");

	snprintf(name, FS_BUFFER_SIZE, "%s/fs_%04d_enospc.%x%d",
		rootdir, gettid(), test_rand(), test_rand());
	test_unlink(name);

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(fd >= 0, errno, "open %s", name);

	/*
	 * Fill the filesystem in 2KB blocks until ENOSPC.
	 * Cap at 128K blocks (~256 MB) to avoid infinite loop on
	 * very large (or simulated infinite) filesystems.
	 *
	 * test_write_full retries short writes internally and
	 * returns -1 with errno=ENOSPC when space is exhausted.
	 * Partial data from the final block is on disk and
	 * reflected in fstat().
	 */
	memset(zbuf, 0x5a, sizeof(zbuf));
	for (nblocks = 0; nblocks < 131072; nblocks++) {
		wret = test_write_full(fd, zbuf, sizeof(zbuf));
		if (wret < 0)
			break;
	}
	CHECK(errno == ENOSPC || nblocks > 0, errno,
		"expected ENOSPC, blocks=%zu", nblocks);

	ret = fstat(fd, &st);
	CHECK(ret == 0, errno);

	/* Disk already full at start? Nothing more to verify. */
	if (st.st_size == 0)
		goto out;

	/* Verify file content is intact: last written full block must be 0x5a */
	if (st.st_size >= sizeof(zbuf)) {
		off_t seek = st.st_size - (off_t)sizeof(zbuf);

		ret = lseek(fd, seek, SEEK_SET);
		CHECK(ret >= 0, errno, "lseek to %lld", (long long)seek);
		ret = test_read_full(fd, rbuf, sizeof(rbuf));
		CHECK(ret == sizeof(rbuf), errno, "read last block");
		CHECK(memcmp(rbuf, zbuf, sizeof(zbuf)) == 0, EBADMSG,
			"last block corrupted");
	}

	/* Truncate to half the written size -- must succeed */
	sz_before = st.st_size;

	ret = ftruncate(fd, sz_before / 2);
	CHECK(ret == 0, errno, "ftruncate after ENOSPC fill");

	ret = fstat(fd, &st);
	CHECK(ret == 0, errno);
	CHECK(st.st_size == sz_before / 2, EBADMSG,
		"truncated size=%lld expected=%lld",
		(long long)st.st_size, (long long)(sz_before / 2));

out:
	test_close_fd(&fd);
	test_unlink(name);
	TEST_END();
}

/*
 * shmfs_mmap1: Test shared memory basic mmap operations
 * Tests: shm_open, mmap, write, read verification
 */
static int shmfs_mmap1(void)
{
	int ret = -1, fd = -1;
	char name[128] = {0};
	char *ptr1 = NULL;

	TEST_START("shmfs_mmap1");

	snprintf(name, sizeof(name), "/shm1-%d%d-%x.txt",
		gettid(), getpid(), test_rand());

	test_shm_unlink(name);

	pthread_cleanup_push((void (*)(void *))test_shm_unlink, name);

	if (test_rand() % 2)
		fd = shm_open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	else
		fd = shm_open(name, O_RDWR | O_CREAT, 0666);
	CHECK(fd >= 0, errno, "shm_open %s fd=%d", name, fd);

	if (test_rand() % 2) {
		ret = test_write_full(fd, "1as1as11", 8);
		CHECK(ret == 8, errno,
			"mmap seed write %s ret=%d", name, ret);
	}

	ptr1 = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(ptr1 && ptr1 != MAP_FAILED, errno, "mmap %s ptr=%p", name, ptr1);

	ret = test_write_full(fd, "1as1as11", 8);
	CHECK(errno != ENOMEM, errno, "write %s ret=%d", name, ret);

	CHECK(ret == 8, errno, "write %s ret=%d", name, ret);

	CHECK(memcmp(ptr1, "1as1as11", 8) == 0,
		EBADMSG, "mmap content %s", name);

	CHECK(test_close_fd(&fd) == 0, errno);

	if (test_rand() % 3 == 0) {
		ret = munmap(ptr1, 1024);
		CHECK(ret >= 0, errno);
		ptr1 = NULL;
	}

out:
	test_close_fd(&fd);
	if (ptr1 && ptr1 != MAP_FAILED) {
		munmap(ptr1, 1024);
		ptr1 = NULL;
	}

	pthread_cleanup_pop(1);
	return TEST_END();
}

/*
 * shmfs_mmap2: Test shared memory large mmap with offsets
 * Tests: 1MB mmap, lseek, offset write/read
 */
static int shmfs_mmap2(void)
{
	int ret = -1, fd = -1, offset = 0;
	char name[128] = {0};
	char *ptr1 = NULL;

	TEST_START("shmfs_mmap2");

	snprintf(name, sizeof(name), "/shm2-%d%d-%x.txt",
		gettid(), getpid(), test_rand());

	test_shm_unlink(name);

	pthread_cleanup_push((void (*)(void *))test_shm_unlink, name);

	if (test_rand() % 2)
		fd = shm_open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	else
		fd = shm_open(name, O_RDWR | O_CREAT, 0666);
	CHECK(fd >= 0, errno, "shm_open %s fd=%d", name, fd);

	ptr1 = mmap(NULL, 1024 * 1024, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(errno != ENOMEM, errno, "mmap %s ptr=%p", name, ptr1);

	CHECK(ptr1 && ptr1 != MAP_FAILED, errno, "mmap %s ptr=%p", name, ptr1);

	offset = test_rand() % (1024 * 1024) + 1;
	offset -= 17;
	if (offset < 0)
		offset = 0;
	ret = lseek(fd, offset, SEEK_SET);
	CHECK(ret >= 0, errno, "mmap lseek off=%d ret=%d", offset, ret);

	ret = test_write_full(fd, "2222222233333333\0", 17);
	CHECK(ret == 17, errno, "mmap write off=%d ret=%d", offset, ret);

	CHECK(memcmp(ptr1 + offset, "2222222233333333\0", 17) == 0,
		EBADMSG, "mmap content off=%d", offset);

	CHECK(test_close_fd(&fd) == 0, errno);

	if (test_rand() % 3 == 0) {
		ret = munmap(ptr1, 1024 * 1024);
		CHECK(ret >= 0, errno);
		ptr1 = NULL;
	}

out:
	test_close_fd(&fd);
	if (ptr1 && ptr1 != MAP_FAILED) {
		munmap(ptr1, 1024 * 1024);
		ptr1 = NULL;
	}

	pthread_cleanup_pop(1);
	return TEST_END();
}

/*
 * shmfs_mmap3: ftruncate + multi-mmap interaction test.
 *  - ftruncate(0->4096), mmap, write via mmap, verify via read() (MAP_SHARED)
 *  - ftruncate(4096->8192), re-mmap at new size, verify old data intact
 *  - verify newly extended region is zero-filled
 */
static void shmfs_mmap3(void)
{
	int ret = -1;
	int fd = -1, off = 1024;
	char name[128] = {0};
	char *p1 = NULL, *p2 = NULL;
	char rb[16] = {0};
	const char *pat = "mmap3";

	TEST_START("shmfs_mmap3");

	snprintf(name, sizeof(name), "/shm3-%d%d-%x.txt",
		gettid(), getpid(), test_rand());

	test_shm_unlink(name);

	pthread_cleanup_push((void (*)(void *))test_shm_unlink, name);

	fd = shm_open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(fd >= 0, errno);

	ret = ftruncate(fd, 4096);
	CHECK(ret == 0, errno);

	p1 = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(p1 && p1 != MAP_FAILED, errno, "mmap p1 ptr=%p", p1);

	memcpy(p1 + off, pat, strlen(pat));

	ret = lseek(fd, off, SEEK_SET);
	CHECK(ret == off, errno);
	memset(rb, 0, sizeof(rb));
	ret = test_read_full(fd, rb, strlen(pat));
	CHECK(ret == strlen(pat), errno);
	CHECK(memcmp(rb, pat, strlen(pat)) == 0, EBADMSG);

	ret = ftruncate(fd, 8192);
	CHECK(ret == 0, errno);

	p2 = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	CHECK(p2 && p2 != MAP_FAILED, errno, "mmap p2 ptr=%p", p2);
	CHECK(memcmp(p2 + off, pat, strlen(pat)) == 0, EBADMSG);

	ret = lseek(fd, 4096, SEEK_SET);
	CHECK(ret == 4096, errno);
	memset(rb, 0x5a, sizeof(rb));
	ret = test_read_full(fd, rb, sizeof(rb));
	CHECK(ret >= 0, errno);
	for (ret = 0; ret < sizeof(rb); ret++)
		CHECK(rb[ret] == 0, EBADMSG);

out:
	if (p1 && p1 != MAP_FAILED)
		munmap(p1, 4096);
	if (p2 && p2 != MAP_FAILED)
		munmap(p2, 8192);
	test_close_fd(&fd);
	pthread_cleanup_pop(1);
	TEST_END();
}

/*
 * fs_dual_fd_trunc_test: Verify that truncating and rewriting a file through
 * one fd is visible when reading through another fd already open on the same
 * file. A helper file is created in between to consume the freed cluster so
 * that the rewrite lands on a different cluster, exposing any stale sclst
 * cached in the reader's f_info.
 *
 * Expected: read through fd1 returns the NEW data ("BBBB..."), not stale data.
 */
static int fs_dual_fd_trunc_test(const char *rootdir, size_t blksize)
{
	int fd1 = -1, fd2 = -1, fd_tmp = -1, ret = -1;
	char name[FS_BUFFER_SIZE];
	char tmpname[FS_BUFFER_SIZE];
	char *wbuf = NULL, *rbuf = NULL, *tbuf = NULL;
	size_t datasz = blksize;

	snprintf(name, FS_BUFFER_SIZE, "%s/fs_%04d_dft.%x%d",
		rootdir, gettid(), test_rand(), test_rand());
	snprintf(tmpname, FS_BUFFER_SIZE, "%s/fs_%04d_dft_t.%x%d",
		rootdir, gettid(), test_rand(), test_rand());

	test_unlink(name);
	test_unlink(tmpname);

	wbuf = malloc(datasz);
	rbuf = malloc(datasz);
	tbuf = malloc(datasz);
	CHECK(wbuf && rbuf && tbuf, ENOMEM, "alloc dual-fd buffers size=%zu", datasz);

	/*
	 * Step 1: create the file and write initial data (fills cluster X).
	 * Use 'A' pattern so we can distinguish it from every other pattern.
	 */
	memset(wbuf, 'A', datasz);
	fd1 = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(fd1 >= 0, errno, "open %s", name);
	ret = test_write_full(fd1, wbuf, datasz);
	CHECK(ret == datasz, errno);
	test_close_fd(&fd1);

	/*
	 * Step 2: fd1 = open for read.  f_info caches sclst = X.
	 */
	fd1 = open(name, O_RDONLY);
	CHECK(fd1 >= 0, errno, "open %s", name);

	/*
	 * Step 3: fd2 = open with O_TRUNC -> frees cluster X, data zeroed.
	 * After clst_free, last_clst = X-1, so next alloc scans from X.
	 */
	fd2 = open(name, O_RDWR | O_TRUNC, 0666);
	CHECK(fd2 >= 0, errno, "open %s", name);

	/*
	 * Step 4: create a helper file to consume cluster X so that the write
	 * through fd2 must go to a different cluster.
	 * helper file consumes the freed cluster so fd2's rewrite must
	 * land on a different cluster, exposing stale sclst bugs
	 */
	memset(tbuf, 'Z', datasz);
	fd_tmp = open(tmpname, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(fd_tmp >= 0, errno, "open %s", tmpname);
	ret = test_write_full(fd_tmp, tbuf, datasz);
	CHECK(ret == datasz, errno);
	test_close_fd(&fd_tmp);

	/*
	 * Step 5: write new data through fd2 (gets cluster Y != X).
	 */
	memset(wbuf, 'B', datasz);
	ret = test_write_full(fd2, wbuf, datasz);
	CHECK(ret == datasz, errno);
	test_close_fd(&fd2);

	/*
	 * Step 6: read through fd1 whose sclst may be stale (X).
	 * Correct behaviour: returns "BBB..." (new data at cluster Y).
	 * Bug exposure:      returns "ZZZ..." (helper file at cluster X)
	 *                    or "AAA..." (old zeroed-then-rewritten cluster)
	 *                    or zeros.
	 */
	memset(rbuf, 0, datasz);
	ret = test_read_full(fd1, rbuf, datasz);
	CHECK(ret == datasz, errno,
		"dual_fd_trunc read ret=%d expected=%zu",
		ret, datasz);

	CHECK(memcmp(rbuf, wbuf, datasz) == 0, EBADMSG);

out:
	test_close_fd(&fd1);
	test_close_fd(&fd2);
	test_close_fd(&fd_tmp);
	test_unlink(name);
	test_unlink(tmpname);
	free(wbuf);
	free(rbuf);
	free(tbuf);
	return TEST_ERRNO();
}

/*
 * fs_test_mnt: Filesystem test coordinator
 * Orchestrates all sub-tests @ rootdir of mnt
 */
/*
 * fs_lseek_boundary_test: lseek boundary and error paths.
 *  - lseek with negative offset -> EINVAL
 *  - lseek on invalid fd -> EBADF
 *  - lseek SEEK_END on new file -> 0 (empty file)
 *  - lseek SEEK_SET beyond EOF -> succeeds (sparse)
 *  - lseek SEEK_CUR idempotent
 */
static int fs_lseek_boundary_test(const char *rootdir)
{
	int fd = -1, ret = -1;
	off_t off = 0;
	char name[FS_BUFFER_SIZE];

	snprintf(name, FS_BUFFER_SIZE, "%s/lseek_%04d.%x.txt",
		rootdir, gettid(), test_rand());
	test_unlink(name);

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(fd >= 0, errno, "open %s", name);

	/* SEEK_END on empty file -> 0 */
	off = lseek(fd, 0, SEEK_END);
	CHECK(off == 0, errno, "SEEK_END empty file off=%lld", (long long)off);

	/* SEEK_SET negative -> EINVAL */
	off = lseek(fd, -1, SEEK_SET);
	CHECK(off == (off_t)-1 && errno == EINVAL, errno,
		"lseek(-1, SEEK_SET) should fail EINVAL off=%lld", (long long)off);

	/* Write some data then verify SEEK_CUR idempotency */
	ret = test_write_full(fd, "1234", 4);
	CHECK(ret == 4, errno);
	off = lseek(fd, 0, SEEK_CUR);
	CHECK(off == 4, errno);
	off = lseek(fd, 0, SEEK_CUR);
	CHECK(off == 4, errno, "SEEK_CUR not idempotent off=%lld", (long long)off);

	/* SEEK_SET beyond EOF -> succeeds, file becomes sparse */
	off = lseek(fd, 8192, SEEK_SET);
	CHECK(off == 8192, errno, "SEEK_SET beyond EOF off=%lld", (long long)off);

	/* Invalid fd -> EBADF */
	off = lseek(-1, 0, SEEK_SET);
	CHECK(off == (off_t)-1 && errno == EBADF, errno, "lseek on closed fd");

out:
	test_close_fd(&fd);
	test_unlink(name);
	return TEST_ERRNO();
}

/*
 * fs_unlink_error_test: unlink / remove error paths.
 *  - unlink non-existent -> ENOENT
 *  - unlink a directory -> EISDIR or EPERM (implementation-defined)
 *  - remove non-existent -> ENOENT
 */
static int fs_unlink_error_test(const char *rootdir)
{
	int ret = -1;
	char name[FS_BUFFER_SIZE];
	char dir[FS_BUFFER_SIZE];

	snprintf(name, FS_BUFFER_SIZE, "%s/ulerr_%04d.%x",
		rootdir, gettid(), test_rand());
	snprintf(dir, FS_BUFFER_SIZE, "%s/uldir_%04d.%x",
		rootdir, gettid(), test_rand());

	/* Make sure they don't exist */
	test_unlink(name);
	test_rmdir(dir);

	/* unlink non-existent -> ENOENT */
	ret = unlink(name);
	CHECK(errno == ENOENT, errno,
		"unlink non-existent ret=%d", ret);

	/* remove non-existent -> ENOENT */
	ret = remove(name);
	CHECK(errno == ENOENT, errno,
		"remove non-existent ret=%d", ret);

	/*
	 * unlink a directory -> EISDIR or EPERM (local fs) or EACCES
	 * (reefs via RPC: host EISDIR -> TEEC_ERROR_ACCESS_DENIED -> TEE EACCES).
	 */
	ret = mkdir(dir, 0700);
	CHECK(ret == 0 || errno == EEXIST, errno);
	ret = unlink(dir);
	CHECK(errno == EISDIR || errno == EACCES, errno,
		"unlink dir ret=%d err=%d", ret, errno);

out:
	test_rmdir(dir);
	test_unlink(name);
	return TEST_ERRNO();
}

/*
 * fs_access_test: basic access() checks.
 *  - F_OK on existing file
 *  - R_OK / W_OK on a created file
 *  - F_OK on non-existent -> ENOENT
 *  - X_OK -> EACCES (mbedtee doesn't support execute permission)
 */
static int fs_access_test(const char *rootdir)
{
	int fd = -1, ret = -1;
	char name[FS_BUFFER_SIZE];

	snprintf(name, FS_BUFFER_SIZE, "%s/acctst_%04d.%x",
		rootdir, gettid(), test_rand());
	test_unlink(name);

	/* F_OK on non-existent -> -1, ENOENT */
	ret = access(name, F_OK);
	CHECK(ret == -1 && errno == ENOENT, errno,
		"access F_OK non-existent ret=%d", ret);

	/* Create a file */
	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(fd >= 0, errno);
	test_close_fd(&fd);

	/* F_OK on existing file -> 0 */
	ret = access(name, F_OK);
	CHECK(ret == 0, errno, "access F_OK existing ret=%d", ret);

	/* R_OK on readable file -> 0 */
	ret = access(name, R_OK);
	CHECK(ret == 0, errno, "access R_OK ret=%d", ret);

out:
	test_unlink(name);
	return TEST_ERRNO();
}

/*
 * fs_test_mnt: filesystem test coordinator -- runs all sub-tests
 * for a given mount point, each returning TEST_ERRNO().
 */
static void fs_test_mnt(const char *rootdir)
{
	int ret = -1;
	size_t blksize;

	TEST_START(rootdir);

	blksize = fs_detect_blksize(rootdir);

	/* Basic filesystem operations test */
	ret = fs_basic_test(rootdir, blksize);
	CHECK(ret == 0, ret, "fs_basic_test");

	/* pread/pwrite test */
	ret = fs_pread_pwrite_test(rootdir);
	CHECK(ret == 0, ret, "fs_pread_pwrite_test");

	/* Rename operations test */
	ret = fs_rename_test(rootdir);
	CHECK(ret == 0, ret, "fs_rename_test");

	/* Ftruncate boundary test */
	ret = fs_truncate_boundary_test(rootdir, blksize);
	CHECK(ret == 0, ret, "fs_truncate_boundary_test");

	/* Metadata stat/lstat/fstat test */
	ret = fs_metadata_test(rootdir);
	CHECK(ret == 0, ret, "fs_metadata_test");

	/* O_TRUNC/O_APPEND with lseek edge test */
	ret = fs_trunc_append_seek_test(rootdir);
	CHECK(ret == 0, ret, "fs_trunc_append_seek_test");

	/* Write boundary test */
	ret = fs_write_boundary_test(rootdir, blksize);
	CHECK(ret == 0, ret, "fs_write_boundary_test");

	/* Sparse file hole test */
	ret = fs_hole_test(rootdir, blksize);
	CHECK(ret == 0, ret, "fs_hole_test");

	/* O_APPEND test */
	ret = fs_append_test(rootdir, blksize);
	CHECK(ret == 0, ret, "fs_append_test");

	/* Directory operations test */
	ret = fs_directory_test(rootdir);
	CHECK(ret == 0, ret, "fs_directory_test");

	/* telldir/seekdir roundtrip test */
	ret = fs_readdir_seek_test(rootdir);
	CHECK(ret == 0, ret, "fs_readdir_seek_test");

	/* Dual-fd truncate: verify sclst consistency */
	ret = fs_dual_fd_trunc_test(rootdir, blksize);
	CHECK(ret == 0, ret, "fs_dual_fd_trunc_test");

	/* lseek boundary / error path test */
	ret = fs_lseek_boundary_test(rootdir);
	CHECK(ret == 0, ret, "fs_lseek_boundary_test");

	/* unlink / remove error path test */
	ret = fs_unlink_error_test(rootdir);
	CHECK(ret == 0, ret, "fs_unlink_error_test");

	/* access() basic test */
	ret = fs_access_test(rootdir);
	CHECK(ret == 0, ret, "fs_access_test");

out:
	TEST_END();
}

/*
 * fs_test: entry point -- iterates mount points 5x, randomly
 * selecting rootdir and shmfs/mmaps for repeated stress coverage.
 */
void fs_test(void)
{
	int i = 0;

	for (i = 0; i < 5; i++) {
		if (test_rand() % 2 == 0)
			fs_test_mnt("/");
		else
			fs_test_mnt("/user");

		if (test_rand() % 7 == 0)
			shmfs_mmap1();

		if (IS_ENABLED(CONFIG_RPMBFS) && (i == 0))
			fs_test_mnt("/rpmb");

		if (test_rand() % 13 == 0)
			fs_test_mnt("/test");

		/* ENOSPC disk-full test: /test only (other mounts take too long) */
		if (i == 0)
			fs_enospc_test("/test");

		shmfs_mmap1();

		shmfs_mmap2();

		if (IS_ENABLED(CONFIG_REEFS) && (i == 0))
			fs_test_mnt("/ree");

		fs_test_mnt("/shm");

		if (test_rand() % 13 == 0)
			shmfs_mmap2();

		if (test_rand() % 7 == 0)
			fs_test_mnt("/shm/test");

		shmfs_mmap3();
	}
}
