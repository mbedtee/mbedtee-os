/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Define the structures and macros for REEFS rpc
 */

#ifndef _RPC_REEFS_H
#define _RPC_REEFS_H

#include <rpc/supplicant.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * REEFS functions
 */
#define REEFS_OPEN       1
#define REEFS_CLOSE      2
#define REEFS_READ       3
#define REEFS_WRITE      4
#define REEFS_SEEK       5
#define REEFS_UNLINK     6
#define REEFS_RENAME     7
#define REEFS_TRUNC      8
#define REEFS_MKDIR      9
#define REEFS_OPENDIR   10
#define REEFS_CLOSEDIR  11
#define REEFS_READDIR   12
#define REEFS_SEEKDIR   13
#define REEFS_RMDIR     14
#define REEFS_FSTAT     15
#define REEFS_PREAD     16
#define REEFS_PWRITE    17

/*
 * REEFS open flags (Fixed values for RPC)
 */
#define REEFS_O_RDONLY      00000000
#define REEFS_O_WRONLY      00000001
#define REEFS_O_RDWR        00000002
#define REEFS_O_CREAT       00000100
#define REEFS_O_EXCL        00000200
#define REEFS_O_TRUNC       00001000
#define REEFS_O_APPEND      00002000
#define REEFS_O_DIRECTORY   00200000

/*
 * REEFS seek flags (Fixed values for RPC)
 */
#define REEFS_SEEK_SET      0
#define REEFS_SEEK_CUR      1
#define REEFS_SEEK_END      2

struct reefs_cmd {
	struct supp_cmd_hdr hdr;

	int flags;
	int fd;

	uint64_t len;

	char data[];
};

struct reefs_dirent {
	uint64_t	d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[];
};

struct reefs_stat {
	uint64_t rst_size;
	uint64_t rst_atime;
	uint64_t rst_mtime;
	uint64_t rst_ctime;
};

#ifdef __cplusplus
}
#endif

#endif
