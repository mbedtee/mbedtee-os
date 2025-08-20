/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * directory operations
 */

#ifndef _DIRENT_H
#define	_DIRENT_H

#include <sys/lock.h>

#ifdef __cplusplus
extern "C" {
#endif

/* d_type */
#define DT_UNKNOWN  0
#define DT_FIFO     1
#define DT_CHR      2
#define DT_DIR      4
#define DT_BLK      6
#define DT_REG      8
#define DT_LNK      10
#define DT_SOCK     12
#define DT_WHT      14

typedef struct {
	int dd_fd;
	long dd_loc;
	long dd_len;
	long dd_size;
	long dd_off;
	_LOCK_RECURSIVE_T dd_lock;
	char *dd_buf;
} DIR;

struct dirent {
	unsigned long	d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char			d_name[];
};

DIR *opendir(const char *name);
struct dirent *readdir(DIR *d);
int closedir(DIR *d);
void seekdir(DIR *d, long offset);
void rewinddir(DIR *d);
long telldir(DIR *d);

#ifdef __cplusplus
}
#endif

#endif
