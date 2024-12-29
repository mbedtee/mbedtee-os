// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * misc functions
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>

#include <file.h>
#include <thread.h>
#include <panic.h>

__weak_symbol void abort(void)
{
	panic("aborted\n");
}

__weak_symbol int raise(int signo)
{
	IMSG("raising %d\n", signo);
	backtrace();
	int ret = sigenqueue(current_id, signo, SI_QUEUE,
			 (union sigval)((void *)-ESRCH), true);

	if (ret != 0)
		abort();

	return ret;
}

__weak_symbol int stat(const char *fpath, struct stat *s)
{
	int fd = -1, ret = -1;

	fd = sys_open(fpath, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = sys_fstat(fd, s);

	sys_close(fd);

	return ret;
}

__weak_symbol int access(const char *fpath, int mode)
{
	struct stat s;

	if (mode & X_OK)
		return -1;

	if (stat(fpath, &s))
		return -1;

	if (s.st_mode & S_IFDIR)
		return 0;

	if ((mode & W_OK) && !(s.st_mode & S_IWRITE))
		return -1;

	return 0;
}

__weak_symbol int creat(const char *path, mode_t mode)
{
	return sys_open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
}
