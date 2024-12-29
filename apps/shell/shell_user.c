// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * simple shell @ user-space
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <getopt.h>
#include <dirent.h>
#include <stdbool.h>
#include <poll.h>
#include <math.h>
#include <sys/syslimits.h>

#include <defs.h>
#include <misc.h>
#include <sched.h>
#include <shell.h>
#include <utrace.h>

#include <pthread.h>

#define IS_EOF(buf, bufsize, rdbytes) (((rdbytes) < (bufsize)) ||	\
	(((rdbytes) == (bufsize)) && ((buf)[(rdbytes) - 1] == 0)))

static __printf(2, 3)
void shmsg(struct shell *sh, const char *fmt, ...)
{
	int len = 0;
	va_list ap = {0};
	struct ring_print *r = &sh->ringprint;

	if (fmt == NULL)
		return;

	if (r->pos < sizeof(r->ringbuf)) {
		va_start(ap, fmt);
		len = vsnprintf(r->ringbuf + r->pos,
			sizeof(r->ringbuf) - r->pos, fmt, ap);
		va_end(ap);
	}

	if (len >= sizeof(r->ringbuf) - r->pos) {
		write(r->fd, r->ringbuf, r->pos);

		r->pos = 0;
		va_start(ap, fmt);
		len = vsnprintf(r->ringbuf, sizeof(r->ringbuf), fmt, ap);
		va_end(ap);
	}

	r->pos = min((size_t)(len + r->pos), sizeof(r->ringbuf));
}

void shmsg_flush(struct shell *sh)
{
	struct ring_print *r = &sh->ringprint;

	if (r->pos) {
		write(r->fd, r->ringbuf, r->pos);
		r->pos = 0;
	}
}

static void read_debugfs(struct shell *sh, int fd)
{
	int ret = -1;
	struct ring_print *r = &sh->ringprint;

	shmsg_flush(sh);

	do {
		ret = read(fd, r->ringbuf, sizeof(r->ringbuf));
		if (ret < 0)
			break;

		write(r->fd, r->ringbuf, ret);

		/* EOF ? */
		if (IS_EOF(r->ringbuf, sizeof(r->ringbuf), ret))
			break;
	} while (1);
}

static void cmd_ps(struct shell *sh)
{
	int fd = -1;
	const char *path = "/debug/threads";
	const char *option = sh->argv[1];

	fd = open(path, O_RDWR);
	if (fd < 0) {
		shmsg(sh, "open(%s) failed - errno %d\n", path, errno);
		return;
	}

	/* show the thread's waiting information */
	if (option && strcmp(option, "w") == 0)
		write(fd, "w", 1);

	read_debugfs(sh, fd);

	close(fd);
}

static void ls_fstat(struct shell *sh,
	const char *path)
{
	struct stat st = {0};
	struct tm *tinfo = NULL;
	int fd = -1;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno == EISDIR)
			fd = open(path, O_RDONLY | O_DIRECTORY);

		if (fd < 0) {
			shmsg(sh, "open %s failed %d\n", path, errno);
			return;
		}
	}

	fstat(fd, &st);

	tinfo = localtime(&st.st_mtime);

	shmsg(sh, "%s\t%ld\t%ld\t%ld\t%04d-%02d-%02d %02d:%02d:%02d %s\n",
		st.st_mode == S_IFDIR ? "DIR" : "File",
		st.st_size, st.st_blksize, st.st_blocks,
		tinfo->tm_year+1900, tinfo->tm_mon+1, tinfo->tm_mday,
		tinfo->tm_hour, tinfo->tm_min, tinfo->tm_sec, basename(path));

	close(fd);
}

static void cmd_ls(struct shell *sh)
{
	DIR *dir = NULL;
	struct dirent *d = NULL;
	char filepath[PATH_MAX];
	const char *path = sh->argv[1] ? sh->argv[1] : "/";

	dir = opendir(path);
	if (dir == NULL) {
		ls_fstat(sh, path);
		return;
	}

	while (1) {
		d = readdir(dir);
		if (d == NULL)
			break;

		snprintf(filepath, sizeof(filepath), "%s/%s", path, d->d_name);

		ls_fstat(sh, filepath);
	}

	closedir(dir);
}

static inline char *dirname(char *path)
{
	int i = 0;
	unsigned int l = 0;

	if (path == NULL || *path == 0)
		return NULL;

	l = strlen(path);

	while (l && (path[l - 1] == '/')) {
		path[l - 1] = 0;
		l--;
	}

	for (i = l - 1; i >= 0; i--) {
		if (path[i] == '/') {
			path[i] = 0;
			break;
		}
	}

	return (i < 0 || *path == 0) ? "/" : path;
}

static void rmdir_recursive(struct shell *sh,
	const char *dirpath, const char *expected, bool recursion)
{
	char fpath[PATH_MAX];
	DIR *dir = NULL;
	struct dirent *d = NULL;
	struct stat st;
	char *extstart = NULL;
	char *isext = NULL;
	int rewind = 0, err = 0;

	dir = opendir(dirpath);
	if (dir == NULL)
		return;

	while (1) {
		d = readdir(dir);
		if (d == NULL) {
			if (rewind) {
				rewinddir(dir);
				d = readdir(dir);
				rewind = 0;
			}
			if (d == NULL)
				break;
		}

		isext = strchr(expected, '.');
		extstart = strrchr(d->d_name, '.');

		if ((strcmp(expected, "*") == 0) || (isext &&
			extstart && strcmp(extstart, expected) == 0) ||
			(!isext && strstr(d->d_name, expected))) {

			snprintf(fpath, sizeof(fpath), "%s/%s",
				strcmp(dirpath, "/") ? dirpath : "", d->d_name);

			stat(fpath, &st);
			if (st.st_mode == S_IFDIR) {
				if (recursion)
					rmdir_recursive(sh, fpath, "*", recursion);
				else {
					err = rmdir(fpath);
					shmsg(sh, "rmdir %s errno = %d\n", fpath, errno);
				}
			} else {
				err = unlink(fpath);
				shmsg(sh, "unlink %s errno = %d\n", fpath, errno);
			}
			st.st_mode = 0;
			if (err == 0)
				rewind++;
		}
	}

	closedir(dir);

	if (strcmp(expected, "*") == 0) {
		rmdir(dirpath);
		shmsg(sh, "rmdir %s errno = %d\n", dirpath, errno);
	}
}

static void cmd_rmpath(struct shell *sh, char *path, bool recursion)
{
	int fd = -1;
	struct stat st;

	fd = open(path, O_RDONLY);

	if (fd > 0) {
		fstat(fd, &st);
		close(fd);
		if (st.st_mode == S_IFDIR) {
			if (recursion)
				rmdir_recursive(sh, path, "*", recursion);
			else {
				rmdir(path);
				shmsg(sh, "rmdir %s errno = %d\n", path, errno);
			}
		} else {
			unlink(path);
			shmsg(sh, "unlink %s errno = %d\n", path, errno);
		}
	} else {
		char *fname = basename(path);
		char *dir = dirname(path);
		char *expected = strchr(fname, '*');

		shmsg(sh, "dir %s name %s expected %s\n", dir, fname,
			expected ? expected : "null");

		if (expected == NULL)
			return;

		if (strlen(expected + 1) == 0) {
			*expected = 0;
			expected = fname;
		} else
			expected++;

		shmsg(sh, "dir %s name %s expected %s\n", dir, fname,
			expected ? expected : "null");

		rmdir_recursive(sh, dir, expected, recursion);
	}
}

static void cmd_rm(struct shell *sh)
{
	int recuridx = 1, pathidx = 1;
	int opt = -1, recursion = false;
	char *path = NULL, *recurstr = NULL;

	if (sh->argc < 2)
		return;

	while ((opt = getopt(sh->argc, sh->argv, "r")) != -1) {
		switch (opt) {
		case 'r':
			recursion = true;
			break;
		default:
			break;
		}
	}
	optarg = NULL; optind = opterr = optopt = 0;

	if (recursion) {
		while ((recurstr = sh->argv[recuridx]) != NULL) {
			if (strncmp(recurstr, "-r", 3) == 0)
				break;
			recuridx++;
		}
		sh->argv[recuridx] = NULL;
		if (recuridx == 1)
			pathidx = 2;
	}

	while ((path = sh->argv[pathidx++]) != NULL)
		cmd_rmpath(sh, path, recursion);
}

static void cmd_mem(struct shell *sh)
{
	int fd = -1;
	const char *path = "/debug/mem";

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		shmsg(sh, "open(%s) failed - errno %d\n", path, errno);
		return;
	}

	read_debugfs(sh, fd);

	close(fd);
}

static void cmd_irq(struct shell *sh)
{
	int fd = -1;
	const char *path = "/debug/irq";

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		shmsg(sh, "open(%s) failed - errno %d\n", path, errno);
		return;
	}

	read_debugfs(sh, fd);

	close(fd);
}

static void cmd_date(struct shell *sh)
{
	struct timespec ts;
	struct timespec stamp;
	struct tm *tinfo = NULL;

	clock_gettime(CLOCK_MONOTONIC, &stamp);

	clock_gettime(CLOCK_REALTIME, &ts);

	shmsg(sh, "CPU%d Monotonic - %llu.%09lus\n",
		sched_getcpu(), (long long)stamp.tv_sec, stamp.tv_nsec);

	tinfo = localtime(&ts.tv_sec);

	shmsg(sh, "System - %04d-%02d-%02d %02d:%02d:%02d.%09ld\n",
		tinfo->tm_year+1900, tinfo->tm_mon+1, tinfo->tm_mday,
		tinfo->tm_hour, tinfo->tm_min, tinfo->tm_sec, ts.tv_nsec);
}

static void cmd_mount(struct shell *sh)
{
	int fd = -1;
	const char *path = "/debug/mount";

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		shmsg(sh, "open(%s) failed - errno %d\n", path, errno);
		return;
	}

	read_debugfs(sh, fd);

	close(fd);
}

static void kill_common(const char *str, int digits, int idx,
	int signo, int decimal, bool istkill)
{
	int i = 0;
	pid_t tid = 0;
	int decimal_nxt = 0;

	if (idx < digits) {
		for (i = 0; i < 10; i++) {
			if ((str[idx] != '*') && ((str[idx] - '0') != i))
				continue;
			if (idx == (digits - 1)) {
				tid = decimal + i;
				if (tid != gettid() && tid != getpid()) {
					if (!istkill)
						kill(tid, signo);
					else
						pthread_kill(tid, signo);
				}
			} else {
				decimal_nxt = decimal + i * __pow(10, digits - idx - 1);
				if (decimal_nxt >= gettid_max())
					return;
				kill_common(str, digits, idx + 1, signo, decimal_nxt, istkill);
			}
		}
	}
}

static void do_kill(struct shell *sh, bool istkill)
{
	int signo = 0;
	pid_t tid = 0;
	int i = 0, len = 0;
	const char *sigstr = sh->argv[1];
	const char *tidstr = sh->argv[2];

	if (!tidstr && !sigstr) {
		shmsg(sh, "invalid tid/sig argv\n");
		return;
	}

	if (!tidstr) {
		tidstr = sh->argv[1];
		signo = istkill ? SIGCANCEL : SIGKILL;
	} else {
		signo = strtoul(sigstr, NULL, 10);
		if ((unsigned int)signo >= NSIG) {
			shmsg(sh, "invalid signo - %d\n", signo);
			return;
		}
	}

	len = strlen(tidstr);
	if (len > 5) {
		shmsg(sh, "invalid tid - %s\n", tidstr);
		return;
	}

	for (i = 0; i < len; i++) {
		if (!isdigit((int)tidstr[i]) && (tidstr[i] != '*')) {
			shmsg(sh, "invalid tid - %s\n", tidstr);
			return;
		}
	}

	if (!strchr(tidstr, '*')) {
		tid = strtoul(tidstr, NULL, 10);
		if (!istkill)
			kill(tid, signo);
		else
			pthread_kill(tid, signo);
	} else {
		char str[5] = {'0', '0', '0', '0', '0'};

		memcpy(&str[5 - len], tidstr, len);
		kill_common(str, 5, 0, signo, 0, istkill);
	}
}

static void cmd_kill(struct shell *sh)
{
	do_kill(sh, false);
}

static void cmd_tkill(struct shell *sh)
{
	do_kill(sh, true);
}

static int mkmultidirs(struct shell *sh, const char *path, mode_t mode)
{
	int ret = -1;
	int i, len = strlen(path);
	char dir[PATH_MAX];

	strlcpy(dir, path, sizeof(dir));

	for (i = 0; i <= len; i++) {
		if ((dir[i] == '/' && i > 0) || (i == len)) {
			dir[i] = 0;
			if (access(dir, R_OK) < 0) {
				ret = mkdir(dir, mode);
				if (ret != 0) {
					ret = errno;
					shmsg(sh, "mkdir %s errno %d\n", dir, ret);
					return ret;
				}
			}
			dir[i] = '/';
		}
	}

	return 0;
}

static void cmd_mkdir(struct shell *sh)
{
	char *path = sh->argv[1];
	struct stat st;
	int ret = -1;

	if (!path) {
		shmsg(sh, "miss dir path\n");
		return;
	}

	ret = stat(path, &st);
	if (ret == 0) {
		if (st.st_mode & S_IFDIR)
			return;
		shmsg(sh, "%s already exists\n", path);
		return;
	}

	mkmultidirs(sh, path, 0666);
}

static void cmd_mkfile(struct shell *sh)
{
	char *path = sh->argv[1];
	char dir[PATH_MAX];
	char *dirpath = NULL;
	int ret = -1;

	if (!path) {
		shmsg(sh, "miss file path\n");
		return;
	}

	strlcpy(dir, path, sizeof(dir));
	dirpath = dirname(dir);

	ret = mkmultidirs(sh, dirpath, 0666);
	if (ret != 0)
		return;

	ret = creat(path, 0666);
	if (ret < 0)
		shmsg(sh, "creat %s errno=%d\n", path, errno);
}

static void cmd_help(struct shell *sh);
static const struct shell_cmd cmd_handlers[] = {
	{"help", "List the supported commands\n", cmd_help},
	{"ps", "Show information of all threads\n", cmd_ps},
	{"ls", "Show files in file system\n", cmd_ls},
	{"rm", "Remove files in file system\n", cmd_rm},
	{"mem", "Show memory info\n", cmd_mem},
	{"irq", "Show IRQ info\n", cmd_irq},
	{"date", "Elapsed time since startup\n", cmd_date},
	{"kill", "Send signal to a process\n", cmd_kill},
	{"tkill", "Send signal to a thread\n", cmd_tkill},
	{"mkdir", "make a dir\n", cmd_mkdir},
	{"mkfile", "make a file\n", cmd_mkfile},
	{"mount", "Show the FS nodes\n", cmd_mount},
};

static void cmd_help(struct shell *sh)
{
	int i = 0;

	for (i = 0; i < ARRAY_SIZE(cmd_handlers); i++)
		shmsg(sh, "%s	%s", cmd_handlers[i].cmd, cmd_handlers[i].help);
}

static int cmd_parse_argv(struct shell *sh)
{
	int i = 0, len = sh->cmd_pos;
	int argc = 0, pos = 0;
	int lastchar = 0;
	char **argv = NULL;

	while (i < len) {
		if (sh->cmd[i] == ' ')
			sh->cmd[i] = 0;
		i++;
	}

	/* roughly get the argc */
	i = 0;
	while (i < len) {
		if (sh->cmd[i] && (lastchar == 0))
			argc++;

		lastchar = sh->cmd[i];
		i++;
	}

	if (argc >= CMD_DFTARGV_NUM) {
		argv = calloc(argc + 1, sizeof(char *));
		if (argv == NULL)
			return -ENOMEM;
	} else
		argv = sh->dft_argv;

	i = 0;
	lastchar = 0;
	while (i < len) {
		if (sh->cmd[i] && (lastchar == 0))
			argv[pos++] = &sh->cmd[i];

		lastchar = sh->cmd[i];
		i++;
	}

	sh->argv = argv;
	sh->argc = argc;

	argv[argc] = NULL;

	return 0;
}

static void cmd_free_argv(struct shell *sh)
{
	if (sh->argv != sh->dft_argv)
		free(sh->argv);
}

static void cmd_record(struct shell *sh)
{
	struct cmd_history *h = NULL;

	h = &sh->history[sh->history_rec_pos];

	memcpy(h->cmd, sh->cmd, sh->cmd_pos);
	h->cmd[sh->cmd_pos] = 0;
	h->cmd_pos = sh->cmd_pos;

	sh->history_show_pos = sh->history_rec_pos;

	if (++sh->history_rec_pos == CMD_HISTORY_NUM)
		sh->history_rec_pos = 0;
}

static cmd_handler cmd_handler_of(const char *cmd)
{
	int i = 0;

	if (cmd) {
		for (i = 0; i < ARRAY_SIZE(cmd_handlers); i++) {
			if (strcmp(cmd_handlers[i].cmd, cmd) == 0)
				return cmd_handlers[i].func;
		}
	}

	return NULL;
}

static void key_up(struct shell *sh)
{
	struct cmd_history *h = NULL;

	h = &sh->history[sh->history_show_pos];

	while (sh->cmd_pos) {
		write(sh->fd, "\b \b", 3);
		sh->cmd_pos--;
	}

	memcpy(sh->cmd, h->cmd, h->cmd_pos);
	sh->cmd[h->cmd_pos] = 0;
	sh->cmd_pos = h->cmd_pos;
	sh->cursor_pos = h->cmd_pos;

	write(sh->fd, sh->cmd, sh->cmd_pos);

	if (sh->history_show_pos == 0)
		sh->history_show_pos = CMD_HISTORY_NUM;

	sh->history_show_pos--;
}

static void key_down(struct shell *sh)
{
	struct cmd_history *h = NULL;

	h = &sh->history[sh->history_show_pos];

	while (sh->cmd_pos) {
		write(sh->fd, "\010\040\010", 3);
		sh->cmd_pos--;
	}

	memcpy(sh->cmd, h->cmd, h->cmd_pos);
	sh->cmd[h->cmd_pos] = 0;
	sh->cmd_pos = h->cmd_pos;
	sh->cursor_pos = h->cmd_pos;

	write(sh->fd, sh->cmd, sh->cmd_pos);

	if (++sh->history_show_pos == CMD_HISTORY_NUM)
		sh->history_show_pos = 0;
}

static void cmd_runapp(struct shell *sh)
{
	int ret = -1;

	ret = execve(sh->argv[0], sh->argv, NULL);
	if (ret < 0)
		shmsg(sh, "execve(%s) failed - errno %d\n",
			sh->argv[0] ? sh->argv[0] : "null", errno);
}

static void key_backspace(struct shell *sh)
{
	int cursor = sh->cursor_pos;
	int diff = sh->cmd_pos - cursor;

	if (cursor != 0) {
		write(sh->fd, "\b", 1);

		while (cursor < sh->cmd_pos) {
			sh->cmd[cursor - 1] = sh->cmd[cursor];
			cursor++;
		}

		sh->cursor_pos--;
		sh->cmd_pos--;
		sh->cmd[sh->cmd_pos] = 0;
		write(sh->fd, &sh->cmd[sh->cursor_pos], diff);
		/* erase last char */
		write(sh->fd, "\033[J", 3);
		/* cursor back to original pos */
		while (diff--)
			write(sh->fd, "\b", 1);
	}
}

static void key_delete(struct shell *sh)
{
	int cursor = sh->cursor_pos;
	int diff = sh->cmd_pos - cursor;

	if (diff != 0) {
		while (cursor < sh->cmd_pos) {
			sh->cmd[cursor] = sh->cmd[cursor + 1];
			cursor++;
		}

		sh->cmd_pos--;
		sh->cmd[sh->cmd_pos] = 0;
		write(sh->fd, &sh->cmd[sh->cursor_pos], --diff);
		/* erase last char */
		write(sh->fd, "\033[J", 3);
		/* cursor back to original pos */
		while (diff--)
			write(sh->fd, "\b", 1);
	}
}

static void key_ctrlc(struct shell *sh)
{
	sh->cmd[0] = 0;
	sh->cmd_pos = 0;
	sh->cursor_pos = 0;
	write(sh->fd, "\n# ", 3);
}

static void key_left(struct shell *sh)
{
	if (sh->cursor_pos) {
		write(sh->fd, "\033[1D", 4);
		sh->cursor_pos--;
	}
}

static void key_right(struct shell *sh)
{
	if (sh->cursor_pos < sh->cmd_pos) {
		write(sh->fd, "\033[1C", 4);
		sh->cursor_pos++;
	}
}

static void key_enter(struct shell *sh)
{
	cmd_handler func = NULL;

	shmsg(sh, "\n");
	shmsg_flush(sh);

	if (sh->cmd_pos) {
		cmd_record(sh);
		cmd_parse_argv(sh);
		func = cmd_handler_of(sh->argv[0]);
		if (func)
			func(sh);
		else
			cmd_runapp(sh);
		cmd_free_argv(sh);
	}

	shmsg(sh, "# ");
	shmsg_flush(sh);

	memset(sh->cmd, 0, sizeof(sh->cmd));
	memset(sh->dft_argv, 0, sizeof(sh->dft_argv));

	sh->cmd_pos = 0;
	sh->cursor_pos = 0;
}

/* known sequence */
static const struct key_code key_handlers[] = {
	{key_enter,     "\x0D",                        1},
	{key_ctrlc,     "\x03",                        1},
	{key_backspace, "\x08",                        1},
	{key_backspace, "\x7F",                        1},
	{key_up,        "\x1B\x5B\x41",                3},
	{key_down,      "\x1B\x5B\x42",                3},
	{key_right,     "\x1B\x5B\x43",                3},
	{key_left,      "\x1B\x5B\x44",                3},
	{key_delete,    "\x1B\x5B\x33\x7E",            4},
	{key_backspace, "\x1B\x5B\x33\x3B\x32\x7E",    6},
};

static void handle_keys(struct shell *sh)
{
	size_t i = 0, k = 0;
	size_t diff = 0;

	for (k = 0; k < sh->key_len; k++) {
		for (i = 0; i < ARRAY_SIZE(key_handlers); i++) {
			if ((key_handlers[i].raw_key_size <= (sh->key_len - k)) &&
					!memcmp(key_handlers[i].raw_key, &sh->key[k],
					key_handlers[i].raw_key_size)) {
				key_handlers[i].func(sh);
				k += key_handlers[i].raw_key_size - 1;
				break;
			}
		}
		if (i == ARRAY_SIZE(key_handlers)) {
			diff = sh->cmd_pos - sh->cursor_pos;
			if (diff == 0) {
				sh->cmd[sh->cmd_pos] = sh->key[k];
				write(sh->fd, &sh->key[k], 1);
			} else {
				memmove(&sh->cmd[sh->cursor_pos + 1],
						&sh->cmd[sh->cursor_pos], diff);

				sh->cmd[sh->cursor_pos] = sh->key[k];

				write(sh->fd, &sh->cmd[sh->cursor_pos], diff + 1);

				/* cursor back to original char */
				while (diff--)
					write(sh->fd, "\b", 1);
			}
			sh->cmd_pos += 1;
			sh->cursor_pos += 1;
			if (sh->cmd_pos == sizeof(sh->cmd) - 1) {
				sh->cmd_pos = 0;
				sh->cursor_pos = 0;
			}
		}
	}
	sh->key_len = 0;
}

int main(void)
{
	struct shell *sh = NULL;
	struct sched_param p;
	int ret = -1, rdbytes = 0, sleepus = 1000;
	struct pollfd fds = {0, POLLIN, 0};

	sh = calloc(1, sizeof(struct shell));
	if (sh == NULL) {
		EMSG("alloc shell failed\n");
		return -ENOMEM;
	}

	p.sched_priority = sched_get_priority_max(SCHED_FIFO);
	p.sched_priority = 62; /* kernel max */
	sched_setscheduler(0, SCHED_FIFO, &p);

	sh->fd = STDIN_FILENO;
	sh->ringprint.fd = STDOUT_FILENO;

	write(sh->ringprint.fd, "\n# ", 3);

	for (;;) {
		fds.fd = sh->fd;

		ret = poll(&fds, 1, -1);
		if (ret && (fds.revents & POLLIN)) {
			rdbytes = read(sh->fd, sh->key + sh->key_len,
						sizeof(sh->key) - sh->key_len - 1);
			sh->key_len += rdbytes;
		}

		if (rdbytes == 0) {
			usleep(sleepus);
			sleepus *= 2;
			/* not a shell input dev ? */
			if (sleepus > 1000000)
				return -ENODEV;
		} else {
			sleepus = 1000;
			handle_keys(sh);
		}
	}

	return 0;
}
