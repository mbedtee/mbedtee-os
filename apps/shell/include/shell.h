/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * simple shell
 */

#ifndef _SHELL_H
#define _SHELL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <generated/autoconf.h>
#define _GNU_SOURCE
#include <defs.h>
#include <misc.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <list.h>
#include <dirent.h>
#include <ctype.h>
#include <assert.h>
#include <poll.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <eventfd.h>
#include <spawn.h>
#include <waitpid.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syslimits.h>

#include <shell_lock.h>

#define shell_stdfd(x)    ((unsigned int)(x) <= STDERR_FILENO)

#define SHELL_CTRL_C      0x03
#define SHELL_CTRL_BACKSL 0x1C
#define SHELL_CTRL_US     0x1F

#define SHELL_PATH_MAX 256

/* Maximum recursion depth to prevent stack overflow */
#define MAX_RECURSION_DEPTH 20

#define CMD_MAX_LEN			704

/*
 * Command history storage:
 * - Variable-length ring buffer to avoid wasting CMD_MAX_LEN bytes per entry.
 * - Sized to fit in a single ~4KB allocator bucket (32/64-bit friendly).
 */
/* metadata slots for history entries (not a fixed storage cost per entry) */
#define CMD_HISTORY_ENT_MAX	64
/* keep sizeof(struct shell_history) <= 4096 on 32/64-bit */
#define CMD_HISTORY_BUFSZ	3824
#define CMD_DFTARGV_NUM		32

/* Default terminal width if detection fails */
#define SHELL_DEFAULT_WIDTH	100

/* Shell prompt string and length */
#define SHELL_PROMPT		"# "
#define SHELL_PROMPT_LEN	2

struct shell_history_ent {
	unsigned short off;
	unsigned short len;
};

struct shell_history {
	unsigned short ent_wr;   /* next write index in ent[] */
	unsigned short ent_nav;  /* navigation cursor (Up/Down) */
	unsigned short ent_cnt;  /* number of valid entries */
	unsigned short buf_wr;   /* next write offset in buf[] */
	unsigned short buf_rd;   /* offset of oldest entry in buf[] */

	struct shell_history_ent ent[CMD_HISTORY_ENT_MAX];
	char buf[CMD_HISTORY_BUFSZ];
};

struct ring_print {
	int pos; /* current print position */
	unsigned char ringbuf[2048-4];  /* ring buffer for output buffering */
};

/* I/O redirection state for a command execution */
struct shell_io {
	int stdin_fd;   /* input source (default: STDIN_FILENO) */
	int stdout_fd;  /* output target (default: STDOUT_FILENO) */
	int stderr_fd;  /* error output (default: STDERR_FILENO) */
};

struct shell {
	/* Terminal/UART file descriptor for interactive input */
	int tty_fd;

	/* Current I/O redirection state */
	struct shell_io io;

	/* Saved I/O state (for restoring after redirection) */
	struct shell_io saved_io;

	/* terminal width in columns */
	int term_width;

	/* cursor position in cmdline buffer */
	int cursor;

	/* current terminal display position (column on current line) */
	int term_col;

	/* received key sequence buffer */
	char input_buf[CMD_MAX_LEN];
	/* received key sequence length */
	int input_len;

	/* current command line being edited */
	int cmdline_len;
	char cmdline[CMD_MAX_LEN];

	/* current working directory */
	char cwd[SHELL_PATH_MAX];

	/* Foreground builtin execution mode (0: cmd queue, 1: new thread for each cmd) */
	bool fg_builtin_new_thread;

	/* argv, if argv num less than default, use the default array */
	int argc;
	char *argv[CMD_DFTARGV_NUM];

	struct ring_print ringprint;

	/* command history, allocated for interactive shells */

	/* request stop flag, set by Ctrl+C to interrupt blocking reads */
	volatile int stop_request;
	struct shell_history *history;
};

typedef void (*key_handler)(struct shell *);

struct key_code {
	key_handler func;
	char raw_key[10];
	int raw_key_size;
};

typedef void (*cmd_handler)(struct shell *);

struct shell_cmd {
	const char *cmd;
	const char *help;
	cmd_handler func;
};

typedef long (*shell_thread_entry_t)(void *);

typedef long shell_tid_t;

int shell_thread_create(shell_tid_t *out,
	shell_thread_entry_t entry, void *arg);
int shell_thread_join(shell_tid_t tid);
int shell_thread_detach(shell_tid_t tid);

/* Abstraction Layer */
#define IS_EOF(buf, bufsize, rdbytes) (((rdbytes) < (bufsize)) ||	\
	(((rdbytes) == (bufsize)) && ((buf)[(rdbytes) - 1] == 0)))

void *shell_malloc(size_t size);
void *shell_calloc(size_t nmemb, size_t size);
void shell_free(void *ptr);

int shell_open(const char *path, int flags, ...);
int shell_close(int fd);
ssize_t shell_read(int fd, void *buf, size_t count);
ssize_t shell_write(int fd, const void *buf, size_t count);
off_t shell_lseek(int fd, off_t offset, int whence);

int shell_fstat(int fd, struct stat *statbuf);
int shell_mkdir(const char *path, mode_t mode);
int shell_unlink(const char *path);
int shell_rmdir(const char *path);
int shell_rename(const char *oldpath, const char *newpath);
int shell_creat(const char *path, mode_t mode);

int shell_pipe(int pipefd[2]);

int shell_dup(int oldfd);

int shell_fcntl(int fd, int cmd, unsigned long arg);

pid_t shell_get_pid(void);
pid_t shell_get_tid(void);
pid_t shell_get_tid_max(void);

int shell_kill(pid_t pid, int sig);
int shell_tkill(pid_t tid, int sig);

/*
 * Spawn a new process without replacing the current one.
 * Returns 0 on success, negative errno on failure.
 */
int shell_spawn(pid_t *pid, const posix_spawn_file_actions_t *,
	char *const argv[]);

/*
 * Wait for a spawned child process.
 * Returns 0 on success, negative errno on failure.
 * If status is non-NULL, receives child's raw _exit() value.
 */
int shell_waitpid(pid_t pid, int *status, int options);

/*
 * Wait for a spawned child process.
 * Returns pid (>0) when a child is reaped,
 * 0 when WNOHANG is specified and no child has exited,
 * negative errno on failure.
 */
pid_t shell_waitpid_raw(pid_t pid, int *status, int options);

/*
 * External command/process support hooks for the shell.
 *
 * Userspace/Kernel shell builds may provide them when external process
 * support is enabled (CONFIG_SPAWN + CONFIG_WAITPID).
 */
int shell_ext_runapp_argv(struct shell *sh, char *const argv[]);
int shell_ext_spawnapp_argv(struct shell *sh, char *const argv[], pid_t *pid_out);
int shell_ext_spawn_pipeline_stage(pid_t *pid_out, int in_fd, int out_fd,
	char *const argv[]);

void shell_time2date(time_t time, struct tm *tm);
int shell_get_monotonic(struct timespec *tp);
int shell_get_realtime(struct timespec *tp);

void shell_entry(void);

static inline unsigned long long __pow(
	unsigned long long x, int y)
{
	int i = 0;
	unsigned long long res = 1;

	for (i = 0; i < y; i++)
		res = res * x;

	return res;
}

/*
 * Custom dirname implementation that modifies the path in-place.
 * Returns "/" for root or empty paths.
 */
static inline char *shell_dirname(char *path)
{
	int i = 0;
	unsigned int l = 0;

	if (!path || *path == 0)
		return "/";

	l = __builtin_strlen(path);

	/* Remove trailing slashes */
	while (l && (path[l - 1] == '/')) {
		path[l - 1] = 0;
		l--;
	}

	/* Find last slash */
	for (i = l - 1; i >= 0; i--) {
		if (path[i] == '/') {
			path[i] = 0;
			break;
		}
	}

	return (i < 0 || *path == 0) ? "/" : path;
}

/*
 * Returns pointer to the last component of the path.
 * Does not modify the input string.
 */
static inline const char *shell_basename(const char *path)
{
	const char *p = strrchr(path, '/');
	return p ? p + 1 : path;
}

static inline void shell_set_nonblocking(int fd)
{
	int flags = shell_fcntl(fd, F_GETFL, 0);

	if (flags >= 0)
		shell_fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static inline int shell_ctrl_to_signo(unsigned char ch)
{
	switch (ch) {
	case SHELL_CTRL_C:
		return SIGINT;
	case SHELL_CTRL_BACKSL:
		return SIGQUIT;
	case SHELL_CTRL_US:
		return SIGTERM;
	default:
		return 0;
	}
}

static inline void shell_echo_and_buffer_typeahead(struct shell *sh,
	int echo_fd, char ch)
{
	int len = sh->input_len;

	if (echo_fd >= 0) {
		if (ch == '\r')
			shell_write(echo_fd, "\r\n", 2);
		else
			shell_write(echo_fd, &ch, 1);
	}

	if (len < 0)
		len = 0;
	if (len < sizeof(sh->input_buf)) {
		sh->input_buf[len++] = ch;
		sh->input_len = len;
	}
}

#ifdef __cplusplus
}
#endif

#endif

