// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Shared shell core implementation
 */

#include <shell.h>

#define MAX_PIPE_STAGES 8
#define MAX_SEMICOLON_COMMANDS 16
#define SHELL_REALPATH_MAX_COMPONENTS 64

/*
 * Background job bookkeeping.
 *
 * Lifetime/ownership:
 * - Allocated in shell_start_background() as a single block:
 *     [struct shell_job][cwd '\0'][cmdline '\0']
 *   so job->cwd/job->cmdline are pointers into that same allocation.
 * - Owned by job-manager once enqueued; freed by shell_jobmgr_job_free().
 *
 * Concurrency:
 * - job-manager thread and worker threads can touch fields under
 *   shell_jobmgr_lock (e.g., stages_left/status).
 */
struct shell_job {
	struct list_head node;
	/* captured terminal width (for shmsg wrapping/formatting) */
	int term_width;
	/* cached length of cmdline string (bounded by CMD_MAX_LEN-1) */
	int cmdline_len;
	/* points into the same allocation block as struct shell_job */
	const char *cmdline;
	/* points into the same allocation block as struct shell_job */
	const char *cwd;
	/* captured io at enqueue time; stdin may be rewritten to /dev/null */
	struct shell_io io;
	/* if >= 0, this fd is owned and must be closed when job is freed */
	int owned_stdin_fd;
	/* 1 for pipeline job, 0 for single command */
	int is_pipeline;
	/* number of pipeline stages */
	int stage_count;
	/* remaining stages (externals waited by jobmgr, builtins by workers) */
	int stages_left;
	/* external stage PIDs (pid > 0 means spawned) */
	pid_t pids[MAX_PIPE_STAGES];
	/* single non-pipeline external PID (legacy field for non-pipeline jobs) */
	pid_t pid;
	/* job exit status (0 success, -errno on internal errors) */
	int status;
};

/*
 * Pipeline stage execution context.
 *
 * Used for both:
 * - external stage spawn (ctx is short-lived and freed after spawn)
 * - builtin stage execution
 *
 * When used for background pipeline builtin stages:
 * - one stage == one thread
 * - ctx->job + ctx->stage_idx identify which job counters to update
 * - ctx is freed by the stage thread after completion
 *
 * When used for foreground builtin execution:
 * - ctx is run in a dedicated thread for the builtin
 * - ctx->done is set by the worker to unblock the UI thread wait loop
 * - ctx is freed by the caller after join
 */
struct shell_pipe_stage {
	/* queue linkage for foreground builtin worker */
	struct list_head task_node;
	/* background pipeline builtin bookkeeping */
	struct shell_job *job;
	int stage_idx;
	/* set when the stage thread should free ctx */
	int free_on_finish;

	struct shell *sh;
	shell_tid_t tid;
	pid_t pid;
	cmd_handler func;
	int in_fd, out_fd;
	int out_is_pipe, in_is_pipe;
	int ret;
	volatile int done;
};

/*
 * Helper-thread waitpid context.
 *
 * Foreground execution sometimes needs to:
 * - wait for the child AND
 * - keep reading the tty to forward Ctrl keys / buffer typeahead
 *
 * So we waitpid() in a helper thread and poll the tty in the caller.
 */
struct shell_waitpid_ctx {
	pid_t pid;
	int status;
	volatile int done;
};

static struct shell_lock shell_jobmgr_lock = SHELL_LOCK_INIT;
static LIST_HEAD(shell_jobmgr_q);
static LIST_HEAD(shell_jobmgr_run);
static volatile int shell_jobmgr_started;

/* Foreground builtin worker (dedicated), avoids per-command threads */
static LIST_HEAD(shell_fg_builtin_q);
static struct shell_lock shell_fg_builtin_lock = SHELL_LOCK_INIT;
static volatile int shell_fg_builtin_started;
static shell_tid_t shell_fg_builtin_tid;

static void shell_jobmgr_lock_enter(void)
{
	shell_lock_enter(&shell_jobmgr_lock);
}

static void shell_jobmgr_lock_exit(void)
{
	shell_lock_exit(&shell_jobmgr_lock);
}

static void shell_fg_builtin_lock_enter(void)
{
	shell_lock_enter(&shell_fg_builtin_lock);
}

static void shell_fg_builtin_lock_exit(void)
{
	shell_lock_exit(&shell_fg_builtin_lock);
}

static void shell_job_init(struct shell_job *job, const struct shell *sh,
	bool is_pipeline, int cmdline_len)
{
	int i = 0;

	job->pid = -1;
	job->term_width = sh->term_width;
	job->owned_stdin_fd = -1;
	job->is_pipeline = !!is_pipeline;
	job->io = sh->io;
	job->cmdline_len = cmdline_len;

	/* Keep pipeline bookkeeping in a known state for all jobs. */
	for (i = 0; i < MAX_PIPE_STAGES; i++)
		job->pids[i] = -1;
}

/* Init per-stage shell context (pipeline stage inherits io/cwd/term from parent). */
static void shell_init_stage_shell(struct shell *dst, const struct shell *parent,
	const char *cmdline)
{
	dst->tty_fd = -1;
	dst->io = parent->io;
	dst->saved_io = parent->saved_io;
	dst->term_width = parent->term_width;
	strlcpy(dst->cwd, parent->cwd, sizeof(dst->cwd));
	if (cmdline)
		strlcpy(dst->cmdline, cmdline, sizeof(dst->cmdline));
	dst->cmdline_len = strlen(dst->cmdline);
}

/*
 * Thread: waitpid helper (foreground external commands)
 *
 * Purpose:
 * - Blocks in shell_waitpid() for a single child process while the caller
 *   (foreground UI thread) keeps polling tty to:
 *     - translate Ctrl keys into signals (stop_request / SIGINT)
 *     - buffer and echo typeahead
 *
 * Lifetime:
 * - One thread per waited child; exits once waitpid() returns.
 *
 * Data flow:
 * - Writes ctx->ret/status and then sets ctx->done=1 for the caller to observe.
 */
static long shell_waitpid_thread(void *arg)
{
	struct shell_waitpid_ctx *ctx = arg;
	int status = 0;

	shell_waitpid(ctx->pid, &status, 0);
	ctx->status = status;
	__atomic_store_n(&ctx->done, 1, __ATOMIC_RELEASE);

	return 0;
}

static inline void shell_build_asserts(void)
{
	BUILD_ERROR_ON(sizeof(struct shell) > 4096);
	BUILD_ERROR_ON(sizeof(struct shell_history) > 4096);
	BUILD_ERROR_ON(sizeof(struct shell_job) > 256);
}

/*
 * Detect terminal width using ANSI escape sequences.
 */
static int shell_detect_terminal_width(struct shell *sh)
{
	char buf[32];
	char *cursor_report = NULL, *end_pos = NULL, *semicolon = NULL;
	const char *ta_src = NULL;
	int ta_len = 0, extra = 0;
	int width = SHELL_DEFAULT_WIDTH, out_fd = sh->tty_fd;
	int ret = 0, len = 0, detected_width = 0;
	struct pollfd fds = {sh->tty_fd, POLLIN, 0};

	/* method 1 */
	/* ANSI sequence: save cursor, move far right, query position, restore cursor */
	/* shell_write(out_fd, "\x1b[s\x1b[2047C\x1b[6n\x1b[u", 17); */

	/* method 2 */
	/* ANSI sequence: move far right, query position, set cursor to 3 (#  ) */
	shell_write(out_fd, "\x1b[2047C\x1b[6n\x1b[3G", 15);

	/* Wait for response - 400ms */
	ret = poll(&fds, 1, 400);
	if (ret > 0) {
		len = shell_read(sh->tty_fd, buf, sizeof(buf) - 1);
		if (len <= 0)
			return width;

		buf[len] = '\0';

		/* Parse response */
		cursor_report = strstr(buf, "\x1b[");
		if (cursor_report) {
			end_pos = strchr(cursor_report + 2, 'R');
			if (end_pos) {
				extra = ((buf + len) - (end_pos + 1));
				*end_pos = '\0';
				semicolon = strchr(cursor_report + 2, ';');
				if (semicolon) {
					detected_width = atoi(semicolon + 1);
					if (detected_width >= 20 && detected_width <= 2047)
						width = detected_width;
				}

				/* If this read also captured user input, push it back. */
				if (extra > 0) {
					ta_src = end_pos + 1;
					ta_len = extra;
				}
			} else {
				/* Partial/unknown response: treat as typeahead. */
				ta_src = buf;
				ta_len = len;
			}
		} else {
			/* Not a terminal response: treat as typeahead input. */
			ta_src = buf;
			ta_len = len;
		}

		if (ta_len > 0) {
			int copy = ta_len;

			if (copy > (int)(sizeof(sh->input_buf) - sh->input_len))
				copy = sizeof(sh->input_buf) - sh->input_len;
			if (copy > 0) {
				memcpy(&sh->input_buf[sh->input_len], ta_src, copy);
				sh->input_len += copy;
			}
		}
	}

	return width;
}


/*
 * Output control sequence without updating term_col.
 * Use for: ANSI escapes, backspace, etc.
 */
static inline void shmsg_raw(struct shell *sh, const char *str, int len)
{
	shell_write(sh->io.stdout_fd, str, len);
}

/*
 * Output a single character with line-wrap support.
 * Automatically wraps at term_width columns.
 * Handles '\n' specially to reset term_col.
 */
static inline void shmsg_putc(struct shell *sh, char c)
{
	if (sh->term_width < 10 || sh->term_width > 2048)
		sh->term_width = SHELL_DEFAULT_WIDTH;

	/* Handle newline specially */
	if (c == '\n') {
		shell_write(sh->io.stdout_fd, &c, 1);
		sh->term_col = 0;
		return;
	}

	/* If at line boundary, wrap to next line before writing */
	if (sh->term_col >= sh->term_width)
		shmsg_putc(sh, '\n');  /* Recursive call for newline */

	/* Write the character */
	shell_write(sh->io.stdout_fd, &c, 1);
	sh->term_col++;
}

static inline void shmsg_puts_flush_segment(struct shell *sh,
	const char *str, int start, int end)
{
	int n = 0;

	if (end <= start)
		return;
	n = end - start;
	shell_write(sh->io.stdout_fd, &str[start], n);
	sh->term_col += n;
}

/*
 * Output a string with line-wrap support.
 * Optimized to write in chunks rather than character-by-character.
 */
static inline void shmsg_puts(struct shell *sh, const char *str, int len)
{
	int i = 0, start = 0, remaining = 0, fit = 0;

	if (sh->term_width < 10 || sh->term_width > 2048)
		sh->term_width = SHELL_DEFAULT_WIDTH;

	/* Fast path: no wrapping needed, enough space, no embedded newlines */
	if (sh->term_col + len < sh->term_width &&
		!memchr(str, '\n', len)) {
		shell_write(sh->io.stdout_fd, str, len);
		sh->term_col += len;
		return;
	}

	/* Need to handle line wrapping: write in segments */
	for (i = 0; i < len; i++) {
		if (str[i] == '\n') {
			shmsg_puts_flush_segment(sh, str, start, i);
			shmsg_putc(sh, '\n');
			start = i + 1;
		} else if (sh->term_col >= sh->term_width) {
			shmsg_puts_flush_segment(sh, str, start, i);
			shmsg_putc(sh, '\n');
			start = i;
		}
	}

	/* Write remaining characters (iterative, no recursion) */
	while (start < len) {
		remaining = len - start;
		if (sh->term_col + remaining < sh->term_width) {
			shmsg_puts_flush_segment(sh, str, start, len);
			break;
		}

		fit = sh->term_width - sh->term_col;
		if (fit > 0) {
			shmsg_puts_flush_segment(sh, str, start, start + fit);
			start += fit;
		}
		shmsg_putc(sh, '\n');
	}
}

/*
 * Move cursor left by one position.
 * Handles wrapping to previous line if at column 0.
 */
static inline void shmsg_back(struct shell *sh)
{
	char buf[16];
	int len = 0;

	if (sh->term_col > 0) {
		shmsg_raw(sh, "\b", 1);
		sh->term_col--;
	} else {
		/* At column 0, need to go to end of previous line */
		/* Use ANSI: move up 1 line, then forward to column term_width */
		len = snprintf(buf, sizeof(buf), "\033[A\033[%dG",
			sh->term_width);
		shmsg_raw(sh, buf, len);
		sh->term_col = sh->term_width - 1;
	}
}

/*
 * Move cursor left by n positions.
 * Fast path: if all n positions are on the current line, use a single
 * ANSI CSI sequence instead of n individual shmsg_back() calls.
 */
static inline void shmsg_back_n(struct shell *sh, int n)
{
	char esc[10];
	int len = 0;

	if (n <= 0)
		return;

	if (n < 3 || sh->term_col < n) {
		while (n-- > 0)
			shmsg_back(sh);
		return;
	}

	/* Batch: all on same line, use ANSI cursor backward */
	len = snprintf(esc, sizeof(esc), "\033[%dD", n);
	shmsg_raw(sh, esc, len);
	sh->term_col -= n;
}

static inline void shmsg_flush_pending(struct shell *sh,
	struct ring_print *r, int start, int end)
{
	if (end > start)
		shmsg_puts(sh, (const char *)&r->ringbuf[start], end - start);
}

static void shmsg_flush(struct shell *sh)
{
	struct ring_print *r = &sh->ringprint;
	int i = 0, start = 0, spaces = 0;
	unsigned char c = 0;

	if (r->pos == 0)
		return;

	/*
	 * Fast path: if output is redirected to file (not terminal),
	 * write entire buffer at once without processing special characters
	 */
	if (sh->io.stdout_fd != STDOUT_FILENO) {
		shell_write(sh->io.stdout_fd, r->ringbuf, r->pos);
		r->pos = 0;
		return;
	}

	/*
	 * Terminal output: scan printable characters in a tight inner
	 * loop and flush each segment, only switching on control chars.
	 */
	while (i < r->pos) {
		/* Fast scan: skip printable characters (>= 0x20) */
		start = i;
		while (i < r->pos && r->ringbuf[i] >= 0x20)
			i++;

		/* Flush accumulated printable segment */
		shmsg_flush_pending(sh, r, start, i);

		if (i >= r->pos)
			break;

		/* Handle control character */
		c = r->ringbuf[i];
		switch (c) {
		case '\n':
			shmsg_putc(sh, '\n');
			break;
		case '\r':
			shmsg_raw(sh, "\r", 1);
			sh->term_col = 0;
			break;
		case '\t':
			spaces = 8 - (sh->term_col % 8);
			shmsg_puts(sh, "        ", spaces);
			break;
		case '\b':
			shmsg_back(sh);
			break;
		default:
			shmsg_raw(sh, (const char *)&r->ringbuf[i], 1);
			break;
		}
		i++;
	}

	r->pos = 0;
}

static void shmsg_vprintf(struct shell *sh, const char *fmt, va_list ap)
{
	struct ring_print *r = &sh->ringprint;
	int avail, len, pos = r->pos, max = sizeof(r->ringbuf);
	va_list aq;

	avail = max - pos;

	if (avail <= 0) {
		shmsg_flush(sh);
		return;
	}

	va_copy(aq, ap);
	len = vsnprintf((char *)r->ringbuf + pos, avail, fmt, aq);
	va_end(aq);

	if (len < avail) {
		r->pos += len;
		return;
	}

	/* Flush current buffer and retry */
	shmsg_flush(sh);

	va_copy(aq, ap);
	len = vsnprintf((char *)r->ringbuf, max, fmt, aq);
	va_end(aq);

	if (len < max) {
		r->pos = len;
		return;
	}

	/* Message too large - truncate to ring buffer size. */
	r->pos = max - 1;
	shmsg_flush(sh);
}

static __printf(2, 3) void shmsg(struct shell *sh, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	shmsg_vprintf(sh, fmt, ap);
	va_end(ap);
}

static __printf(2, 3) void shmsg_err(struct shell *sh, const char *fmt, ...)
{
	va_list ap;
	char buf[256];
	int len = 0, avail = 0;
	static const char prefix[] = "sherr -> ";
	int off = sizeof(prefix) - 1;

	memcpy(buf, prefix, off);
	avail = sizeof(buf) - off;

	va_start(ap, fmt);
	len = vsnprintf(buf + off, avail, fmt, ap);
	va_end(ap);

	if (len <= 0)
		return;
	if (len >= avail)
		len = avail - 1;
	shell_write(sh->io.stderr_fd, buf, off + len);
}

static void shell_print_exec_error(struct shell *sh, const char *cmd, int ret)
{
	/* Match common shell wording for typical exec/spawn failures. */
	if (ret == -ENOENT)
		shmsg_err(sh, "%s: command not found\n", cmd);
	else if (ret == -EACCES)
		shmsg_err(sh, "%s: permission denied\n", cmd);
	else
		shmsg_err(sh, "%s: failed - ret %d\n", cmd, ret);
}

static inline bool is_ws(char c)
{
	return c == ' ' || c == '\t';
}

static inline void shell_sanitize_cmdline(struct shell *sh)
{
	size_t max_len = sizeof(sh->cmdline) - 1;

	if (sh->cmdline_len > max_len)
		sh->cmdline_len = 0;
	if (sh->cursor > sh->cmdline_len)
		sh->cursor = 0;
	sh->cmdline[min((size_t)sh->cmdline_len, max_len)] = '\0';
}

static char *trim_ws_inplace(char *s)
{
	char *end;

	if (!s)
		return s;

	while (is_ws(*s))
		s++;

	end = s + strlen(s);
	while (end > s && is_ws(end[-1]))
		*--end = '\0';

	return s;
}

/* Check if name is "." or ".." */
static inline bool is_dotdir(const char *name)
{
	return name[0] == '.' && (name[1] == '\0' ||
		(name[1] == '.' && name[2] == '\0'));
}

/*
 * Construct a path by joining directory and filename.
 * Handles root directory specially to avoid double slashes.
 */
static inline void path_join(char *out, size_t outsize,
	const char *dir, const char *name)
{
	size_t dir_len = strlen(dir);
	size_t pos;

	/* Handle root directory */
	if (dir_len == 1 && dir[0] == '/') {
		out[0] = '/';
		strlcpy(out + 1, name, outsize - 1);
		return;
	}

	/* Remove a single trailing slash from dir if present */
	if (dir_len > 0 && dir[dir_len - 1] == '/')
		dir_len--;

	if (dir_len >= outsize)
		dir_len = outsize - 1;
	memcpy(out, dir, dir_len);
	pos = dir_len;
	if (pos < outsize - 1)
		out[pos++] = '/';
	strlcpy(out + pos, name, outsize - pos);
}

/*
 * Simple glob pattern matching supporting:
 *   *  - matches zero or more characters
 *   ?  - matches exactly one character
 * Returns true if string matches pattern.
 */
static bool glob_match(const char *pattern, const char *str)
{
	const char *p = pattern;
	const char *s = str;
	const char *star_p = NULL;
	const char *star_s = NULL;

	while (*s) {
		if (*p == '*') {
			/* Collapse consecutive '*' and save backtracking position. */
			while (*p == '*')
				p++;
			star_p = p;
			star_s = s;
		} else if (*p == '?' || *p == *s) {
			/* Match single char or exact match */
			p++;
			s++;
		} else if (star_p) {
			/* Backtrack: * matches one more char */
			p = star_p;
			s = ++star_s;
		} else {
			return false;
		}
	}

	/* Skip trailing *'s in pattern */
	while (*p == '*')
		p++;

	return *p == '\0';
}

/*
 * Convert a relative path to absolute path based on
 * current working directory.
 *
 * Handles ".", "..", and normalizes the path.
 * Returns the resulting absolute path in 'out' buffer.
 */
static void shell_realpath(struct shell *sh, const char *path,
	char *out, size_t outsize)
{
	char temp[SHELL_PATH_MAX];
	char *token = NULL, *saveptr = NULL;
	char *components[SHELL_REALPATH_MAX_COMPONENTS];
	int depth = 0, i = 0;
	size_t len = 0;

	/* If path is absolute, start fresh; otherwise start from cwd. */
	if (path[0] == '/')
		temp[0] = '\0';
	else
		strlcpy(temp, sh->cwd, sizeof(temp));

	/* Append path to temp for tokenizing. */
	if (path[0] != '/' && temp[0] != '\0') {
		len = strlen(temp);
		if (len > 0 && temp[len - 1] != '/')
			strlcat(temp, "/", sizeof(temp));
	}
	strlcat(temp, path, sizeof(temp));

	/* Parse and normalize the path */
	out[0] = '\0';

	token = strtok_r(temp, "/", &saveptr);
	while (token) {
		/* Current directory */
		if (token[0] == '.' && token[1] == '\0')
			goto next;

		/* Parent directory */
		if (token[0] == '.' && token[1] == '.' && token[2] == '\0') {
			if (depth > 0)
				depth--;
			goto next;
		}

		/* Regular component */
		if (token[0] != '\0') {
			if (depth >= SHELL_REALPATH_MAX_COMPONENTS) {
				out[0] = '\0';
				return;
			}
			components[depth++] = token;
		}

next:
		token = strtok_r(NULL, "/", &saveptr);
	}

	/* Build the result path in O(n) instead of O(n2) strlcat loop */
	if (depth == 0)
		strlcpy(out, "/", outsize);
	else {
		size_t pos = 0, clen;

		for (i = 0; i < depth; i++) {
			if (pos >= outsize - 1)
				break;
			out[pos++] = '/';
			clen = strlen(components[i]);
			if (pos + clen > outsize - 1)
				clen = outsize - 1 - pos;
			memcpy(&out[pos], components[i], clen);
			pos += clen;
		}
		out[pos] = '\0';
	}
}

/*
 * Get absolute path for a given path argument.
 * If path is NULL or empty, returns current working directory.
 */
static const char *shell_abspath(struct shell *sh, const char *path,
	char *buf, size_t bufsize)
{
	if (!path || path[0] == '\0')
		return sh->cwd;

	shell_realpath(sh, path, buf, bufsize);
	return buf;
}

static void read_debugfs(struct shell *sh, int fd)
{
	int ret = -1;
	struct ring_print *r = &sh->ringprint;

	shmsg_flush(sh);

	do {
		ret = shell_read(fd, r->ringbuf, sizeof(r->ringbuf));
		if (ret <= 0)
			break;

		shell_write(sh->io.stdout_fd, r->ringbuf, ret);

		/* EOF ? */
		if (IS_EOF(r->ringbuf, sizeof(r->ringbuf), ret))
			break;
	} while (1);
}

/*
 * Open, read and display a debugfs file.
 * Optionally write a command byte before reading.
 */
static void read_debugfs_path(struct shell *sh, const char *path, const char *cmd)
{
	int fd = shell_open(path, O_RDWR);

	if (fd < 0) {
		shmsg_err(sh, "open(%s) failed - errno %d\n", path, fd);
		return;
	}

	if (cmd)
		shell_write(fd, cmd, strlen(cmd));

	read_debugfs(sh, fd);
	shell_close(fd);
}

static void cmd_ps(struct shell *sh)
{
	const char *opt = sh->argv[1];

	/* 'w' option shows thread waiting information */
	read_debugfs_path(sh, "/debug/threads",
		(opt && strcmp(opt, "w") == 0) ? "w" : NULL);
}

static void ls_fstat(struct shell *sh,
	const char *path, bool firstfile)
{
	struct stat st;
	struct tm tm;
	int fd = -1;

	fd = shell_open(path, O_RDONLY);
	if (fd < 0) {
		/* Try opening as directory if file open fails */
		fd = shell_open(path, O_RDONLY | O_DIRECTORY);

		if (fd < 0) {
			shmsg_err(sh, "open %s failed %d\n", path, fd);
			return;
		}
	}

	shell_fstat(fd, &st);

	shell_time2date(st.st_mtime, &tm);

	if (firstfile)
		shmsg(sh, "Type\tSize\tBlksize\tBlocks\tMTime\t\t\tName\n");

	shmsg(sh, "%s\t%ld\t%ld\t%ld\t%04d-%02d-%02d %02d:%02d:%02d\t%s\n",
		S_ISDIR(st.st_mode) ? "DIR" : "File",
		(long)st.st_size, (long)st.st_blksize, (long)st.st_blocks,
		tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec, shell_basename(path));

	shell_close(fd);
}

static void cmd_ls(struct shell *sh)
{
	DIR *dir = NULL;
	struct dirent *d = NULL;
	char filepath[SHELL_PATH_MAX];
	char abspath[SHELL_PATH_MAX];
	const char *path;
	bool firstfile = true;

	/* Use current directory if no argument given */
	path = shell_abspath(sh, sh->argv[1], abspath, sizeof(abspath));

	dir = opendir(path);
	if (!dir) {
		ls_fstat(sh, path, firstfile);
		return;
	}

	while ((!sh->stop_request) && (d = readdir(dir)) != NULL) {
		path_join(filepath, sizeof(filepath), path, d->d_name);
		ls_fstat(sh, filepath, firstfile);
		firstfile = false;
	}

	closedir(dir);
}
static void rmdir_recursive_impl(struct shell *sh,
	const char *dirpath, const char *pattern, bool recursion,
	bool remove_self, int depth)
{
	char *fpath = NULL;
	DIR *dir = NULL;
	struct dirent *d = NULL;
	int ret = 0;

	if (depth > MAX_RECURSION_DEPTH) {
		shmsg_err(sh, "max recursion depth (%d) reached at %s\n",
			MAX_RECURSION_DEPTH, dirpath);
		return;
	}

	fpath = shell_malloc(SHELL_PATH_MAX);
	if (!fpath) {
		shmsg_err(sh, "out of memory\n");
		return;
	}

	dir = opendir(dirpath);
	if (!dir) {
		shell_free(fpath);
		return;
	}

	while (!sh->stop_request && (d = readdir(dir)) != NULL) {
		if (!glob_match(pattern, d->d_name))
			continue;

		path_join(fpath, SHELL_PATH_MAX, dirpath, d->d_name);

		if (d->d_type == DT_DIR) {
			if (recursion)
				rmdir_recursive_impl(sh, fpath, "*", recursion,
					true, depth + 1);
			else {
				ret = shell_rmdir(fpath);
				shmsg(sh, "rmdir %s ret = %d\n", fpath, ret);
			}
		} else {
			ret = shell_unlink(fpath);
			shmsg(sh, "unlink %s ret = %d\n", fpath, ret);
		}
	}

	closedir(dir);

	if (remove_self && strcmp(pattern, "*") == 0) {
		ret = shell_rmdir(dirpath);
		shmsg(sh, "rmdir %s ret = %d\n", dirpath, ret);
	}

	shell_free(fpath);
}

static void rmdir_recursive(struct shell *sh,
	const char *dirpath, const char *pattern, bool recursion,
	bool remove_self)
{
	rmdir_recursive_impl(sh, dirpath, pattern, recursion, remove_self, 0);
}

static void cmd_rmpath(struct shell *sh, const char *arg, bool recursion)
{
	char abspath[SHELL_PATH_MAX];
	char dirbuf[SHELL_PATH_MAX];
	char abs_dir[SHELL_PATH_MAX];
	const char *path = NULL, *pattern = NULL;
	char *dir = NULL;
	struct stat st;
	int ret = 0;

	if (!arg || *arg == '\0')
		return;

	path = shell_abspath(sh, arg, abspath, sizeof(abspath));
	pattern = shell_basename(path);

	if (strchr(pattern, '*') || strchr(pattern, '?')) {
		strlcpy(dirbuf, path, sizeof(dirbuf));
		dir = shell_dirname(dirbuf);

		if (*dir == '\0')
			strlcpy(abs_dir, sh->cwd, sizeof(abs_dir));
		else
			strlcpy(abs_dir, dir, sizeof(abs_dir));

		rmdir_recursive(sh, abs_dir, pattern, recursion, false);
		return;
	}

	ret = stat(path, &st);
	if (ret != 0) {
		shmsg_err(sh, "rm: cannot remove '%s'\n", arg);
		return;
	}

	if (S_ISDIR(st.st_mode)) {
		if (recursion)
			rmdir_recursive(sh, path, "*", recursion, true);
		else {
			ret = shell_rmdir(path);
			if (ret != 0)
				shmsg_err(sh, "rmdir %s ret = %d\n", arg, ret);
		}
	} else {
		ret = shell_unlink(path);
		if (ret != 0)
			shmsg_err(sh, "unlink %s ret = %d\n", arg, ret);
	}
}

static void cmd_rm(struct shell *sh)
{
	int i;
	bool recursion = false;

	if (sh->argc < 2)
		return;

	/* First pass: check for -r flag */
	for (i = 1; i < sh->argc; i++) {
		if (strcmp(sh->argv[i], "-r") == 0 ||
		    strcmp(sh->argv[i], "-rf") == 0) {
			recursion = true;
			break;
		}
	}

	/* Second pass: remove files/directories */
	for (i = 1; i < sh->argc; i++) {
		if (strcmp(sh->argv[i], "-r") != 0 &&
		    strcmp(sh->argv[i], "-rf") != 0) {
			cmd_rmpath(sh, sh->argv[i], recursion);
		}
	}
}

static void cmd_mem(struct shell *sh)
{
	read_debugfs_path(sh, "/debug/mem", NULL);
}

static void cmd_files(struct shell *sh)
{
	read_debugfs_path(sh, "/debug/files", NULL);
}

static void cmd_irq(struct shell *sh)
{
	read_debugfs_path(sh, "/debug/irq", NULL);
}

static void cmd_date(struct shell *sh)
{
	struct tm t;
	struct timespec ts = {0};
	struct timespec stamp = {0};

	shell_get_monotonic(&stamp);
	shell_get_realtime(&ts);

	shell_time2date(ts.tv_sec, &t);

	shmsg(sh, "CPU%d Monotonic - %llu.%09lus\n",
		sched_getcpu(), (long long)stamp.tv_sec, stamp.tv_nsec);

	shmsg(sh, "System - %04d-%02d-%02d %02d:%02d:%02d.%09ld\n",
		t.tm_year+1900, t.tm_mon+1, t.tm_mday,
		t.tm_hour, t.tm_min, t.tm_sec, ts.tv_nsec);
}

static void cmd_mount(struct shell *sh)
{
	read_debugfs_path(sh, "/debug/mount", NULL);
}

static void kill_common(struct shell *sh, const char *str, int digits,
	int idx, int signo, int decimal, bool istkill)
{
	int i = 0;
	pid_t tid = 0;
	int decimal_nxt = 0;

	if (idx < digits) {
		for (i = 0; i < 10 && !sh->stop_request; i++) {
			if ((str[idx] != '*') && ((str[idx] - '0') != i))
				continue;
			if (idx == (digits - 1)) {
				tid = decimal + i;
				/* Skip self */
				if (tid != shell_get_tid() && tid != shell_get_pid()) {
					if (istkill)
						shell_tkill(tid, signo);
					else
						shell_kill(tid, signo);
				}
			} else {
				decimal_nxt = decimal + i * __pow(10, digits - idx - 1);
				if (decimal_nxt >= shell_get_tid_max())
					return;
				kill_common(sh, str, digits, idx + 1, signo, decimal_nxt, istkill);
			}
		}
	}
}

static void do_kill(struct shell *sh, bool istkill)
{
	char str[5] = {'0', '0', '0', '0', '0'};
	int ret = -1, signo = 0;
	pid_t tid = 0;
	int i = 0, len = 0;
	const char *sigstr = sh->argv[1];
	const char *tidstr = sh->argv[2];

	if (!tidstr && !sigstr) {
		shmsg_err(sh, "invalid tid/sig argv\n");
		return;
	}

	if (!tidstr) {
		tidstr = sh->argv[1];
		signo = istkill ? SIGCANCEL : SIGKILL;
	} else {
		signo = strtoul(sigstr, NULL, 10);
		if (signo >= NSIG) {
			shmsg_err(sh, "invalid signo - %d\n", signo);
			return;
		}
	}

	len = strlen(tidstr);
	if (len > 5) {
		shmsg_err(sh, "invalid tid - %s\n", tidstr);
		return;
	}

	for (i = 0; i < len; i++) {
		if (!isdigit((unsigned char)tidstr[i]) && (tidstr[i] != '*')) {
			shmsg_err(sh, "invalid tid - %s\n", tidstr);
			return;
		}
	}

	if (!strchr(tidstr, '*')) {
		tid = strtoul(tidstr, NULL, 10);
		if (istkill)
			ret = shell_tkill(tid, signo);
		else
			ret = shell_kill(tid, signo);

		if (ret != 0)
			shmsg_err(sh, "kill/tkill failed - ret %d\n", ret);
	} else {
		memcpy(&str[5 - len], tidstr, len);
		kill_common(sh, str, 5, 0, signo, 0, istkill);
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

/*
 * Wait for a foreground pipeline to complete while polling the tty.
 *
 * Semantics:
 * - Foreground only: reads from sh->tty_fd to:
 *     - echo/typeahead buffer
 *     - translate Ctrl keys to signals (e.g. Ctrl+C -> SIGINT)
 * - Waits for external stages via waitpid helper threads.
 * - Waits for builtin stages via per-stage done flags (ctx->done).
 *
 */
/* Foreground pipeline wait: UI thread polls tty while stage waiters run. */
static int shell_wait_pipeline_fg(struct shell *sh,
	struct shell_pipe_stage *stages, int stage_count)
{
	struct shell_waitpid_ctx waiters[MAX_PIPE_STAGES] = {0};
	shell_tid_t tids[MAX_PIPE_STAGES] = {0};
	char inbuf[64];
	struct pollfd pfds[1] = {0};
	int pending = 0, pending_builtins = 0, ret = 0;
	int echo_fd = -1, i = 0, j, signo = 0, rdbytes = 0;

	echo_fd = sh->tty_fd;

	for (i = 0; i < stage_count; i++) {
		if (stages[i].pid <= 0)
			continue;

		waiters[i].pid = stages[i].pid;
		ret = shell_thread_create(&tids[i], shell_waitpid_thread, &waiters[i]);
		if (ret != 0)
			tids[i] = 0;
	}

	pfds[0].fd = sh->tty_fd;
	pfds[0].events = POLLIN;

	for (;;) {
		pending = pending_builtins = 0;

		for (i = 0; i < stage_count; i++) {
			/* External stages with waiter threads */
			if (waiters[i].pid > 0 && tids[i] != 0 &&
			    !__atomic_load_n(&waiters[i].done, __ATOMIC_ACQUIRE)) {
				if (shell_thread_detach(tids[i]) != -ESRCH)
					pending++;
			}

			/* External stages without waiter threads: use WNOHANG */
			if (waiters[i].pid > 0 && tids[i] == 0 && !waiters[i].done) {
				int status = 0;
				pid_t r = shell_waitpid_raw(waiters[i].pid, &status, WNOHANG);

				if (r != 0) {
					waiters[i].status = (r > 0) ? status : r;
					waiters[i].done = 1;
				} else {
					pending++;
				}
			}

			/* Builtin stages */
			if (stages[i].tid != 0 &&
			    !__atomic_load_n(&stages[i].done, __ATOMIC_ACQUIRE)) {
				if (shell_thread_detach(stages[i].tid) != -ESRCH)
					pending_builtins++;
			}
		}

		if (pending == 0 && pending_builtins == 0)
			break;

		ret = poll(pfds, 1, 50);
		if (ret <= 0)
			continue;

		if ((pfds[0].revents & POLLIN) == 0)
			continue;

		rdbytes = shell_read(sh->tty_fd, inbuf, sizeof(inbuf));
		if (rdbytes <= 0)
			continue;

		for (i = 0; i < rdbytes; i++) {
			signo = shell_ctrl_to_signo(inbuf[i]);
			if (signo != 0) {
				sh->stop_request = 1;
				for (j = 0; j < stage_count; j++) {
					stages[j].sh->stop_request = 1;
					if (stages[j].pid > 0)
						shell_kill(stages[j].pid, signo);
				}
				continue;
			}
			shell_echo_and_buffer_typeahead(sh, echo_fd, inbuf[i]);
		}
	}

	/* Join waiter threads and collect last stage result */
	for (i = 0; i < stage_count; i++) {
		shell_thread_join(tids[i]);
		shell_thread_join(stages[i].tid);
		stages[i].tid = 0;
	}

	/* Return last stage's exit status */
	i = stage_count - 1;
	return (stages[i].pid > 0) ? waiters[i].status : stages[i].ret;
}

static int mkmultidirs(struct shell *sh, const char *path, mode_t mode)
{
	int ret = -1;
	int i, len = 0;
	char dir[SHELL_PATH_MAX];

	strlcpy(dir, path, sizeof(dir));
	len = strnlen(dir, sizeof(dir));

	for (i = 0; i <= len; i++) {
		if ((dir[i] == '/' && i > 0) || (i == len)) {
			dir[i] = 0;
			if (access(dir, R_OK) < 0) {
				ret = shell_mkdir(dir, mode);
				if (ret != 0) {
					shmsg(sh, "mkdir %s ret %d\n", dir, ret);
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
	char abspath[SHELL_PATH_MAX];
	const char *path = NULL;
	struct stat st;

	if (!sh->argv[1]) {
		shmsg(sh, "miss dir path\n");
		return;
	}

	path = shell_abspath(sh, sh->argv[1], abspath, sizeof(abspath));

	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode))
			return;
		shmsg(sh, "%s already exists\n", sh->argv[1]);
		return;
	}

	mkmultidirs(sh, path, 0666);
}

static void cmd_mkfile(struct shell *sh)
{
	int fd = -1;
	char abspath[SHELL_PATH_MAX];
	const char *path = NULL;
	char dir[SHELL_PATH_MAX];
	char *dirpath = NULL;

	if (!sh->argv[1]) {
		shmsg(sh, "miss file path\n");
		return;
	}

	path = shell_abspath(sh, sh->argv[1], abspath, sizeof(abspath));

	strlcpy(dir, path, sizeof(dir));
	dirpath = shell_dirname(dir);

	/* Only create directories if dirpath is not root and different from the full path */
	if (strcmp(dirpath, "/") != 0 && strcmp(dirpath, path) != 0) {
		if (mkmultidirs(sh, dirpath, 0666) != 0)
			return;
	}

	fd = shell_creat(path, 0666);
	if (fd < 0)
		shmsg(sh, "creat %s ret=%d\n", sh->argv[1], fd);
	else
		shell_close(fd);
}

/* Print current working directory */
static void cmd_pwd(struct shell *sh)
{
	shmsg(sh, "%s\n", sh->cwd);
}

/* Change current working directory */
static void cmd_cd(struct shell *sh)
{
	char abspath[SHELL_PATH_MAX];
	const char *path;
	DIR *dir = NULL;

	/* cd without argument goes to root */
	if (!sh->argv[1]) {
		strlcpy(sh->cwd, "/", sizeof(sh->cwd));
		return;
	}

	path = sh->argv[1];

	/* Handle special case: cd - (could be implemented later) */
	if (strcmp(path, "-") == 0) {
		shmsg_err(sh, "cd -: not supported\n");
		return;
	}

	/* Convert to absolute path */
	shell_realpath(sh, path, abspath, sizeof(abspath));

	/* Verify the directory exists */
	dir = opendir(abspath);
	if (!dir) {
		shmsg_err(sh, "cd: %s: No such directory\n", path);
		return;
	}
	closedir(dir);

	/* Update current working directory */
	strlcpy(sh->cwd, abspath, sizeof(sh->cwd));
}

/* Copy file: cp <src> <dst> */
static void cmd_cp(struct shell *sh)
{
	char srcpath[SHELL_PATH_MAX];
	char dstpath[SHELL_PATH_MAX];
	char backupbuf[256], *buf = NULL;
	ssize_t bufsz = 4096;
	const char *src, *dst;
	int srcfd = -1, dstfd = -1;
	ssize_t rdbytes, wrbytes;

	if (sh->argc < 3) {
		shmsg_err(sh, "usage: cp <source> <dest>\n");
		return;
	}

	src = shell_abspath(sh, sh->argv[1], srcpath, sizeof(srcpath));
	dst = shell_abspath(sh, sh->argv[2], dstpath, sizeof(dstpath));

	/* If destination is a directory, append source filename */
	{
		struct stat dst_st;

		if (stat(dst, &dst_st) == 0 && S_ISDIR(dst_st.st_mode)) {
			char dir_tmp[SHELL_PATH_MAX];

			strlcpy(dir_tmp, dst, sizeof(dir_tmp));
			path_join(dstpath, sizeof(dstpath), dir_tmp,
				shell_basename(src));
		}
	}

	srcfd = shell_open(src, O_RDONLY);
	if (srcfd < 0) {
		shmsg_err(sh, "cp: cannot open '%s': %d\n", sh->argv[1], srcfd);
		return;
	}

	dstfd = shell_creat(dst, 0666);
	if (dstfd < 0) {
		shmsg_err(sh, "cp: cannot create '%s': %d\n", sh->argv[2], dstfd);
		goto out;
	}

	buf = shell_malloc(bufsz);
	if (!buf) {
		buf = backupbuf;
		bufsz = sizeof(backupbuf);
	}

	while (!sh->stop_request && (rdbytes = shell_read(srcfd, buf, bufsz)) > 0) {
		wrbytes = shell_write(dstfd, buf, rdbytes);
		if (wrbytes != rdbytes) {
			shmsg_err(sh, "cp: write error\n");
			/* Delete corrupted destination file */
			shell_unlink(dst);
			goto out;
		}
	}

out:
	if (buf != backupbuf)
		shell_free(buf);
	shell_close(srcfd);
	if (dstfd >= 0)
		shell_close(dstfd);
}

/* Display file contents: cat <file> [file2...] */
static void cmd_cat(struct shell *sh)
{
	int fd, i, in_fd = -1;
	const char *path;
	ssize_t rdbytes, bufsz = 4096;
	struct stat st;
	char filepath[SHELL_PATH_MAX];
	char backupbuf[1024], *buf = NULL;

	/* If no files specified, read from stdin and write to stdout. */
	if (sh->argc < 2)
		in_fd = sh->io.stdin_fd;

	buf = shell_malloc(bufsz);
	if (!buf) {
		buf = backupbuf;
		bufsz = sizeof(backupbuf);
	}

	if (in_fd >= 0) {
		shmsg_flush(sh);
		while (!sh->stop_request && (rdbytes = shell_read(in_fd, buf, bufsz)) > 0)
			shell_write(sh->io.stdout_fd, buf, rdbytes);
		goto out;
	}

	for (i = 1; i < sh->argc; i++) {
		path = shell_abspath(sh, sh->argv[i], filepath, sizeof(filepath));

		fd = shell_open(path, O_RDONLY);
		if (fd < 0) {
			shmsg_err(sh, "cat: %s: No such file\n", sh->argv[i]);
			continue;
		}

		/* Check if it's a regular file */
		if (shell_fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
			shmsg_err(sh, "cat: %s: Not a regular file\n", sh->argv[i]);
			shell_close(fd);
			continue;
		}

		shmsg_flush(sh);
		while (!sh->stop_request && (rdbytes = shell_read(fd, buf, bufsz)) > 0)
			shell_write(sh->io.stdout_fd, buf, rdbytes);

		shell_close(fd);
	}


out:
	if (buf != backupbuf)
		shell_free(buf);
}

/* Echo text: echo [-n] <text...> or echo <text> > file */
/* Helper: process escape sequences in a string and output via shmsg */
static void echo_process_escapes(struct shell *sh, const char *s)
{
	char c = 0, esc_char = 0;
	int d = 0, val = 0, cnt = 0;
	const char *run_start = s;

	while (*s && !sh->stop_request) {
		if (*s == '\\' && s[1]) {
			/* Flush any pending normal characters */
			if (s > run_start)
				shmsg_puts(sh, run_start, s - run_start);
			s++;
			esc_char = 0;
			switch (*s) {
			case 'n': esc_char = '\n'; break;
			case 't': esc_char = '\t'; break;
			case 'r': esc_char = '\r'; break;
			case '\\': esc_char = '\\'; break;
			case '0':
				/* Octal: \0NNN */
				val = 0;
				cnt = 0;
				while (s[1] >= '0' && s[1] <= '7' && cnt < 3) {
					s++;
					val = val * 8 + (*s - '0');
					cnt++;
				}
				if (val < 256)
					esc_char = val;
				break;
			case 'x':
				/* Hex: \xNN */
				val = 0;
				cnt = 0;
				while (cnt < 2) {
					c = s[1];
					d = -1;
					if (c >= '0' && c <= '9')
						d = c - '0';
					else if (c >= 'a' && c <= 'f')
						d = c - 'a' + 10;
					else if (c >= 'A' && c <= 'F')
						d = c - 'A' + 10;
					if (d < 0)
						break;
					s++;
					val = val * 16 + d;
					cnt++;
				}
				if (cnt > 0 && val < 256)
					esc_char = val;
				break;
			default:
				/* Unknown escape, output as-is */
				shmsg(sh, "\\%c", *s);
				break;
			}
			if (esc_char != 0)
				shmsg_putc(sh, esc_char);
			s++;
			run_start = s;
		} else {
			s++;
		}
	}

	/* Flush trailing normal characters */
	if (s > run_start)
		shmsg_puts(sh, run_start, s - run_start);
}

static void cmd_echo(struct shell *sh)
{
	int i, start = 1;
	bool newline = true;
	bool escape = false;

	if (sh->argc < 2) {
		shmsg(sh, "\n");
		return;
	}

	/* Parse options */
	for (i = 1; i < sh->argc; i++) {
		if (sh->argv[i][0] != '-')
			break;
		if (strcmp(sh->argv[i], "-n") == 0) {
			newline = false;
		} else if (strcmp(sh->argv[i], "-e") == 0) {
			escape = true;
		} else if (strcmp(sh->argv[i], "-ne") == 0 ||
			   strcmp(sh->argv[i], "-en") == 0) {
			newline = false;
			escape = true;
		} else {
			/* Not an option, treat as argument */
			break;
		}
	}
	start = i;

	for (i = start; i < sh->argc; i++) {
		if (i > start)
			shmsg(sh, " ");
		if (escape)
			echo_process_escapes(sh, sh->argv[i]);
		else
			shmsg(sh, "%s", sh->argv[i]);
	}

	if (newline)
		shmsg(sh, "\n");
}

/* Search for pattern in files: grep <pattern> <file> [file2...] */

/* Helper: case-insensitive strstr */
static const char *strcasestr_simple(const char *haystack, const char *needle)
{
	size_t nlen = strlen(needle);
	size_t hlen = strlen(haystack);
	size_t i, j;

	if (nlen > hlen)
		return NULL;

	for (i = 0; i <= hlen - nlen; i++) {
		for (j = 0; j < nlen; j++) {
			if (tolower((unsigned char)haystack[i + j]) !=
			    tolower((unsigned char)needle[j]))
				break;
		}
		if (j == nlen)
			return &haystack[i];
	}
	return NULL;
}

/* Helper: output a grep match line */
static void grep_output_match(struct shell *sh, const char *filepath,
	int linenum, const char *line, bool show_filename, bool show_linenum)
{
	if (show_filename)
		shmsg(sh, "%s: ", filepath);

	if (show_linenum)
		shmsg(sh, "%d: ", linenum);

	shmsg(sh, "%s\n", line);

	shmsg_flush(sh);
}

/* Helper: grep a single file, returns true if any match found */
static bool grep_file(struct shell *sh, const char *filepath,
	const char *pattern, bool show_filename, bool show_linenum,
	bool list_only, bool ignore_case)
{
	char line[256], buf[256];
	int fd, linenum = 1;
	ssize_t rdbytes;
	int linepos = 0, bufpos;
	bool found = false;
	const char *match;

	fd = shell_open(filepath, O_RDONLY);
	if (fd < 0)
		return false;

	while (!sh->stop_request) {
		/* Regular file fds are always ready; poll() is unnecessary overhead. */
		rdbytes = shell_read(fd, buf, sizeof(buf));
		if (rdbytes <= 0)
			break;

		for (bufpos = 0; bufpos < rdbytes; bufpos++) {
			if (buf[bufpos] == '\n' || linepos >= (int)sizeof(line) - 1) {
				line[linepos] = '\0';
				match = ignore_case ? strcasestr_simple(line, pattern)
				                    : strstr(line, pattern);
				if (match) {
					found = true;
					if (list_only) {
						shmsg(sh, "%s\n", filepath);
						shell_close(fd);
						return true;
					}
					grep_output_match(sh, filepath, linenum, line,
						show_filename, show_linenum);
				}
				linenum++;
				linepos = 0;
			} else {
				line[linepos++] = buf[bufpos];
			}
		}
	}

	/* Check last line without newline */
	if (linepos > 0) {
		line[linepos] = '\0';
		match = ignore_case ? strcasestr_simple(line, pattern)
		                    : strstr(line, pattern);
		if (match) {
			found = true;
			if (list_only)
				shmsg(sh, "%s\n", filepath);
			else
				grep_output_match(sh, filepath, linenum, line,
					show_filename, show_linenum);
		}
	}

	shell_close(fd);
	return found;
}

/* Helper: grep from an fd (stdin), returns true if any match found */
static bool grep_fd(struct shell *sh, int fd, const char *pattern,
	bool show_linenum, bool list_only, bool ignore_case)
{
	char line[256], buf[256];
	int linenum = 1, linepos = 0, bufpos;
	ssize_t rdbytes;
	bool found = false;
	const char *match;
	struct pollfd pfd;
	int ret = 0;

	pfd.fd = fd;
	pfd.events = POLLIN;

	while (!sh->stop_request) {
		ret = poll(&pfd, 1, 200);
		if (ret < 0)
			break;
		if (ret == 0)
			continue;

		rdbytes = shell_read(fd, buf, sizeof(buf));
		if (rdbytes <= 0)
			break;
		for (bufpos = 0; bufpos < rdbytes; bufpos++) {
			if (buf[bufpos] == '\n' || linepos >= (int)sizeof(line) - 1) {
				line[linepos] = '\0';
				match = ignore_case ? strcasestr_simple(line, pattern)
				                    : strstr(line, pattern);
				if (match) {
					found = true;
					if (list_only) {
						shmsg(sh, "(stdin)\n");
						return true;
					}
					grep_output_match(sh, NULL, linenum, line,
						false, show_linenum);
				}
				linenum++;
				linepos = 0;
			} else {
				line[linepos++] = buf[bufpos];
			}
		}
	}

	if (linepos > 0) {
		line[linepos] = '\0';
		match = ignore_case ? strcasestr_simple(line, pattern)
		                    : strstr(line, pattern);
		if (match) {
			found = true;
			if (list_only)
				shmsg(sh, "(stdin)\n");
			else
				grep_output_match(sh, NULL, linenum, line, false, show_linenum);
		}
	}

	return found;
}

/* Helper: recursively grep directory */
static void grep_recursive(struct shell *sh, const char *dirpath,
	const char *pattern, const char *file_pattern,
	bool show_linenum, bool list_only, bool ignore_case, int depth)
{
	char *fpath = NULL;
	DIR *dir = NULL;
	struct dirent *d = NULL;

	if (sh->stop_request || depth > MAX_RECURSION_DEPTH)
		return;

	/* Skip special directories that may cause hangs or infinite loops */
	if (strcmp(dirpath, "/dev") == 0 ||
	    strcmp(dirpath, "/proc") == 0 ||
	    strcmp(dirpath, "/sys") == 0 ||
	    strcmp(dirpath, "/debug") == 0)
		return;

	fpath = shell_malloc(SHELL_PATH_MAX);
	if (!fpath)
		return;

	dir = opendir(dirpath);
	if (!dir) {
		shell_free(fpath);
		return;
	}

	while (!sh->stop_request && (d = readdir(dir)) != NULL) {
		if (is_dotdir(d->d_name))
			continue;

		path_join(fpath, SHELL_PATH_MAX, dirpath, d->d_name);

		if (d->d_type == DT_DIR) {
			grep_recursive(sh, fpath, pattern, file_pattern,
				show_linenum, list_only, ignore_case, depth + 1);
		} else if (d->d_type == DT_REG) {
			/* Only grep regular files, skip devices/pipes/etc */
			if (!file_pattern || glob_match(file_pattern, d->d_name)) {
				grep_file(sh, fpath, pattern, true,
					show_linenum, list_only, ignore_case);
			}
		}
	}

	closedir(dir);
	shell_free(fpath);
}

static void cmd_grep(struct shell *sh)
{
	char filepath[SHELL_PATH_MAX];
	char dirpath[SHELL_PATH_MAX], fpath[SHELL_PATH_MAX];
	const char *path = NULL, *pattern = NULL;
	const char *file_pattern = NULL, *pattern_part = NULL;
	char *opt = NULL, *dir_part = NULL;
	int i = 0, path_count = 0, fd = -1;
	DIR *dir = NULL;
	struct dirent *d = NULL;
	bool recursive = false, show_linenum = true;
	bool list_only = false, ignore_case = false, show_filename;
	struct stat st;

	if (sh->argc < 2) {
		shmsg(sh, "usage: grep [-rinlR] [--include=PATTERN] <pattern> <path>...\n");
		shmsg(sh, "  -r, -R  recursive search\n");
		shmsg(sh, "  -i      ignore case\n");
		shmsg(sh, "  -n      show line numbers (default)\n");
		shmsg(sh, "  -l      list matching files only\n");
		shmsg(sh, "  --include=*.c  search only matching files\n");
		return;
	}

	/*
	 * Two-pass parsing to support options anywhere:
	 * Pass 1: Scan all args to find options and pattern
	 * Pass 2: Process path arguments
	 */

	/* Pass 1: Parse all options first, find pattern */
	for (i = 1; i < sh->argc; i++) {
		if (strncmp(sh->argv[i], "--include=", 10) == 0) {
			file_pattern = sh->argv[i] + 10;
		} else if (sh->argv[i][0] == '-' && sh->argv[i][1] != '\0') {
			/* Parse combined options like -rni */
			opt = sh->argv[i] + 1;
			while (*opt) {
				switch (*opt) {
				case 'r':
				case 'R':
					recursive = true;
					break;
				case 'i':
					ignore_case = true;
					break;
				case 'n':
					show_linenum = true;
					break;
				case 'l':
					list_only = true;
					break;
				}
				opt++;
			}
		} else {
			/* Non-option argument */
			if (!pattern)
				pattern = sh->argv[i];
			else
				path_count++;
		}
	}

	if (!pattern) {
		shmsg(sh, "grep: missing pattern\n");
		return;
	}

	/* If no path specified, use current directory with recursive */
	if (path_count == 0) {
		if (recursive) {
			grep_recursive(sh, sh->cwd, pattern, file_pattern,
				show_linenum, list_only, ignore_case, 0);
		} else {
			/* No path: behave like grep from stdin */
			grep_fd(sh, sh->io.stdin_fd, pattern,
				show_linenum, list_only, ignore_case);
		}
		return;
	}

	show_filename = recursive || (path_count > 1);

	/* Pass 2: Process path arguments */
	for (i = 1; i < sh->argc && !sh->stop_request; i++) {
		/* Skip options and pattern */
		if (sh->argv[i][0] == '-' || sh->argv[i] == pattern)
			continue;
		if (strncmp(sh->argv[i], "--", 2) == 0)
			continue;

		path = shell_abspath(sh, sh->argv[i], filepath, sizeof(filepath));

		/* Check if path is directory */
		fd = shell_open(path, O_RDONLY);
		if (fd < 0) {
			/* Try as glob pattern in current directory */
			if (strchr(sh->argv[i], '*') || strchr(sh->argv[i], '?')) {
				/* It's a glob pattern - search matching files */
				strlcpy(dirpath, path, sizeof(dirpath));
				dir_part = shell_dirname(dirpath);
				pattern_part = shell_basename(path);

				if (*dir_part == '\0')
					strlcpy(dirpath, sh->cwd, sizeof(dirpath));
				else
					strlcpy(dirpath, dir_part, sizeof(dirpath));

				dir = opendir(dirpath);
				if (dir) {
					while (!sh->stop_request && (d = readdir(dir)) != NULL) {
						if (glob_match(pattern_part, d->d_name)) {
							path_join(fpath, sizeof(fpath), dirpath, d->d_name);
							grep_file(sh, fpath, pattern, show_filename,
								show_linenum, list_only, ignore_case);
						}
					}
					closedir(dir);
				}
			} else {
				shmsg_err(sh, "grep: %s: No such file or directory\n", sh->argv[i]);
			}
			continue;
		}

		if (shell_fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
			shell_close(fd);
			if (recursive) {
				grep_recursive(sh, path, pattern, file_pattern,
					show_linenum, list_only, ignore_case, 0);
			} else {
				shmsg_err(sh, "grep: %s: Is a directory\n", sh->argv[i]);
			}
		} else {
			shell_close(fd);
			/* Check file pattern if specified */
			if (!file_pattern ||
				glob_match(file_pattern, shell_basename(path))) {
				grep_file(sh, path, pattern, show_filename,
					show_linenum, list_only, ignore_case);
			}
		}
	}
}

/* Find files: find <path> -name <pattern> */
static void cmd_find_recursive(struct shell *sh, const char *dirpath,
	const char *pattern, int depth)
{
	char *fpath = NULL;
	DIR *dir = NULL;
	struct dirent *d = NULL;

	if (sh->stop_request || depth > MAX_RECURSION_DEPTH)
		return;

	fpath = shell_malloc(SHELL_PATH_MAX);
	if (!fpath)
		return;

	dir = opendir(dirpath);
	if (!dir) {
		shell_free(fpath);
		return;
	}

	while (!sh->stop_request && (d = readdir(dir)) != NULL) {
		if (is_dotdir(d->d_name))
			continue;

		path_join(fpath, SHELL_PATH_MAX, dirpath, d->d_name);

		/* Check if name matches pattern (glob wildcards supported) */
		if (!pattern || glob_match(pattern, d->d_name)) {
			shmsg(sh, "%s\n", fpath);
			shmsg_flush(sh);
		}

		/* Recurse into directories */
		if (d->d_type == DT_DIR)
			cmd_find_recursive(sh, fpath, pattern, depth + 1);
	}

	closedir(dir);
	shell_free(fpath);
}

static void cmd_find(struct shell *sh)
{
	char startpath[SHELL_PATH_MAX];
	const char *path = NULL;
	const char *pattern = NULL;
	int i;

	if (sh->argc < 2)
		path = sh->cwd;
	else
		path = shell_abspath(sh, sh->argv[1], startpath, sizeof(startpath));

	/* Parse -name option */
	for (i = 2; i < sh->argc - 1; i++) {
		if (strcmp(sh->argv[i], "-name") == 0) {
			pattern = sh->argv[i + 1];
			break;
		}
	}

	cmd_find_recursive(sh, path, pattern, 0);
}

/* Tee: read from stdin and write to file and stdout */
/* For shell, we implement: tee <file> (writes following input to file) */
/* Actually simpler: echo text | tee file  -> tee <file> <text> */
static void cmd_tee(struct shell *sh)
{
	char filepath[SHELL_PATH_MAX], buf[256];
	const char *path = NULL;
	int fd, i, flags;
	bool append = false;
	int filearg = 1, min_argc = 2;
	size_t arglen;
	ssize_t rdbytes;

	/* Check for -a (append) option */
	if (sh->argc > 1 && strcmp(sh->argv[1], "-a") == 0) {
		append = true;
		filearg = 2;
		min_argc = 3;
	}

	if (sh->argc < min_argc) {
		shmsg_err(sh, "usage: tee [-a] <file> [text...]\n");
		return;
	}

	path = shell_abspath(sh, sh->argv[filearg], filepath, sizeof(filepath));
	flags = O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC);
	fd = shell_open(path, flags, 0666);

	if (fd < 0) {
		shmsg_err(sh, "tee: cannot open '%s': %d\n", sh->argv[filearg], fd);
		return;
	}

	/* If extra args exist, keep old convenience behavior: tee file text... */
	if (sh->argc > filearg + 1) {
		for (i = filearg + 1; i < sh->argc; i++) {
			if (i > filearg + 1) {
				shell_write(fd, " ", 1);
				shmsg(sh, " ");
			}
			arglen = strlen(sh->argv[i]);
			shell_write(fd, sh->argv[i], arglen);
			shmsg(sh, "%s", sh->argv[i]);
		}
		shell_write(fd, "\n", 1);
		shmsg(sh, "\n");
		shmsg_flush(sh);
		shell_close(fd);
		return;
	}

	/* Standard tee behavior: read stdin and write to file and stdout */
	shmsg_flush(sh);
	while (!sh->stop_request) {
		struct pollfd pfd = {sh->io.stdin_fd, POLLIN, 0};
		int ret = poll(&pfd, 1, 200);
		if (ret <= 0)
			continue;

		rdbytes = shell_read(sh->io.stdin_fd, buf, sizeof(buf));
		if (rdbytes <= 0)
			break;

		shell_write(fd, buf, rdbytes);
		shell_write(sh->io.stdout_fd, buf, rdbytes);
	}
	shmsg_flush(sh);

	shell_close(fd);
}

/* Hexdump: display file in hex format */
static void cmd_hexdump(struct shell *sh)
{
	char filepath[SHELL_PATH_MAX];
	unsigned char backupbuf[1024], *buf = NULL;
	ssize_t bufsz = 4096, rdbytes = 0;
	const char *path = NULL;
	unsigned long offset = 0;
	int fd = -1, i = 0, pos = 0, chunk_len = 0, lp = 0;
	unsigned char c = 0;
	struct stat hd_st;
	/* 8(offset)+2+48(hex)+1(mid)+2(" |")+16(ascii)+2("|\n")+1(NUL) = ~80 */
	char line[96];

	if (sh->argc < 2) {
		shmsg_err(sh, "usage: hexdump <file>\n");
		return;
	}

	path = shell_abspath(sh, sh->argv[1], filepath, sizeof(filepath));
	fd = shell_open(path, O_RDONLY);
	if (fd < 0) {
		shmsg_err(sh, "hexdump: %s: No such file\n", sh->argv[1]);
		return;
	}

	if (shell_fstat(fd, &hd_st) == 0 && !S_ISREG(hd_st.st_mode)) {
		shmsg_err(sh, "hexdump: %s: Not a regular file\n", sh->argv[1]);
		shell_close(fd);
		return;
	}

	buf = shell_malloc(bufsz);
	if (!buf) {
		buf = backupbuf;
		bufsz = sizeof(backupbuf);
	}

	while (!sh->stop_request && (rdbytes = shell_read(fd, buf, bufsz)) > 0) {
		pos = 0;
		while (pos < rdbytes) {
			chunk_len = (rdbytes - pos) > 16 ? 16 : (rdbytes - pos);

			/* Build entire line in local buffer to avoid per-byte shmsg calls */
			lp = snprintf(line, sizeof(line), "%08lx  ", offset);

			/* Hex bytes */
			for (i = 0; i < 16; i++) {
				if (i == 8)
					line[lp++] = ' ';
				if (i < chunk_len) {
					static const char hex[] = "0123456789abcdef";

					line[lp++] = hex[buf[pos + i] >> 4];
					line[lp++] = hex[buf[pos + i] & 0xf];
					line[lp++] = ' ';
				} else {
					line[lp++] = ' ';
					line[lp++] = ' ';
					line[lp++] = ' ';
				}
			}

			/* ASCII representation */
			line[lp++] = ' ';
			line[lp++] = '|';
			for (i = 0; i < chunk_len; i++) {
				c = buf[pos + i];
				line[lp++] = (c >= 0x20 && c < 0x7f) ? c : '.';
			}
			line[lp++] = '|';
			line[lp++] = '\n';

			shmsg_puts(sh, line, lp);

			offset += chunk_len;
			pos += chunk_len;
		}
	}

	shmsg(sh, "%08lx\n", offset);
	shell_close(fd);

	if (buf != backupbuf)
		shell_free(buf);
}

/*
 * mv_copy_delete - fallback for cross-filesystem move
 * Copy file content then delete source
 */
static int mv_copy_delete(struct shell *sh, const char *src, const char *dst)
{
	char backupbuf[256], *buf = NULL;
	ssize_t bufsz = 4096;
	int fd_src, fd_dst, ret = 0;
	ssize_t rdbytes, wrbytes;

	fd_src = shell_open(src, O_RDONLY);
	if (fd_src < 0)
		return -1;

	fd_dst = shell_open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd_dst < 0) {
		shell_close(fd_src);
		return -1;
	}

	buf = shell_malloc(bufsz);
	if (!buf) {
		buf = backupbuf;
		bufsz = sizeof(backupbuf);
	}

	while (!sh->stop_request && (rdbytes = shell_read(fd_src, buf, bufsz)) > 0) {
		wrbytes = shell_write(fd_dst, buf, rdbytes);
		if (wrbytes != rdbytes) {
			ret = -1;
			break;
		}
	}

	shell_close(fd_src);
	shell_close(fd_dst);

	if (buf != backupbuf)
		shell_free(buf);

	if (ret == 0) {
		/* Copy succeeded, delete source */
		ret = shell_unlink(src);
		if (ret < 0) {
			/* Failed to delete source, try to remove dest */
			shell_unlink(dst);
		}
	} else {
		/* Copy failed, remove partial dest */
		shell_unlink(dst);
	}

	return ret;
}

/* mv - move/rename file or directory */
static void cmd_mv(struct shell *sh)
{
	char oldpath[SHELL_PATH_MAX];
	char newpath[SHELL_PATH_MAX];
	const char *src, *dst;
	int ret = 0;

	if (sh->argc < 3) {
		shmsg_err(sh, "Usage: mv <source> <dest>\n");
		return;
	}

	src = shell_abspath(sh, sh->argv[1], oldpath, sizeof(oldpath));
	dst = shell_abspath(sh, sh->argv[2], newpath, sizeof(newpath));

	/* If destination is a directory, move source into it */
	{
		struct stat dst_st;

		if (stat(dst, &dst_st) == 0 && S_ISDIR(dst_st.st_mode)) {
			char dir_tmp[SHELL_PATH_MAX];

			strlcpy(dir_tmp, dst, sizeof(dir_tmp));
			path_join(newpath, sizeof(newpath), dir_tmp,
				shell_basename(src));
		}
	}

	/* Try rename first (atomic, same filesystem) */
	ret = shell_rename(src, dst);
	if (ret == -EXDEV) {
		/* Cross-filesystem move: fallback to copy + delete */
		ret = mv_copy_delete(sh, src, dst);
	}

	if (ret < 0)
		shmsg_err(sh, "mv: cannot move '%s' to '%s'\n", sh->argv[1], sh->argv[2]);
}

static int cmd_runapp_argv(struct shell *sh, char *const argv[])
{
	return shell_ext_runapp_argv(sh, argv);
}

static int cmd_spawnapp_argv(struct shell *sh, char *const argv[], pid_t *pid_out)
{
	return shell_ext_spawnapp_argv(sh, argv, pid_out);
}

/*
 * Set or show terminal width.
 * Usage: stty [cols N]
 *   stty        - show current terminal width
 *   stty cols N - set terminal width to N columns
 */
static void cmd_stty(struct shell *sh)
{
	int old_width = 0, width = 0;

	if (sh->argc == 1) {
		/* Show current setting */
		shmsg(sh, "columns %d\n", sh->term_width);
	} else if (sh->argc == 2 && strcmp(sh->argv[1], "detect") == 0) {
		/* Auto-detect terminal width */
		old_width = sh->term_width;
		sh->term_width = shell_detect_terminal_width(sh);
		shmsg(sh, "terminal width %s: %d\n",
		      (sh->term_width != old_width) ? "changed to" : "is", sh->term_width);
	} else if (sh->argc == 3 && strcmp(sh->argv[1], "cols") == 0) {
		width = atoi(sh->argv[2]);
		if (width >= 20 && width <= 500) {
			sh->term_width = width;
			shmsg(sh, "terminal width set to %d\n", width);
		}
	} else {
		shmsg(sh, "usage: stty [cols N] | stty detect\n");
	}
}

static void cmd_history(struct shell *sh)
{
	struct shell_history *hist = NULL;
	struct shell_history_ent *ent = NULL;
	int pos = 0, i = 0, idx = 0, n = 0;

	hist = sh->history;
	if (!hist || hist->ent_cnt == 0)
		return;

	pos = (hist->ent_wr + CMD_HISTORY_ENT_MAX - hist->ent_cnt) % CMD_HISTORY_ENT_MAX;
	n = 1;
	for (i = 0; i < hist->ent_cnt; i++) {
		idx = (pos + i) % CMD_HISTORY_ENT_MAX;
		ent = &hist->ent[idx];
		if (!ent->len)
			continue;
		shmsg(sh, "%d\t%s\n", n++, &hist->buf[ent->off]);
	}
}

static void cmd_help(struct shell *sh);

static const struct shell_cmd cmd_handlers[] = {
	{"ps", "Show information of all threads\n", cmd_ps},
	{"ls", "Show files in file system\n", cmd_ls},
	{"mem", "Show memory info\n", cmd_mem},
	{"files", "Show open files info\n", cmd_files},
	{"irq", "Show IRQ info\n", cmd_irq},
	{"date", "Elapsed time since startup\n", cmd_date},
	{"mkdir", "make a dir\n", cmd_mkdir},
	{"mkfile", "make a file\n", cmd_mkfile},
	{"mount", "Show the FS nodes\n", cmd_mount},
	{"cat", "Display file contents\n", cmd_cat},
	{"cp", "Copy file\n", cmd_cp},
	{"mv", "Move/rename file\n", cmd_mv},
	{"rm", "Remove files in file system\n", cmd_rm},
	{"echo", "Echo text to output\n", cmd_echo},
	{"grep", "Search pattern in files [-rinl] [--include=PATTERN]\n", cmd_grep},
	{"find", "Find files by name\n", cmd_find},
	{"stty", "Set terminal width: stty [cols N] | stty detect\n", cmd_stty},
	{"history", "List command history\n", cmd_history},
	{"tee", "Write text to file and stdout\n", cmd_tee},
	{"hexdump", "Display file in hex format\n", cmd_hexdump},
	{"kill", "Send signal to a process\n", cmd_kill},
	{"tkill", "Send signal to a thread\n", cmd_tkill},
	{"pwd", "Print current working directory\n", cmd_pwd},
	{"cd", "Change current working directory\n", cmd_cd},
	/* External command (kept for tab completion) */
	{"mbedtest", "Run mbedtest\n", NULL},
	{"help", "List the supported commands\n", cmd_help},
	{NULL, NULL, NULL},
};

static void cmd_help(struct shell *sh)
{
	int i = 0;

	for (i = 0; cmd_handlers[i].cmd; i++) {
		if (strlen(cmd_handlers[i].cmd) < 8)
			shmsg(sh, "%s\t\t%s", cmd_handlers[i].cmd, cmd_handlers[i].help);
		else
			shmsg(sh, "%s\t%s", cmd_handlers[i].cmd, cmd_handlers[i].help);
	}
}

/*
 * Parse command line into argv array.
 * Supports single quotes ('...') and double quotes ("...").
 * Quotes are removed from the arguments.
 */
static int cmd_parse_argv(struct shell *sh)
{
	int i = 0, j = 0, len = sh->cmdline_len;
	int argc = 0, pos = 0;
	char quote = 0, c = 0;
	bool in_arg = false;

	shell_sanitize_cmdline(sh);
	len = sh->cmdline_len;

	sh->argc = 0;

	/*
	 * First pass: process quotes and count arguments.
	 * Replace spaces outside quotes with NUL, remove quote chars.
	 */
	for (i = 0, j = 0; i < len; i++) {
		c = sh->cmdline[i];

		if (quote) {
			/* Inside quoted string */
			if (c == quote) {
				/* End of quoted string */
				quote = 0;
			} else {
				sh->cmdline[j++] = c;
			}
		} else if (c == '"' || c == '\'') {
			/* Start of quoted string */
			quote = c;
			if (!in_arg) {
				in_arg = true;
				argc++;
			}
		} else if (c == ' ' || c == '\t') {
			/* Whitespace - end of argument */
			if (in_arg) {
				sh->cmdline[j++] = '\0';
				in_arg = false;
			}
		} else {
			/* Regular character */
			if (!in_arg) {
				in_arg = true;
				argc++;
			}
			sh->cmdline[j++] = c;
		}
	}

	/* Terminate last argument */
	if (j < len)
		sh->cmdline[j] = '\0';

	/* Check for unclosed quotes */
	if (quote != 0) {
		shmsg_err(sh, "syntax error: unclosed quote\n");
		return -EINVAL;
	}

	if (argc >= CMD_DFTARGV_NUM)
		return -E2BIG;

	/* Second pass: collect argument pointers */
	in_arg = false;
	for (i = 0; i <= j; i++) {
		if (sh->cmdline[i] && !in_arg) {
			if (pos >= argc) {
				shmsg_err(sh, "argv overflow: argc=%d pos=%d\n", argc, pos);
				return -E2BIG;
			}
			sh->argv[pos++] = &sh->cmdline[i];
			in_arg = true;
		} else if (!sh->cmdline[i]) {
			in_arg = false;
		}
	}

	sh->argc = argc;
	sh->argv[argc] = NULL;

	return argc ? 0 : -EINVAL;
}

static inline int hist_free_space(const struct shell_history *hist)
{
	if (hist->buf_wr >= hist->buf_rd)
		return CMD_HISTORY_BUFSZ - (hist->buf_wr - hist->buf_rd) - 1;
	return hist->buf_rd - hist->buf_wr - 1;
}

static void cmd_record(struct shell *sh)
{
	struct shell_history *hist = NULL;
	struct shell_history_ent *ent = NULL;
	unsigned short off = 0, size = 0;
	int i = 0, len = 0, free = 0;

	hist = sh->history;
	if (!hist)
		return;

	len = sh->cmdline_len;
	if (len <= 0)
		return;
	if (len >= CMD_HISTORY_BUFSZ)
		len = CMD_HISTORY_BUFSZ - 1;

	/* Skip recording if identical to the most recent entry */
	if (hist->ent_cnt > 0) {
		i = (hist->ent_wr + CMD_HISTORY_ENT_MAX - 1) % CMD_HISTORY_ENT_MAX;
		ent = &hist->ent[i];
		if (ent->len == len &&
		    memcmp(&hist->buf[ent->off], sh->cmdline, len) == 0) {
			hist->ent_nav = hist->ent_wr;
			return;
		}
	}

	size = len + 1;

	/* Ensure there's a free entry slot and enough ring-buffer space */
	for (;;) {
		free = hist_free_space(hist);

		if (hist->ent_cnt < CMD_HISTORY_ENT_MAX && free >= (int)size)
			break;
		if (hist->ent_cnt == 0)
			break;

		/* Evict oldest entry */
		i = (hist->ent_wr + CMD_HISTORY_ENT_MAX - hist->ent_cnt) % CMD_HISTORY_ENT_MAX;
		ent = &hist->ent[i];
		if (ent->len) {
			hist->buf_rd = ent->off + ent->len + 1;
			if (hist->buf_rd >= CMD_HISTORY_BUFSZ)
				hist->buf_rd -= CMD_HISTORY_BUFSZ;
			ent->len = 0;
			if (hist->ent_cnt)
				hist->ent_cnt--;
			if (hist->ent_nav == i)
				hist->ent_nav = hist->ent_wr;
		} else {
			/* Inconsistent state; reset history */
			memset(hist, 0, sizeof(*hist));
			break;
		}
	}

	/* Wrap write pointer if needed; keep each entry contiguous in buf[] */
	if ((hist->buf_wr + size) > CMD_HISTORY_BUFSZ)
		hist->buf_wr = 0;

	/* If wrapping caused overlap, evict until it fits */
	for (;;) {
		free = hist_free_space(hist);

		if (free >= (int)size || hist->ent_cnt == 0)
			break;

		i = (hist->ent_wr + CMD_HISTORY_ENT_MAX - hist->ent_cnt) % CMD_HISTORY_ENT_MAX;
		ent = &hist->ent[i];
		if (!ent->len)
			break;
		hist->buf_rd = ent->off + ent->len + 1;
		if (hist->buf_rd >= CMD_HISTORY_BUFSZ)
			hist->buf_rd -= CMD_HISTORY_BUFSZ;
		ent->len = 0;
		hist->ent_cnt--;
		if (hist->ent_nav == i)
			hist->ent_nav = hist->ent_wr;
	}

	off = hist->buf_wr;
	memcpy(&hist->buf[off], sh->cmdline, len);
	hist->buf[off + len] = 0;

	hist->buf_wr = off + size;
	if (hist->buf_wr >= CMD_HISTORY_BUFSZ)
		hist->buf_wr -= CMD_HISTORY_BUFSZ;

	ent = &hist->ent[hist->ent_wr];
	ent->off = off;
	ent->len = len;

	hist->ent_wr++;
	if (hist->ent_wr == CMD_HISTORY_ENT_MAX)
		hist->ent_wr = 0;

	if (hist->ent_cnt < CMD_HISTORY_ENT_MAX)
		hist->ent_cnt++;

	hist->ent_nav = hist->ent_wr;
}

static cmd_handler cmd_handler_of(const char *cmd)
{
	int i = 0;

	if (cmd) {
		for (i = 0; cmd_handlers[i].cmd; i++) {
			if (strcmp(cmd_handlers[i].cmd, cmd) == 0)
				return cmd_handlers[i].func;
		}
	}

	return NULL;
}

static void pipe_stage_close_fds(struct shell_pipe_stage *ctx)
{
	if (ctx->out_is_pipe) {
		if (ctx->out_fd >= 0)
			shell_close(ctx->out_fd);
		ctx->out_is_pipe = 0;
		ctx->out_fd = -1;
	}
	if (ctx->in_is_pipe) {
		if (ctx->in_fd >= 0)
			shell_close(ctx->in_fd);
		ctx->in_is_pipe = 0;
		ctx->in_fd = -1;
	}
}

static void pipe_stage_free_ctx(struct shell_pipe_stage **pctx)
{
	struct shell_pipe_stage *ctx;

	ctx = *pctx;

	pipe_stage_close_fds(ctx);
	shell_free(ctx);
	*pctx = NULL;
}

static void pipe_stage_free_range(struct shell_pipe_stage **stages,
	int start, int count)
{
	int i = 0;

	for (i = start; i < count; i++)
		if (stages[i])
			pipe_stage_free_ctx(&stages[i]);
}

static void shell_job_fail_drop(struct shell_job *job,
	int ret, int drop_cnt, bool set_if_zero)
{
	shell_jobmgr_lock_enter();
	if (!set_if_zero || job->status == 0)
		job->status = (ret < 0) ? ret : -ret;
	job->stages_left -= drop_cnt;
	shell_jobmgr_lock_exit();
}

/*
 * Worker routine: execute a single builtin pipeline stage
 *
 * This is NOT a standalone thread entry by itself; it is invoked by:
 * - shell_pipe_stage_thread() (background pipeline: one stage per thread)
 * - shell_pipe_stage_thread() (foreground builtin: one thread per command)
 *
 * Ownership / lifetime:
 * - ctx is owned by the caller/queue. For background pipeline stages, ctx is a
 *   heap block that includes an embedded struct shell (ctx->sh points inside).
 * - For foreground builtin execution, ctx is a small heap block and ctx->sh
 *   points to the live foreground shell (must not be freed).
 * - Stages with ctx->free_on_finish are freed by the stage thread.
 * - Other stages are freed by the caller.
 *
 * Side effects:
 * - Redirects sh->io to ctx->{in_fd,out_fd}.
 * - Runs ctx->func(sh) for builtins.
 * - Flushes output, frees parsed argv, and closes owned pipe fds.
 */
static int shell_pipe_stage_run(struct shell_pipe_stage *ctx)
{
	struct shell *sh = ctx->sh;

	if (sh->stop_request)
		return 0;

	sh->io.stdin_fd = ctx->in_fd;
	sh->io.stdout_fd = ctx->out_fd;

	if (ctx->func) {
		ctx->func(sh);
		return 0;
	}

	return -EINVAL;
}

static void shell_pipe_stage_finish(struct shell_pipe_stage *ctx, int ret)
{
	struct shell *sh = ctx->sh;

	ctx->ret = ret;

	shmsg_flush(sh);
	pipe_stage_close_fds(ctx);
	/* Use release semantics so ret is visible before done is observed */
	__atomic_store_n(&ctx->done, 1, __ATOMIC_RELEASE);
}

static long shell_pipe_stage_thread(void *arg)
{
	struct shell_pipe_stage *ctx = arg;
	struct shell_job *job = ctx->job;
	int stage_idx = ctx->stage_idx;
	int stage_count = job ? job->stage_count : 0;
	int free_self = ctx->free_on_finish;
	int ret = shell_pipe_stage_run(ctx);

	/*
	 * After finish sets ctx->done = 1, the caller may free ctx
	 * immediately (foreground builtin path). Use only local copies
	 * of ctx fields beyond this point.
	 */
	shell_pipe_stage_finish(ctx, ret);

	if (job) {
		shell_jobmgr_lock_enter();
		job->stages_left--;
		if (stage_idx == stage_count - 1)
			job->status = (ret < 0) ? ret : 0;
		shell_jobmgr_lock_exit();
	}

	if (free_self)
		shell_free(ctx);
	return ret;
}

static struct shell_pipe_stage *shell_fg_builtin_dequeue(void)
{
	struct shell_pipe_stage *ctx = NULL;

	shell_fg_builtin_lock_enter();
	ctx = list_first_entry_or_null(&shell_fg_builtin_q,
		struct shell_pipe_stage, task_node);
	if (ctx)
		list_del(&ctx->task_node);
	shell_fg_builtin_lock_exit();
	return ctx;
}

static long shell_fg_builtin_thread(void *arg)
{
	struct shell_pipe_stage *ctx = NULL;
	int timeout = 0, idle_ms = 0;
	int did_work = 0, busy = 0;

	for (;;) {
		did_work = 0;
		while ((ctx = shell_fg_builtin_dequeue()) != NULL) {
			did_work = 1;
			shell_pipe_stage_thread(ctx);
		}

		busy = !list_empty(&shell_fg_builtin_q);

		timeout = busy ? 50 : 100;
		if (did_work || busy) {
			idle_ms = 0;
			continue;
		}

		poll(NULL, 0, timeout);
		idle_ms += timeout;
		if (idle_ms >= 10000) {
			shell_fg_builtin_lock_enter();
			busy = !list_empty(&shell_fg_builtin_q);
			if (!busy)
				shell_fg_builtin_started = 0;
			shell_fg_builtin_lock_exit();
			if (!busy)
				break;
		}
	}

	return 0;
}

static int shell_fg_builtin_thread_start(void)
{
	shell_tid_t tid = 0;
	int ret = 0;

	if (shell_fg_builtin_started)
		return 0;

	ret = shell_thread_create(&tid, shell_fg_builtin_thread, NULL);
	if (ret == 0) {
		shell_fg_builtin_tid = tid;
		shell_fg_builtin_started = 1;
		shell_thread_detach(tid);
	}

	return ret;
}

static int shell_fg_builtin_enqueue(struct shell_pipe_stage *ctx)
{
	int ret = 0;

	shell_fg_builtin_lock_enter();
	ret = shell_fg_builtin_thread_start();
	if (ret == 0)
		list_add_tail(&ctx->task_node, &shell_fg_builtin_q);
	shell_fg_builtin_lock_exit();

	return ret;
}

/* Spawn one external stage in a pipeline (parent closes its pipe ends). */
static int shell_spawn_pipeline_external_stage(struct shell_pipe_stage *ctx)
{
	pid_t pid = -1;
	int ret = 0, in_fd = ctx->in_fd, out_fd = ctx->out_fd;
	struct shell *sh = ctx->sh;

	ctx->ret = 0;
	ctx->pid = -1;

	sh->io.stdin_fd = ctx->in_fd;
	sh->io.stdout_fd = ctx->out_fd;

	ret = shell_ext_spawn_pipeline_stage(&pid, in_fd, out_fd, sh->argv);
	if (ret != 0)
		return ret;

	ctx->pid = pid;

	shmsg_flush(sh);
	return 0;
}

static void cmdline_split_unquoted_inplace(char *buf, int cmd_len, char delim,
	char **segments, int max_segments, int *seg_count_out, int *scan_i_out, char *quote_out)
{
	int seg_count = 0, i = 0;
	char quote = 0, c = 0;

	if (seg_count_out)
		*seg_count_out = 0;
	if (scan_i_out)
		*scan_i_out = 0;
	if (quote_out)
		*quote_out = 0;
	if (max_segments <= 0)
		return;

	segments[seg_count++] = buf;
	for (i = 0; i < cmd_len && seg_count < max_segments; i++) {
		c = buf[i];
		if (quote) {
			if (c == quote)
				quote = 0;
			continue;
		}
		if (c == '\'' || c == '"') {
			quote = c;
			continue;
		}
		if (c == delim) {
			buf[i] = '\0';
			if (i + 1 < cmd_len && seg_count < max_segments)
				segments[seg_count++] = &buf[i + 1];
		}
	}

	*seg_count_out = seg_count;
	if (scan_i_out)
		*scan_i_out = i;
	if (quote_out)
		*quote_out = quote;
}

static int pipeline_split_cmdline(struct shell *sh, char *buf,
	int buf_sz, char **segments, int *stage_count_out)
{
	int stage_count = 0, i = 0, cmd_len = 0;
	char quote = 0;

	*stage_count_out = 0;

	if (sh->cmdline_len <= 0)
		return 0;

	/* Copy original cmdline, then split by unquoted | into NUL-terminated segments */
	cmd_len = sh->cmdline_len;
	if (cmd_len >= buf_sz)
		cmd_len = buf_sz - 1;
	memcpy(buf, sh->cmdline, cmd_len);
	buf[cmd_len] = '\0';

	cmdline_split_unquoted_inplace(buf, cmd_len, '|', segments,
		MAX_PIPE_STAGES, &stage_count, &i, &quote);

	if (quote) {
		shmsg_err(sh, "syntax error: unclosed quote\n");
		return -EINVAL;
	}

	if (stage_count >= MAX_PIPE_STAGES && i < cmd_len) {
		shmsg_err(sh, "pipe: too many stages (max %d)\n", MAX_PIPE_STAGES);
		return -E2BIG;
	}

	/* Trim leading/trailing spaces for each segment and validate */
	for (i = 0; i < stage_count; i++) {
		segments[i] = trim_ws_inplace(segments[i]);
		if (segments[i][0] == '\0') {
			shmsg_err(sh, "syntax error near unexpected token '|'\n");
			return -EINVAL;
		}
	}

	*stage_count_out = stage_count;
	return 0;
}

static int pipeline_open_pipes(int (*pipefds)[2], int stage_count)
{
	int i = 0, ret = 0;

	for (i = 0; i < stage_count - 1; i++) {
		ret = shell_pipe(pipefds[i]);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static void pipeline_close_pipefds(int (*pipefds)[2], int stage_count)
{
	int i = 0;

	if (!pipefds || stage_count <= 1)
		return;

	for (i = 0; i < stage_count - 1; i++) {
		if (pipefds[i][0] >= 0) {
			shell_close(pipefds[i][0]);
			pipefds[i][0] = -1;
		}
		if (pipefds[i][1] >= 0) {
			shell_close(pipefds[i][1]);
			pipefds[i][1] = -1;
		}
	}
}

static int pipeline_setup_stage(struct shell *sh, struct shell_pipe_stage *ctx,
	const char *segment, int stage_idx, int stage_count, int (*pipefds)[2],
	bool use_tty)
{
	struct shell *stage_sh = ctx->sh;
	int ret = 0;

	shell_init_stage_shell(stage_sh, sh, segment);
	if (use_tty)
		stage_sh->tty_fd = sh->tty_fd;

	ctx->in_is_pipe = (stage_idx != 0);
	ctx->out_is_pipe = (stage_idx != stage_count - 1);

	if (ctx->in_is_pipe) {
		ctx->in_fd = shell_dup(pipefds[stage_idx - 1][0]);
		if (ctx->in_fd < 0)
			return ctx->in_fd;
	} else {
		ctx->in_fd = sh->io.stdin_fd;
	}

	if (ctx->out_is_pipe) {
		ctx->out_fd = shell_dup(pipefds[stage_idx][1]);
		if (ctx->out_fd < 0)
			return ctx->out_fd;
	} else {
		ctx->out_fd = sh->io.stdout_fd;
	}

	ret = cmd_parse_argv(stage_sh);
	if (ret < 0)
		return ret;

	if (stage_sh->argv[0])
		ctx->func = cmd_handler_of(stage_sh->argv[0]);

	return 0;
}

static int pipeline_prepare_stages(struct shell *sh,
	struct shell_pipe_stage *stages, char **segments,
	int stage_count, int (*pipefds)[2])
{
	struct shell_pipe_stage *ctx = NULL;
	int i = 0, j = 0, ret = 0;

	for (i = 0; i < stage_count; i++) {
		ctx = &stages[i];
		ret = pipeline_setup_stage(sh, ctx, segments[i], i, stage_count,
			pipefds, true);
		if (ret < 0)
			goto fail;
	}

	return ret;

fail:
	/* Clean up stages 0 to i (including the partially failed stage) */
	for (j = 0; j <= i; j++)
		pipe_stage_close_fds(&stages[j]);
	return ret;
}

/* Foreground pipeline executor: split, spawn stages, then wait. */
static int shell_exec_pipeline_fg(struct shell *sh)
{
	char *buf = NULL;
	char *segments[MAX_PIPE_STAGES];
	int (*pipefds)[2] = NULL;
	struct shell_pipe_stage *stages = NULL, *ctx = NULL;
	struct shell *stage_shells = NULL;
	int stage_count = 0, i = 0, j = 0, ret = 0;

	buf = shell_malloc(CMD_MAX_LEN);
	if (!buf)
		return -ENOMEM;

	ret = pipeline_split_cmdline(sh, buf, CMD_MAX_LEN, segments, &stage_count);
	if (ret < 0)
		goto cleanup_alloc;
	if (stage_count <= 0)
		goto cleanup_alloc;

	stages = shell_calloc(stage_count, sizeof(*stages));
	stage_shells = shell_calloc(stage_count, sizeof(*stage_shells));
	if (!stages || !stage_shells) {
		ret = -ENOMEM;
		goto cleanup_alloc;
	}

	for (i = 0; i < stage_count; i++)
		stages[i].sh = &stage_shells[i];

	if (stage_count > 1) {
		pipefds = shell_malloc(sizeof(int[2]) * (stage_count - 1));
		if (!pipefds) {
			ret = -ENOMEM;
			goto cleanup_alloc;
		}
		for (i = 0; i < stage_count - 1; i++)
			pipefds[i][0] = pipefds[i][1] = -1;
	}

	/* Create pipes */
	if (stage_count > 1) {
		ret = pipeline_open_pipes(pipefds, stage_count);
		if (ret < 0)
			goto cleanup_fds;
	}

	/* Prepare stage contexts */
	ret = pipeline_prepare_stages(sh, stages, segments, stage_count, pipefds);
	if (ret < 0)
		goto cleanup_fds;

	/* Close the original pipe fds now (stages hold dup'ed fds). */
	pipeline_close_pipefds(pipefds, stage_count);

	/* Start pipeline: builtins in threads, externals spawned in this thread */
	for (i = 0; i < stage_count; i++) {
		ctx = &stages[i];

		if (ctx->func) {
			/* Builtin pipeline stages require concurrent execution (threads). */
			ret = shell_thread_create(&ctx->tid, shell_pipe_stage_thread, ctx);
			if (ret != 0)
				goto cleanup_started;
		} else {
			ret = shell_spawn_pipeline_external_stage(ctx);
			if (ret != 0)
				goto cleanup_started;
		}
		/* close the pipe fds in parent, otherwise the reader will not get EOF */
		pipe_stage_close_fds(ctx);
	}

	/* Wait pipeline stages (Ctrl+C -> SIGINT for the pipeline) */
	ret = shell_wait_pipeline_fg(sh, stages, stage_count);
	goto cleanup_fds;

cleanup_started:
	/*
	 * Some stages started (0 to i-1), some didn't (i to stage_count-1).
	 * Close fds for stages that didn't start.
	 */
	for (j = i; j < stage_count; j++)
		pipe_stage_close_fds(&stages[j]);

	/* Wait for stages that did start */
	if (i > 0)
		shell_wait_pipeline_fg(sh, stages, i);
	goto cleanup_alloc;

cleanup_fds:
	pipeline_close_pipefds(pipefds, stage_count);
	/*
	 * If pipeline_prepare_stages failed, stages may be partially initialized.
	 * If shell_wait_pipeline_fg interrupted by signal, shell may still own the
	 * ends of the pipes.
	 */
	if (stages) {
		for (j = 0; j < stage_count; j++)
			pipe_stage_close_fds(&stages[j]);
	}
cleanup_alloc:
	shell_free(buf);
	shell_free(stages);
	shell_free(stage_shells);
	shell_free(pipefds);
	return ret;
}

static bool cmdline_has_unquoted_char(const char *s, int len, char target)
{
	char quote = 0, c;
	int i;

	for (i = 0; i < len; i++) {
		c = s[i];
		if (quote) {
			if (c == quote)
				quote = 0;
			continue;
		}
		if (c == '\'' || c == '"') {
			quote = c;
			continue;
		}
		if (c == target)
			return true;
	}
	return false;
}

static inline bool cmdline_has_unquoted_pipe(const char *s, int len)
{
	return cmdline_has_unquoted_char(s, len, '|');
}

static inline bool cmdline_has_unquoted_semicolon(const char *s, int len)
{
	return cmdline_has_unquoted_char(s, len, ';');
}

/*
 * Combined metacharacter scan: detect trailing '&', ';', and '|' in one pass.
 * If trailing unquoted '&' is found, strip it and whitespace before it.
 * Returns bitmask of META_* flags.
 */
#define META_SEMICOLON  0x01
#define META_PIPE       0x02
#define META_BACKGROUND 0x04

static unsigned int cmdline_scan_meta(char *s, int *len)
{
	unsigned int flags = 0;
	char quote = 0, c;
	int i, last_non_ws = -1;

	for (i = 0; i < *len; i++) {
		c = s[i];
		if (quote) {
			if (c == quote)
				quote = 0;
			continue;
		}
		if (c == '\'' || c == '"') {
			quote = c;
			continue;
		}
		if (c == ';')
			flags |= META_SEMICOLON;
		else if (c == '|')
			flags |= META_PIPE;
		if (!is_ws(c))
			last_non_ws = i;
	}

	/* Don't strip anything if quotes are unclosed */
	if (quote)
		return flags;

	/* Check for trailing unquoted '&' */
	if (last_non_ws >= 0 && s[last_non_ws] == '&') {
		flags |= META_BACKGROUND;
		*len = last_non_ws;
		while (*len > 0 && is_ws(s[*len - 1]))
			(*len)--;
		s[*len] = '\0';
	}

	return flags;
}

/*
 * Handle output redirection: > (overwrite) and >> (append)
 * Scans argv for redirection operators and sets up file output.
 * Returns: fd of opened file (caller must close), or -1 if no redirection.
 * On error, returns -2 and prints error message.
 * Modifies argc to exclude redirection operator and filename.
 */
static int cmd_setup_redirect(struct shell *sh)
{
	int i = 0, fd = -1, flags = (O_WRONLY | O_CREAT);
	const char *filename = NULL;
	char filepath[SHELL_PATH_MAX];
	bool append = false;

	for (i = 1; i < sh->argc; i++) {
		if (strcmp(sh->argv[i], ">") == 0) {
			if (i + 1 >= sh->argc) {
				shmsg_err(sh, "syntax error: missing filename after >\n");
				return -2;
			}
			filename = sh->argv[i + 1];
			append = false;
			sh->argc = i;
			break;
		} else if (strcmp(sh->argv[i], ">>") == 0) {
			if (i + 1 >= sh->argc) {
				shmsg_err(sh, "syntax error: missing filename after >>\n");
				return -2;
			}
			filename = sh->argv[i + 1];
			append = true;
			sh->argc = i;
			break;
		} else if (sh->argv[i][0] == '>' && sh->argv[i][1] != '\0') {
			if (sh->argv[i][1] == '>') {
				filename = &sh->argv[i][2];
				append = true;
			} else {
				filename = &sh->argv[i][1];
				append = false;
			}
			if (*filename == '\0') {
				shmsg_err(sh, "syntax error: missing filename\n");
				return -2;
			}
			sh->argc = i;
			break;
		}
	}

	if (!filename)
		return -1;

	filename = shell_abspath(sh, filename, filepath, sizeof(filepath));
	flags |= append ? O_APPEND : O_TRUNC;
	fd = shell_open(filename, flags, 0644);
	if (fd < 0) {
		shmsg_err(sh, "%s: cannot open for writing\n", filename);
		return -2;
	}

	return fd;
}

static void cmd_runapp(struct shell *sh)
{
	int ret = 0;

	if (sh->argv[0]) {
		ret = cmd_runapp_argv(sh, sh->argv);
		if (ret < 0)
			shell_print_exec_error(sh, sh->argv[0], ret);
	}
}

static int cmd_run_foreground_builtin(struct shell *sh,
	cmd_handler func)
{
	struct shell_pipe_stage *ctx = NULL;
	struct pollfd pfds[1];
	char inbuf[64];
	ssize_t rdbytes = 0;
	int i = 0, signo = 0;
	int echo_fd = -1, ret = 0;
	shell_tid_t tid = 0;

	ctx = shell_calloc(1, sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;

	ctx->sh = sh;
	ctx->func = func;
	ctx->in_fd = sh->io.stdin_fd;
	ctx->out_fd = sh->io.stdout_fd;
	ctx->free_on_finish = 0;

	echo_fd = sh->tty_fd;
	if (sh->fg_builtin_new_thread) {
		ret = shell_thread_create(&tid, shell_pipe_stage_thread, ctx);
		if (ret != 0) {
			shell_free(ctx);
			return ret;
		}
		shell_thread_detach(tid);
	} else {
		ret = shell_fg_builtin_enqueue(ctx);
		if (ret != 0) {
			shell_free(ctx);
			return ret;
		}
		tid = shell_fg_builtin_tid;
	}

	pfds[0].fd = sh->tty_fd;
	pfds[0].events = POLLIN;

	while (!__atomic_load_n(&ctx->done, __ATOMIC_ACQUIRE)) {
		/* thread aborted ? */
		if (shell_thread_detach(tid) == -ESRCH)
			break;

		ret = poll(pfds, 1, 50);
		if (ret <= 0)
			continue;

		if ((pfds[0].revents & POLLIN) == 0)
			continue;

		rdbytes = shell_read(sh->tty_fd, inbuf, sizeof(inbuf));
		if (rdbytes <= 0)
			continue;

		for (i = 0; i < rdbytes; i++) {
			signo = shell_ctrl_to_signo(inbuf[i]);
			if (signo != 0) {
				sh->stop_request = 1;
				continue;
			}
			shell_echo_and_buffer_typeahead(sh, echo_fd, inbuf[i]);
		}
	}

	if (sh->fg_builtin_new_thread)
		shell_thread_join(tid);
	shell_free(ctx);
	return 0;
}

/* Foreground single command line executor (builtin or external). */
static int shell_exec_single_cmdline(struct shell *sh)
{
	cmd_handler func = NULL;
	int ret = 0, redir_fd = -1;

	shell_sanitize_cmdline(sh);

	/*
	 * Ensure any buffered output from previous commands is emitted before
	 * running this command (external programs write directly to stdout).
	 */
	shmsg_flush(sh);

	/* Handle pipelines first (built-ins and external apps) */
	if (cmdline_has_unquoted_pipe(sh->cmdline, sh->cmdline_len)) {
		ret = shell_exec_pipeline_fg(sh);
		goto cleanup;
	}

	ret = cmd_parse_argv(sh);
	if (ret < 0) {
		shmsg_err(sh, "parse argv failed: %d\n", ret);
		goto cleanup;
	}

	/* Handle output redirection */
	redir_fd = cmd_setup_redirect(sh);
	if (redir_fd == -2) {
		/* Redirection failed, skip command execution */
		goto cleanup;
	}
	if (redir_fd >= 0) {
		/* Redirect output to file */
		shmsg_flush(sh);
		sh->saved_io = sh->io;
		sh->io.stdout_fd = redir_fd;
	}

	if (sh->argc > 0) {
		func = cmd_handler_of(sh->argv[0]);
		if (func) {
			/*
			 * Foreground builtins must remain interruptible (Ctrl+C/typeahead).
			 * Run builtin in a worker thread so the UI thread can keep polling tty.
			 */
			ret = cmd_run_foreground_builtin(sh, func);
		} else {
			cmd_runapp(sh);
		}
	}

	/* Restore output and close redirect file */
	if (redir_fd >= 0) {
		shmsg_flush(sh);
		sh->io = sh->saved_io;
		shell_close(redir_fd);
	}

cleanup:
	return ret;
}

static int cmd_execute_semicolon_list(struct shell *sh)
{
	char *buf = NULL;
	char *segments[MAX_SEMICOLON_COMMANDS];
	int seg_count = 0, i = 0, ret = 0, cmd_len = 0;
	char quote = 0;
	char *seg = NULL;

	buf = shell_malloc(CMD_MAX_LEN);
	if (!buf)
		return -ENOMEM;

	shell_sanitize_cmdline(sh);
	cmd_len = sh->cmdline_len;
	if (cmd_len >= CMD_MAX_LEN)
		cmd_len = CMD_MAX_LEN - 1;
	memcpy(buf, sh->cmdline, cmd_len);
	buf[cmd_len] = '\0';

	cmdline_split_unquoted_inplace(buf, cmd_len, ';',
		segments, MAX_SEMICOLON_COMMANDS, &seg_count, NULL, &quote);

	if (quote) {
		shmsg_err(sh, "syntax error: unclosed quote\n");
		ret = -EINVAL;
		goto out;
	}

	if (seg_count >= MAX_SEMICOLON_COMMANDS) {
		shmsg_err(sh, "semicolon: too many commands (max %d)\n",
			MAX_SEMICOLON_COMMANDS);
		ret = -E2BIG;
		goto out;
	}

	for (i = 0; i < seg_count; i++) {
		seg = trim_ws_inplace(segments[i]);
		if (seg[0] == '\0') {
			shmsg_err(sh, "syntax error near unexpected token ';'\n");
			ret = -EINVAL;
			goto out;
		}

		/* Execute each segment by copying into sh->cmdline (parser mutates it). */
		strlcpy(sh->cmdline, seg, sizeof(sh->cmdline));
		sh->cmdline_len = strlen(sh->cmdline);
		ret = shell_exec_single_cmdline(sh);
	}

out:
	shell_free(buf);
	return ret;
}

/* Background pipeline executor: spawn stages under job manager. */
static int shell_spawn_pipeline_bg_job(struct shell *sh,
	struct shell_job *job)
{
	char *buf = NULL;
	char *segments[MAX_PIPE_STAGES];
	int (*pipefds)[2] = NULL;
	struct shell_pipe_stage *builtins[MAX_PIPE_STAGES] = {0};
	struct shell_pipe_stage *ctx = NULL;
	int stage_count = 0, i = 0;
	int builtins_cnt = 0, ret = 0;
	int stages_setup = 0;
	size_t buflen = 0;

	buflen = job->cmdline_len + 1;
	if (buflen > CMD_MAX_LEN)
		buflen = CMD_MAX_LEN;

	buf = shell_malloc(buflen);
	if (!buf) {
		ret = -ENOMEM;
		goto cleanup_alloc;
	}

	ret = pipeline_split_cmdline(sh, buf, buflen, segments, &stage_count);
	if (ret < 0)
		goto cleanup_alloc;
	if (stage_count <= 0)
		goto cleanup_alloc;

	if (stage_count > 1) {
		pipefds = shell_malloc(sizeof(int[2]) * (stage_count - 1));
		if (!pipefds) {
			ret = -ENOMEM;
			goto cleanup_alloc;
		}

		for (i = 0; i < stage_count - 1; i++)
			pipefds[i][0] = pipefds[i][1] = -1;

		ret = pipeline_open_pipes(pipefds, stage_count);
		if (ret < 0)
			goto cleanup_fds;
	}

	job->stage_count = stage_count;
	job->stages_left = stage_count;

	/*
	 * Spawn / prepare each stage.
	 *
	 * Important: do NOT enqueue builtin stages until the whole pipeline is
	 * successfully set up, otherwise an early return would free job while
	 * queued tasks still reference it (use-after-free).
	 */
	for (i = 0; i < stage_count; i++) {
		ctx = shell_calloc(1, sizeof(*ctx) + sizeof(struct shell));
		if (!ctx) {
			ret = -ENOMEM;
			break;
		}
		ctx->sh = (struct shell *)(ctx + 1);
		ret = pipeline_setup_stage(sh, ctx, segments[i], i, stage_count,
			pipefds, false);
		if (ret < 0) {
			pipe_stage_close_fds(ctx);
			shell_free(ctx);
			break;
		}

		if (!ctx->func) {
			ret = shell_spawn_pipeline_external_stage(ctx);
			/* close the pipe fds in parent, otherwise the reader will not get EOF */
			pipe_stage_close_fds(ctx);
			if (ret != 0) {
				shell_free(ctx);
				break;
			}
			job->pids[i] = ctx->pid;
			shell_free(ctx);
			ctx = NULL;
		} else {
			/* close the pipe fds in parent, otherwise the reader will not get EOF */
			pipe_stage_close_fds(ctx);
			/* Builtin stage: keep ctx around for thread launch later */
			ctx->job = job;
			ctx->stage_idx = i;
			ctx->free_on_finish = 1;
			builtins[builtins_cnt++] = ctx;
			ctx = NULL;
		}
		stages_setup++;
	}

	pipeline_close_pipefds(pipefds, stage_count);

	if (ret != 0) {
		/* Free any builtin contexts we allocated but haven't launched */
		pipe_stage_free_range(builtins, 0, builtins_cnt);

		if (stages_setup > 0) {
			/*
			 * Some stages started successfully. Mark job as failed
			 * and let jobmgr handle cleanup of running processes.
			 */
			shell_job_fail_drop(job, ret, stage_count - stages_setup, false);
			ret = 0; /* Job is queued, don't return error */
		}
		goto cleanup_alloc;
	}

	/* Launch builtin stages: background pipeline uses one thread per stage. */
	for (i = 0; i < builtins_cnt; i++) {
		shell_tid_t tid = 0;

		ret = shell_thread_create(&tid, shell_pipe_stage_thread, builtins[i]);
		if (ret != 0)
			break;

		shell_thread_detach(tid);
		builtins[i] = NULL; /* Ownership transferred to thread */
	}

	if (ret != 0) {
		/*
		 * Thread creation failed for some builtins. External stages
		 * may already be running. Mark job failed and free unstarted
		 * builtin contexts.
		 */
		int not_launched = builtins_cnt - i;

		shell_job_fail_drop(job, ret, not_launched, true);
		pipe_stage_free_range(builtins, i, builtins_cnt);
	}
	ret = 0;
	goto cleanup_alloc;

cleanup_fds:
	pipeline_close_pipefds(pipefds, stage_count);

cleanup_alloc:
	shell_free(buf);
	shell_free(pipefds);
	return ret;
}

static struct shell_job *shell_jobmgr_dequeue(void)
{
	struct shell_job *job = NULL;

	shell_jobmgr_lock_enter();
	job = list_first_entry_or_null(&shell_jobmgr_q,
		struct shell_job, node);
	if (job)
		list_del(&job->node);
	shell_jobmgr_lock_exit();
	return job;
}

static void shell_jobmgr_job_free(struct shell_job *job)
{
	if (job->owned_stdin_fd >= 0)
		shell_close(job->owned_stdin_fd);
	shell_free(job);
}

static int shell_jobmgr_do_job(struct shell_job *job)
{
	struct shell *sh = NULL;
	cmd_handler func = NULL;
	pid_t pid = -1;
	int ret = 0;
	bool queued = false;

	sh = shell_calloc(1, sizeof(*sh));
	if (!sh) {
		shell_jobmgr_job_free(job);
		return -ENOMEM;
	}

	sh->tty_fd = -1;
	sh->io = job->io;
	sh->saved_io = job->io;
	strlcpy(sh->cwd, job->cwd, sizeof(sh->cwd));
	strlcpy(sh->cmdline, job->cmdline, sizeof(sh->cmdline));
	sh->cmdline_len = job->cmdline_len;
	sh->term_width = job->term_width;

	if (cmdline_has_unquoted_semicolon(sh->cmdline, sh->cmdline_len)) {
		ret = cmd_execute_semicolon_list(sh);
		goto out;
	}

	if (job->is_pipeline) {
		ret = shell_spawn_pipeline_bg_job(sh, job);
		if (ret == 0) {
			list_add_tail(&job->node, &shell_jobmgr_run);
			queued = true;
		}
		goto out;
	}

	ret = cmd_parse_argv(sh);
	if (ret < 0)
		goto out;

	func = cmd_handler_of(sh->argv[0]);
	if (func) {
		/* Background builtins: run inline (stdin is /dev/null). */
		func(sh);
		goto out;
	}

	ret = cmd_spawnapp_argv(sh, sh->argv, &pid);
	if (ret == 0) {
		job->pid = pid;
		list_add_tail(&job->node, &shell_jobmgr_run);
		queued = true;
	}

out:
	shell_free(sh);
	if (!queued)
		shell_jobmgr_job_free(job);
	return ret;
}

static void shell_jobmgr_reap_running(void)
{
	struct shell_job *job = NULL;
	struct shell_job *next = NULL;
	pid_t r = 0;
	int status = 0, i = 0, idx = 0;
	bool done = false;
	int cleared[MAX_PIPE_STAGES] = {0};
	int cleared_cnt = 0, last_idx = -1, last_status = 0;

	list_for_each_entry_safe(job, next, &shell_jobmgr_run, node) {
		if (job->is_pipeline) {
			cleared_cnt = 0;
			last_idx = -1;
			for (i = 0; i < job->stage_count; i++) {
				if (job->pids[i] <= 0)
					continue;
				r = shell_waitpid_raw(job->pids[i], &status, WNOHANG);
				if (r != 0) {
					if (cleared_cnt < MAX_PIPE_STAGES)
						cleared[cleared_cnt++] = i;
					if (i == job->stage_count - 1) {
						last_idx = i;
						last_status = (r < 0) ? r : status;
					}
				}
			}
			shell_jobmgr_lock_enter();
			if (cleared_cnt > 0 || last_idx >= 0) {
				for (i = 0; i < cleared_cnt; i++) {
					idx = cleared[i];
					if (job->pids[idx] > 0) {
						job->pids[idx] = 0;
						job->stages_left--;
						if (idx == last_idx)
							job->status = last_status;
					}
				}
			}
			done = (job->stages_left <= 0);
			shell_jobmgr_lock_exit();
		} else {
			r = shell_waitpid_raw(job->pid, &status, WNOHANG);
			if (r != 0) {
				shell_jobmgr_lock_enter();
				job->status = (r < 0) ? r : status;
				done = true;
				shell_jobmgr_lock_exit();
			}
		}

		if (done) {
			done = false;
			list_del(&job->node);
			shell_jobmgr_job_free(job);
		}
	}
}

/*
 * Thread: background job manager
 *
 * Purpose:
 * - Owns background job lifecycle:
 *     - dequeues jobs from shell_jobmgr_q and starts them
 *     - periodically reaps running external processes (WNOHANG)
 * - Background pipelines may include builtin stages; those builtin stages run
 *   as one thread per stage (shell_pipe_stage_thread).
 *
 * Lifetime:
 * - Spawned on demand by shell_jobmgr_start().
 * - Exits after being idle for ~10s (no pending/running jobs).
 */
static long shell_jobmgr_thread(void *arg)
{
	struct shell_job *job = NULL;
	int timeout = 0, busy = 0;
	int idle_ms = 0, did_work = 0;

	for (;;) {
		did_work = 0;
		while ((job = shell_jobmgr_dequeue()) != NULL) {
			shell_jobmgr_do_job(job);
			did_work = 1;
		}

		shell_jobmgr_reap_running();

		busy = (!list_empty(&shell_jobmgr_q)) ||
			(!list_empty(&shell_jobmgr_run));

		timeout = busy ? 100 : 300;
		if (busy || did_work)
			idle_ms = 0;
		else {
			idle_ms += timeout;
			if (idle_ms >= 10000) {
				shell_jobmgr_lock_enter();
				busy = (!list_empty(&shell_jobmgr_q)) ||
					(!list_empty(&shell_jobmgr_run));
				if (!busy)
					shell_jobmgr_started = 0;
				shell_jobmgr_lock_exit();
				if (!busy)
					break;
			}
		}

		poll(NULL, 0, timeout);
	}

	return 0;
}

static int shell_jobmgr_thread_start(void)
{
	int ret = 0;
	shell_tid_t tid = 0;

	if (shell_jobmgr_started)
		return 0;

	ret = shell_thread_create(&tid, shell_jobmgr_thread, NULL);
	if (ret != 0)
		return ret;

	shell_jobmgr_started = 1;

	shell_thread_detach(tid);
	return 0;
}

static int shell_jobmgr_enqueue(struct shell_job *job)
{
	int ret = 0;

	shell_jobmgr_lock_enter();
	ret = shell_jobmgr_thread_start();
	if (ret == 0)
		list_add_tail(&job->node, &shell_jobmgr_q);
	shell_jobmgr_lock_exit();

	return ret;
}

static int shell_start_background(struct shell *sh, const char *cmdline, int cmdline_len)
{
	struct shell_job *job = NULL;
	char *blk = NULL;
	size_t cwd_len = 0, cmd_len = 0;
	int ret = 0, nullfd = -1;
	bool is_pipe = false;

	/* Pipelines are handled by the background job-manager. */
	is_pipe = cmdline_has_unquoted_pipe(cmdline, cmdline_len);

	cwd_len = strlen(sh->cwd);
	cmd_len = cmdline_len;
	if (cmd_len >= CMD_MAX_LEN)
		cmd_len = CMD_MAX_LEN - 1;

	blk = shell_calloc(1, sizeof(*job) + cwd_len + 1 + cmd_len + 1);
	if (!blk)
		return -ENOMEM;

	job = (struct shell_job *)blk;
	job->cwd = blk + sizeof(*job);
	job->cmdline = blk + sizeof(*job) + cwd_len + 1;
	memcpy((char *)job->cwd, sh->cwd, cwd_len);
	((char *)job->cwd)[cwd_len] = '\0';
	memcpy((char *)job->cmdline, cmdline, cmd_len);
	((char *)job->cmdline)[cmd_len] = '\0';

	shell_job_init(job, sh, is_pipe, cmd_len);

	/*
	 * Prefer /dev/null as background stdio to avoid stealing keystrokes
	 * and to prevent background output from blocking prompt rendering.
	 */
	nullfd = shell_open("/dev/null", O_RDWR);
	if (nullfd < 0) {
		shell_free(job);
		return nullfd;
	}
	job->io.stdin_fd = nullfd;
	job->owned_stdin_fd = nullfd;

	ret = shell_jobmgr_enqueue(job);
	if (ret < 0) {
		shell_free(job);
		shell_close(nullfd);
	}

	return ret;
}

/*
 * Clear current command line from display and reset cursor.
 * Uses a safe approach: move to start of line, clear to end of screen,
 * then rewrite the prompt.
 */
static void cmdline_clear(struct shell *sh)
{
	int lines_up = 0;

	if (sh->cmdline_len == 0) {
		sh->cursor = 0;
		return;
	}

	/*
	 * If the command wraps to multiple terminal lines, move the
	 * cursor up to the prompt line first, otherwise \r\033[J only
	 * clears the current line downward and leaves stale text above.
	 */
	lines_up = (sh->cursor + SHELL_PROMPT_LEN) / sh->term_width;
	if (lines_up > 0) {
		char buf[10];
		int len = snprintf(buf, sizeof(buf), "\033[%dA",
				lines_up);

		shmsg_raw(sh, buf, len);
	}

	shmsg_raw(sh, "\r\033[J" SHELL_PROMPT, 1 + 3 + SHELL_PROMPT_LEN);

	sh->cmdline_len = 0;
	sh->cursor = 0;
	sh->term_col = SHELL_PROMPT_LEN;
}

/*
 * Replace current command line with history entry and display.
 */
static void cmdline_set(struct shell *sh, struct shell_history_ent *h)
{
	struct shell_history *hist;
	int len;

	hist = sh->history;
	if (hist && h && h->len != 0) {
		len = h->len;
		if (len >= (int)sizeof(sh->cmdline))
			len = sizeof(sh->cmdline) - 1;
		memcpy(sh->cmdline, &hist->buf[h->off], len);
		sh->cmdline[len] = 0;
		sh->cmdline_len = len;
		sh->cursor = len;
		shmsg_puts(sh, sh->cmdline, sh->cmdline_len);
	} else {
		sh->cmdline[0] = 0;
		sh->cmdline_len = 0;
	}
}

static void history_navigate(struct shell *sh, int dir)
{
	struct shell_history *hist;
	int cnt, pos;
	struct shell_history_ent *h;

	hist = sh->history;
	if (!hist || hist->ent_cnt == 0)
		return;

	pos = hist->ent_nav;
	h = NULL;

	if (dir > 0 && pos == hist->ent_wr)
		return;

	for (cnt = 0; cnt < CMD_HISTORY_ENT_MAX; cnt++) {
		if (dir > 0) {
			pos = (pos + 1) % CMD_HISTORY_ENT_MAX;
			if (pos == hist->ent_wr)
				break;
		} else {
			pos = (pos == 0) ? CMD_HISTORY_ENT_MAX - 1 : pos - 1;
		}

		h = &hist->ent[pos];
		if (h->len != 0)
			break;
	}

	if (dir < 0 && (!h || h->len == 0))
		return;

	hist->ent_nav = pos;
	cmdline_clear(sh);
	cmdline_set(sh, (dir > 0 && pos == hist->ent_wr) ? NULL : h);
}

/*
 * Navigate to previous command in history (Up arrow key).
 */
static void key_up(struct shell *sh)
{
	history_navigate(sh, -1);
}

/*
 * Navigate to next command in history (Down arrow key).
 */
static void key_down(struct shell *sh)
{
	history_navigate(sh, 1);
}

static void cmdline_delete_range(struct shell *sh, int start, int end)
{
	int del_len = 0;
	int tail_len = 0;

	if (start < 0 || end < 0 || start >= end)
		return;
	if (end > sh->cmdline_len)
		return;

	del_len = end - start;

	if (sh->cursor > start) {
		shmsg_back_n(sh, sh->cursor - start);
		sh->cursor = start;
	}

	tail_len = sh->cmdline_len - end;
	memmove(&sh->cmdline[start], &sh->cmdline[end], tail_len + 1);
	sh->cmdline_len -= del_len;

	if (tail_len > 0)
		shmsg_puts(sh, &sh->cmdline[start], tail_len);
	/* Clear residual characters from the old (longer) content */
	shmsg_raw(sh, "\033[J", 3);
	shmsg_back_n(sh, tail_len);
}

/*
 * Delete the character before cursor (Backspace key).
 */
static void key_backspace(struct shell *sh)
{
	if (sh->cursor == 0)
		return;
	cmdline_delete_range(sh, sh->cursor - 1, sh->cursor);
}

/*
 * Delete the character at cursor position (Delete key).
 */
static void key_delete(struct shell *sh)
{
	if (sh->cursor >= sh->cmdline_len)
		return;
	cmdline_delete_range(sh, sh->cursor, sh->cursor + 1);
}

/*
 * Cancel current input (Ctrl+C).
 * Clears the command buffer and starts a new prompt line.
 */
static void key_ctrlc(struct shell *sh)
{
	sh->cmdline[0] = 0;
	sh->cmdline_len = 0;
	sh->cursor = 0;
	sh->stop_request = 1;
	shmsg_putc(sh, '\n');
	shmsg_raw(sh, SHELL_PROMPT, SHELL_PROMPT_LEN);
	sh->term_col = SHELL_PROMPT_LEN;
}

/*
 * Move cursor one position left (Left arrow key).
 */
static void key_left(struct shell *sh)
{
	if (sh->cursor > 0) {
		sh->cursor--;
		shmsg_back(sh);
	}
}

/*
 * Move cursor one position right (Right arrow key).
 */
static void key_right(struct shell *sh)
{
	if (sh->cursor < sh->cmdline_len) {
		shmsg_putc(sh, sh->cmdline[sh->cursor]);
		sh->cursor++;
	}
}

/* Move cursor to beginning of line (Home / Ctrl+A) */
static void key_home(struct shell *sh)
{
	char buf[20];
	char *p = NULL;
	int lines_up;

	if (sh->cursor == 0)
		return;

	/*
	 * Calculate how many wrapped lines the cursor is below the prompt.
	 * Each character from the prompt start consumes one column; wrapping
	 * occurs every term_width columns.
	 */
	lines_up = (sh->cursor + SHELL_PROMPT_LEN) / sh->term_width;
	p = buf;
	*p++ = '\r';
	if (lines_up > 0)
		p += snprintf(p, sizeof(buf) - 1, "\033[%dA", lines_up);
	p += snprintf(p, buf + sizeof(buf) - p, "\033[%dG",
		SHELL_PROMPT_LEN + 1);
	shmsg_raw(sh, buf, p - buf);
	sh->term_col = SHELL_PROMPT_LEN;
	sh->cursor = 0;
}

/* Move cursor to end of line (End / Ctrl+E) */
static void key_end(struct shell *sh)
{
	if (sh->cursor < sh->cmdline_len) {
		/* Write remaining chars to move cursor to end */
		shmsg_puts(sh, &sh->cmdline[sh->cursor],
			sh->cmdline_len - sh->cursor);
		sh->cursor = sh->cmdline_len;
	}
}

/* Delete word before cursor (Ctrl+W) */
static void key_delete_word(struct shell *sh)
{
	int start;

	if (sh->cursor == 0)
		return;

	/* Work from current cursor */
	start = sh->cursor;

	/* Skip trailing spaces before cursor */
	while (start > 0 && is_ws(sh->cmdline[start - 1]))
		start--;

	/* Find start of word */
	while (start > 0 && !is_ws(sh->cmdline[start - 1]))
		start--;

	if (start == sh->cursor)
		return;

	cmdline_delete_range(sh, start, sh->cursor);
}

/*
 * Insert text at cursor position.
 * Handles both cursor at end and cursor in middle of line.
 * Returns number of characters inserted, or 0 if buffer full.
 */
static int insert_text_at_cursor(struct shell *sh,
	const char *text, int len)
{
	int tail_len;

	shell_sanitize_cmdline(sh);

	if (sh->cmdline_len + len >= sizeof(sh->cmdline))
		return 0;

	tail_len = sh->cmdline_len - sh->cursor;

	/* Make room: move tail right */
	if (tail_len > 0)
		memmove(&sh->cmdline[sh->cursor + len],
			&sh->cmdline[sh->cursor], tail_len + 1);

	/* Insert new text */
	memcpy(&sh->cmdline[sh->cursor], text, len);
	sh->cmdline_len += len;
	sh->cmdline[sh->cmdline_len] = '\0';

	/* Update display: output new text + tail, then move cursor back */
	shmsg_puts(sh, text, len);
	if (tail_len > 0) {
		shmsg_puts(sh, &sh->cmdline[sh->cursor + len], tail_len);
		shmsg_back_n(sh, tail_len);
	}

	sh->cursor += len;
	return len;
}

/*
 * Check if a character needs escaping in shell.
 * Returns true for characters that have special meaning: space, quotes, etc.
 */
static inline bool shell_needs_escape(char c)
{
	return (c == ' ' || c == '\t' || c == '\'' || c == '"' ||
	        c == '\\' || c == ';' || c == '&' || c == '|' ||
	        c == '(' || c == ')' || c == '<' || c == '>' ||
	        c == '$' || c == '`' || c == '*' || c == '?' ||
	        c == '[' || c == ']' || c == '!' || c == '#');
}

/*
 * Safely insert filename into command line with escaping.
 * Returns number of characters inserted, or 0 if buffer full.
 */
static int insert_escaped_filename(struct shell *sh, const char *name, int len)
{
	int i;
	bool has_special = false;
	char escaped[512];
	int esc_len = 0;
	int limit = sizeof(escaped) - 5;

	for (i = 0; i < len; i++) {
		if (shell_needs_escape(name[i])) {
			has_special = true;
			break;
		}
	}

	if (!has_special)
		return insert_text_at_cursor(sh, name, len);

	escaped[esc_len++] = '\'';
	for (i = 0; i < len && esc_len < limit; i++) {
		if (name[i] == '\'') {
			escaped[esc_len++] = '\'';
			escaped[esc_len++] = '\\';
			escaped[esc_len++] = '\'';
			escaped[esc_len++] = '\'';
		} else {
			escaped[esc_len++] = name[i];
		}
	}
	escaped[esc_len++] = '\'';

	return insert_text_at_cursor(sh, escaped, esc_len);
}

/*
 * Tab completion (Tab key).
 * Completes built-in commands and file paths.
 * - If input is empty or first word: complete command names
 * - Otherwise: complete file/directory paths
 */
/* Helper: Add trailing slash for directory */
static inline void add_directory_slash(struct shell *sh)
{
	insert_text_at_cursor(sh, "/", 1);
}

/* Helper: Complete a single match with optional trailing slash for directories */
static void complete_single_match(struct shell *sh,
	const char *completion, int prefix_len, bool is_dir)
{
	int to_add = strlen(completion) - prefix_len;

	if (to_add == 0) {
		if (is_dir)
			add_directory_slash(sh);
	} else if (to_add > 0 && insert_escaped_filename(sh,
			&completion[prefix_len], to_add) > 0) {
		if (is_dir)
			add_directory_slash(sh);
	}
}

/* Helper: scan directory matches and compute common prefix in one pass */
static int scan_dir_matches(DIR *dir, const char *basename_part, int base_len,
	char *first_match, size_t first_size, bool *first_is_dir,
	char *common_name, size_t common_size, int *common_len_out,
	bool *exact_dir_match, bool *completed_is_dir)
{
	struct dirent *d = NULL;
	int common_len = -1, match_count = 0;
	int new_common, j, scan_count = 0;
	size_t len;

	*exact_dir_match = false;
	*completed_is_dir = false;
	if (common_len_out)
		*common_len_out = -1;

	while ((d = readdir(dir)) != NULL) {
		if (strncmp(d->d_name, basename_part, base_len) != 0)
			continue;

		if (++scan_count > 1000) {
			common_len = base_len;
			break;
		}

		match_count++;
		len = strlen(d->d_name);

		if (match_count == 1) {
			strlcpy(first_match, d->d_name, first_size);
			*first_is_dir = (d->d_type == DT_DIR);
		}

		if (len == base_len && d->d_type == DT_DIR)
			*exact_dir_match = true;

		if (common_len < 0) {
			common_len = len;
			strlcpy(common_name, d->d_name, common_size);
			*completed_is_dir = (d->d_type == DT_DIR);
		} else {
			new_common = common_len < (int)len ? common_len : (int)len;
			for (j = base_len; j < new_common; j++) {
				if (d->d_name[j] != common_name[j]) {
					common_len = j;
					*completed_is_dir = false;
					break;
				}
			}
			if (common_len > new_common) {
				common_len = new_common;
				*completed_is_dir = false;
			}
		}

		if (common_len == (int)len && strcmp(d->d_name, common_name) == 0)
			*completed_is_dir = (d->d_type == DT_DIR);
	}

	if (common_len_out)
		*common_len_out = common_len;
	return match_count;
}

/* Helper: Complete command (first word) */
static void complete_command(struct shell *sh,
	const char *prefix, int prefix_len)
{
	size_t len;
	int match_count = 0;
	const char *completion = NULL;
	int limit, to_add, i, j, common_len = -1;
	int saved_cursor = 0;

	/* Count matches and find common prefix */
	for (i = 0; cmd_handlers[i].cmd; i++) {
		const char *cmd = cmd_handlers[i].cmd;
		if (strncmp(cmd, prefix, prefix_len) != 0)
			continue;
		match_count++;
		len = strlen(cmd);
		if (common_len < 0) {
			common_len = len;
			completion = cmd;
			continue;
		}
		limit = common_len < len ? common_len : len;
		for (j = prefix_len; j < limit; j++) {
			if (cmd[j] != completion[j]) {
				common_len = j;
				break;
			}
		}
		if (common_len > limit)
			common_len = limit;
	}

	if (match_count == 0)
		return;

	if (match_count == 1) {
		to_add = common_len - prefix_len;
		if (insert_text_at_cursor(sh, &completion[prefix_len], to_add) > 0)
			insert_text_at_cursor(sh, " ", 1);
		return;
	}

	if (common_len > prefix_len) {
		to_add = common_len - prefix_len;
		insert_text_at_cursor(sh, &completion[prefix_len], to_add);
		return;
	}

	/* Show all matches */
	saved_cursor = sh->cursor;
	shmsg(sh, "\n");
	for (i = 0; cmd_handlers[i].cmd; i++) {
		if (strncmp(cmd_handlers[i].cmd, prefix, prefix_len) == 0)
			shmsg(sh, "%s  ", cmd_handlers[i].cmd);
	}
	shmsg(sh, "\n" SHELL_PROMPT "%s", sh->cmdline);
	shmsg_flush(sh);
	/* Move cursor back to original position */
	shmsg_back_n(sh, sh->cmdline_len - saved_cursor);
}

/* Helper: Parse path and get directory + basename for completion */
static void parse_completion_path(struct shell *sh,
	const char *prefix, int prefix_len,
	char *dirpath, size_t dirpath_size,
	char *basename_buf, size_t basename_size)
{
	char path[SHELL_PATH_MAX];
	char temp[SHELL_PATH_MAX];
	const char *dirname_part = NULL;
	const char *basename_part = NULL;
	bool is_abs = false;
	size_t plen;

	if (prefix_len == 0) {
		strlcpy(dirpath, sh->cwd, dirpath_size);
		basename_buf[0] = '\0';
		return;
	}

	strlcpy(path, prefix, min((size_t)prefix_len + 1, sizeof(path)));
	path[prefix_len] = '\0';
	is_abs = (path[0] == '/');

	/* Handle trailing slash */
	plen = strlen(path);
	if (plen > 1 && path[plen - 1] == '/') {
		path[plen - 1] = '\0';
		if (is_abs)
			strlcpy(dirpath, path, dirpath_size);
		else
			shell_realpath(sh, path, dirpath, dirpath_size);
		basename_buf[0] = '\0';
		return;
	}

	/* Split into dirname and basename */
	if (strchr(path, '/')) {
		strlcpy(temp, path, sizeof(temp));
		dirname_part = shell_dirname(temp);
		basename_part = shell_basename(path);

		strlcpy(basename_buf, basename_part, basename_size);

		if (*dirname_part == '\0' || strcmp(dirname_part, ".") == 0) {
			strlcpy(dirpath, is_abs ? "/" : sh->cwd, dirpath_size);
		} else if (is_abs) {
			strlcpy(dirpath, dirname_part, dirpath_size);
		} else {
			shell_realpath(sh, dirname_part, dirpath, dirpath_size);
		}
	} else {
		strlcpy(dirpath, sh->cwd, dirpath_size);
		strlcpy(basename_buf, path, basename_size);
	}
}

/* Helper: Complete path (argument) */
static void complete_path(struct shell *sh,
	const char *prefix, int prefix_len)
{
	char dirpath[SHELL_PATH_MAX];
	char basename_part[NAME_MAX];
	char match_name[NAME_MAX];
	char common_name[NAME_MAX];
	DIR *dir = NULL;
	struct dirent *d = NULL;
	int match_count = 0, base_len;
	bool match_is_dir = false;
	bool exact_dir_match, completed_is_dir;
	int common_len, to_add, displayed;
	const int MAX_DISPLAY = 1000;
	int saved_cursor = 0;

	parse_completion_path(sh, prefix, prefix_len, dirpath,
		sizeof(dirpath), basename_part, sizeof(basename_part));

	base_len = strlen(basename_part);
	dir = opendir(dirpath);
	if (!dir)
		return;
	match_count = scan_dir_matches(dir, basename_part, base_len,
		match_name, sizeof(match_name), &match_is_dir,
		common_name, sizeof(common_name), &common_len,
		&exact_dir_match, &completed_is_dir);

	if (match_count == 1) {
		complete_single_match(sh, match_name, base_len, match_is_dir);
		goto out_close;
	}

	if (match_count <= 1)
		goto out_close;

	if (common_len > base_len) {
		to_add = common_len - base_len;
		if (sh->cmdline_len + to_add < sizeof(sh->cmdline) - 1)
			insert_text_at_cursor(sh, &common_name[base_len], to_add);
		goto out_close;
	}

	/* Show all matches */
	saved_cursor = sh->cursor;
	shmsg(sh, "\n");
	rewinddir(dir);
	displayed = 0;
	while ((d = readdir(dir)) != NULL) {
		if (strncmp(d->d_name, basename_part, base_len) == 0) {
			if (displayed++ >= MAX_DISPLAY) {
				shmsg(sh, "\n... (%d+ files truncated)", MAX_DISPLAY);
				break;
			}
			shmsg(sh, "%s  ", d->d_name);
		}
	}
	shmsg(sh, "\n" SHELL_PROMPT "%s", sh->cmdline);
	shmsg_flush(sh);
	/* Move cursor back to original position */
	shmsg_back_n(sh, sh->cmdline_len - saved_cursor);

out_close:
	closedir(dir);
}

static void key_tab(struct shell *sh)
{
	int word_start = 0, word_end = 0, prefix_len = 0;
	int chars_to_delete = 0;
	char prefix_buf[SHELL_PATH_MAX];

	/* Find the start and end of current word */
	word_start = sh->cursor;
	while (word_start > 0 && !is_ws(sh->cmdline[word_start - 1]))
		word_start--;

	word_end = sh->cursor;
	while (word_end < sh->cmdline_len && !is_ws(sh->cmdline[word_end]))
		word_end++;

	/* Copy prefix before cursor to buffer */
	prefix_len = sh->cursor - word_start;
	if (prefix_len >= sizeof(prefix_buf))
		prefix_len = sizeof(prefix_buf) - 1;
	memcpy(prefix_buf, &sh->cmdline[word_start], prefix_len);
	prefix_buf[prefix_len] = '\0';

	/* If cursor is not at word end, delete the rest of the word first */
	if (sh->cursor < word_end) {
		chars_to_delete = word_end - sh->cursor;
		cmdline_delete_range(sh, sh->cursor, sh->cursor + chars_to_delete);
	}

	if (word_start == 0)
		complete_command(sh, prefix_buf, prefix_len);
	else
		complete_path(sh, prefix_buf, prefix_len);
}

/*
 * Execute command on Enter key press.
 * Parses the command line into argv, looks up the command handler,
 * and executes either a built-in command or external application.
 */
static void key_enter(struct shell *sh)
{
	int ret = 0, cmd_len = 0;
	unsigned int meta;

	sh->stop_request = 0;

	shmsg(sh, "\n");
	shmsg_flush(sh);

	if (sh->cmdline_len) {
		shell_sanitize_cmdline(sh);
		cmd_record(sh);
		cmd_len = sh->cmdline_len;
		meta = cmdline_scan_meta(sh->cmdline, &cmd_len);
		sh->cmdline_len = cmd_len;

		if (meta & META_BACKGROUND) {
			ret = shell_start_background(sh, sh->cmdline, sh->cmdline_len);
			if (ret < 0)
				shmsg_err(sh, "background start failed: %d\n", ret);
		} else if (meta & META_SEMICOLON) {
			ret = cmd_execute_semicolon_list(sh);
		} else {
			ret = shell_exec_single_cmdline(sh);
		}
	}

	shmsg(sh, SHELL_PROMPT);
	shmsg_flush(sh);
	sh->term_col = SHELL_PROMPT_LEN;

	sh->cmdline_len = 0;
	sh->cmdline[0] = '\0';
	sh->cursor = 0;
}

/* Dummy handler that ignores terminal control sequences */
static void key_dummy(struct shell *sh)
{
	/* Do nothing - just ignore the sequence */
}

/* Compare with wildcard support (* matches any character) */
static int memcmp_wildcard(const char *pattern, const char *input, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (pattern[i] != '*' && pattern[i] != input[i])
			return 1; /* Not match */
	}

	return 0; /* Match */
}

/* Known key sequences and their handlers */
static const struct key_code key_handlers[] = {
	{key_enter,       "\x0D\x0A",                             2}, /* Enter (CRLF) */
	{key_enter,       "\x0D",                                 1}, /* Enter (CR) */
	{key_enter,       "\x0A",                                 1}, /* Enter (LF) */
	{key_ctrlc,       "\x03",                                 1}, /* Ctrl+C (ETX) */
	{key_dummy,       "\x1C",                                 1}, /* Ctrl+\ (FS) */
	{key_dummy,       "\x1F",                                 1}, /* Ctrl+/ (US) */
	{key_tab,         "\x09",                                 1}, /* Tab (HT) */
	{key_backspace,   "\x08",                                 1}, /* Backspace (BS) */
	{key_backspace,   "\x7F",                                 1}, /* Backspace (DEL) */
	{key_home,        "\x01",                                 1}, /* Ctrl+A */
	{key_end,         "\x05",                                 1}, /* Ctrl+E */
	{key_delete_word, "\x17",                                 1}, /* Ctrl+W */
	{key_up,          "\x1B\x5B\x41",                         3}, /* Up Arrow (ESC [ A) */
	{key_down,        "\x1B\x5B\x42",                         3}, /* Down Arrow (ESC [ B) */
	{key_right,       "\x1B\x5B\x43",                         3}, /* Right Arrow (ESC [ C) */
	{key_left,        "\x1B\x5B\x44",                         3}, /* Left Arrow (ESC [ D) */
	{key_home,        "\x1B\x5B\x48",                         3}, /* Home (ESC [ H) */
	{key_end,         "\x1B\x5B\x46",                         3}, /* End (ESC [ F) */
	{key_home,        "\x1B\x5B\x31\x7E",                     4}, /* Home (ESC [ 1 ~) */
	{key_end,         "\x1B\x5B\x34\x7E",                     4}, /* End (ESC [ 4 ~) */
	{key_delete,      "\x1B\x5B\x33\x7E",                     4}, /* Delete (ESC [ 3 ~) */
	{key_backspace,   "\x1B\x5B\x33\x3B\x32\x7E",             6}, /* Shift+Delete (ESC [ 3 ; 2 ~) */
	{key_dummy,       "\x1B\x5B\x2A\x3B\x2A\x2A\x2A\x52",     8}, /* ESC [ * ; * * * R = Terminal responses */
	{key_dummy,       "\x1B\x5B\x2A\x2A\x3B\x2A\x2A\x2A\x52", 9}, /* ESC [ * * ; * * * R = More terminal responses */
};

/*
 * Insert a character at cursor position.
 * Uses term_* functions for controlled line wrapping.
 */
static void key_insert_char(struct shell *sh, char c)
{
	insert_text_at_cursor(sh, &c, 1);
}

static void shell_handle_inputs(struct shell *sh)
{
	int i = 0, k = 0, end = 0, newlen = 0;
	const struct key_code *kc = NULL;

	/*
	 * Snapshot input_len so bytes appended while we execute a command (e.g.
	 * while waiting for a foreground job) are preserved for later processing.
	 */
	end = min(sh->input_len, (int)sizeof(sh->input_buf) - 1);
	for (k = 0; k < end; k++) {
		unsigned char ch = sh->input_buf[k];

		/* Fast path: batch consecutive printable characters */
		if (ch >= 0x20 && ch != 0x7F && ch != 0x1B) {
			int run_start = k;

			while (k + 1 < end) {
				unsigned char next = sh->input_buf[k + 1];

				if (next < 0x20 || next == 0x7F || next == 0x1B)
					break;
				k++;
			}
			insert_text_at_cursor(sh, &sh->input_buf[run_start],
				k - run_start + 1);
			continue;
		}

		/* Try to match a key sequence */
		for (i = 0; i < ARRAY_SIZE(key_handlers); i++) {
			kc = &key_handlers[i];

			if (kc->raw_key_size <= (end - k) &&
			    !memcmp_wildcard(kc->raw_key, &sh->input_buf[k], kc->raw_key_size)) {
				/*
				 * Avoid probing terminal width when more bytes are already buffered
				 * (e.g. multi-line paste). The width probe reads from tty_fd and can
				 * otherwise consume and drop the next command's bytes.

				if (key_enter == kc->func && (end - k) == kc->raw_key_size)
					sh->term_width = shell_detect_terminal_width(sh);*/
				kc->func(sh);
				k += kc->raw_key_size - 1;
				break;
			}
		}

		/* No key sequence matched - insert as regular character */
		if (i == ARRAY_SIZE(key_handlers))
			key_insert_char(sh, sh->input_buf[k]);
	}

	newlen = sh->input_len;
	if (newlen > end) {
		memmove(sh->input_buf, &sh->input_buf[end], newlen - end);
		sh->input_len -= end;
		if (sh->input_len >= sizeof(sh->input_buf))
			sh->input_len = 0;
	} else {
		sh->input_len = 0;
	}
}

void shell_entry(void)
{
	struct shell *sh = NULL;
	int ret = -1, rdbytes = 0, room = 0;
	int in_len = 0;
	struct pollfd fds = {0, POLLIN, 0};

	shell_build_asserts();

	sh = shell_calloc(1, sizeof(struct shell));
	if (!sh)
		return;

	sh->history = shell_calloc(1, sizeof(*sh->history));
	/* History is optional; continue without it. */

	/* Initialize current working directory to root */
	strlcpy(sh->cwd, "/", sizeof(sh->cwd));

	sh->tty_fd = STDIN_FILENO;
	sh->io.stdin_fd = STDIN_FILENO;
	sh->io.stdout_fd = STDOUT_FILENO;
	sh->io.stderr_fd = STDERR_FILENO;

	/* Foreground builtin execution mode (0: cmd queue, 1: new thread for each cmd) */
	sh->fg_builtin_new_thread = 0;

	shell_set_nonblocking(sh->tty_fd);

	/* Discard the old strings - 20ms timeout */
	ret = poll(&fds, 1, 20);
	if (ret > 0)
		shell_read(sh->tty_fd, sh->input_buf, sizeof(sh->input_buf));

	/* Try to auto-detect terminal width */
	sh->term_width = shell_detect_terminal_width(sh);

	shell_write(sh->io.stdout_fd, "\n" SHELL_PROMPT, 1 + SHELL_PROMPT_LEN);
	sh->term_col = SHELL_PROMPT_LEN;

	for (;;) {
		fds.fd = sh->tty_fd;

		ret = poll(&fds, 1, 1000);
		if (ret && (fds.revents & POLLIN)) {
			in_len = sh->input_len;
			room = sizeof(sh->input_buf) - 1 - in_len;
			if (room > 0) {
				rdbytes = shell_read(sh->tty_fd, &sh->input_buf[in_len], room);
				if (rdbytes > 0)
					sh->input_len += rdbytes;
				if (sh->input_len >= sizeof(sh->input_buf))
					sh->input_len = 0;
			}
		}

		while (sh->input_len > 0)
			shell_handle_inputs(sh);
	}
}

