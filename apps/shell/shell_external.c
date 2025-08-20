// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * shell external process support (posix_spawnp/waitpid).
 * Built only when CONFIG_SPAWN=y and CONFIG_WAITPID=y.
 */

#include <shell.h>

struct shell_waitfg_ctx {
	pid_t pid;
	int status;
	int ret;
	volatile int done;
	volatile int start;
};

struct shell_stdio_plan {
	int in_fd;
	int out_fd;
	int err_fd;
	int in_tmp;
	int out_tmp;
	int err_tmp;
	int proxy_in;
	int proxy_out;
	int proxy_enabled;
};

static void shell_stdio_plan_init(struct shell_stdio_plan *plan)
{
	memset(plan, 0, sizeof(*plan));
	plan->in_fd = plan->out_fd = plan->err_fd = -1;
	plan->in_tmp = plan->out_tmp = plan->err_tmp = -1;
	plan->proxy_in = plan->proxy_out = -1;
}

static int shell_stdio_plan_prepare(struct shell *sh, int orig_in_fd,
	int in_fd, int out_fd, int err_fd, bool allow_proxy,
	struct shell_stdio_plan *plan)
{
	shell_stdio_plan_init(plan);

	plan->in_fd = in_fd;
	plan->out_fd = out_fd;
	plan->err_fd = err_fd;

	if (shell_stdfd(plan->in_fd) && plan->in_fd != STDIN_FILENO) {
		plan->in_tmp = shell_dup(plan->in_fd);
		if (plan->in_tmp < 0)
			return plan->in_tmp;
		plan->in_fd = plan->in_tmp;
	}
	if (shell_stdfd(plan->out_fd)) {
		plan->out_tmp = shell_dup(plan->out_fd);
		if (plan->out_tmp < 0)
			return plan->out_tmp;
		plan->out_fd = plan->out_tmp;
	}
	if (shell_stdfd(plan->err_fd)) {
		plan->err_tmp = shell_dup(plan->err_fd);
		if (plan->err_tmp < 0)
			return plan->err_tmp;
		plan->err_fd = plan->err_tmp;
	}

	plan->proxy_enabled = 0;
	if (allow_proxy && sh->tty_fd >= 0 && orig_in_fd == STDIN_FILENO) {
		int proxy_pipe[2] = {-1, -1};
		int ret = 0;

		ret = shell_pipe(proxy_pipe);
		if (ret < 0)
			return ret;

		plan->proxy_in = proxy_pipe[0];
		plan->proxy_out = proxy_pipe[1];
		shell_set_nonblocking(plan->proxy_out);
		plan->proxy_enabled = 1;
	}

	return 0;
}

static int shell_stdio_add_actions(posix_spawn_file_actions_t *fa,
	const struct shell_stdio_plan *plan, bool close_sources)
{
	int ret = 0;
	int stdin_src = plan->proxy_enabled ? plan->proxy_in : plan->in_fd;

	ret = posix_spawn_file_actions_adddup2(fa, stdin_src, STDIN_FILENO);
	if (ret != 0)
		return ret;
	ret = posix_spawn_file_actions_adddup2(fa, plan->out_fd, STDOUT_FILENO);
	if (ret != 0)
		return ret;
	ret = posix_spawn_file_actions_adddup2(fa, plan->err_fd, STDERR_FILENO);
	if (ret != 0)
		return ret;

	if (plan->proxy_enabled) {
		ret = posix_spawn_file_actions_addclose(fa, plan->proxy_in);
		if (ret != 0)
			return ret;
		ret = posix_spawn_file_actions_addclose(fa, plan->proxy_out);
		if (ret != 0)
			return ret;
	} else if (close_sources) {
		if (stdin_src != STDIN_FILENO) {
			ret = posix_spawn_file_actions_addclose(fa, stdin_src);
			if (ret != 0)
				return ret;
		}
		if (plan->out_fd != STDOUT_FILENO && plan->out_fd != STDERR_FILENO
			&& plan->out_fd != stdin_src) {
			ret = posix_spawn_file_actions_addclose(fa, plan->out_fd);
			if (ret != 0)
				return ret;
		}
		if (plan->err_fd != STDERR_FILENO && plan->err_fd != STDOUT_FILENO
			&& plan->err_fd != stdin_src && plan->err_fd != plan->out_fd) {
			ret = posix_spawn_file_actions_addclose(fa, plan->err_fd);
			if (ret != 0)
				return ret;
		}
	}

	if (plan->in_tmp >= 0) {
		ret = posix_spawn_file_actions_addclose(fa, plan->in_tmp);
		if (ret != 0)
			return ret;
	}
	if (plan->out_tmp >= 0 && plan->out_tmp != plan->in_tmp) {
		ret = posix_spawn_file_actions_addclose(fa, plan->out_tmp);
		if (ret != 0)
			return ret;
	}
	if (plan->err_tmp >= 0 && plan->err_tmp != plan->in_tmp
		&& plan->err_tmp != plan->out_tmp) {
		ret = posix_spawn_file_actions_addclose(fa, plan->err_tmp);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static void shell_stdio_plan_cleanup(const struct shell_stdio_plan *plan,
	bool keep_proxy_out)
{
	if (plan->proxy_in >= 0)
		shell_close(plan->proxy_in);
	if (!keep_proxy_out && plan->proxy_out >= 0)
		shell_close(plan->proxy_out);
	if (plan->in_tmp >= 0)
		shell_close(plan->in_tmp);
	if (plan->out_tmp >= 0 && plan->out_tmp != plan->in_tmp)
		shell_close(plan->out_tmp);
	if (plan->err_tmp >= 0 && plan->err_tmp != plan->in_tmp
		&& plan->err_tmp != plan->out_tmp)
		shell_close(plan->err_tmp);
}

static long shell_waitfg_thread(void *arg)
{
	struct shell_waitfg_ctx *ctx = arg;
	pid_t pid;

	/* Wait for main thread to set start flag and pid (with RELEASE) */
	while (!__atomic_load_n(&ctx->start, __ATOMIC_ACQUIRE))
		poll(NULL, 0, 10);

	pid = __atomic_load_n(&ctx->pid, __ATOMIC_ACQUIRE);
	if (pid <= 0) {
		ctx->ret = -EINVAL;
		__atomic_store_n(&ctx->done, 1, __ATOMIC_RELEASE);
		return ctx->ret;
	}

	ctx->ret = shell_waitpid(pid, &ctx->status, 0);
	__atomic_store_n(&ctx->done, 1, __ATOMIC_RELEASE);
	return ctx->ret;
}

static int shell_wait_foreground_child(struct shell *sh,
	struct shell_waitfg_ctx *w, shell_tid_t wait_tid, int proxy_out)
{
	int ret = 0, i = 0, echo_fd = -1, signo = 0;
	struct pollfd pfds[1] = {0};
	char inbuf[64];
	ssize_t rdbytes = 0;

	/* Wait child in a helper thread so we can proxy stdin and Ctrl+C. */
	echo_fd = sh->tty_fd;

	pfds[0].fd = sh->tty_fd;
	pfds[0].events = POLLIN;

	while (!__atomic_load_n(&w->done, __ATOMIC_ACQUIRE)) {
		/* thread aborted ?*/
		if (shell_thread_detach(wait_tid) == -ESRCH)
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
				shell_kill(w->pid, signo);
				continue;
			}
			if (proxy_out >= 0)
				shell_write(proxy_out, &inbuf[i], 1);
			shell_echo_and_buffer_typeahead(sh, echo_fd, inbuf[i]);
		}
	}

	if (proxy_out >= 0)
		shell_close(proxy_out);
	shell_thread_join(wait_tid);

	return w->ret;
}

int shell_ext_runapp_argv(struct shell *sh, char *const argv[])
{
	pid_t pid = -1;
	shell_tid_t wait_tid = 0;
	int ret = 0, orig_in_fd = sh->io.stdin_fd;
	struct shell_stdio_plan plan;
	struct shell_waitfg_ctx w;
	posix_spawn_file_actions_t fa;
	bool wait_thread_started = false;

	BUILD_ERROR_ON(sizeof(fa) < 256);

	ret = posix_spawn_file_actions_init(&fa);
	if (ret != 0)
		return -ret;

	ret = shell_stdio_plan_prepare(sh, orig_in_fd, sh->io.stdin_fd,
		sh->io.stdout_fd, sh->io.stderr_fd, true, &plan);
	if (ret < 0)
		goto fail;

	ret = shell_stdio_add_actions(&fa, &plan, false);
	if (ret != 0)
		goto fail;

	memset(&w, 0, sizeof(w));
	w.pid = -1;
	ret = shell_thread_create(&wait_tid, shell_waitfg_thread, &w);
	if (ret != 0)
		goto fail;
	wait_thread_started = true;

	ret = shell_spawn(&pid, &fa, argv);

	__atomic_store_n(&w.pid, ret == 0 ? pid : -1, __ATOMIC_RELEASE);
	__atomic_store_n(&w.start, 1, __ATOMIC_RELEASE);

fail:
	posix_spawn_file_actions_destroy(&fa);
	shell_stdio_plan_cleanup(&plan, ret == 0);
	if (ret == 0) /* still has job to do */
		return shell_wait_foreground_child(sh, &w, wait_tid, plan.proxy_out);
	if (wait_thread_started)
		shell_thread_join(wait_tid);
	return (ret < 0) ? ret : -ret;
}

int shell_ext_spawnapp_argv(struct shell *sh, char *const argv[], pid_t *pid_out)
{
	pid_t pid = -1;
	int ret = 0;
	posix_spawn_file_actions_t fa;
	struct shell_stdio_plan plan;

	*pid_out = -1;

	ret = posix_spawn_file_actions_init(&fa);
	if (ret != 0)
		return -ret;

	ret = shell_stdio_plan_prepare(sh, sh->io.stdin_fd, sh->io.stdin_fd,
		sh->io.stdout_fd, sh->io.stderr_fd, false, &plan);
	if (ret < 0)
		goto fail;

	ret = shell_stdio_add_actions(&fa, &plan, false);
	if (ret != 0)
		goto fail;

	ret = shell_spawn(&pid, &fa, argv);
	if (ret == 0)
		*pid_out = pid;

fail:
	posix_spawn_file_actions_destroy(&fa);
	shell_stdio_plan_cleanup(&plan, false);
	return (ret < 0) ? ret : -ret;
}

int shell_ext_spawn_pipeline_stage(pid_t *pid_out, int in_fd, int out_fd,
	char *const argv[])
{
	int ret = 0;
	pid_t pid = -1;
	struct shell_stdio_plan plan;
	posix_spawn_file_actions_t fa;

	ret = posix_spawn_file_actions_init(&fa);
	if (ret != 0)
		return -ret;

	ret = shell_stdio_plan_prepare(NULL, in_fd, in_fd, out_fd, out_fd, false, &plan);
	if (ret < 0)
		goto fail;

	ret = shell_stdio_add_actions(&fa, &plan, true);
	if (ret != 0)
		goto fail;

	ret = shell_spawn(&pid, &fa, argv);
	if (ret == 0)
		*pid_out = pid;

fail:
	posix_spawn_file_actions_destroy(&fa);
	shell_stdio_plan_cleanup(&plan, false);
	return (ret < 0) ? ret : -ret;
}
