// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * mbedtest_process.c -- Process lifecycle + pipeline helpers.
 *
 * Functions defined here:
 *   pipeline_stdin_to_stdout, pipeline_gen_bytes, pipeline_sink_bytes,
 *   wait_expect_exit, spawn_pipe_chain, pipeline_redirect_chk,
 *   pipe_chain_run, posix_spawn_enoent_run, execve_enoent_run,
 *   proc_execve_probe_write, proc_execve_spawn_probe,
 *   execve_spawn_probe_run, waitpid_error_paths_run,
 *   posix_spawn_file_redirect_run, posix_spawn_file_pipe_capture_run,
 *   waitpid_options_run, proc_spawn_waitpid_basic_test
 */
#define _GNU_SOURCE
#include <generated/autoconf.h>

#include "mbedtest.h"
#include "mbedtest_internal.h"

/* ---- Local tuning constants ------------------------------------- */
#define EXECVE_PROBE_MAGIC        "mbedtest-execve-ok"

/*
 * pipeline_stdin_to_stdout: cat-like helper for pipe chain tests.
 */
int pipeline_stdin_to_stdout(void)
{
	char buf[512];
	ssize_t n, w;

	for (;;) {
		n = read(STDIN_FILENO, buf, sizeof(buf));
		if (n == 0)
			break;
		if (n < 0)
			return errno;
		w = test_write_full(STDOUT_FILENO, buf, n);
		if (w != n)
			return w < 0 ? errno : EIO;
	}
	return 0;
}

/*
 * Pipeline helper: write a marker to stdout (expected to be redirected to a
 * file), then read back that file and echo its contents to stderr.
 *
 * This avoids relying on parent/child seeing the same filesystem namespace.
 */
void __dead2 pipeline_redirect_chk(const char *path, int code)
{
	char msg[32], emsg[64];
	char buf[256];
	int fd = -1, rc = 0, err = 0, len = 0, got = 0;
	int wait_cnt = 0;

	len = snprintf(msg, sizeof(msg), "PASS:%d", code);
	for (wait_cnt = 0; wait_cnt < 400; wait_cnt++) {
		rc = test_write_full(STDOUT_FILENO, msg, len);
		if (rc == len)
			break;
		err = rc < 0 ? errno : EIO;
		if (!test_is_resource_error(err))
			break;
		usleep(30000);
	}
	if (rc != len) {
		err = rc < 0 ? errno : EIO;
		len = snprintf(emsg, sizeof(emsg), "WRITEFAIL:%d", err);
		test_write_full(STDERR_FILENO, emsg, len);
		exit(code);
	}

	for (wait_cnt = 0; wait_cnt < 400; wait_cnt++) {
		fd = open(path, O_RDONLY);
		if (fd >= 0)
			break;
		err = errno;
		if (!test_is_resource_error(err) && err != ENOENT)
			break;
		usleep(20000);
	}
	if (fd < 0) {
		err = errno;
		len = snprintf(emsg, sizeof(emsg), "OPENFAIL:%d", err);
		test_write_full(STDERR_FILENO, emsg, len);
		exit(code);
	}

	for (wait_cnt = 0; wait_cnt < 400; wait_cnt++) {
		rc = test_read_full(fd, buf, sizeof(buf) - 1);
		if (rc > 0)
			break;
		err = rc < 0 ? errno : ETIMEDOUT;
		if (rc < 0 && !test_is_resource_error(err))
			break;
		usleep(20000);
	}
	if (rc <= 0) {
		err = rc < 0 ? errno : ETIMEDOUT;
		test_close_fd(&fd);
		len = snprintf(emsg, sizeof(emsg), "READFAIL:%d\n", err);
		test_write_full(STDERR_FILENO, emsg, len);
		exit(code);
	}
	got = rc;

	test_close_fd(&fd);
	for (wait_cnt = 0; wait_cnt < 400; wait_cnt++) {
		rc = test_write_full(STDERR_FILENO, buf, got);
		if (rc == got)
			break;
		err = rc < 0 ? errno : EIO;
		if (!test_is_resource_error(err))
			break;
		usleep(30000);
	}
	if (rc == 0) {
		len = snprintf(emsg, sizeof(emsg), "EMPTY\n");
		test_write_full(STDERR_FILENO, emsg, len);
	}

	exit(code);
}

/*
 * Pipeline helper: generate deterministic bytes to stdout.
 */
int pipeline_gen_bytes(size_t nbytes)
{
	char block[2048];

	memset(block, 'A', sizeof(block));
	while (nbytes != 0) {
		size_t chunk = nbytes < sizeof(block) ? nbytes : sizeof(block);
		int rc = test_write_full(STDOUT_FILENO, block, chunk);

		if (rc < 0)
			return errno;
		nbytes -= chunk;
	}

	return 0;
}

/*
 * Pipeline helper: read exactly 'expect' bytes, fail on mismatch/early EOF.
 */
int pipeline_sink_bytes(size_t expect)
{
	char buf[2048];
	size_t got = 0;

	while (got < expect) {
		size_t want = expect - got;
		size_t chunk = want < sizeof(buf) ? want : sizeof(buf);
		ssize_t n = read(STDIN_FILENO, buf, chunk);
		ssize_t i;

		if (n == 0)
			break;
		if (n < 0)
			return errno;

		for (i = 0; i < n; i++) {
			if (buf[i] != 'A') {
				TERR("mbedtest: sink saw non-'A' byte at off=%zu\n",
					got + i);
				return EBADMSG;
			}
		}

		got += n;
	}

	if (got != expect)
		return EBADMSG;

	TDBG("mbedtest: sink OK got=%zu\n", got);
	return 0;
}

/*
 * Utility: waitpid(pid) and verify raw exit code equals expected.
 */
static int wait_expect_exit(pid_t pid, int expected)
{
	int st = 0;
	pid_t got;

	got = waitpid(pid, &st, 0);
	if (got < 0)
		return -errno;

	if (st != expected) {
		TERR("st = %d peer = %d expected= %d\n", st, pid, expected);
		if (st == EPIPE) /* peer is down */
			st = ENOMEM;
		/* st == 0 would yield -0 == 0, masking the failure. */
		if (st == 0)
			st = EBADMSG;
		return -st;
	}

	return 0;
}

/*
 * Spawn a multi-process pipe chain using file-actions:
 * gen -> (cat...)-> sink, validating cross-process pipe EOF/backpressure.
 */
static int spawn_pipe_chain(size_t nbytes, int cats, bool mismatch)
{
	/* gen -> (cat...)-> sink; all are /apps/mbedtest.elf stages */
	posix_spawn_file_actions_t fa;
	int pipes[16][2];
	pid_t pids[16];
	char nb[32] = {0};
	char *argv_gen[5] = {0};
	char *argv_cat[4] = {0};
	char *argv_sink[5] = {0};
	pid_t pid = -1;
	size_t expect = 0;
	int npipes = 0, nprocs = 0, rc = 0, i = 0;
	int j = 0, spawned = 0, expected = 0, st = 0;

	if (cats < 0 || cats > 8)
		return EINVAL;

	npipes = cats + 1;
	nprocs = cats + 2;
	if (npipes > ARRAY_SIZE(pipes) || nprocs > ARRAY_SIZE(pids))
		return EINVAL;

	for (i = 0; i < npipes; i++) {
		pipes[i][0] = -1;
		pipes[i][1] = -1;
	}

	for (i = 0; i < npipes; i++) {
		if (pipe(pipes[i]) < 0) {
			rc = errno;
			goto fail;
		}
	}

	for (i = 0; i < nprocs; i++)
		pids[i] = -1;
	spawned = 0;

	/* Spawn generator */
	pid = -1;
	snprintf(nb, sizeof(nb), "%zu", nbytes);
	argv_gen[0] = (char *)"/apps/mbedtest.elf";
	argv_gen[1] = (char *)"--pipeline";
	argv_gen[2] = (char *)"gen";
	argv_gen[3] = nb;
	argv_gen[4] = NULL;

	rc = posix_spawn_file_actions_init(&fa);
	if (rc != 0)
		goto fail;
	rc = posix_spawn_file_actions_adddup2(&fa, pipes[0][1], STDOUT_FILENO);
	if (rc != 0) {
		posix_spawn_file_actions_destroy(&fa);
		goto fail;
	}
	for (i = 0; i < npipes; i++) {
		rc = posix_spawn_file_actions_addclose(&fa, pipes[i][0]);
		if (rc != 0) {
			posix_spawn_file_actions_destroy(&fa);
			goto fail;
		}
		rc = posix_spawn_file_actions_addclose(&fa, pipes[i][1]);
		if (rc != 0) {
			posix_spawn_file_actions_destroy(&fa);
			goto fail;
		}
	}

	rc = posix_spawn(&pid, argv_gen[0], &fa, NULL, argv_gen, NULL);
	posix_spawn_file_actions_destroy(&fa);
	if (rc != 0)
		goto fail;

	pids[0] = pid;
	spawned = 1;

	/* Spawn cat stages */
	for (i = 0; i < cats; i++) {
		pid = -1;
		argv_cat[0] = (char *)"/apps/mbedtest.elf";
		argv_cat[1] = (char *)"--pipeline";
		argv_cat[2] = (char *)"cat";
		argv_cat[3] = NULL;

		rc = posix_spawn_file_actions_init(&fa);
		if (rc != 0)
			goto fail;
		rc = posix_spawn_file_actions_adddup2(&fa, pipes[i][0], STDIN_FILENO);
		if (rc != 0) {
			posix_spawn_file_actions_destroy(&fa);
			goto fail;
		}
		rc = posix_spawn_file_actions_adddup2(&fa, pipes[i + 1][1], STDOUT_FILENO);
		if (rc != 0) {
			posix_spawn_file_actions_destroy(&fa);
			goto fail;
		}
		for (j = 0; j < npipes; j++) {
			rc = posix_spawn_file_actions_addclose(&fa, pipes[j][0]);
			if (rc != 0) {
				posix_spawn_file_actions_destroy(&fa);
				goto fail;
			}
			rc = posix_spawn_file_actions_addclose(&fa, pipes[j][1]);
			if (rc != 0) {
				posix_spawn_file_actions_destroy(&fa);
				goto fail;
			}
		}
		rc = posix_spawn(&pid, argv_cat[0], &fa, NULL, argv_cat, NULL);
		posix_spawn_file_actions_destroy(&fa);
		if (rc != 0)
			goto fail;
		pids[1 + i] = pid;
		spawned = 1 + i + 1;
	}

	/* Spawn sink */
	expect = mismatch ? nbytes + 1 : nbytes;
	snprintf(nb, sizeof(nb), "%zu", expect);
	pid = -1;
	argv_sink[0] = (char *)"/apps/mbedtest.elf";
	argv_sink[1] = (char *)"--pipeline";
	argv_sink[2] = (char *)"sink";
	argv_sink[3] = nb;
	argv_sink[4] = NULL;

	rc = posix_spawn_file_actions_init(&fa);
	if (rc != 0)
		goto fail;
	rc = posix_spawn_file_actions_adddup2(&fa, pipes[npipes - 1][0], STDIN_FILENO);
	if (rc != 0) {
		posix_spawn_file_actions_destroy(&fa);
		goto fail;
	}
	for (i = 0; i < npipes; i++) {
		rc = posix_spawn_file_actions_addclose(&fa, pipes[i][0]);
		if (rc != 0) {
			posix_spawn_file_actions_destroy(&fa);
			goto fail;
		}
		rc = posix_spawn_file_actions_addclose(&fa, pipes[i][1]);
		if (rc != 0) {
			posix_spawn_file_actions_destroy(&fa);
			goto fail;
		}
	}
	rc = posix_spawn(&pid, argv_sink[0], &fa, NULL, argv_sink, NULL);
	posix_spawn_file_actions_destroy(&fa);
	if (rc != 0)
		goto fail;
	pids[nprocs - 1] = pid;
	spawned = nprocs;

	for (i = 0; i < npipes; i++) {
		test_close_fd(&pipes[i][0]);
		test_close_fd(&pipes[i][1]);
	}

	for (i = 0; i < nprocs; i++) {
		expected = 0;
		if (i == nprocs - 1 && mismatch)
			expected = EBADMSG;
		rc = wait_expect_exit(pids[i], expected);
		if (rc != 0) {
			/* Kill and reap remaining children */
			for (j = i + 1; j < nprocs; j++) {
				if (pids[j] > 0)
					kill(pids[j], SIGKILL);
			}
			for (j = i + 1; j < nprocs; j++) {
				if (pids[j] > 0)
					waitpid(pids[j], &st, 0);
			}
			return rc;
		}
	}

	return 0;

fail:
	/* Close all pipes first so children see EOF/EPIPE */
	for (i = 0; i < npipes; i++) {
		test_close_fd(&pipes[i][0]);
		test_close_fd(&pipes[i][1]);
	}
	/* Kill all spawned children to prevent blocking on pipe */
	for (i = 0; i < spawned; i++) {
		if (pids[i] > 0)
			kill(pids[i], SIGKILL);
	}
	/* Now safe to wait */
	for (i = 0; i < spawned; i++) {
		if (pids[i] > 0)
			waitpid(pids[i], &st, 0);
	}
	return rc;
}

/*
 * Automated coverage for the multi-process pipe-chain helper above.
 */
static int pipe_chain_run(void)
{
	int rc;

	rc = spawn_pipe_chain(0, 0, false);
	CHECK(rc == 0, rc);
	rc = spawn_pipe_chain(1024, 0, false);
	CHECK(rc == 0, rc);
	rc = spawn_pipe_chain(131072, 1, false);
	CHECK(rc == 0, rc);
	rc = spawn_pipe_chain(262144, 2, false);
	CHECK(rc == 0, rc);

	/* Negative: sink must fail on mismatch (expects exit code EBADMSG). */
	rc = spawn_pipe_chain(4096, 1, true);
	CHECK(rc == 0, rc);

out:
	return TEST_ERRNO();
}

/*
 * posix_spawn() should report ENOENT for a missing file.
 */
static int posix_spawn_enoent_run(void)
{
	pid_t pid = -1;
	char *argv[] = {
		(char *)"/no/such/file",
		NULL,
	};
	int rc;

	rc = posix_spawn(&pid, argv[0], NULL, NULL, argv, NULL);
	if (rc == 0) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
	}
	CHECK(rc == ENOENT, rc);

out:
	return TEST_ERRNO();
}

/*
 * execve(): missing executable should fail with ENOENT (error path only).
 */
static int execve_enoent_run(void)
{
	char *argv[] = {
		(char *)"/no/such/file",
		NULL,
	};
	char *envp[] = { NULL };
	int ret;

	ret = execve(argv[0], argv, envp);
	CHECK(ret < 0, EIO);
	CHECK(errno == ENOENT, errno);

out:
	return TEST_ERRNO();
}

/*
 * proc_execve_probe_write: write magic string to a file.
 * Called by the execve'd child to signal successful exec.
 */
int proc_execve_probe_write(const char *path)
{
	const char *magic = EXECVE_PROBE_MAGIC;
	ssize_t want, got = 0;
	int fd = -1, err = 0, wait_cnt = 0;

	want = strlen(magic);

	if (!path || path[0] == '\0')
		return EINVAL;
	for (wait_cnt = 0; wait_cnt < 300; wait_cnt++) {
		fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd >= 0)
			break;
		err = errno;
		if (!test_is_resource_error(err))
			break;
		usleep(20000);
	}
	if (fd < 0)
		return errno;

	for (wait_cnt = 0; wait_cnt < 300; wait_cnt++) {
		got = test_write_full(fd, magic, want);
		if (got == want)
			break;
		err = got < 0 ? errno : EIO;
		if (!test_is_resource_error(err))
			break;
		usleep(20000);
	}
	if (got < 0)
		err = errno;
	else if (got != want)
		err = EBADMSG;
	else
		err = 0;

	test_close_fd(&fd);
	return err;
}

/*
 * proc_execve_spawn_probe: execve into a new mbedtest instance
 * that writes the probe file, verifying execve replaces the
 * calling process image.
 */
int proc_execve_spawn_probe(const char *self, const char *probe_path)
{
	char *argv[] = {
		(char *)(self ? self : "mbedtest"),
		(char *)"--execve-probe",
		(char *)probe_path,
		NULL,
	};
	char *envp[] = { NULL };
	int err = 0, pid = 0;

	if (!probe_path || probe_path[0] == '\0')
		return EINVAL;

	pid = execve(argv[0], argv, envp);

	/* if execve success, never return to here */
	err = errno;
	TERR("execve %s peer %04d error %d\n", argv[0], pid, err);
	if (pid < 0)
		return err;
	return 0;
}

/*
 * execve(): "success" path for this kernel means:
 * - a new process is spawned
 * - the calling process is terminated (no return to caller)
 *
 * To test it without killing the main test process, we:
 * - spawn a child process that calls execve("mbedtest", "--execve-probe <file>")
 * - that execve terminates the child and spawns a new mbedtest instance
 * - the spawned mbedtest instance writes <file>
 */
static int execve_spawn_probe_run(void)
{
	char probe_path[128];
	char buf[64];
	pid_t pid = -1;
	int fd = -1, rc = 0, st = -1, wait_cnt = 0, l = 0;
	struct timeval tv;
	char *argv[] = {
		(char *)"mbedtest",
		(char *)"--execve-spawn-probe",
		probe_path,
		NULL,
	};

	gettimeofday(&tv, NULL);
	l = snprintf(probe_path, sizeof(probe_path),
			"/shm/execve_spawn_probe_%ld_%ld_%ld.txt",
			(long)getpid(), (long)tv.tv_sec, (long)tv.tv_usec);
	if ((unsigned)l >= sizeof(probe_path))
		return 0;
	test_unlink(probe_path);

	rc = posix_spawn(&pid, argv[0], NULL, NULL, argv, NULL);
	CHECK(rc == 0, rc);

	CHECK(waitpid(pid, &st, 0) >= 0, errno);
	CHECK(st == 0, st);
	for (wait_cnt = 0; wait_cnt < 500; wait_cnt++) {
		fd = open(probe_path, O_RDONLY);
		if (fd >= 0)
			break;
		CHECK(!test_is_resource_error(errno), errno,
			"open execve probe %s", probe_path);
		usleep(20000);
	}
	CHECK(fd >= 0, errno == ENOENT ? ENOMEM : errno);

	for (wait_cnt = 0; wait_cnt < 100; wait_cnt++) {
		rc = test_read_full(fd, buf, sizeof(buf));
		CHECK(!(rc < 0 && test_is_resource_error(errno)), errno,
			"read execve probe %s", probe_path);
		if (rc != 0)
			break;
		usleep(50000);
	}
	CHECK(rc > 0, rc < 0 ? errno : ETIMEDOUT);

	buf[rc] = 0;
	CHECK(strcmp(buf, EXECVE_PROBE_MAGIC) == 0, EBADMSG);

	TDBG("got %s - rc=%d peer %04d\n", buf, rc, pid);

out:
	test_close_fd(&fd);
	test_unlink(probe_path);
	return TEST_ERRNO();
}

/*
 * waitpid_error_paths_run: verify waitpid error returns --
 * pid=0->EINVAL, -1 with no children->ECHILD, invalid pid->ECHILD.
 */
static int waitpid_error_paths_run(void)
{
	int st = 0;
	pid_t got;

	/*
	 * Error paths (minimal semantics):
	 * - pid == 0 is invalid (EINVAL)
	 * - pid == -1 is supported; with no children it should fail with ECHILD
	 */
	got = waitpid(0, &st, 0);
	CHECK(got < 0, EIO);
	CHECK(errno == EINVAL, errno);

	got = waitpid(-1, &st, WNOHANG);
	CHECK(got < 0, EIO);
	CHECK(errno == ECHILD, errno);

	got = waitpid(-1, &st, 0);
	CHECK(got < 0, EIO);
	CHECK(errno == ECHILD, errno);

	got = waitpid(999999, &st, 0);
	CHECK(got < 0, EIO);
	CHECK(errno == ECHILD, errno);

out:
	return TEST_ERRNO();
}

/*
 * Validate file-actions OPEN + DUP2 redirecting child's stdout to a file.
 */
static int posix_spawn_file_redirect_run(void)
{
	posix_spawn_file_actions_t fa;
	char buf[256], out_path_buf[256];
	char *argv[7] = {
		(char *)"mbedtest",
		(char *)"--pipeline",
		(char *)"redirchk",
		NULL,
		(char *)"7",
		NULL,
		NULL,
	};
	const char *out_path = NULL;
	int epfd[2] = {-1, -1};
	int outfd = -1, st = 0;
	pid_t pid = -1;
	int rc = 0, l = 0, wait_cnt = 0;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	l = snprintf(out_path_buf, sizeof(out_path_buf),
			"/shm/spawn_redirect_%ld_%ld_%ld.txt",
			(long)getpid(), (long)tv.tv_sec, (long)tv.tv_usec);
	if ((unsigned)l >= sizeof(out_path_buf))
		return 0;
	out_path = out_path_buf;
	argv[3] = (char *)out_path;

	test_unlink(out_path);

	outfd = open("/dev/null", O_RDWR);
	CHECK(outfd >= 0, errno);

	CHECK(pipe(epfd) == 0, errno);

	rc = posix_spawn_file_actions_init(&fa);
	CHECK(rc == 0, rc);

	rc = posix_spawn_file_actions_addopen(&fa, outfd, out_path,
				O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (rc == 0)
		rc = posix_spawn_file_actions_adddup2(&fa, outfd, STDOUT_FILENO);
	if (rc == 0)
		rc = posix_spawn_file_actions_addclose(&fa, outfd);
	if (rc == 0)
		rc = posix_spawn_file_actions_adddup2(&fa, epfd[1], STDERR_FILENO);
	if (rc == 0)
		rc = posix_spawn_file_actions_addclose(&fa, epfd[1]);
	if (rc != 0) {
		posix_spawn_file_actions_destroy(&fa);
		goto out;
	}

	rc = posix_spawn(&pid, argv[0], &fa, NULL, argv, NULL);
	posix_spawn_file_actions_destroy(&fa);
	CHECK(rc == 0, rc);

	test_close_fd(&epfd[1]);

	for (wait_cnt = 0; wait_cnt < 400; wait_cnt++) {
		rc = test_read_full(epfd[0], buf, sizeof(buf) - 1);
		if (rc > 0)
			break;
		if (rc < 0 && !test_is_resource_error(errno))
			break;
		usleep(20000);
	}
	test_close_fd(&epfd[0]);

	CHECK(rc > 0, rc < 0 ? errno : ETIMEDOUT);
	CHECK(waitpid(pid, &st, 0) >= 0, errno);
	CHECK(st == 7, st);

	buf[rc] = 0;
	CHECK(strstr(buf, "PASS:7") != NULL, EBADMSG);

	TDBG("got: '%s' peer %04d\n", buf, pid);
	pid = -1;

out:
	if (pid > 0) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
	}
	test_close_fd(&outfd);
	test_close_fd(&epfd[0]);
	test_close_fd(&epfd[1]);
	test_unlink(out_path);
	return TEST_ERRNO();
}

/*
 * posix_spawn_file_pipe_capture_run: spawn child with stdout
 * redirected to a pipe via file_actions, read and verify output.
 */
static int posix_spawn_file_pipe_capture_run(void)
{
	/*
	 * Redirect child's stdout to a pipe via file-actions, then validate we can
	 * read the expected output from the parent.
	 */
	posix_spawn_file_actions_t fa;
	char buf[256];
	char *argv[5] = {
		(char *)"mbedtest",
		(char *)"--pipeline",
		(char *)"gen",
		(char *)"128",
		NULL,
	};
	int pfd[2] = {-1, -1};
	pid_t pid = -1;
	int st = 0, rc = 0, wait_cnt = 0;
	size_t i = 0;

	CHECK(pipe(pfd) == 0, errno);

	rc = posix_spawn_file_actions_init(&fa);
	CHECK(rc == 0, rc);

	rc = posix_spawn_file_actions_adddup2(&fa, pfd[1], STDOUT_FILENO);
	if (rc == 0)
		rc = posix_spawn_file_actions_addclose(&fa, pfd[0]);
	if (rc == 0)
		rc = posix_spawn_file_actions_addclose(&fa, pfd[1]);
	if (rc != 0) {
		posix_spawn_file_actions_destroy(&fa);
		goto out;
	}

	rc = posix_spawn(&pid, argv[0], &fa, NULL, argv, NULL);
	posix_spawn_file_actions_destroy(&fa);
	CHECK(rc == 0, rc);

	test_close_fd(&pfd[1]);

	for (wait_cnt = 0; wait_cnt < 150; wait_cnt++) {
		rc = test_read_full(pfd[0], buf, sizeof(buf));
		if (rc != 0)
			break;
		usleep(50000);
	}
	CHECK(rc >= 0, errno);

	CHECK(waitpid(pid, &st, 0) >= 0, errno);
	CHECK(st == 0, st);
	CHECK(rc == 128, EBADMSG);

	for (i = 0; i < 128; i++)
		CHECK(buf[i] == 'A', EBADMSG);

	pid = -1;

out:
	if (pid > 0) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
	}
	test_close_fd(&pfd[0]);
	test_close_fd(&pfd[1]);
	return TEST_ERRNO();
}

/*
 * waitpid(): supports WNOHANG; other option bits should fail with ENOTSUP.
 */
static int waitpid_options_run(void)
{
	pid_t pid = -1;
	int st = 0, rc = 0;
	int i = 0;
	pid_t r = -1;
	char *argv[5] = {
		(char *)"mbedtest",
		(char *)"--pipeline",
		(char *)"exit",
		(char *)"5",
		NULL,
	};

	rc = posix_spawn(&pid, argv[0], NULL, NULL, argv, NULL);
	CHECK(rc == 0, rc);

	CHECK(waitpid(pid, &st, 2) < 0, EIO);
	CHECK(errno == ENOTSUP, errno);

	/* WNOHANG: should not block. Poll until child exits. */
	st = 0;
	for (i = 0; i < 200; i++) {
		r = waitpid(pid, &st, WNOHANG);
		if (r == pid)
			break;
		CHECK(r == 0, errno);
		usleep(20000);
	}
	CHECK(r == pid, ETIMEDOUT);
	CHECK(st == 5, st);

	/* After reaping once, a second wait should fail with ECHILD. */
	CHECK(waitpid(pid, &st, 0) < 0, EIO);
	CHECK(errno == ECHILD, errno);

	pid = -1;

out:
	if (pid >= 0) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
	}
	return TEST_ERRNO();
}

/*
 * Process lifecycle sanity: posix_spawn() + waitpid()
 */
void proc_spawn_waitpid_basic_test(void)
{
	int rc = 0;

	TEST_START("posix_spawn_waitpid");

	rc = waitpid_error_paths_run();
	CHECK(rc == 0, rc, "waitpid_error_paths");
	rc = waitpid_options_run();
	CHECK(rc == 0, rc, "waitpid_options");
	rc = posix_spawn_enoent_run();
	CHECK(rc == 0, rc, "posix_spawn_enoent");
	rc = execve_enoent_run();
	CHECK(rc == 0, rc, "execve_enoent");
	rc = execve_spawn_probe_run();
	CHECK(rc == 0, rc, "execve_spawn_probe");
	rc = posix_spawn_file_redirect_run();
	CHECK(rc == 0, rc, "spawn_file_actions_redirect");
	rc = posix_spawn_file_pipe_capture_run();
	CHECK(rc == 0, rc, "spawn_file_actions_pipe");
	rc = pipe_chain_run();
	CHECK(rc == 0, rc, "pipe_chain");

out:
	TEST_END();
}
