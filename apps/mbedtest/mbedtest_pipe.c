// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * mbedtest_pipe.c -- Pipe tests: basic, 2-proc, wraparound, backpressure.
 */
#define _GNU_SOURCE
#include <sys/syslimits.h>
#include "mbedtest.h"
#include "mbedtest_internal.h"
#include <poll.h>
#include <epoll.h>

struct pipe_thread_ctx {
	int fd;
	int *started;
	int *done;
};

/*
 * pipe_basic_test: create pipe, verify lseek->ESPIPE, O_NONBLOCK
 * read->EAGAIN, write/read round-trip, close->EOF, write after close->EPIPE.
 */
void pipe_basic_test(void)
{
	int ret = -1, err = 0, flags = 0;
	int p[2] = {-1, -1};
	int p2[2] = {-1, -1};
	void (*old)(int) = NULL;
	char buf[8] = {0};
	struct pollfd fds[2] = {{0}};

	TEST_START("pipe_basic_test");

	ret = pipe(p);
	CHECK(ret >= 0, errno);

	ret = lseek(p[0], 0, SEEK_SET);
	CHECK(ret < 0 && errno == ESPIPE, errno);

	flags = fcntl(p[0], F_GETFL);
	CHECK(flags >= 0, errno);

	ret = fcntl(p[0], F_SETFL, flags | O_NONBLOCK);
	CHECK(ret >= 0, errno);

	ret = read(p[0], buf, sizeof(buf));
	CHECK(ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
		errno);

	ret = write(p[1], "X", 1);
	CHECK(ret == 1, errno);

	fds[0].fd = p[0];
	fds[0].events = POLLIN;
	fds[1].fd = -1;
	fds[1].events = POLLIN;
	ret = poll(fds, 2, 5000);
	CHECK(ret > 0, errno);
	CHECK(fds[0].revents & POLLIN, EPROTO);

	memset(buf, 0, sizeof(buf));
	ret = read(p[0], buf, 1);
	CHECK(ret == 1, errno);
	CHECK(buf[0] == 'X', EBADMSG);

	CHECK(test_close_fd(&p[1]) == 0, errno);

	ret = read(p[0], buf, 1);
	CHECK(ret == 0, errno);

	/* EPIPE when writing to a pipe with no readers (Linux/POSIX style). */
	ret = pipe(p2);
	CHECK(ret >= 0, errno);
	test_close_fd(&p2[0]);
	old = signal(SIGPIPE, SIG_IGN);
	ret = write(p2[1], "Y", 1);
	err = errno;
	signal(SIGPIPE, old);
	CHECK(ret < 0 && err == EPIPE, err);

out:
	test_close_fd(&p[0]);
	test_close_fd(&p[1]);
	test_close_fd(&p2[0]);
	test_close_fd(&p2[1]);
	TEST_END();
}

/*
 * pipe_2proc_recv: child side of 2-process pipe test.
 * Receives data/ack fds via MQ fd-passing, reads message,
 * waits for EOF (parent closes writer), then sends ack.
 */
int pipe_2proc_recv(const char *mq_name)
{
	int ret = -1, mqdes = -1;
	int data_rfd = -1, ack_wfd = -1;
	char name[128] = {0}, buf[64] = {0};
	const char *msg = "pipe2proc";
	const size_t msglen = 8;
	char ack = 0;
	struct pollfd pfd;

	TEST_START("pipe_2proc_recv");

	strlcpy(name, mq_name, sizeof(name));

	TEST_POLL_OPEN(mqdes, -1, mq_open(name, O_RDONLY | O_NONBLOCK), 30000);
	CHECK(mqdes >= 0, errno ? errno : ETIMEDOUT);

	ret = mq_receive_fd_timed(mqdes, &data_rfd, 10000);
	CHECK(ret == 0, ret, "mq_receive_fd data fd=%d ret=%d", data_rfd, ret);
	CHECK(data_rfd >= 0, EBADMSG, "mq_receive_fd data invalid fd=%d", data_rfd);

	ret = mq_receive_fd_timed(mqdes, &ack_wfd, 10000);
	CHECK(ret == 0, ret, "mq_receive_fd ack fd=%d ret=%d", ack_wfd, ret);
	CHECK(ack_wfd >= 0, EBADMSG, "mq_receive_fd ack invalid fd=%d", ack_wfd);

	pfd.fd = data_rfd;
	pfd.events = POLLIN;
	ret = poll(&pfd, 1, 10000);
	CHECK(ret > 0, errno);
	CHECK(pfd.revents & (POLLIN | POLLHUP), EPROTO);

	ret = read(data_rfd, buf, msglen);
	CHECK(ret == msglen, errno);
	CHECK(memcmp(buf, msg, msglen) == 0, EBADMSG);

	/* Parent should close writer; verify EOF */
	pfd.fd = data_rfd;
	pfd.events = POLLIN | POLLHUP;
	ret = poll(&pfd, 1, 10000);
	CHECK(ret > 0, errno);
	CHECK(pfd.revents & (POLLIN | POLLHUP), EPROTO);

	ret = read(data_rfd, buf, 1);
	CHECK(ret == 0, errno);

	ack = 'K';
	ret = write(ack_wfd, &ack, 1);
	CHECK(ret == 1, errno);

out:
	test_close_fd(&data_rfd);
	test_close_fd(&ack_wfd);
	test_close_mq_fd(&mqdes);
	test_mq_unlink(name);
	return TEST_END();
}

/*
 * pipe_2proc_send: parent side of 2-process pipe test.
 * Spawns child, passes pipe fds via MQ fd-passing, writes
 * message, closes writer, waits for ack on ack pipe.
 */
void pipe_2proc_send(void)
{
	int ret = -1;
	pid_t peer;
	int mqdes = -1;
	int data_p[2] = {-1, -1};
	int ack_p[2] = {-1, -1};
	char name[128] = {0}, ack = 0;
	struct pollfd pfd = {0};
	char *argv[4] = {"mbedtest", "--pipe", name, NULL};
	const char *msg = "pipe2proc";
	const size_t msglen = 8;
	int st;
	int rc;

	TEST_START("pipe_2proc_send");

	snprintf(name, sizeof(name), "/pipe_2proc_%04d_%x%d.msg",
		gettid(), test_rand(), test_rand());
	test_mq_unlink(name);

	mqdes = mq_open(name, O_RDWR | O_CREAT, 0666, NULL);
	CHECK(mqdes >= 0, errno, "mq_open pipe fd-pass %s", name);

	peer = -1;
	st = 0;
	rc = posix_spawn(&peer, argv[0], NULL, NULL, argv, NULL);
	CHECK(rc == 0, rc);

	ret = pipe(data_p);
	CHECK(ret >= 0, errno);

	ret = pipe(ack_p);
	CHECK(ret >= 0, errno);

	/*
	 * Send required fds to peer via MQ fd passing
	 * (execve doesn't inherit fds here).
	 * Peer needs data read end and ack write end.
	 */
	ret = mq_send_fd(mqdes, data_p[0]);
	CHECK(ret >= 0, errno, "mq_send_fd data_rfd=%d ret=%d", data_p[0], ret);
	test_close_fd(&data_p[0]);

	ret = mq_send_fd(mqdes, ack_p[1]);
	CHECK(ret >= 0, errno, "mq_send_fd ack_wfd=%d ret=%d", ack_p[1], ret);
	test_close_fd(&ack_p[1]);

	ret = write(data_p[1], msg, msglen);
	CHECK(ret == msglen, errno,
		"pipe data write ret=%d expected=%zu", ret, msglen);

	/* Close writer to signal EOF to peer */
	test_close_fd(&data_p[1]);

	/* Wait for peer ack */
	pfd.fd = ack_p[0];
	pfd.events = POLLIN;
	ret = poll(&pfd, 1, 10000);
	if (ret <= 0 && mq_test_peer_died(peer))
		peer = -1;
	CHECK(ret > 0 || peer >= 0, ENOMEM);
	CHECK(ret > 0, errno ? errno : ETIMEDOUT);
	CHECK(pfd.revents & POLLIN, EPROTO);

	ret = read(ack_p[0], &ack, 1);
	CHECK(ret == 1, errno);
	CHECK(ack == 'K', EBADMSG);

	/* Reap peer deterministically. */
	CHECK(waitpid(peer, &st, 0) >= 0, errno);
	CHECK(st == 0, st);
	peer = -1;

out:
	if (TEST_FAILED() && peer >= 0)
		kill(peer, SIGKILL);
	if (peer >= 0) {
		waitpid(peer, &st, 0);
		peer = -1;
	}

	test_close_mq_fd(&mqdes);
	test_mq_unlink(name);

	test_close_fd(&data_p[0]);
	test_close_fd(&data_p[1]);
	test_close_fd(&ack_p[0]);
	test_close_fd(&ack_p[1]);
	TEST_END();
}

/*
 * pipe_wraparound_test: random-sized write/read pairs to
 * hit internal pipe buffer boundaries (wraparound, partial
 * reads, page edges).
 */
void pipe_wraparound_test(void)
{
	int ret = -1;
	int p[2] = {-1, -1};
	unsigned int i = 0;
	unsigned int j = 0;
	unsigned int loops = 0;
	size_t sz = 0;
	unsigned char wbuf[64];
	unsigned char rbuf[64];

	TEST_START("pipe_wraparound_test");

	ret = pipe(p);
	CHECK(ret >= 0, errno);

	/*
	 * Random-sized write/read pairs to hit internal pipe buffer
	 * boundaries (wraparound, partial reads, page edges).
	 * ~512 iterations with sizes in [1, 64] guarantee multiple
	 * wraparounds while keeping runtime bounded.
	 */
	loops = 512;
	for (i = 0; i < loops; i++) {
		sz = (test_rand() % ARRAY_SIZE(wbuf)) + 1;
		for (j = 0; j < sz; j++)
			wbuf[j] = i ^ j;

		ret = write(p[1], wbuf, sz);
		CHECK(ret == sz, errno);

		memset(rbuf, 0, sz);
		ret = read(p[0], rbuf, sz);
		CHECK(ret == sz, errno);

		CHECK(memcmp(wbuf, rbuf, sz) == 0, EBADMSG);
	}

out:
	test_close_fd(&p[0]);
	test_close_fd(&p[1]);
	TEST_END();
}

/*
 * pipe_read_eof_thread: reader thread -- blocks on empty pipe
 * until writer closes, expecting read()=0 (EOF).
 */
static void *pipe_read_eof_thread(void *arg)
{
	struct pipe_thread_ctx *ctx = arg;
	char c = 0;
	int ret = 0, err = 0;

	__atomic_store_n(ctx->started, 1, __ATOMIC_RELEASE);
	for (;;) {
		ret = read(ctx->fd, &c, 1);
		err = errno;
		if (ret < 0 && err == EINTR)
			continue;
		break;
	}
	if (ctx->done)
		__atomic_store_n(ctx->done, 1, __ATOMIC_RELEASE);
	if (ret == 0)
		return (void *)(uintptr_t)8080u;
	TERR("ret %d errno %d\n", ret, err);
	return (void *)(intptr_t)(ret < 0 ? err : ret);
}

/*
 * pipe_blocking_read_eof_on_close_test: spawn reader thread
 * blocked on empty pipe, verify close(writer) wakes reader
 * with EOF (read returns 0).
 */
void pipe_blocking_read_eof_on_close_test(void)
{
	int ret = -1, terr = 0;
	int p[2] = {-1, -1}, tries = 0;
	int started = 0;
	int done = 0;
	pthread_t th = 0;
	void *thret = NULL;
	struct pipe_thread_ctx ctx = {0};

	TEST_START("pipe_blocking_read_eof_on_close_test");

	ret = pipe(p);
	CHECK(ret >= 0, errno);

	ctx.fd = p[0];
	ctx.started = &started;
	ctx.done = &done;
	__atomic_store_n(&started, 0, __ATOMIC_RELEASE);
	ret = pthread_create(&th, NULL, pipe_read_eof_thread, &ctx);
	CHECK(ret == 0, ret);
	while (!__atomic_load_n(&started, __ATOMIC_ACQUIRE) && ++tries < 200)
		usleep(20000);
	if (!__atomic_load_n(&started, __ATOMIC_ACQUIRE))
		pthread_kill(th, SIGCANCEL);

	CHECK(__atomic_load_n(&started, __ATOMIC_ACQUIRE), ENOMEM);

	usleep(100000);

	/* Close writer: reader should wake and observe EOF (read returns 0). */
	test_close_fd(&p[1]);

	for (tries = 0; !__atomic_load_n(&done, __ATOMIC_ACQUIRE) &&
	     tries < 200; tries++)
		usleep(50000);
	if (!__atomic_load_n(&done, __ATOMIC_ACQUIRE)) {
		pthread_kill(th, SIGCANCEL);
		pthread_join(th, NULL);
		th = 0;
	}
	CHECK(__atomic_load_n(&done, __ATOMIC_ACQUIRE), ENOMEM);

	pthread_join(th, &thret);
	th = 0;
	if (thret != (void *)(uintptr_t)8080u)
		terr = (intptr_t)thret;
	CHECK(thret == (void *)(uintptr_t)8080u, terr);

out:
	if (th != 0) {
		pthread_join(th, NULL);
		th = 0;
	}
	test_close_fd(&p[0]);
	test_close_fd(&p[1]);
	TEST_END();
}

/*
 * pipe_write_epipe_thread: writer thread -- writes in a loop
 * until SIGPIPE or EPIPE when reader closes.
 */
static void *pipe_write_epipe_thread(void *arg)
{
	struct pipe_thread_ctx *ctx = arg;
	char c = 'Z';
	int ret = 0;

	__atomic_store_n(ctx->started, 1, __ATOMIC_RELEASE);

	/* Expect to block (pipe full), then wake with EPIPE when reader closes. */
	for (;;) {
		ret = write(ctx->fd, &c, 1);
		if (ret < 0 && errno == EPIPE) {
			if (ctx->done)
				__atomic_store_n(ctx->done, 1, __ATOMIC_RELEASE);
			return (void *)(uintptr_t)1u;
		}
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0) {
			if (ctx->done)
				__atomic_store_n(ctx->done, 1, __ATOMIC_RELEASE);
			return (void *)(intptr_t)errno;
		}
	}
}

/*
 * pipe_blocking_write_epipe_on_close_test: fill pipe until
 * write blocks, spawn reader thread that closes after short
 * delay, verify writer gets EPIPE.
 */
void pipe_blocking_write_epipe_on_close_test(void)
{
	int ret = -1;
	int p[2] = {-1, -1};
	int fl = 0, wait_cnt = 0;
	char fill[256];
	int started = 0;
	int done = 0;
	pthread_t th = 0;
	void *thret = NULL;
	struct pipe_thread_ctx ctx = {0};
	void (*old)(int) = NULL;

	TEST_START("pipe_blocking_write_epipe_on_close_test");

	ret = pipe(p);
	CHECK(ret >= 0, errno);

	memset(fill, 'Q', sizeof(fill));
	fl = fcntl(p[1], F_GETFL);
	CHECK(fl >= 0, errno);
	ret = fcntl(p[1], F_SETFL, fl | O_NONBLOCK);
	CHECK(ret >= 0, errno);

	/* Fill pipe until it reports full (EAGAIN/EWOULDBLOCK). */
	for (;;) {
		ret = test_write_full(p[1], fill, sizeof(fill));
		if (ret == sizeof(fill))
			continue;
		CHECK(errno == EAGAIN || errno == EWOULDBLOCK, errno,
			"pipe fill errno=%d", errno);
		break;
	}

	/*
	 * Ensure no remaining space for a 1-byte write. The loop above can
	 * stop with < sizeof(fill) bytes free, which would let the thread
	 * write succeed without blocking.
	 */
	for (;;) {
		ret = test_write_full(p[1], fill, 1);
		if (ret == 1)
			continue;
		CHECK(errno == EAGAIN || errno == EWOULDBLOCK, errno,
			"pipe fill byte errno=%d", errno);
		break;
	}

	/* Switch writer back to blocking mode so the thread really blocks. */
	ret = fcntl(p[1], F_SETFL, fl & ~O_NONBLOCK);
	CHECK(ret >= 0, errno);

	ctx.fd = p[1];
	ctx.started = &started;
	ctx.done = &done;
	__atomic_store_n(&started, 0, __ATOMIC_RELEASE);

	old = signal(SIGPIPE, SIG_IGN);
	ret = pthread_create(&th, NULL, pipe_write_epipe_thread, &ctx);
	if (ret != 0)
		signal(SIGPIPE, old);
	CHECK(ret == 0, ret);
	while (!__atomic_load_n(&started, __ATOMIC_ACQUIRE) &&
	       wait_cnt++ < 500)
		usleep(10000);
	if (!__atomic_load_n(&started, __ATOMIC_ACQUIRE)) {
		pthread_kill(th, SIGCANCEL);
		pthread_join(th, NULL);
		th = 0;
		signal(SIGPIPE, old);
	}
	CHECK(__atomic_load_n(&started, __ATOMIC_ACQUIRE), ETIMEDOUT);
	usleep(10000);

	/* Close reader: blocked writer should wake and return EPIPE. */
	test_close_fd(&p[0]);

	for (ret = 0; !__atomic_load_n(&done, __ATOMIC_ACQUIRE) &&
	     ret < 200; ret++)
		usleep(50000);
	if (!__atomic_load_n(&done, __ATOMIC_ACQUIRE)) {
		pthread_kill(th, SIGCANCEL);
		pthread_join(th, NULL);
		th = 0;
		signal(SIGPIPE, old);
	}
	CHECK(__atomic_load_n(&done, __ATOMIC_ACQUIRE), ENOMEM);

	pthread_join(th, &thret);
	th = 0;
	signal(SIGPIPE, old);
	CHECK(thret == (void *)(uintptr_t)1u, (uintptr_t)thret,
		"pipe writer join=%ld", (long)thret);

out:
	if (th != 0) {
		pthread_join(th, NULL);
		th = 0;
	}
	test_close_fd(&p[0]);
	test_close_fd(&p[1]);
	TEST_END();
}

/*
 * pipe2_flags_test: Test pipe2 O_NONBLOCK/FD_CLOEXEC atomically
 */
void pipe2_flags_test(void)
{
	int ret = -1;
	int p[2] = {-1, -1};
	int fl = 0, fdfl = 0;
	char buf[4] = {0};

	TEST_START("pipe2_flags_test");

	ret = pipe2(p, O_NONBLOCK | O_CLOEXEC);
	CHECK(ret >= 0, errno);

	fl = fcntl(p[0], F_GETFL);
	CHECK(fl >= 0, errno);
	CHECK(fl & O_NONBLOCK, EIO);

	fdfl = fcntl(p[0], F_GETFD);
	CHECK(fdfl >= 0, errno);
	CHECK(fdfl & FD_CLOEXEC, EIO);

	ret = read(p[0], buf, sizeof(buf));
	CHECK(errno == EAGAIN || errno == EWOULDBLOCK, errno);

out:
	test_close_fd(&p[0]);
	test_close_fd(&p[1]);
	TEST_END();
}

/*
 * pipe_epollout_backpressure_test: verify EPOLLOUT triggers
 * only when pipe has write space, and stops when full.
 */
void pipe_epollout_backpressure_test(void)
{
	int ret = -1;
	int p[2] = {-1, -1};
	int efd = -1, fl = 0;
	struct epoll_event ev = {0};
	struct epoll_event out_ev = {0};
	char buf[256];
	size_t total = 0;
	int i = 0;
	char c = 0;

	TEST_START("pipe_epollout_backpressure_test");

	ret = pipe(p);
	CHECK(ret >= 0, errno);

	fl = fcntl(p[1], F_GETFL);
	CHECK(fl >= 0, errno);

	ret = fcntl(p[1], F_SETFL, fl | O_NONBLOCK);
	CHECK(ret >= 0, errno);

	efd = epoll_create(1);
	CHECK(efd >= 0, errno);

	ev.events = EPOLLOUT;
	ev.data.fd = p[1];
	ret = epoll_ctl(efd, EPOLL_CTL_ADD, p[1], &ev);
	CHECK(ret == 0, errno);

	ret = epoll_wait(efd, &out_ev, 1, 0);
	CHECK(ret == 1, errno);
	CHECK(out_ev.events & EPOLLOUT, EPROTO);

	/* fill pipe until write blocks (EAGAIN) */
	memset(buf, 'P', sizeof(buf));
	for (i = 0; i < 4096; i++) {
		ret = test_write_full(p[1], buf, sizeof(buf));
		if (ret > 0) {
			total += ret;
			continue;
		}
		CHECK(errno == EAGAIN || errno == EWOULDBLOCK, errno,
			"epollout fill errno=%d", errno);
		break;
	}
	CHECK(i != 4096, EIO);
	CHECK(total != 0, EIO);

	/* pipe full: EPOLLOUT should NOT be set */
	ret = epoll_wait(efd, &out_ev, 1, 0);
	CHECK(ret == 0, errno);

	/* drain one byte: EPOLLOUT should now be set */
	ret = read(p[0], &c, 1);
	CHECK(ret == 1, errno);

	ret = epoll_wait(efd, &out_ev, 1, 10000);
	CHECK(ret == 1, errno);
	CHECK(out_ev.events & EPOLLOUT, EPROTO);

out:
	test_close_fd(&efd);
	test_close_fd(&p[0]);
	test_close_fd(&p[1]);
	TEST_END();
}
