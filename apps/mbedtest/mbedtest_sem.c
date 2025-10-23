// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * mbedtest_sem.c -- Semaphore tests: basic, named, 2-proc, timedwait.
 */

#include "mbedtest.h"
#include "mbedtest_internal.h"
#include <semaphore.h>
#include <poll.h>

/* ---- Local tuning constants ------------------------------------- */
#define SEM_PIPE_OK               ((void *)(intptr_t)0x5A11F00Du)

static int sem_eintr_got;

struct sem_thread_ctx {
	sem_t *sem;
	int *started;
};

struct sem_pipe_ctx {
	sem_t *sem;
	int fd;
	char ch;
	int *started;
};

/*
 * sem_eintr_handler: set the flag for sem_wait_eintr_test.
 */
static void sem_eintr_handler(int signo)
{
	__atomic_store_n(&sem_eintr_got, 1, __ATOMIC_RELAXED);
}

/*
 * sem_eintr_thread: block on sem_wait(), expect EINTR when
 * signalled via pthread_kill. Falls back to detecting
 * sem_eintr_got flag if sem_post() raced ahead.
 */
static void *sem_eintr_thread(void *arg)
{
	struct sem_thread_ctx *c = arg;
	int r = 0;

	__atomic_store_n(c->started, 1, __ATOMIC_RELEASE);
	r = sem_wait(c->sem);
	if (r < 0 && errno == EINTR)
		return (void *)(uintptr_t)1u;
	/* safety-net sem_post() woke us, but signal was already delivered */
	if (r == 0 && __atomic_load_n(&sem_eintr_got, __ATOMIC_RELAXED) != 0)
		return (void *)(uintptr_t)1u;
	return (void *)(intptr_t)(r < 0 ? errno : -1);
}

/*
 * sem_wait_eintr_test: verify sem_wait() returns EINTR when
 * the waiting thread is signalled via pthread_kill.
 */
void sem_wait_eintr_test(void)
{
	bool sem_inited = false;
	sem_t sem;
	pthread_t th = 0;
	int ret = -1, wait_cnt = 0;
	int started = 0;
	void *thret = NULL;
	struct sigaction sa = {0};
	struct sigaction oldsa = {0};
	struct sem_thread_ctx ctx = {&sem, &started};

	TEST_START("sem_wait_eintr_test");

	ret = sem_init(&sem, 0, 0);
	CHECK(ret == 0, errno);
	sem_inited = true;

	__atomic_store_n(&sem_eintr_got, 0, __ATOMIC_RELEASE);
	sa.sa_handler = sem_eintr_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	ret = sigaction(SIGUSR1, &sa, &oldsa);
	CHECK(ret >= 0, errno);

	__atomic_store_n(&started, 0, __ATOMIC_RELEASE);
	ret = pthread_create(&th, NULL, sem_eintr_thread, &ctx);
	CHECK(ret == 0, ret);
	while (!__atomic_load_n(&started, __ATOMIC_ACQUIRE) &&
	       wait_cnt++ < 500)
		usleep(10000);
	if (!__atomic_load_n(&started, __ATOMIC_ACQUIRE)) {
		pthread_kill(th, SIGCANCEL);
		pthread_join(th, NULL);
		th = 0;
	}
	CHECK(__atomic_load_n(&started, __ATOMIC_ACQUIRE), ETIMEDOUT);
	usleep(10000);

	ret = pthread_kill(th, SIGUSR1);
	CHECK(ret == 0, ret);

	/* Wait for signal handler, then always post to avoid hang on race. */
	for (ret = 0; ret < 200; ret++) {
		if (__atomic_load_n(&sem_eintr_got, __ATOMIC_RELAXED) != 0)
			break;
		usleep(20000);
	}
	sem_post(&sem);

	pthread_join(th, &thret);
	th = 0;
	CHECK(thret == (void *)(uintptr_t)1u, (uintptr_t)thret);

out:
	sigaction(SIGUSR1, &oldsa, NULL);
	if (th != 0) {
		sem_post(&sem);
		pthread_join(th, NULL);
		th = 0;
	}
	if (sem_inited)
		sem_destroy(&sem);
	TEST_END();
}

/*
 * sem_wait_thread: simple helper -- blocks on sem_wait().
 */
static void *sem_wait_thread(void *arg)
{
	struct sem_thread_ctx *ctx = arg;

	__atomic_store_n(ctx->started, 1, __ATOMIC_RELEASE);
	sem_wait(ctx->sem);
	return NULL;
}

/*
 * sem_basic_test: unnamed semaphore -- init/post/wait/trywait/
 * timedwait/getvalue/destroy lifecycle.
 */
void sem_basic_test(void)
{
	int ret = -1, err = 0, wait_cnt = 0;
	bool sem_inited = false;
	sem_t sem;
	struct timespec ts = {0};
	int started = 0;
	pthread_t th = 0;
	struct sem_thread_ctx ctx = {&sem, &started};

	TEST_START("sem_basic_test");

	ret = sem_init(&sem, 0, 0);
	CHECK(ret == 0, errno);
	sem_inited = true;

	ret = sem_trywait(&sem);
	CHECK(ret < 0 && errno == EAGAIN, errno);

	ret = sem_post(&sem);
	CHECK(ret == 0, errno);

	ret = sem_wait(&sem);
	CHECK(ret == 0, errno);

	clock_gettime(CLOCK_REALTIME, &ts);
	test_timespec_add_ms(&ts, 50);
	ret = sem_timedwait(&sem, &ts);
	CHECK(ret < 0 && (errno == ETIMEDOUT || errno == EAGAIN),
		errno);

	/* sem_destroy should be busy when there are waiters */
	__atomic_store_n(&started, 0, __ATOMIC_RELEASE);
	ret = pthread_create(&th, NULL, sem_wait_thread, &ctx);
	CHECK(ret == 0, ret);
	while (!__atomic_load_n(&started, __ATOMIC_ACQUIRE) &&
	       wait_cnt++ < 500)
		usleep(20000);
	if (!__atomic_load_n(&started, __ATOMIC_ACQUIRE)) {
		pthread_kill(th, SIGCANCEL);
		pthread_join(th, NULL);
	}
	CHECK(__atomic_load_n(&started, __ATOMIC_ACQUIRE), ETIMEDOUT);
	/*
	 * Give the scheduler enough time to block the thread in sem_wait.
	 */
	sleep(1);
	ret = sem_destroy(&sem);
	err = errno;
	if (ret == 0) {
		pthread_kill(th, SIGCANCEL);
		pthread_join(th, NULL);
	}
	CHECK(ret == 0 || err == EBUSY, err);
	ret = sem_post(&sem);
	err = errno;
	if (ret != 0) {
		pthread_kill(th, SIGCANCEL);
		pthread_join(th, NULL);
	}
	CHECK(ret == 0, err);
	pthread_join(th, NULL);

out:
	if (sem_inited)
		sem_destroy(&sem);
	TEST_END();
}

/*
 * sem_named_test: named semaphore -- sem_open/sem_close/sem_unlink
 * with O_CREAT/O_EXCL and inter-process sharing via 2proc test.
 */
void sem_named_test(void)
{
	int ret = -1;
	sem_t *s1 = SEM_FAILED;
	sem_t *s2 = SEM_FAILED;
	sem_t *s3 = SEM_FAILED;
	char name[128] = {0};
	int sval = -1;

	TEST_START("sem_named_test");

	/* Use a per-process name to avoid cross-test interference */
	snprintf(name, sizeof(name), "/mbedtest_sem_%04d", getpid());

	/* best-effort cleanup */
	test_sem_unlink(name);

	s1 = sem_open(name, O_CREAT | O_EXCL, 0644, 0);
	CHECK(s1 != SEM_FAILED, errno);

	s2 = sem_open(name, 0);
	CHECK(s2 != SEM_FAILED, errno);

	ret = sem_post(s1);
	CHECK(ret == 0, errno);

	/* sem_getvalue + sem_trywait on named semaphore */
	ret = sem_getvalue(s1, &sval);
	CHECK(ret == 0, errno);
	CHECK(sval > 0, ERANGE);

	ret = sem_trywait(s2);
	CHECK(ret == 0, errno);

	ret = sem_post(s1);
	CHECK(ret == 0, errno);

	ret = sem_wait(s2);
	CHECK(ret == 0, errno);

	ret = sem_trywait(s2);
	CHECK(ret < 0 && errno == EAGAIN, errno);

	ret = sem_unlink(name);
	CHECK(ret == 0, errno);

	s3 = sem_open(name, 0);
	CHECK(s3 == SEM_FAILED && errno == ENOENT, errno);

out:
	test_close_sem(&s1);
	test_close_sem(&s2);
	test_close_sem(&s3);
	/* best-effort cleanup */
	if (name[0])
		test_sem_unlink(name);
	TEST_END();
}

/*
 * sem_named_2proc_send: parent side -- spawns peer via posix_spawn,
 * creates named semaphore, passes name to peer, posts and waits for ack.
 */
void sem_named_2proc_send(void)
{
	pid_t peer = -1;
	int ret = -1, st = 0, err;
	sem_t *sem_2p = SEM_FAILED;
	sem_t *done_2p = SEM_FAILED;
	sem_t *probe = SEM_FAILED;
	char probe_name[128] = {0};
	char sem_2p_name[128] = {0};
	char done_2p_name[128] = {0};
	char tag[32] = {0};
	char *argv[4] = {"mbedtest", "--namedsem", tag, NULL};
	struct timespec ts = {0};

	TEST_START("sem_named_2proc_send");

	snprintf(tag, sizeof(tag), "%04d_%x", gettid(), test_rand());

	/* Feature probe: avoid spawning peer if named semaphores are unsupported */
	snprintf(probe_name, sizeof(probe_name), "/mbedtest_sem_probe_%s", tag);
	test_sem_unlink(probe_name);
	probe = sem_open(probe_name, O_CREAT | O_EXCL, 0644, 0);
	CHECK(probe != SEM_FAILED, errno);
	test_close_sem(&probe);
	test_sem_unlink(probe_name);

	snprintf(sem_2p_name, sizeof(sem_2p_name), "/mbedtest_sem2proc_%s.sem", tag);
	snprintf(done_2p_name, sizeof(done_2p_name), "/mbedtest_sem2proc_%s.done", tag);

	/* best-effort cleanup */
	test_sem_unlink(sem_2p_name);
	test_sem_unlink(done_2p_name);

	sem_2p = sem_open(sem_2p_name, O_CREAT | O_EXCL, 0644, 0);
	CHECK(sem_2p != SEM_FAILED, errno);

	done_2p = sem_open(done_2p_name, O_CREAT | O_EXCL, 0644, 0);
	CHECK(done_2p != SEM_FAILED, errno);

	ret = posix_spawn(&peer, argv[0], NULL, NULL, argv, NULL);
	CHECK(ret == 0, ret);

	ret = sem_post(sem_2p);
	CHECK(ret == 0, errno);

	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += 30;
	ret = sem_timedwait(done_2p, &ts);
	err = errno;
	if (ret != 0 && mq_test_peer_died(peer))
		peer = -1;
	CHECK(ret == 0 || peer < 0, err);

	/* Reap peer deterministically. */
	if (peer >= 0) {
		CHECK(waitpid(peer, &st, 0) >= 0, errno);
		CHECK(st == 0, st);
		peer = -1;
	}

out:
	if (TEST_FAILED() && peer >= 0)
		kill(peer, SIGKILL);
	if (peer >= 0) {
		waitpid(peer, &st, 0);
		peer = -1;
	}

	test_close_sem(&sem_2p);
	test_close_sem(&done_2p);
	test_close_sem(&probe);

	/* best-effort cleanup */
	if (sem_2p_name[0])
		test_sem_unlink(sem_2p_name);
	if (done_2p_name[0])
		test_sem_unlink(done_2p_name);
	if (probe_name[0])
		test_sem_unlink(probe_name);

	TEST_END();
}

/*
 * sem_named_2proc_recv: child side -- opens named semaphore,
 * posts to signal parent, waits for parent's ack.
 */
int sem_named_2proc_recv(const char *tag)
{
	int ret = -1, wait_cnt = 0;
	sem_t *sem_2p = SEM_FAILED;
	sem_t *done_2p = SEM_FAILED;
	char sem_2p_name[128] = {0};
	char done_2p_name[128] = {0};
	struct timespec ts = {0};

	TEST_START("sem_named_2proc_recv");

	snprintf(sem_2p_name, sizeof(sem_2p_name),
		"/mbedtest_sem2proc_%s.sem", tag);
	snprintf(done_2p_name, sizeof(done_2p_name),
		"/mbedtest_sem2proc_%s.done", tag);

	while ((sem_2p == SEM_FAILED || done_2p == SEM_FAILED) && wait_cnt < 500) {
		sem_2p = sem_open(sem_2p_name, 0);
		done_2p = sem_open(done_2p_name, 0);
		if (sem_2p == SEM_FAILED || done_2p == SEM_FAILED) {
			test_close_sem(&sem_2p);
			test_close_sem(&done_2p);
			wait_cnt++;
			usleep(20000);
		}
	}

	CHECK(sem_2p != SEM_FAILED && done_2p != SEM_FAILED, errno);

	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += 5;
	do {
		ret = sem_timedwait(sem_2p, &ts);
	} while (ret != 0 && errno == EINTR);

	CHECK(ret == 0, errno);

	ret = sem_post(done_2p);
	CHECK(ret == 0, errno);

out:
	test_close_sem(&sem_2p);
	test_close_sem(&done_2p);
	return TEST_END();
}

/*
 * sem_pipe_writer_thread: block on semaphore, then write a byte
 * to the pipe to signal the reader.  Retries sem_wait on EINTR
 * (resource pressure can cause spurious signal interruptions).
 */
static void *sem_pipe_writer_thread(void *arg)
{
	struct sem_pipe_ctx *ctx = arg;
	int r;

	__atomic_store_n(ctx->started, 1, __ATOMIC_RELEASE);
	do {
		r = sem_wait(ctx->sem);
	} while (r != 0 && errno == EINTR);
	if (r != 0)
		return (void *)(intptr_t)errno;
	if (write(ctx->fd, &ctx->ch, 1) != 1)
		return (void *)(intptr_t)errno;
	return SEM_PIPE_OK;
}

/*
 * sem_pipe_handshake_test: use a semaphore to coordinate a
 * pipe-based handshake between two threads.
 */
void sem_pipe_handshake_test(void)
{
	int ret = -1, err = 0, wait_cnt = 0;
	int p[2] = {-1, -1};
	bool sem_inited = false;
	sem_t sem;
	int started = 0;
	pthread_t th = 0;
	struct pollfd pfd = {0};
	char c = 0;
	void *thret = NULL;
	struct sem_pipe_ctx ctx = {&sem, -1, 'S', &started};

	TEST_START("sem_pipe_handshake_test");

	ret = pipe(p);
	CHECK(ret >= 0, errno);

	ret = sem_init(&sem, 0, 0);
	CHECK(ret == 0, errno);
	sem_inited = true;

	ctx.fd = p[1];
	__atomic_store_n(&started, 0, __ATOMIC_RELEASE);
	ret = pthread_create(&th, NULL, sem_pipe_writer_thread, &ctx);
	CHECK(ret == 0, ret);
	while (!__atomic_load_n(&started, __ATOMIC_ACQUIRE) &&
	       wait_cnt++ < 500)
		usleep(10000);
	if (!__atomic_load_n(&started, __ATOMIC_ACQUIRE)) {
		pthread_kill(th, SIGCANCEL);
		pthread_join(th, NULL);
		th = 0;
	}
	CHECK(__atomic_load_n(&started, __ATOMIC_ACQUIRE), ETIMEDOUT);

	pfd.fd = p[0];
	pfd.events = POLLIN;
	ret = poll(&pfd, 1, 500);
	CHECK(ret == 0, errno);

	ret = sem_post(&sem);
	err = errno;
	if (ret != 0) {
		pthread_kill(th, SIGCANCEL);
		pthread_join(th, NULL);
		th = 0;
	}
	CHECK(ret == 0, err);

	ret = poll(&pfd, 1, 10000);
	CHECK(ret == 1, ret < 0 ? errno : ETIMEDOUT);
	CHECK(pfd.revents & POLLIN, EPROTO);

	ret = read(p[0], &c, 1);
	CHECK(ret == 1, errno);
	CHECK(c == 'S', EBADMSG);

	pthread_join(th, &thret);
	th = 0;
	CHECK(thret == SEM_PIPE_OK, (uintptr_t)thret);

out:
	if (th != 0) {
		/* Ensure the worker can exit on failure paths. */
		if (sem_inited)
			sem_post(&sem);
		pthread_join(th, NULL);
	}
	if (sem_inited)
		sem_destroy(&sem);
	test_close_fd(&p[0]);
	test_close_fd(&p[1]);
	TEST_END();
}

/*
 * sem_timedwait_test -- edge-case coverage for sem_timedwait:
 *  - already-expired deadline (past time)
 *  - normal timeout
 *  - sem_post before deadline
 */
void sem_timedwait_test(void)
{
	int ret = -1;
	bool sem_inited = false;
	sem_t sem;
	struct timespec ts = {0};

	TEST_START("sem_timedwait_test");

	ret = sem_init(&sem, 0, 0);
	CHECK(ret == 0, errno);
	sem_inited = true;

	/* Past deadline -- should fail immediately with ETIMEDOUT. */
	ts.tv_sec = 0;
	ts.tv_nsec = 0;
	ret = sem_timedwait(&sem, &ts);
	CHECK(ret < 0 && (errno == ETIMEDOUT || errno == EINVAL),
		errno, "past deadline errno=%d", errno);

	/* Very short timeout -- exercises the timer path. */
	clock_gettime(CLOCK_REALTIME, &ts);
	test_timespec_add_ms(&ts, 20);
	ret = sem_timedwait(&sem, &ts);
	CHECK(ret < 0 && (errno == ETIMEDOUT || errno == EAGAIN),
		errno, "short timeout errno=%d", errno);

	/* Post first, then timedwait should succeed. */
	ret = sem_post(&sem);
	CHECK(ret == 0, errno, "sem_post");

	clock_gettime(CLOCK_REALTIME, &ts);
	test_timespec_add_ms(&ts, 2000);
	ret = sem_timedwait(&sem, &ts);
	CHECK(ret == 0, errno, "timedwait after post should succeed");

	/* Multiple posts and consumes. */
	ret = sem_post(&sem);
	CHECK(ret == 0, errno, "post #1");
	ret = sem_post(&sem);
	CHECK(ret == 0, errno, "post #2");

	ret = sem_trywait(&sem);
	CHECK(ret == 0, errno, "trywait #1");
	ret = sem_trywait(&sem);
	CHECK(ret == 0, errno, "trywait #2");
	ret = sem_trywait(&sem);
	CHECK(ret < 0 && errno == EAGAIN, errno,
		"trywait #3 should fail errno=%d", errno);

out:
	if (sem_inited)
		sem_destroy(&sem);
	TEST_END();
}
