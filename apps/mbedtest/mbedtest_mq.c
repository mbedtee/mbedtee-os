// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * mbedtest_mq.c -- Message queue tests: send/receive, fd-passing, notify.
 */

#include "mbedtest.h"
#include "mbedtest_internal.h"

/* ---- Local tuning constants ------------------------------------- */
#define NOTIFY_TEST_BUF_SIZE      256
#define NOTIFY_TEST_ROUND         20
#define MQ_2PROC_TESTRUNS         15

static int mqnotify_exit[NOTIFY_TEST_ROUND];
static mqd_t mqdes[NOTIFY_TEST_ROUND];
static char mq_notify_name[NOTIFY_TEST_ROUND][64] = {{0}};
static int mq_oneshot_cnt = 0;
static char mqbigbuff[16384];

/*
 * mq_notify_sigev: signal handler for SIGEV_SIGNAL mq_notify --
 * reads one message and re-registers notification if it was oneshot.
 */
static void mq_notify_sigev(int signo, siginfo_t *info, void *ctx)
{
	struct mq_attr attr;
	ssize_t nr = -1;
	void *buf = NULL;
	char dftbuf[NOTIFY_TEST_BUF_SIZE];
	int idx = -1;

	idx = info ? info->si_value.sival_int : -1;

	if (idx < 0 || idx >= ARRAY_SIZE(mqdes))
		return;

	/*
	 * Async-signal-safety:
	 * - In SIGEV_SIGNAL context, do the minimum (set flag).
	 * - In SIGEV_THREAD context (this test passes signo == -1), it's safe
	 *   to call malloc/mq_receive/logging.
	 */
	if (signo != -1) {
		__atomic_store_n(&mqnotify_exit[idx], true, __ATOMIC_RELEASE);
		return;
	}

	TDBG("mq_notify signo %d i=%d mqdes %d\n", signo, idx, mqdes[idx]);

	/* Determine maximum msg size; allocate buffer to receive msg */

	if (mq_getattr(mqdes[idx], &attr) == -1) {
		TERR("mq_getattr %d errno %d\n", mqdes[idx], errno);
		goto out;
	}

	buf = malloc(attr.mq_msgsize);

	if (!buf)
		buf = dftbuf;

	nr = mq_receive(mqdes[idx], buf, attr.mq_msgsize, NULL);
	if (nr == -1) {
		TERR("mq_receive %d errno %d\n", mqdes[idx], errno);
		goto out;
	}

	TDBG("Read %ld bytes from message queue\n", (long) nr);

out:
	if (buf != dftbuf)
		free(buf);

	__atomic_store_n(&mqnotify_exit[idx], true, __ATOMIC_RELEASE);
}

/*
 * mq_notify_thread_cb: mq_notify callback - spawns thread
 * to receive message, then re-registers notification.
 */
static void mq_notify_thread_cb(union sigval sv)
{
	siginfo_t info;

	info.si_signo = -1;
	info.si_value = sv;
	info.si_code = SI_MESGQ;
	mq_notify_sigev(info.si_signo, &info, NULL);
}

/*
 * mq_notify_thread: Test mq_notify with SIGEV_THREAD
 * Tests: message queue notification via thread callback
 */
int mq_notify_thread(void)
{
	int ret = -1, i = 0, cnt = 0;
	struct sigevent not;
	struct mq_attr attr = {
		.mq_maxmsg = 100,
		.mq_msgsize = NOTIFY_TEST_BUF_SIZE,
	};

	TEST_START("mq_notify_thread");

	for (i = 0; i < NOTIFY_TEST_ROUND/2; i++) {
		__atomic_store_n(&mqnotify_exit[i], false, __ATOMIC_RELEASE);
		snprintf(mq_notify_name[i], sizeof(mq_notify_name[i]),
			"/%04d.msgq.notify%d", gettid(), i);
		mqdes[i] = mq_open(mq_notify_name[i], O_CREAT | O_RDWR, 0666, &attr);
		CHECK(mqdes[i] != (mqd_t)-1, errno,
			"mq_open notify thread %s", mq_notify_name[i]);

		not.sigev_notify = SIGEV_THREAD;
		not.sigev_notify_function = mq_notify_thread_cb;
		not.sigev_notify_attributes = NULL;
		not.sigev_value.sival_int = i; /* Arg. to thread func. */
		ret = mq_notify(mqdes[i], &not);
		CHECK(ret == 0 || errno == EBUSY, errno,
			"mq_notify thread %s ret=%d", mq_notify_name[i], ret);

		ret = mq_send(mqdes[i], (void *)mq_notify_name,
			test_rand() % 256, test_rand() % (MQ_PRIO_MAX - 1));
		CHECK(ret == 0, errno, "mq_send notify thread %s", mq_notify_name[i]);

		while (!__atomic_load_n(&mqnotify_exit[i], __ATOMIC_ACQUIRE) &&
		       (++cnt < 50)) {
			usleep(5000);
			TDBG("wating tfunc_exit i=%d\n", i);
		}
		CHECK(__atomic_load_n(&mqnotify_exit[i], __ATOMIC_ACQUIRE),
			ETIMEDOUT, "mq_notify thread callback %s", mq_notify_name[i]);
		ret = test_close_mq_fd(&mqdes[i]);
		CHECK(ret >= 0, errno, "mq_close notify thread %s", mq_notify_name[i]);
		test_mq_unlink(mq_notify_name[i]);
		cnt = 0;
	}

out:
	if (i >= 0 && i < NOTIFY_TEST_ROUND/2 && mqdes[i] != -1) {
		test_close_mq_fd(&mqdes[i]);
		test_mq_unlink(mq_notify_name[i]);
	}
	return TEST_END();
}

/*
 * mq_notify_signal: Test mq_notify with SIGEV_SIGNAL
 * Tests: message queue notification via signal handler
 */
int mq_notify_signal(void)
{
	int ret = -1, i = 0, cnt = 0;
	struct sigevent evp = {0};
	struct mq_attr attr = {
		.mq_maxmsg = 100,
		.mq_msgsize = NOTIFY_TEST_BUF_SIZE,
	};
	struct sigaction sa = {0};

	TEST_START("mq_notify_signal");

	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = mq_notify_sigev;
	sigemptyset(&sa.sa_mask);
	ret = sigaction(SIGUSR1, &sa, NULL);
	CHECK(ret >= 0, errno);

	for (i = NOTIFY_TEST_ROUND/2; i < NOTIFY_TEST_ROUND; i++) {
		__atomic_store_n(&mqnotify_exit[i], false, __ATOMIC_RELEASE);
		snprintf(mq_notify_name[i], sizeof(mq_notify_name[i]),
			"/%04d.msgq.notify%d", gettid(), i);
		mqdes[i] = mq_open(mq_notify_name[i], O_CREAT | O_RDWR, 0666, &attr);
		CHECK(mqdes[i] != (mqd_t)-1, errno,
			"mq_open notify signal %s", mq_notify_name[i]);

		evp.sigev_notify = SIGEV_SIGNAL;
		evp.sigev_signo = SIGUSR1;
		evp.sigev_value.sival_int = i; /* Arg. to func for idx. */

		ret = mq_notify(mqdes[i], &evp);
		CHECK(ret == 0 || errno == EBUSY, errno,
			"mq_notify signal %s ret=%d", mq_notify_name[i], ret);

		ret = mq_send(mqdes[i], (void *)mq_notify_name,
			test_rand() % 256, test_rand() % (MQ_PRIO_MAX - 1));
		CHECK(ret == 0, errno, "mq_send notify signal %s", mq_notify_name[i]);

		while (!__atomic_load_n(&mqnotify_exit[i], __ATOMIC_ACQUIRE) &&
		       (++cnt < 20)) {
			usleep(5000);
			TDBG("wating tfunc_exit i=%d\n", i);
		}
		CHECK(__atomic_load_n(&mqnotify_exit[i], __ATOMIC_ACQUIRE),
			ETIMEDOUT, "mq_notify signal callback %s", mq_notify_name[i]);
		ret = test_close_mq_fd(&mqdes[i]);
		CHECK(ret >= 0, errno, "mq_close notify signal %s", mq_notify_name[i]);
		test_mq_unlink(mq_notify_name[i]);
		cnt = 0;
	}

out:
	if (i >= NOTIFY_TEST_ROUND/2 && i < NOTIFY_TEST_ROUND &&
	    mqdes[i] != -1) {
		test_close_mq_fd(&mqdes[i]);
		test_mq_unlink(mq_notify_name[i]);
	}
	return TEST_END();
}

/*
 * mq_static_test: Test message queue static operations
 * Tests: mq_open, send, receive with static buffer
 */
int mq_static_test(void)
{
	int ret = -1, fd = -1;
	unsigned int prio = 0;
	struct mq_attr attr = {0};
	char name[256] = {0};

	TEST_START("mq_static");

	snprintf(name, 256, "/%04d%x%d.msg",
		gettid(), test_rand(), test_rand());

	attr.mq_maxmsg = 100;
	attr.mq_msgsize = sizeof(mqbigbuff);

	test_mq_unlink(name);

	fd = mq_open(name, O_RDWR | O_CREAT | O_NONBLOCK, 0666, &attr);
	CHECK(fd >= 0, errno, "mq_open static %s", name);

	ret = mq_send(fd, "11111111", 9, test_rand() % (MQ_PRIO_MAX - 1));
	CHECK(ret == 0, errno, "mq_send static #1");

	ret = mq_send(fd, "22222222", 9, test_rand() % (MQ_PRIO_MAX - 1));
	CHECK(ret == 0, errno, "mq_send static #2");

	ret = mq_send(fd, "33333333", 9, test_rand() % (MQ_PRIO_MAX - 1));
	CHECK(ret == 0, errno, "mq_send static #3");

	ret = mq_receive(fd, mqbigbuff, sizeof(mqbigbuff), &prio);
	CHECK(ret == 9, errno, "mq_receive static #1 ret=%d", ret);

	ret = mq_receive(fd, mqbigbuff, sizeof(mqbigbuff), &prio);
	CHECK(ret == 9, errno, "mq_receive static #2 ret=%d", ret);

	ret = mq_receive(fd, mqbigbuff, sizeof(mqbigbuff), &prio);
	CHECK(ret == 9, errno, "mq_receive static #3 ret=%d", ret);

out:
	test_close_mq_fd(&fd);

	test_mq_unlink(name);
	return TEST_END();
}

bool mq_test_peer_died(pid_t peer)
{
	int st = 0;
	pid_t w;

	if (peer < 0)
		return false;

	w = waitpid(peer, &st, WNOHANG);
	if (w == peer) {
		/* Peer already exited - likely resource exhaustion */
		TDBG("peer %04d exited early (st=%d)\n", peer, st);
		return true;
	}
	if (w < 0 && errno == ECHILD) {
		/* No such child - already reaped or never existed */
		return true;
	}
	return false;
}

int mq_receive_fd_timed(mqd_t mqdes, int *outfd, long timeout_ms)
{
	struct timeval start = {0}, now = {0};
	long long elapsed = 0;
	int ret = -1;

	if (!outfd)
		return EINVAL;

	gettimeofday(&start, NULL);

	for (;;) {
		ret = mq_receive_fd(mqdes, outfd);
		if (ret >= 0)
			return 0;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			gettimeofday(&now, NULL);
			elapsed = (now.tv_sec - start.tv_sec) * 1000LL +
				(now.tv_usec - start.tv_usec) / 1000LL;
			if (elapsed >= timeout_ms)
				return ETIMEDOUT;
			usleep(20000);
			continue;
		}
		return errno;
	}
}

/*
 * Test mq_send with file descriptor passing between processes
 */
int mq_fd_2proc_send(void)
{
	pid_t peer = -1;
	int ret = -1, fd = -1, mqdes = -1;
	int st = 0, rc = 0;
	char name[128] = {0}, fdtestfile[128] = {0};
	char *argv[4] = {"mbedtest", "--sendfd", name, NULL};

	TEST_START("mq_fd_2proc_send");

	snprintf(name, sizeof(name), "/mq_2procfd_%04d_%x%d.msg",
		gettid(), test_rand(), test_rand());
	snprintf(fdtestfile, sizeof(fdtestfile), "/shm/mq_2procfd_%04d_%x%d.txt",
		gettid(), test_rand(), test_rand());

	test_mq_unlink(name);
	test_unlink(fdtestfile);

	mqdes = mq_open(name, O_RDWR | O_CREAT, 0666, NULL);
	CHECK(mqdes >= 0, errno, "mq_open fd-pass %s", name);

	rc = posix_spawn(&peer, argv[0], NULL, NULL, argv, NULL);
	CHECK(rc == 0, rc);

	/* Coverage: stop peer while setting up fd passing, then resume it. */
	ret = test_rand() % 2 ? kill(peer, SIGSTOP) :
		test_rand() % 2 ? pthread_kill((pthread_t)peer, SIGSTOP) :
		test_rand() % 2 ? pthread_sigqueue((pthread_t)peer, SIGSTOP,
		(union sigval)(0)) : sigqueue(peer, SIGSTOP, (union sigval)(0));
	if (ret != 0 && errno == ESRCH)
		peer = -1;
	CHECK(ret == 0, errno);

	fd = open(fdtestfile, O_RDWR | O_CREAT);
	CHECK(fd >= 0, errno);

	ret = test_write_full(fd, "1234a55a", 9);
	CHECK(ret == 9, errno);
	lseek(fd, 0, SEEK_SET);

	ret = mq_send_fd(mqdes, fd);
	CHECK(ret >= 0, errno, "mq_send_fd fd-pass fd=%d", fd);
	test_close_fd(&fd);

	ret = test_close_mq_fd(&mqdes);
	CHECK(ret >= 0, errno, "mq_close fd-pass ret=%d", ret);

	sleep(2);
	ret = test_rand() % 2 ? kill(peer, SIGCONT) :
		test_rand() % 2 ? pthread_kill((pthread_t)peer, SIGCONT) :
		test_rand() % 2 ? pthread_sigqueue((pthread_t)peer, SIGCONT,
		(union sigval)(0)) : sigqueue(peer, SIGCONT, (union sigval)(0));
	if (ret != 0 && errno == ESRCH)
		peer = -1;
	CHECK(ret == 0, errno);

	/* Reap peer deterministically (posix_spawn child). */
	CHECK(waitpid(peer, &st, 0) >= 0, errno);
	CHECK(st == 0, st);
	peer = -1;

out:
	if (peer >= 0) {
		if (TEST_FAILED())
			kill(peer, SIGKILL);
		waitpid(peer, &st, 0);
	}

	if (TEST_FAILED()) {
		test_mq_unlink(name);
		test_close_fd(&fd);
	}

	test_close_mq_fd(&mqdes);
	test_unlink(fdtestfile);

	return TEST_END();
}

/*
 * Test mq_receive with file descriptor passing between processes
 */
int mq_fd_2proc_recv(const char *mq_name)
{
	int ret = -1, fd = -1, mqdes = -1;
	char buaff[64] = {0};
	char name[128] = {0};

	TEST_START("mq_fd_2proc_recv");

	strlcpy(name, mq_name, sizeof(name));

	TEST_POLL_OPEN(mqdes, -1, mq_open(name, O_RDONLY | O_NONBLOCK), 30000);
	CHECK(mqdes >= 0, errno, "name %s", name);

	ret = mq_receive_fd_timed(mqdes, &fd, 10000);
	CHECK(ret == 0, ret, "mq_receive_fd fd=%d ret=%d", fd, ret);

	ret = test_read_full(fd, buaff, 9);
	CHECK(ret == 9, errno, "fd-pass read ret=%d", ret);
	CHECK(memcmp(buaff, "1234a55a", 9) == 0, EBADMSG,
		"fd-pass payload=%s", buaff);
	close(fd);

	ret = test_close_mq_fd(&mqdes);
	CHECK(ret >= 0, errno, "mq_close fd-pass recv ret=%d", ret);

out:
	test_close_mq_fd(&mqdes);
	test_mq_unlink(name);
	return TEST_END();
}

/*
 * Test message queue send between processes
 */
int mq_2proc_send(void)
{
	pid_t peer = -1;
	int ret = -1, fd = -1, i = 0;
	int st = 0, rc;
	char name[128] = {0};
	struct mq_attr attr = {0};
	struct timespec ts = {0};
	char *argv[4] = {"mbedtest", "--msgq", name, NULL};

	TEST_START("mq_2proc_send");

	/*
	 * Use sender's TID + random for the MQ name to avoid stale-MQ races.
	 * Spawn and stop the child first, then create and fill the MQ while
	 * the child is stopped, so the SIGSTOP/SIGCONT coverage is reliable.
	 */
	snprintf(name, sizeof(name), "/mq_2proc_%04d_%x%d.msg",
		gettid(), test_rand(), test_rand());

	attr.mq_maxmsg = MQ_2PROC_TESTRUNS;
	attr.mq_msgsize = sizeof(mqbigbuff) >> (test_rand() % 8);

	test_mq_unlink(name);

	/* Spawn child first, then stop it while we prepare the MQ */
	rc = posix_spawn(&peer, argv[0], NULL, NULL, argv, NULL);
	CHECK(rc == 0, rc);

	/* Coverage: hold peer stopped while filling the MQ */
	ret = test_rand() % 2 ? kill(peer, SIGSTOP) :
		test_rand() % 2 ? pthread_kill((pthread_t)peer, SIGSTOP) :
		test_rand() % 2 ? pthread_sigqueue((pthread_t)peer, SIGSTOP,
		 (union sigval)(0)) : sigqueue(peer, SIGSTOP, (union sigval)(0));
	if (ret != 0 && errno == ESRCH)
		peer = -1;
	CHECK(ret == 0, errno);
	sleep(1);

	fd = mq_open(name, O_RDWR | O_CREAT, 0666, &attr);
	CHECK(fd >= 0, errno, "mq_open 2proc %s", name);

	for (i = 0; i < MQ_2PROC_TESTRUNS; i++) {
		snprintf(mqbigbuff, sizeof(mqbigbuff), "%d", i);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 5;
		ret = mq_timedsend(fd, mqbigbuff, attr.mq_msgsize, i, &ts);
		CHECK(ret >= 0, errno, "mq_timedsend i=%d", i);
	}

	CHECK(i == MQ_2PROC_TESTRUNS, EBADMSG, "sent msgs=%d", i);
	ret = mq_getattr(fd, &attr);
	CHECK(ret >= 0, errno);

	ret = test_close_mq_fd(&fd);
	CHECK(ret >= 0, errno);

	sleep(1);
	/* Resume child to let it receive all messages */
	ret = test_rand() % 2 ? kill(peer, SIGCONT) :
		test_rand() % 2 ? pthread_kill((pthread_t)peer, SIGCONT) :
		test_rand() % 2 ? pthread_sigqueue((pthread_t)peer, SIGCONT,
		 (union sigval)(0)) : sigqueue(peer, SIGCONT, (union sigval)(0));
	if (ret != 0 && errno == ESRCH)
		peer = -1;
	CHECK(ret == 0, errno);

	/* Reap peer deterministically. */
	CHECK(waitpid(peer, &st, 0) >= 0, errno);
	CHECK(st == 0, st);
	peer = -1;

	/* Best-effort cleanup if peer didn't mq_unlink. */
	test_mq_unlink(name);

out:
	if (peer >= 0) {
		if (TEST_FAILED())
			kill(peer, SIGKILL);
		waitpid(peer, &st, 0);
	}
	if (TEST_FAILED())
		test_mq_unlink(name);

	test_close_mq_fd(&fd);
	return TEST_END();
}

/*
 * Test message queue receive between processes
 */
int mq_2proc_recv(const char *mq_name)
{
	int ret = -1, fd = -1, i = 0;
	int expected = MQ_2PROC_TESTRUNS;
	char name[128] = {0};
	unsigned int prio = 0;
	struct timespec ts = {0};

	TEST_START("mq_2proc_recv");

	strlcpy(name, mq_name, sizeof(name));

	TEST_POLL_OPEN(fd, -1, mq_open(name, O_RDONLY), 30000);
	CHECK(fd >= 0, errno, "name %s", name);

	for (i = 0; i < expected; i++) {
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 5;
		ret = mq_timedreceive(fd, mqbigbuff, sizeof(mqbigbuff), &prio, &ts);
		CHECK(ret >= 0, errno, "mq_timedreceive i=%d prio=%d ret=%d",
			i, prio, ret);
		/*
		 * Sender uses priority 0..N-1 for N messages. The first
		 * message received carries the highest priority = N-1,
		 * so expected = prio + 1 auto-detects the actual count
		 * even if the sender only managed to post a subset.
		 */
		if (i == 0)
			expected = prio + 1;
	}

	CHECK(i == expected, EBADMSG, "received msgs=%d expected=%d",
		i, expected);

	ret = test_close_mq_fd(&fd);
	CHECK(ret >= 0, errno);

out:
	test_close_mq_fd(&fd);
	test_mq_unlink(name);
	return TEST_END();
}

/*
 * mq_setattr_nonblock_test: verify mq_setattr O_NONBLOCK
 * flag -- non-blocking send/receive on full/empty queue.
 */
void mq_setattr_nonblock_test(void)
{
	int ret = -1;
	mqd_t q = (mqd_t)-1;
	char name[64] = {0};
	struct mq_attr a = {0};
	struct mq_attr oa = {0};
	char buf[16] = {0};
	unsigned int prio = 0;

	TEST_START("mq_setattr_nonblock_test");

	snprintf(name, sizeof(name), "/%04d.nbq.%d%x",
			gettid(), test_rand(), test_rand());
	test_mq_unlink(name);
	a.mq_maxmsg = 4;
	a.mq_msgsize = sizeof(buf);
	q = mq_open(name, O_CREAT | O_RDWR, 0666, &a);
	CHECK(q != (mqd_t)-1, errno);

	a.mq_flags = O_NONBLOCK;
	ret = mq_setattr(q, &a, &oa);
	CHECK(ret == 0, errno, "mq_setattr O_NONBLOCK");

	ret = mq_receive(q, buf, sizeof(buf), &prio);
	CHECK(ret < 0, EBADMSG);
	CHECK(errno == EAGAIN, errno);

	ret = mq_send(q, "Z", 2, 1);
	CHECK(ret == 0, errno);

	memset(buf, 0, sizeof(buf));
	ret = mq_receive(q, buf, sizeof(buf), &prio);
	CHECK(ret == 2, errno);
	CHECK(buf[0] == 'Z', EBADMSG);

out:
	test_close_mq_fd(&q);
	test_mq_unlink(name);
	TEST_END();
}

/*
 * mq_priority_order_test: verify messages with different
 * priorities are received in priority order (highest first).
 */
void mq_priority_order_test(void)
{
	int ret = -1;
	mqd_t q = (mqd_t)-1;
	char name[64] = {0};
	struct mq_attr a = {0};
	char buf[16] = {0};
	unsigned int prio = 0;

	TEST_START("mq_priority_order_test");

	snprintf(name, sizeof(name), "/%04d.prioq.%d",
		gettid(), test_rand());
	test_mq_unlink(name);
	a.mq_maxmsg = 8;
	a.mq_msgsize = sizeof(buf);
	q = mq_open(name, O_CREAT | O_RDWR, 0666, &a);
	CHECK(q != (mqd_t)-1, errno);

	ret = mq_send(q, "L", 2, 1);
	CHECK(ret == 0, errno);
	ret = mq_send(q, "H", 2, 3);
	CHECK(ret == 0, errno);

	memset(buf, 0, sizeof(buf));
	ret = mq_receive(q, buf, sizeof(buf), &prio);
	CHECK(ret == 2, errno);
	CHECK(prio == 3, EBADMSG);
	CHECK(buf[0] == 'H', EBADMSG);

	memset(buf, 0, sizeof(buf));
	ret = mq_receive(q, buf, sizeof(buf), &prio);
	CHECK(ret == 2, errno);
	CHECK(prio == 1, EBADMSG);
	CHECK(buf[0] == 'L', EBADMSG);

out:
	test_close_mq_fd(&q);
	test_mq_unlink(name);
	TEST_END();
}

static void mq_oneshot_cb(union sigval)
{
	__atomic_add_fetch(&mq_oneshot_cnt, 1, __ATOMIC_ACQUIRE);
}

static void mq_oneshot_sig(int, siginfo_t *, void *)
{
	__atomic_add_fetch(&mq_oneshot_cnt, 1, __ATOMIC_ACQUIRE);
}

/*
 * mq_notify_oneshot_thread_test: verify mq_notify is
 * oneshot -- only one notification fires, then must be
 * re-registered. Uses thread-based notification.
 */
void mq_notify_oneshot_thread_test(void)
{
	int ret = -1, cnt = 0;
	mqd_t q = (mqd_t)-1;
	char name[64] = {0}, buf[16] = {0};
	struct mq_attr a = {0};
	struct sigevent sev = {0};
	unsigned int prio = 0;

	TEST_START("mq_notify_oneshot_thread");

	snprintf(name, sizeof(name), "/%04d.oneshot.%d%x",
			gettid(), test_rand(), test_rand());
	test_mq_unlink(name);

	a.mq_maxmsg = 8;
	a.mq_msgsize = sizeof(buf);
	q = mq_open(name, O_CREAT | O_RDWR, 0666, &a);
	CHECK(q != (mqd_t)-1, errno);

	__atomic_store_n(&mq_oneshot_cnt, 0, __ATOMIC_RELEASE);
	sev.sigev_notify = SIGEV_THREAD;
	sev.sigev_notify_function = mq_oneshot_cb;
	sev.sigev_notify_attributes = NULL;
	sev.sigev_value.sival_int = 0;
	ret = mq_notify(q, &sev);
	CHECK(ret == 0, errno);
	ret = mq_send(q, "1", 2, 1);
	CHECK(ret == 0, errno);
	while ((__atomic_load_n(&mq_oneshot_cnt, __ATOMIC_ACQUIRE) != 1) && (++cnt < 200))
		usleep(20000);
	CHECK(__atomic_load_n(&mq_oneshot_cnt, __ATOMIC_ACQUIRE) == 1, ETIMEDOUT);

	ret = mq_receive(q, buf, sizeof(buf), &prio);
	CHECK(ret >= 0, errno);

	ret = mq_send(q, "2", 2, 1);
	CHECK(ret == 0, errno);
	usleep(300000);
	CHECK(__atomic_load_n(&mq_oneshot_cnt, __ATOMIC_ACQUIRE) == 1, EBADMSG);

	ret = mq_receive(q, buf, sizeof(buf), &prio);
	CHECK(ret >= 0, errno);

	ret = mq_notify(q, &sev);
	CHECK(ret == 0, errno);

	ret = mq_send(q, "3", 2, 1);
	CHECK(ret == 0, errno);
	cnt = 0;
	while (__atomic_load_n(&mq_oneshot_cnt, __ATOMIC_ACQUIRE) != 2 && (++cnt < 200))
		usleep(20000);
	CHECK(__atomic_load_n(&mq_oneshot_cnt, __ATOMIC_ACQUIRE) == 2, ETIMEDOUT);

	ret = mq_receive(q, buf, sizeof(buf), &prio);
	CHECK(ret >= 0, errno);

out:
	test_close_mq_fd(&q);
	test_mq_unlink(name);
	TEST_END();
}

/*
 * mq_notify_oneshot_signal_test: same as thread variant
 * but uses signal-based notification (SIGEV_SIGNAL).
 */
void mq_notify_oneshot_signal_test(void)
{
	int ret = -1, cnt = 0;
	mqd_t q = (mqd_t)-1;
	char name[64] = {0}, buf[16] = {0};
	struct mq_attr a = {0};
	struct sigevent sev = {0};
	struct sigaction sa = {0}, oldsa = {0};
	int have_oldsa = 0;
	unsigned int prio = 0;
	sigset_t set;

	TEST_START("mq_notify_oneshot_signal");

	sigemptyset(&set);
	sigaddset(&set, SIGUSR2);
	pthread_sigmask(SIG_UNBLOCK, &set, NULL);

	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = mq_oneshot_sig;
	sigemptyset(&sa.sa_mask);
	ret = sigaction(SIGUSR2, &sa, &oldsa);
	CHECK(ret >= 0, errno);
	have_oldsa = 1;

	snprintf(name, sizeof(name), "/%04d.oneshot.%d%x",
			gettid(), test_rand(), test_rand());
	test_mq_unlink(name);

	a.mq_maxmsg = 8;
	a.mq_msgsize = sizeof(buf);
	q = mq_open(name, O_CREAT | O_RDWR, 0666, &a);
	CHECK(q != (mqd_t)-1, errno);

	__atomic_store_n(&mq_oneshot_cnt, 0, __ATOMIC_RELEASE);
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGUSR2;
	sev.sigev_value.sival_int = 0;
	ret = mq_notify(q, &sev);
	CHECK(ret == 0, errno);

	ret = mq_send(q, "1", 2, 1);
	CHECK(ret == 0, errno);
	while (__atomic_load_n(&mq_oneshot_cnt, __ATOMIC_ACQUIRE) != 1 && (++cnt < 200))
		usleep(20000);
	CHECK(__atomic_load_n(&mq_oneshot_cnt, __ATOMIC_ACQUIRE) == 1, ETIMEDOUT);

	ret = mq_receive(q, buf, sizeof(buf), &prio);
	CHECK(ret >= 0, errno);

	ret = mq_send(q, "2", 2, 1);
	CHECK(ret == 0, errno);
	usleep(30000);
	CHECK(__atomic_load_n(&mq_oneshot_cnt, __ATOMIC_ACQUIRE) == 1, EBADMSG);

	ret = mq_receive(q, buf, sizeof(buf), &prio);
	CHECK(ret >= 0, errno);

	ret = mq_notify(q, &sev);
	CHECK(ret == 0, errno);
	ret = mq_send(q, "3", 2, 1);
	CHECK(ret == 0, errno);
	cnt = 0;
	while (__atomic_load_n(&mq_oneshot_cnt, __ATOMIC_ACQUIRE) != 2 && (++cnt < 200))
		usleep(20000);
	CHECK(__atomic_load_n(&mq_oneshot_cnt, __ATOMIC_ACQUIRE) == 2, ETIMEDOUT);

	ret = mq_receive(q, buf, sizeof(buf), &prio);
	CHECK(ret >= 0, errno);

out:
	test_close_mq_fd(&q);
	test_mq_unlink(name);
	if (have_oldsa)
		sigaction(SIGUSR2, &oldsa, NULL);
	TEST_END();
}

/*
 * mq_timed_edges_test -- edge-case coverage for mq_timedsend / mq_timedreceive:
 *  - receive on empty queue with past deadline -> ETIMEDOUT
 *  - send on full queue with short timeout
 *  - getattr round-trip
 */
void mq_timed_edges_test(void)
{
	int ret = -1;
	mqd_t mq = -1;
	struct mq_attr attr = {0};
	struct mq_attr cur = {0};
	struct timespec ts = {0};
	char name[64];
	char buf[64];
	unsigned prio = 0;

	TEST_START("mq_timed_edges_test");
	snprintf(name, sizeof(name), "/%04d.timed.%d", gettid(),
		test_rand());
	test_mq_unlink(name);

	attr.mq_flags = 0;
	attr.mq_maxmsg = 2;
	attr.mq_msgsize = sizeof(buf);
	attr.mq_curmsgs = 0;

	mq = mq_open(name, O_CREAT | O_EXCL | O_RDWR, 0600, &attr);
	CHECK(mq != (mqd_t)-1, errno, "mq_open %s", name);

	/* getattr round-trip */
	ret = mq_getattr(mq, &cur);
	CHECK(ret == 0, errno, "mq_getattr");
	CHECK(cur.mq_maxmsg == 2, EBADMSG, "maxmsg=%ld", cur.mq_maxmsg);
	CHECK(cur.mq_msgsize >= (long)sizeof(buf), EBADMSG,
		"msgsize=%ld", cur.mq_msgsize);
	CHECK(cur.mq_curmsgs == 0, EBADMSG, "curmsgs=%ld", cur.mq_curmsgs);

	/* receive on empty queue with past deadline */
	ts.tv_sec = 0;
	ts.tv_nsec = 0;
	ret = mq_timedreceive(mq, buf, sizeof(buf), &prio, &ts);
	CHECK(ret < 0, errno, "past deadline recv should fail");
	CHECK(errno == ETIMEDOUT || errno == EINVAL || errno == EAGAIN,
		errno, "past deadline errno");

	/* send two messages to fill the queue */
	clock_gettime(CLOCK_REALTIME, &ts);
	test_timespec_add_ms(&ts, 2000);
	memset(buf, 'A', sizeof(buf));
	ret = mq_timedsend(mq, buf, sizeof(buf), 1, &ts);
	CHECK(ret == 0, errno, "send #1");

	memset(buf, 'B', sizeof(buf));
	ret = mq_timedsend(mq, buf, sizeof(buf), 2, &ts);
	CHECK(ret == 0, errno, "send #2");

	/* queue is full -- send with short timeout should fail */
	clock_gettime(CLOCK_REALTIME, &ts);
	test_timespec_add_ms(&ts, 30);
	ret = mq_timedsend(mq, buf, sizeof(buf), 0, &ts);
	CHECK(ret < 0, errno, "full queue send should fail");
	CHECK(errno == ETIMEDOUT || errno == EAGAIN, errno, "full queue errno");

	/* verify curmsgs == 2 */
	ret = mq_getattr(mq, &cur);
	CHECK(ret == 0, errno, "mq_getattr after fill");
	CHECK(cur.mq_curmsgs == 2, EBADMSG,
		"curmsgs after fill=%ld", cur.mq_curmsgs);

	/* receive by priority: highest first (prio=2) */
	clock_gettime(CLOCK_REALTIME, &ts);
	test_timespec_add_ms(&ts, 200);
	ret = mq_timedreceive(mq, buf, sizeof(buf), &prio, &ts);
	CHECK(ret > 0, errno, "recv #1");
	CHECK(prio == 2, EBADMSG, "prio #1=%u", prio);

	clock_gettime(CLOCK_REALTIME, &ts);
	test_timespec_add_ms(&ts, 200);
	ret = mq_timedreceive(mq, buf, sizeof(buf), &prio, &ts);
	CHECK(ret > 0, errno, "recv #2");
	CHECK(prio == 1, EBADMSG, "prio #2=%u", prio);

	/* verify curmsgs back to 0 */
	ret = mq_getattr(mq, &cur);
	CHECK(ret == 0, errno, "mq_getattr after drain");
	CHECK(cur.mq_curmsgs == 0, EBADMSG,
		"curmsgs after drain=%ld", cur.mq_curmsgs);

out:
	test_close_mq_fd(&mq);
	test_mq_unlink(name);
	TEST_END();
}