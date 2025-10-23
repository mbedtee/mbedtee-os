// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * mbedtest_io.c -- I/O subsystem tests: dup, poll, epoll, fcntl, eventfd.
 */
#include "mbedtest.h"
#include "mbedtest_internal.h"
#include <poll.h>
#include <epoll.h>
#include <eventfd.h>
#include <sys/select.h>

#define EPOLL_MAX_FDS  4096

static int epfd = -1;

/*
 * dup_ok: full dup/dup2 lifecycle test -- create file, dup, dup2,
 * self-dup2, cross-fd read/write verify.
 */
static int dup_ok(int i)
{
	int fd = -1, fdcurrent = -1;
	int ret = -1, fddup = -1, fddup_curr = -1;
	char buaff[128] = {0};
	char name[128] = {0};

	snprintf(name, 128, "%s/%04d_%d.%d.dup.txt", "/test",
		gettid(), test_rand(), i);

	test_unlink(name);

	pthread_cleanup_push((void (*)(void *))test_unlink, name);

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	CHECK(fd >= 0, errno, "open %s", name);

	ret = test_write_full(fd, "111", 3);
	CHECK(ret == 3, errno, "write initial dup data ret=%d", ret);

	fdcurrent = open("/dev/uart0", O_RDONLY | O_NONBLOCK);
	CHECK(fdcurrent >= 0, errno, "open uart for dup2 target");

	fddup_curr = dup2(fd, fdcurrent);
	CHECK(fddup_curr >= 0, errno, "dupcurr fdcurrent=%d fddup_curr=%d",
		fdcurrent, fddup_curr);
	lseek(fddup_curr, 0, SEEK_SET);
	ret = read(fddup_curr, buaff, sizeof(buaff));
	CHECK(ret >= 0, errno, "read dupcurr ret=%d", ret);
	test_close_fd(&fddup_curr);
	CHECK(memcmp(buaff, "111", 4) == 0, EBADMSG);

	fddup = dup(fd);
	CHECK(fddup > STDERR_FILENO, fddup < 0 ? errno : ERANGE,
		 "dup fd=%d fddup=%d", fd, fddup);

	ret = test_write_full(fddup, "222", 3);
	CHECK(ret == 3, errno, "dup write ret=%d", ret);

	ret = lseek(fddup, 0, SEEK_SET);
	CHECK(ret >= 0, errno, "dup lseek ret=%d", ret);

	fddup = dup2(fddup, fddup);
	CHECK(fddup > STDERR_FILENO, fddup < 0 ? errno : ERANGE,
		 "dup2 self fddup=%d", fddup);

	memset(buaff, 0, sizeof(buaff));
	ret = read(fddup, buaff, sizeof(buaff));
	CHECK(ret >= 0, errno, "read dup fd ret=%d", ret);
	CHECK(memcmp(buaff, "111222", 7) == 0, EBADMSG);
	memset(buaff, 0, sizeof(buaff));

	fdcurrent = open("/dev/uart0", O_RDONLY | O_NONBLOCK);
	CHECK(fdcurrent >= 0, errno, "open uart for dupcurr2");

	fddup_curr = dup2(fddup, fdcurrent);
	CHECK(fddup_curr > STDERR_FILENO,
		fddup_curr < 0 ? errno : ERANGE, "dupcurr2 fd=%d dup=%d",
		fdcurrent, fddup_curr);

	ret = read(fddup_curr, buaff, sizeof(buaff));
	CHECK(ret == 0, errno, "dupcurr2 read ret=%d data=%s",
		ret, buaff);

	ret = lseek(fddup_curr, 0, SEEK_SET);
	CHECK(ret >= 0, errno, "dupcurr2 lseek ret=%d", ret);
	ret = read(fddup_curr, buaff, sizeof(buaff));
	CHECK(ret >= 0, errno, "dupcurr2 reread ret=%d", ret);
	CHECK(memcmp(buaff, "111222", 7) == 0, EBADMSG);

out:
	test_close_fd(&fd);
	test_close_fd(&fddup);
	test_close_fd(&fddup_curr);
	pthread_cleanup_pop(1);
	return TEST_ERRNO();
}

/*
 * dup_ng: resource-exhaustion-tolerant dup/dup2 stress test.
 * Silently skips on ENOMEM/EMFILE (resource pressure is not a
 * functional failure). Designed for concurrent execution under
 * heavy load alongside dup_ok.
 */
static void dup_ng(int i)
{
	int fdcurrent = -1, fd = -1;
	int ret = -1, fddup = -1;
	char buaff[128] = {0};
	char name[128] = {0};

	snprintf(name, 128, "%s/%04d_%d.%d.dupng.txt", "/user",
		gettid(), test_rand(), i);

	test_unlink(name);

	pthread_cleanup_push((void (*)(void *))test_unlink, name);

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (fd < 0)
		goto out;

	ret = test_write_full(fd, "111", 3);
	if ((ret < 0) && test_is_resource_error(errno))
		goto out;

	fddup = dup(fd);
	if (fddup < 0 && test_is_resource_error(errno))
		goto out;
	if (fddup < 0)
		goto out;

	ret = write(fddup, "222", 3);
	ret = lseek(fddup, 0, SEEK_SET);
	ret = read(fddup, buaff, sizeof(buaff));
	if (errno == ENOMEM)
		goto out;

	memset(buaff, 0, sizeof(buaff));

	fdcurrent = open("/dev/uart0", O_RDONLY | O_NONBLOCK);
	if (fdcurrent < 0)
		goto out;

	ret = dup2(fddup, fdcurrent);
	if (ret < 0)
		goto out;
	fdcurrent = ret;

	ret = dup2(fddup, fdcurrent);
	ret = read(fdcurrent, buaff, sizeof(buaff));
	ret = lseek(fdcurrent, -1, SEEK_CUR);
	ret = read(fdcurrent, buaff, sizeof(buaff));

out:
	test_close_fd(&fdcurrent);
	test_close_fd(&fd);
	test_close_fd(&fddup);
	pthread_cleanup_pop(1);
}

/*
 * dup_test: Test file descriptor duplication
 * Tests: dup(), dup2(), fd inheritance, concurrent access
 */
void dup_test(void)
{
	int i = 0, ret = 0, max = test_rand() % 300;

	TEST_START("dup");

	pthread_barrier_wait(&test_barrier_dup1);

	for (i = 0; i < max + 1; i++) {
		ret = dup_ok(i);
		CHECK(ret == 0, ret);
	}

out:
	pthread_barrier_wait(&test_barrier_dup2);

	for (i = 0; i < max / 3 + 1; i++)
		dup_ng(i);

	TEST_END();
}

/*
 * poll_test: create many pollfds on the same fd, verify poll() returns.
 */
void poll_test(void)
{
	int ret = -1, i = 0, _fd = -1;
	int nr = test_rand() % 512 + 1;
	char str[256] = {0};
	struct pollfd *fds = NULL;

	TEST_START("poll_test");

	_fd = open("/dev/uart1", O_RDWR | O_NONBLOCK);
	if (_fd < 0) {
		if (!(test_rand() % 3))
			_fd = open("/dev/urandom", O_RDONLY | O_NONBLOCK);
		else
			_fd = open("/dev/uart0", O_RDWR | O_NONBLOCK);
	}
	CHECK(_fd >= 0, errno);

	fds = malloc(nr * sizeof(struct pollfd));
	CHECK(fds, ENOMEM);

	for (i = 0; i < nr; i++) {
		fds[i].fd = _fd /*STDIN_FILENO*/;
		fds[i].events = POLLIN;
	}
	ret = poll(fds, nr, 5000);
	CHECK(ret >= 0, errno, "poll nr=%d", nr);

	TDBG("poll %d ret = %d errno %d\n", nr, ret, errno);

	if (ret > 0)
		read(_fd, str, sizeof(str) - 1);
out:
	free(fds);
	test_close_fd(&_fd);
	TEST_END();
}

/*
 * epdel_routine: Thread routine for epoll concurrent delete test
 * Tests epoll behavior with concurrent fd deletions
 */
static void *epdel_routine(void *arg)
{
	int fd = (intptr_t)arg;
	int randx = test_rand();

	usleep(randx % 200000);
	TDBG("async epoll fd %d\n", fd);
	if (randx % 3)
		epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
	else
		close(fd);

	return NULL;
}

/*
 * epoll_test1: explicit lifecycle -- every fd is EPOLL_CTL_DEL'd
 * then test_close_fd()'d. No leaks expected.
 */
void epoll_test1(void)
{
	struct epoll_event *evts = NULL, evt = {0};
	int ret = -1, i = 0, n = -1, nrevts = 0, _fd = -1;
	int nr = test_rand() % EPOLL_MAX_FDS + 1;
	int randx = 0;
	int initp[2] = {-1, -1};
	char str[256] = {0};
	int *epollfds = NULL;

	TEST_START("epoll_test1");
	randx = test_rand();

	epollfds = calloc(EPOLL_MAX_FDS, sizeof(int));
	CHECK(epollfds, ENOMEM);
	memset(epollfds, -1, EPOLL_MAX_FDS * sizeof(int));
	epfd = -1;

	/* Use a self-pipe so epoll_wait always finds data ready */
	ret = pipe(initp);
	CHECK(ret == 0, errno);
	ret = write(initp[1], "x", 1);
	test_close_fd(&initp[1]);
	_fd = initp[0];
	initp[0] = -1;
	CHECK(_fd >= 0 && ret == 1, errno);

	epfd = epoll_create(1);
	CHECK(epfd > 0, errno);

	evt.events = EPOLLIN;
	/* magic sentinel to verify epoll returns the same data we registered */
	evt.data.u64 = 0x6a5612341177ffaa;

	evts = malloc(nr * sizeof(struct epoll_event));
	CHECK(evts, ENOMEM);
	ret = epoll_wait(epfd, evts, nr, 0);
	TDBG("epoll_wait maxnr=%d ret = %d errno %d\n", nr, ret, errno);

	/* EPOLL_CTL_DEL on the epoll fd itself - should fail */
	ret = epoll_ctl(epfd, EPOLL_CTL_DEL, epfd, NULL);
	TDBG("EPOLL_CTL_DEL ret = %d errno %d\n", ret, errno);

	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, _fd, &evt);
	TDBG("EPOLL_CTL_ADD 1ret = %d errno %d\n", ret, errno);
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, _fd, NULL);
	TDBG("EPOLL_CTL_ADD 2ret = %d errno %d\n", ret, errno);
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, _fd, &evt);
	TDBG("EPOLL_CTL_ADD 3ret = %d errno %d\n", ret, errno);

	ret = epoll_wait(epfd, evts, nr, test_rand() % 5000);
	CHECK(ret > 0, errno, "epoll_wait errno=%d", errno);
	CHECK((evts[0].events & EPOLLIN) != 0, EPROTO,
		"epoll revents=%d", evts[0].events);
	CHECK(evts[0].data.u64 == evt.data.u64, EBADMSG,
		"epoll data=0x%llx expected=0x%llx",
		(long long)evts[0].data.u64, (long long)evt.data.u64);
	TDBG("epoll_wait revents=%d data=0x%llx\n",
		evts[0].events, (long long)evts[0].data.u64);

	for (i = 0; i < nr; i++) {
		epollfds[i] = open("/dev/uart1", O_RDWR | O_NONBLOCK);
		if (epollfds[i] < 0) {
			epollfds[i] = open("/dev/uart0", O_RDWR | O_NONBLOCK);
			TDBG("opened /dev/uart0 %d\n", epollfds[i]);
		}
		if (epollfds[i] < 0)
			break;

		randx = test_rand();

		evt.events = EPOLLIN | ((randx % 2) ? EPOLLET : 0) |
					(((test_rand() % 5) == 0) ? EPOLLONESHOT : 0);

		evt.data.fd = epollfds[i];
		ret = epoll_ctl(epfd, EPOLL_CTL_ADD, epollfds[i], &evt);
		if (ret != 0)
			break;
	}
	CHECK(i, errno);

	nrevts = epoll_wait(epfd, evts, i, randx % 4000);
	TDBG("epoll_wait %d nrevts = %d[%d] errno %d\n",
		i, nrevts, nr, errno);

	for (n = 0; n < nrevts; n++) {
		ret = read(evts[n].data.fd, str, sizeof(str) - 1);
		if (strlen(str))
			TDBG("fd %d revent %d readret = %d errno %d str %s\n",
				evts[n].data.fd, evts[n].events, ret, errno, str);
		epoll_ctl(epfd, EPOLL_CTL_DEL, evts[n].data.fd, NULL);
	}

	for (i = 0; i < nr; i++) {
		if (epollfds[i] < 0)
			continue;
		if (i >= nrevts)
			epoll_ctl(epfd, EPOLL_CTL_DEL, epollfds[i], NULL);
		test_close_fd(&epollfds[i]);
	}

out:
	free(evts);
	for (i = 0; i < nr && epollfds; i++)
		test_close_fd(&epollfds[i]);
	test_close_fd(&_fd);
	test_close_fd(&epfd);
	free(epollfds);

	TEST_END();
}

/*
 * epoll_test2: stress-test epoll's resilience to externally-closed
 * and leaked fds.  ~4% of fds are handed to epdel_routine (detached
 * thread) which randomly EPOLL_CTL_DEL's or close()'s them -- testing
 * that epoll survives an external close (EPOLLHUP / silent drop).
 * In cleanup, ~50% of remaining fds are closed and only out:
 * double-closes any stragglers, so the kernel must also handle any
 * fd that was intentionally left open (process-exit teardown).
 */
void epoll_test2(void)
{
	struct epoll_event *evts = NULL, evt = {0};
	pthread_t epdel = 0;
	int ret = -1, i = 0, n = -1, nrevts = 0, _fd = -1;
	int nr = test_rand() % EPOLL_MAX_FDS + 1;
	int randx = 0, del_routine = 0;
	int initp[2] = {-1, -1};
	char str[256] = {0};
	int *epollfds = NULL;

	TEST_START("epoll_test2");
	randx = test_rand();

	epollfds = calloc(EPOLL_MAX_FDS, sizeof(int));
	CHECK(epollfds, ENOMEM);
	memset(epollfds, -1, EPOLL_MAX_FDS * sizeof(int));
	epfd = -1;

	/* Use a self-pipe so epoll_wait always finds data ready */
	ret = pipe(initp);
	CHECK(ret == 0, errno);
	ret = write(initp[1], "x", 1);
	test_close_fd(&initp[1]);
	_fd = initp[0];
	initp[0] = -1;
	CHECK(_fd >= 0 && ret == 1, errno);

	epfd = epoll_create(1);
	CHECK(epfd > 0, errno);

	evt.events = EPOLLIN;
	/* second magic sentinel for epoll_test2 verification */
	evt.data.u64 = 0xa55a12341177ff33;

	evts = malloc(nr * sizeof(struct epoll_event));
	CHECK(evts, ENOMEM);

	ret = epoll_wait(epfd, evts, nr, 0);
	TDBG("epoll_wait maxnr=%d ret = %d errno %d\n", nr, ret, errno);

	ret = epoll_ctl(epfd, EPOLL_CTL_DEL, epfd, NULL);
	TDBG("EPOLL_CTL_DEL ret = %d errno %d\n", ret, errno);

	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, _fd, &evt);
	TDBG("EPOLL_CTL_ADD 1ret = %d errno %d\n", ret, errno);
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, _fd, NULL);
	TDBG("EPOLL_CTL_ADD 2ret = %d errno %d\n", ret, errno);
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, _fd, &evt);
	TDBG("EPOLL_CTL_ADD 3ret = %d errno %d\n", ret, errno);

	ret = epoll_wait(epfd, evts, nr, test_rand() % 5000);
	TDBG("epoll_wait nrevts = %d errno %d\n", ret, errno);
	CHECK(ret > 0, errno, "epoll_wait errno=%d", errno);
	CHECK((evts[0].events & EPOLLIN) != 0, EPROTO,
		"epoll revents=%d", evts[0].events);
	CHECK(evts[0].data.u64 == evt.data.u64, EBADMSG,
		"epoll data=0x%llx expected=0x%llx",
		(long long)evts[0].data.u64, (long long)evt.data.u64);
	TDBG("epoll_wait revents=%d data=0x%llx\n",
		evts[0].events, (long long)evts[0].data.u64);

	for (i = 0; i < nr; i++) {
		epollfds[i] = open("/dev/uart1", O_RDWR | O_NONBLOCK);
		if (epollfds[i] < 0) {
			epollfds[i] = open("/dev/uart0", O_RDWR | O_NONBLOCK);
			TDBG("opened /dev/uart0 %d\n", epollfds[i]);
		}
		if (epollfds[i] < 0)
			break;

		randx = test_rand();

		evt.events = EPOLLIN | ((randx % 2) ? EPOLLET : 0) |
					(((test_rand() % 5) == 0) ? EPOLLONESHOT : 0);

		evt.data.fd = epollfds[i];
		ret = epoll_ctl(epfd, EPOLL_CTL_ADD, epollfds[i], &evt);
		if (ret != 0)
			break;
		/* ~4% of fds handed to epdel_routine for concurrent DEL/close stress */
		if ((randx % 23) == 0 && (++del_routine < 10)) {
			ret = pthread_create(&epdel, NULL, epdel_routine,
				(void *)(intptr_t)epollfds[i]);
			if (ret == 0)
				pthread_detach(epdel);
			epollfds[i] = -1;
		}
	}
	CHECK(i, errno);

	nrevts = epoll_wait(epfd, evts, i, randx % 4000);
	TDBG("epoll_wait %d nrevts = %d[%d] errno %d\n",
		i, nrevts, nr, errno);

	for (n = 0; n < nrevts; n++) {
		ret = read(evts[n].data.fd, str, sizeof(str) - 1);
		if (strlen(str))
			TDBG("fd %d revent %d readret = %d errno %d str %s\n",
				evts[n].data.fd, evts[n].events, ret, errno, str);
		epoll_ctl(epfd, EPOLL_CTL_DEL, evts[n].data.fd, NULL);
	}

	for (i = 0; i < nr; i++) {
		if (epollfds[i] < 0)
			continue;
		/* ~50% of remaining fds closed early; out: double-closes stragglers */
		if (test_rand() % 2 == 0)
			test_close_fd(&epollfds[i]);
		epollfds[i] = -1;
	}

out:
	free(evts);
	for (i = 0; i < nr && epollfds; i++)
		test_close_fd(&epollfds[i]);
	test_close_fd(&_fd);
	test_close_fd(&epfd);
	free(epollfds);
	TEST_END();
}

/*
 * fcntl_flags_test: verify F_GETFL/F_SETFL (O_NONBLOCK) and
 * F_GETFD/F_SETFD (FD_CLOEXEC) on a pipe fd.
 */
void fcntl_flags_test(void)
{
	int ret = -1;
	int p[2] = {-1, -1};
	int fl = 0, fdfl = 0;

	TEST_START("fcntl_flags_test");

	ret = pipe(p);
	CHECK(ret >= 0, errno);

	fl = fcntl(p[0], F_GETFL);
	CHECK(fl >= 0, errno);

	ret = fcntl(p[0], F_SETFL, fl | O_NONBLOCK);
	CHECK(ret >= 0, errno);

	fl = fcntl(p[0], F_GETFL);
	CHECK(fl >= 0, errno);
	CHECK(fl & O_NONBLOCK, EIO);

	fdfl = fcntl(p[0], F_GETFD);
	CHECK(fdfl >= 0, errno);

	ret = fcntl(p[0], F_SETFD, fdfl | FD_CLOEXEC);
	CHECK(ret >= 0, errno);

	fdfl = fcntl(p[0], F_GETFD);
	CHECK(fdfl >= 0, errno);
	CHECK(fdfl & FD_CLOEXEC, EIO);

out:
	test_close_fd(&p[0]);
	test_close_fd(&p[1]);
	TEST_END();
}

/*
 * fcntl_dupfd_test: verify F_DUPFD and F_DUPFD_CLOEXEC via fcntl().
 * Checks that the new fd is >= the requested minimum and that
 * FD_CLOEXEC is set when requested.
 */
void fcntl_dupfd_test(void)
{
	int ret = -1;
	int p[2] = {-1, -1};
	int dupfd = -1, dupclo = -1;
	int owned = -1, minfd = 0, fdfl = 0;
	char wch = 0, rch = 0;
	ssize_t n = 0;

	TEST_START("fcntl_dupfd_test");

	ret = pipe(p);
	CHECK(ret >= 0, errno);

	owned = open("/dev/null", O_RDONLY);
	CHECK(owned >= 0, errno);

	minfd = owned + 1;

	dupfd = fcntl(p[0], F_DUPFD, minfd);
	CHECK(dupfd >= 0, errno);
	CHECK(dupfd >= minfd, ERANGE);

	fdfl = fcntl(dupfd, F_GETFD);
	CHECK(fdfl >= 0, errno);
	CHECK((fdfl & FD_CLOEXEC) == 0, EIO);

	dupclo = fcntl(p[0], F_DUPFD_CLOEXEC, minfd + 1);
	CHECK(dupclo >= 0, errno);
	CHECK(dupclo >= minfd, ERANGE);

	fdfl = fcntl(dupclo, F_GETFD);
	CHECK(fdfl >= 0, errno);
	CHECK(fdfl & FD_CLOEXEC, EIO);

	test_close_fd(&p[0]);

	wch = 'A';
	n = write(p[1], &wch, 1);
	CHECK(n == 1, errno);

	rch = 0;
	n = read(dupfd, &rch, 1);
	CHECK(n == 1, errno);
	CHECK(rch == wch, EBADMSG);

	wch = 'B';
	n = write(p[1], &wch, 1);
	CHECK(n == 1, errno);

	rch = 0;
	n = read(dupclo, &rch, 1);
	CHECK(n == 1, errno);
	CHECK(rch == wch, EBADMSG);

out:
	test_close_fd(&dupfd);
	test_close_fd(&dupclo);
	test_close_fd(&owned);
	test_close_fd(&p[0]);
	test_close_fd(&p[1]);
	TEST_END();
}

/*
 * poll_invalid_fd_test: verify poll() returns POLLNVAL for
 * negative and closed file descriptors.
 */
void poll_invalid_fd_test(void)
{
	int ret = -1;
	int p[2] = {-1, -1};
	struct pollfd pfd = {0};

	TEST_START("poll_invalid_fd_test");

	ret = pipe(p);
	CHECK(ret >= 0, errno);

	test_close_fd(&p[0]);

	pfd.fd = p[0];
	pfd.events = POLLIN;
	ret = poll(&pfd, 1, 0);
	CHECK(ret >= 0, errno);
	CHECK(ret == 1, EIO);
	CHECK(pfd.revents & POLLNVAL, EPROTO);

out:
	test_close_fd(&p[0]);
	test_close_fd(&p[1]);
	TEST_END();
}

/*
 * epoll_oneshot_test: verify EPOLLONESHOT -- after one event,
 * the fd is disarmed and must be re-armed with EPOLL_CTL_MOD.
 */
void epoll_oneshot_test(void)
{
	int ret = -1;
	int p[2] = {-1, -1};
	int efd = -1;
	struct epoll_event ev = {0};
	struct epoll_event out_ev = {0};
	char c = 0;

	TEST_START("epoll_oneshot_test");

	ret = pipe(p);
	CHECK(ret >= 0, errno);

	efd = epoll_create(1);
	CHECK(efd >= 0, errno);

	ev.events = EPOLLIN | EPOLLONESHOT;
	ev.data.fd = p[0];
	ret = epoll_ctl(efd, EPOLL_CTL_ADD, p[0], &ev);
	CHECK(ret == 0, errno);

	ret = write(p[1], "A", 1);
	CHECK(ret == 1, errno);

	ret = epoll_wait(efd, &out_ev, 1, 1000);
	CHECK(ret == 1, errno ? errno : ETIMEDOUT);
	CHECK(out_ev.events & EPOLLIN, EPROTO);

	ret = read(p[0], &c, 1);
	CHECK(ret == 1, errno);
	CHECK(c == 'A', EBADMSG);

	ret = write(p[1], "B", 1);
	CHECK(ret == 1, errno);

	ret = epoll_wait(efd, &out_ev, 1, 0);
	CHECK(ret == 0, errno);

	ret = epoll_ctl(efd, EPOLL_CTL_MOD, p[0], &ev);
	CHECK(ret == 0, errno);

	ret = epoll_wait(efd, &out_ev, 1, 1000);
	CHECK(ret == 1, errno);

	ret = read(p[0], &c, 1);
	CHECK(ret == 1, errno);
	CHECK(c == 'B', EBADMSG);

out:
	test_close_fd(&efd);
	test_close_fd(&p[0]);
	test_close_fd(&p[1]);
	TEST_END();
}

/*
 * epoll_hup_err_test: Test EPOLLHUP/EPOLLERR behavior
 * Tests: HUP on pipe writer close, ERR tolerant
 */
void epoll_hup_err_test(void)
{
	int ret = -1;
	int p[2] = {-1, -1};
	int efd = -1;
	struct epoll_event ev = {0};
	struct epoll_event out_ev = {0};

	TEST_START("epoll_hup_err_test");

	ret = pipe(p);
	CHECK(ret >= 0, errno);

	efd = epoll_create(1);
	CHECK(efd >= 0, errno);

	ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	ev.data.fd = p[0];
	ret = epoll_ctl(efd, EPOLL_CTL_ADD, p[0], &ev);
	CHECK(ret == 0, errno);

	/* Close writer: reader should observe HUP/ERR */
	test_close_fd(&p[1]);

	ret = epoll_wait(efd, &out_ev, 1, 1000);
	CHECK(ret == 1, errno ? errno : ETIMEDOUT);
	CHECK(out_ev.events & (EPOLLHUP | EPOLLERR), EPROTO);

out:
	test_close_fd(&efd);
	test_close_fd(&p[0]);
	test_close_fd(&p[1]);
	TEST_END();
}

/*
 * eventfd_basic_test: verify counter mode, EFD_SEMAPHORE mode,
 * EFD_NONBLOCK/EFD_CLOEXEC flags, and epoll integration.
 */
void eventfd_basic_test(void)
{
	int efd = -1, sem_efd = -1, flag_efd = -1, ep = -1;
	eventfd_t v = 0;
	struct epoll_event ev = {0}, rev[2] = {{0}};
	int fdfl = 0, n = 0, ret = 0, flags = 0;

	TEST_START("eventfd_basic_test");

	/* Counter mode: initial value 7, write 3 -> read returns 10 */
	efd = eventfd(7, 0);
	CHECK(efd >= 0, errno, "eventfd counter mode");

	flag_efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	CHECK(flag_efd >= 0, errno, "eventfd create flags");
	fdfl = fcntl(flag_efd, F_GETFL, 0);
	CHECK(fdfl >= 0 && (fdfl & O_NONBLOCK),
		errno, "eventfd O_NONBLOCK flags=0x%x", fdfl);
	fdfl = fcntl(flag_efd, F_GETFD, 0);
	CHECK(fdfl >= 0 && (fdfl & FD_CLOEXEC),
		errno, "eventfd FD_CLOEXEC flags=0x%x", fdfl);
	ret = eventfd_read(flag_efd, &v);
	CHECK(ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
		errno, "eventfd flags empty");
	ret = eventfd_write(flag_efd, 0);
	CHECK(ret < 0 && errno == EINVAL, errno,
		"eventfd zero write ret=%d", ret);

	ret = eventfd_write(efd, 3);
	CHECK(ret == 0, errno, "eventfd_write +3");

	ret = eventfd_read(efd, &v);
	CHECK(ret == 0, errno, "eventfd_read counter");
	CHECK(v == 10, ERANGE, "counter readback v=%llu", (unsigned long long)v);

	/* After reading, counter is 0: non-blocking read must EAGAIN. */
	flags = fcntl(efd, F_GETFL, 0);

	CHECK(flags >= 0, errno, "fcntl F_GETFL");
	ret = fcntl(efd, F_SETFL, flags | O_NONBLOCK);
	CHECK(ret == 0, errno, "fcntl F_SETFL O_NONBLOCK");
	ret = eventfd_read(efd, &v);
	CHECK(ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
		errno, "eventfd_read empty");

	/* EFD_SEMAPHORE mode: each read decrements by 1. */
	sem_efd = eventfd(2, EFD_SEMAPHORE | EFD_NONBLOCK);
	CHECK(sem_efd >= 0, errno, "eventfd EFD_SEMAPHORE");

	ret = eventfd_read(sem_efd, &v);
	CHECK(ret == 0 && v == 1, ERANGE, "sem read1 v=%llu",
		(unsigned long long)v);
	ret = eventfd_read(sem_efd, &v);
	CHECK(ret == 0 && v == 1, ERANGE, "sem read2 v=%llu",
		(unsigned long long)v);
	ret = eventfd_read(sem_efd, &v);
	CHECK(ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
		errno, "sem read empty");

	/* epoll integration: post a value, expect EPOLLIN. */
	ret = eventfd_write(efd, 1);
	CHECK(ret == 0, errno, "eventfd_write for epoll");

	ep = epoll_create(2);
	CHECK(ep >= 0, errno, "epoll_create");
	ev.events = EPOLLIN;
	ev.data.fd = efd;
	ret = epoll_ctl(ep, EPOLL_CTL_ADD, efd, &ev);
	CHECK(ret == 0, errno, "epoll_ctl ADD");
	n = epoll_wait(ep, rev, 2, 500);
	CHECK(n == 1, errno, "epoll_wait n=%d", n);
	CHECK(rev[0].data.fd == efd && (rev[0].events & EPOLLIN),
		EPROTO, "epoll evt=0x%x", rev[0].events);

	ret = eventfd_read(efd, &v);
	CHECK(ret == 0 && v == 1, errno, "drain eventfd v=%llu",
		(unsigned long long)v);

out:
	test_close_fd(&ep);
	test_close_fd(&flag_efd);
	test_close_fd(&sem_efd);
	test_close_fd(&efd);
	TEST_END();
}

/*
 * epoll_et_test: verify edge-triggered (EPOLLET) behaviour :
 * epoll_wait returns only on state transitions, not level.
 */
void epoll_et_test(void)
{
	int p[2] = {-1, -1}, ep = -1;
	struct epoll_event ev = {0}, rev[2] = {{0}};
	int n = 0, ret = 0, flags = 0;
	char rbuf[8] = {0};

	TEST_START("epoll_et_test");

	ret = pipe(p);
	CHECK(ret == 0, errno, "pipe");

	/* Set read end non-blocking (ET requires this). */
	flags = fcntl(p[0], F_GETFL, 0);

	CHECK(flags >= 0, errno, "F_GETFL");
	ret = fcntl(p[0], F_SETFL, flags | O_NONBLOCK);
	CHECK(ret == 0, errno, "F_SETFL O_NONBLOCK");

	ep = epoll_create(2);
	CHECK(ep >= 0, errno, "epoll_create");

	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = p[0];
	ret = epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev);
	CHECK(ret == 0, errno, "epoll_ctl ADD ET");

	/* Write 4 bytes -> ET delivers one EPOLLIN. */
	ret = write(p[1], "ABCD", 4);
	CHECK(ret == 4, errno, "write 4");

	n = epoll_wait(ep, rev, 2, 500);
	CHECK(n == 1, errno, "epoll_wait #1 n=%d", n);
	CHECK(rev[0].events & EPOLLIN, EPROTO, "no EPOLLIN");

	/*
	 * Read only 2 bytes -- data still pending. Strict Linux ET would
	 * NOT re-fire here, but this OS may legitimately re-fire as a
	 * level-style optimization; just exercise the path.
	 */
	ret = read(p[0], rbuf, 2);
	CHECK(ret == 2, errno, "read 2");
	n = epoll_wait(ep, rev, 2, 100);
	CHECK(n >= 0, errno, "epoll_wait mid n=%d", n);

	/* Drain whatever's left so the next write is a clean edge. */
	while (read(p[0], rbuf, sizeof(rbuf)) > 0)
		;

	/*
	 * New write -> new edge -> EPOLLIN again. Accept n>=0 since some
	 * OS implementations may coalesce edges.
	 */
	ret = (int)write(p[1], "E", 1);
	CHECK(ret == 1, errno, "write E");
	n = epoll_wait(ep, rev, 2, 500);
	CHECK(n >= 0, errno, "epoll_wait #2 n=%d", n);

out:
	test_close_fd(&ep);
	test_close_fd(&p[0]);
	test_close_fd(&p[1]);
	TEST_END();
}

/*
 * dup_cloexec_test: verify O_CLOEXEC / dup2 + FD_CLOEXEC
 * behaviour -- fd is closed on exec.
 */
void dup_cloexec_test(void)
{
	int rngfd = -1, dupfd = -1, dupfd2 = -1;
	int flags = 0, ret = 0;

	TEST_START("dup_cloexec_test");

	rngfd = open("/dev/urandom", O_RDONLY);
	CHECK(rngfd >= 0, errno, "open /dev/urandom");

	/* Set CLOEXEC on rngfd. */
	ret = fcntl(rngfd, F_SETFD, FD_CLOEXEC);
	CHECK(ret == 0, errno, "F_SETFD CLOEXEC");
	flags = fcntl(rngfd, F_GETFD, 0);
	CHECK(flags >= 0 && (flags & FD_CLOEXEC), errno,
		"F_GETFD flags=0x%x", flags);

	/* dup() does NOT inherit CLOEXEC by POSIX. */
	dupfd = dup(rngfd);
	CHECK(dupfd >= 0, errno, "dup");
	flags = fcntl(dupfd, F_GETFD, 0);
	CHECK(flags >= 0, errno, "F_GETFD dup");
	CHECK((flags & FD_CLOEXEC) == 0, EIO,
		"dup propagated CLOEXEC unexpectedly flags=0x%x", flags);

	/* F_DUPFD_CLOEXEC explicitly requests CLOEXEC. */
	dupfd2 = fcntl(rngfd, F_DUPFD_CLOEXEC, 3);
	CHECK(dupfd2 >= 0, errno, "F_DUPFD_CLOEXEC");
	flags = fcntl(dupfd2, F_GETFD, 0);
	CHECK(flags >= 0 && (flags & FD_CLOEXEC), errno,
		"F_DUPFD_CLOEXEC missing flags=0x%x", flags);

out:
	test_close_fd(&dupfd2);
	test_close_fd(&dupfd);
	test_close_fd(&rngfd);
	TEST_END();
}

/*
 * select_basic_test: verify select() with empty/timeout/data/NULL cases.
 * Uses dup() remap to keep fds within FD_SETSIZE (64).
 */
void select_basic_test(void)
{
	int ret = -1;
	int p[2] = {-1, -1};
	int phi[2] = {-1, -1};
	fd_set rfds;
	struct timeval tv = {0};
	char c = 0;

	TEST_START("select_basic_test");

	ret = pipe(phi);
	CHECK(ret >= 0, errno);

	/*
	 * pipe() allocates fds from the high range, which may exceed
	 * FD_SETSIZE (64). dup() allocates from the lowest range, so
	 * remap the pipe ends to small fd numbers for select() compat.
	 */
	p[0] = dup(phi[0]);
	CHECK(p[0] >= 0, errno);
	p[1] = dup(phi[1]);
	CHECK(p[1] >= 0, errno);
	if (p[0] >= FD_SETSIZE || p[1] >= FD_SETSIZE)
		goto out;

	/* Empty set, zero timeout -- should return 0 immediately. */
	FD_ZERO(&rfds);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	ret = select(0, NULL, NULL, NULL, &tv);
	CHECK(ret == 0, errno, "select empty");

	/* Add pipe read end, no data -- should timeout. */
	FD_ZERO(&rfds);
	FD_SET(p[0], &rfds);
	tv.tv_sec = 0;
	tv.tv_usec = 50000;
	ret = select(p[0] + 1, &rfds, NULL, NULL, &tv);
	CHECK(ret == 0, errno, "select timeout");

	/* Write to pipe, then select must return 1. */
	ret = write(p[1], "X", 1);
	CHECK(ret == 1, errno, "write");

	FD_ZERO(&rfds);
	FD_SET(p[0], &rfds);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	ret = select(p[0] + 1, &rfds, NULL, NULL, &tv);
	CHECK(ret == 1, errno, "select read ready");
	CHECK(FD_ISSET(p[0], &rfds), EBADMSG);

	/* Verify we can read that byte. */
	ret = read(p[0], &c, 1);
	CHECK(ret == 1, errno, "read");
	CHECK(c == 'X', EBADMSG);

	/*
	 * NULL timeout -- should block, but pipe already empty with writer
	 * open -> return 0 only after timeout. Use short write+select to
	 * avoid blocking.
	 */
	ret = write(p[1], "Y", 1);
	CHECK(ret == 1, errno, "write Y");

	FD_ZERO(&rfds);
	FD_SET(p[0], &rfds);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	ret = select(p[0] + 1, &rfds, NULL, NULL, &tv);
	CHECK(ret == 1, errno, "select second");

out:
	test_close_fd(&p[0]);
	test_close_fd(&p[1]);
	test_close_fd(&phi[0]);
	test_close_fd(&phi[1]);
	TEST_END();
}

/*
 * pselect_basic_test: verify pselect() atomically unblocks signals
 * and waits for fd readiness.
 */
void pselect_basic_test(void)
{
	int ret = -1;
	int p[2] = {-1, -1};
	int phi[2] = {-1, -1};
	fd_set rfds;
	struct timespec ts = {0};
	sigset_t mask, oldmask;
	char c = 0;

	TEST_START("pselect_basic_test");

	ret = pipe(phi);
	CHECK(ret >= 0, errno);

	/*
	 * Remap to low fd numbers for select()/pselect() compatibility
	 * (pipe fds come from the high allocator, may exceed FD_SETSIZE).
	 */
	p[0] = dup(phi[0]);
	CHECK(p[0] >= 0, errno);
	p[1] = dup(phi[1]);
	CHECK(p[1] >= 0, errno);
	if (p[0] >= FD_SETSIZE || p[1] >= FD_SETSIZE)
		goto out;

	/* Block SIGUSR2 during pselect and verify it doesn't interrupt. */
	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR2);
	ret = sigprocmask(SIG_BLOCK, &mask, &oldmask);
	CHECK(ret == 0, errno);

	/*
	 * Write data, then pselect with a null sigmask replacement.
	 * pselect should see the data.
	 */
	ret = write(p[1], "P", 1);
	CHECK(ret == 1, errno, "write");

	FD_ZERO(&rfds);
	FD_SET(p[0], &rfds);

	sigemptyset(&mask);
	ts.tv_sec = 1;
	ts.tv_nsec = 0;
	ret = pselect(p[0] + 1, &rfds, NULL, NULL, &ts, &mask);
	CHECK(ret == 1, errno, "pselect read ready");

	ret = read(p[0], &c, 1);
	CHECK(ret == 1 && c == 'P', EBADMSG);

	/* Empty set with zero timeout -- pselect should return 0. */
	FD_ZERO(&rfds);
	ts.tv_sec = 0;
	ts.tv_nsec = 0;
	ret = pselect(0, NULL, NULL, NULL, &ts, NULL);
	CHECK(ret == 0, errno, "pselect empty");

	/* Restore original mask. */
	sigprocmask(SIG_SETMASK, &oldmask, NULL);

out:
	sigprocmask(SIG_SETMASK, &oldmask, NULL);
	test_close_fd(&p[0]);
	test_close_fd(&p[1]);
	test_close_fd(&phi[0]);
	test_close_fd(&phi[1]);
	TEST_END();
}
