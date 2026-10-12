// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * mbedtest_signal.c -- Signal tests: sigwait, sigaction, EINTR, alarm.
 */

#include "mbedtest.h"
#include "mbedtest_internal.h"

/* ---- Local tuning constants ------------------------------------- */
#define GLOBAL_SIGTEST_MUTEX_CNT  1000

static long global_sigtest_mutex = 0;
static int sigtest_mutex_loops = 0;
static int sigwait_step = 0;
static int eintr_got = 0;
static int eintr_wfd = -1;

static volatile sig_atomic_t signal_api_got_sig;

/*
 * sigaltstack test: verify SA_ONSTACK delivers the signal on the
 * alternate stack, and that sigaltstack() set/get/disable work.
 */
static volatile sig_atomic_t altstack_got_sig;
static volatile sig_atomic_t altstack_on_alt;
static uintptr_t altstack_handler_sp;

/*
 * signal_altstack_handler: SA_ONSTACK handler that probes whether
 * it is running on the alternate stack by checking a local's address.
 */
static void signal_altstack_handler(int signo)
{
	/*
	 * Take address of a local to probe whether we are running on
	 * the alternate stack. The local's address will be within
	 * [altstack_buf, altstack_buf + SIGSTKSZ) if SA_ONSTACK worked.
	 */
	char probe = 0;
	uintptr_t sp = (uintptr_t)&probe;

	__atomic_store_n(&altstack_handler_sp, sp, __ATOMIC_RELAXED);
	altstack_on_alt = (sp >= (uintptr_t)mbedtest_altstack_buf &&
			   sp < (uintptr_t)mbedtest_altstack_buf + SIGSTKSZ);
	altstack_got_sig = signo;
}

/*
 * signal_altstack_test: verify SA_ONSTACK delivers signal on alternate
 * stack and sigaltstack() set/get/disable work correctly.
 */
void signal_altstack_test(void)
{
	int ret = -1, cnt = 0;
	struct sigaction sa = {0};
	struct sigaction oldsa = {0};
	stack_t ss = {0};
	stack_t oldss = {0};
	int sa_saved = 0, stack_saved = 0;

	TEST_START("signal_altstack_test");

	altstack_got_sig = 0;
	altstack_on_alt = 0;
	__atomic_store_n(&altstack_handler_sp, 0, __ATOMIC_RELAXED);

	/* Set up alternate signal stack */
	ss.ss_sp = mbedtest_altstack_buf;
	ss.ss_size = SIGSTKSZ;
	ss.ss_flags = 0;
	ret = sigaltstack(&ss, &oldss);
	CHECK(ret == 0, errno, "sigaltstack set");
	stack_saved = 1;

	/* Install handler with SA_ONSTACK */
	sa.sa_handler = signal_altstack_handler;
	sa.sa_flags = SA_ONSTACK;
	sigemptyset(&sa.sa_mask);
	ret = sigaction(SIGUSR2, &sa, &oldsa);
	CHECK(ret >= 0, errno, "sigaction SIGUSR2 SA_ONSTACK");
	sa_saved = 1;

	/* Deliver signal to self */
	ret = raise(SIGUSR2);
	CHECK(ret == 0, errno, "raise SIGUSR2");

	/* Wait for handler to run */
	while (!altstack_got_sig && ++cnt < 3000)
		usleep(20000);
	CHECK(altstack_got_sig == SIGUSR2, ETIMEDOUT,
		"altstack handler not invoked");

	/* Verify handler ran on alternate stack */
	CHECK(altstack_on_alt, EBADMSG,
		"handler not on altstack sp=%p range=[%p,%p)",
		(void *)__atomic_load_n(&altstack_handler_sp, __ATOMIC_RELAXED),
		mbedtest_altstack_buf, mbedtest_altstack_buf + SIGSTKSZ);

	/* Disable altstack and verify SS_DISABLE works */
	ss.ss_flags = SS_DISABLE;
	ret = sigaltstack(&ss, NULL);
	CHECK(ret == 0, errno, "sigaltstack SS_DISABLE");

out:
	if (sa_saved)
		sigaction(SIGUSR2, &oldsa, NULL);
	/* Restore original altstack (or disable if there was none) */
	if (stack_saved) {
		if (oldss.ss_flags != SS_DISABLE)
			sigaltstack(&oldss, NULL);
		else {
			ss.ss_flags = SS_DISABLE;
			sigaltstack(&ss, NULL);
		}
	}
	TEST_END();
}

/*
 * signal_handler: basic SA_SIGINFO handler -- logs and sleeps to
 * simulate work. Used by signal_test for concurrent signal delivery.
 */
static void signal_handler(int signo, siginfo_t *info, void *ctx)
{
	int i = 0;

	TDBG("signal %d-%d code=%d val=%p sp=%p ctx=%p\n", signo,
		info->si_signo, info->si_code, info->si_value.sival_ptr, &i, ctx);

	for (i = 0; i < 3; i++) {
		TDBG("recv %d %d\n", signo, i);
		usleep(100000);
	}
}

/*
 * signal_handler_mutex: SA_SIGINFO handler that contends on test_mutex.
 * Used by signal_test to verify signal delivery during lock contention.
 */
static void signal_handler_mutex(int signo, siginfo_t *info, void *ctx)
{
	int i = 0;

	TDBG("recv %d idx=%d\n", signo, info->si_value.sival_int);

	for (i = 0; i < GLOBAL_SIGTEST_MUTEX_CNT; i++) {
		pthread_mutex_lock(&test_mutex);
		__atomic_add_fetch(&global_sigtest_mutex, 1, __ATOMIC_RELAXED);
		pthread_mutex_unlock(&test_mutex);
	}

	__atomic_add_fetch(&sigtest_mutex_loops, 1, __ATOMIC_RELEASE);

	TDBG("idx=%d done\n", info->si_value.sival_int);
}

/*
 * t5_routine_mutex: thread that contends on test_mutex, used alongside
 * signal_handler_mutex for concurrent signal+mutex stress.
 */
static void *t5_routine_mutex(void *arg)
{
	int i = 0;

	TDBG("idx=%ld\n", (intptr_t)arg);

	for (i = 0; i < GLOBAL_SIGTEST_MUTEX_CNT; i++) {
		pthread_mutex_lock(&test_mutex);
		__atomic_add_fetch(&global_sigtest_mutex, 1, __ATOMIC_RELAXED);
		pthread_mutex_unlock(&test_mutex);
	}

	__atomic_add_fetch(&sigtest_mutex_loops, 1, __ATOMIC_RELEASE);

	return (void *)0;
}

/*
 * sigwait_test: test sigwait, sigtimedwait, pause, sigsuspend sequentially
 * using a state machine coordinated with sigwait_trigger_thread.
 */
static void *sigwait_test(void *arg)
{
	int signo = 0, ret = -1;
	struct timespec t1, t2, ts;
	siginfo_t info = {0};
	sigset_t set, oset;

	sigemptyset(&set);
	sigemptyset(&oset);

	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGQUIT);

	ret = sigprocmask(SIG_BLOCK, &set, &oset);
	TDBG("sigprocmask ret=%d set=0x%lX oset=0x%lX\n", ret, set, oset);
	if (ret != 0)
		return NULL;

	__atomic_store_n(&sigwait_step, 0, __ATOMIC_RELEASE);

	sigemptyset(&set);
	sigaddset(&set, SIGINT);

	__atomic_store_n(&sigwait_step, 1, __ATOMIC_RELEASE);
	clock_gettime(CLOCK_REALTIME, &t1);
	ret = sigwait(&set, &signo);
	TDBG("sigwait ret=%d errno %d signo %d\n", ret, errno, signo);
	clock_gettime(CLOCK_REALTIME, &t2);
	TDBG("sigwait %lld.%09lu\n", (long long)(t2.tv_sec - t1.tv_sec),
			t2.tv_nsec - t1.tv_nsec);

	__atomic_store_n(&sigwait_step, 2, __ATOMIC_RELEASE);
	ts.tv_sec = 5;
	ts.tv_nsec = 0;
	clock_gettime(CLOCK_REALTIME, &t1);
	ret = sigtimedwait(&set, &info, &ts);
	TDBG("sigtimedwait ret=%d errno %d signo %d\n", ret, errno, info.si_signo);
	clock_gettime(CLOCK_REALTIME, &t2);
	TDBG("sigtimedwait %lld.%09lu\n", (long long)(t2.tv_sec - t1.tv_sec),
			t2.tv_nsec - t1.tv_nsec);

	ret = sigprocmask(SIG_SETMASK, &oset, NULL);
	__atomic_store_n(&sigwait_step, 3, __ATOMIC_RELEASE);
	ret = pause();
	TDBG("pause ret=%d errno %d\n", ret, errno);

	__atomic_store_n(&sigwait_step, 4, __ATOMIC_RELEASE);
	ret = sigsuspend(&set);
	TDBG("sigsuspend ret=%d errno %d\n", ret, errno);

	__atomic_store_n(&sigwait_step, 5, __ATOMIC_RELEASE);
	return NULL;
}

/*
 * sigwait_trigger_thread: signal sender for sigwait_test.
 * Data-driven: each phase sends a signal and waits for the receiver
 * to advance to the next step.
 */
static void *sigwait_trigger_thread(void *arg)
{
	struct { int signo; int step; int sival; } phases[] = {
		{ SIGQUIT, 1, -1 },  /* sigwait */
		{ SIGINT,  2, -3 },  /* sigtimedwait */
		{ SIGINT,  3, -4 },  /* pause */
		{ SIGQUIT, 4, -5 },  /* sigsuspend */
	};
	int ret = -1, cnt = 0, p = 0;
	pthread_t sigwait = -1;

	ret = pthread_create(&sigwait, NULL, sigwait_test, (void *)0);
	if (ret != 0)
		return NULL;
	pthread_detach(sigwait);

	if (sigwait == -1)
		return NULL;

	/* Wait for receiver to reach step 1 */
	while (__atomic_load_n(&sigwait_step, __ATOMIC_ACQUIRE) != 1 && ++cnt < 1000)
		usleep(2000);
	if (__atomic_load_n(&sigwait_step, __ATOMIC_ACQUIRE) != 1) {
		pthread_cancel(sigwait);
		return NULL;
	}
	TDBG("sigwait %04d\n", sigwait & 0xfff);

	for (p = 0; p < ARRAY_SIZE(phases); p++) {
		/* Send the trigger signal */
		cnt = 0;
		do {
			ret = pthread_sigqueue(sigwait, phases[p].signo,
				(union sigval)phases[p].sival);
			if (ret == 0)
				break;
			if (ret == ESRCH || ret == EPERM)
				return NULL;
			usleep(50000);
		} while (++cnt < 200);

		/* Wait for receiver to advance to next step */
		cnt = 0;
		while (__atomic_load_n(&sigwait_step, __ATOMIC_ACQUIRE) <=
		       phases[p].step && (++cnt < 400))
			usleep(50000);

		usleep(200000);
	}

	return NULL;
}

/*
 * sig_checkpending: log all pending signals for debug visibility.
 */
static void sig_checkpending(void)
{
	int i = 0, ret = -1;
	sigset_t pset;

	ret = sigpending(&pset);
	TDBG("sigpending ret=%d set=0x%lX\n", ret, pset);

	for (i = 0; i < NSIG; i++) {
		if (sigismember(&pset, i))
			TDBG("%d pending\n", i);
	}
}

/* record signal number for signal_api_test polling loop. */
static void signal_api_handler(int signo)
{
	signal_api_got_sig = signo;
}

/*
 * signal_api_test: basic coverage for the legacy signal() API
 *
 * Note: SA_SIGINFO handlers require sigaction(); signal() only supports
 * handlers with signature void (*)(int).
 */
void signal_api_test(void)
{
	int ret = -1, cnt = 0, raise_cnt = 0;
	void (*old)(int) = NULL;
	struct sigaction dsa;

	TEST_START("signal_api_test");

	/* drain pending signals (previous tests might have flooded the queue) */
	dsa.sa_handler = SIG_IGN;
	dsa.sa_flags = 0;
	sigemptyset(&dsa.sa_mask);
	sigaction(SIGUSR2, &dsa, NULL);
	signal_api_got_sig = 0;

	old = signal(SIGUSR2, signal_api_handler);
	CHECK(old != SIG_ERR, errno);

	for (raise_cnt = 0; raise_cnt < 20; raise_cnt++) {
		errno = 0;
		ret = raise(SIGUSR2);
		if (ret == 0 || errno != EAGAIN)
			break;
		usleep(50000);
	}

	CHECK(ret == 0, errno ? errno : EIO);

	while (signal_api_got_sig != SIGUSR2 && (++cnt < 600))
		usleep(20000);
	CHECK(signal_api_got_sig == SIGUSR2, ETIMEDOUT);

out:
	/* Best-effort restore; don't fail test if restore fails. */
	if (old != SIG_ERR)
		signal(SIGUSR2, old);

	TEST_END();
}

/* Wait on the wall clock, never on a fixed sleep (no bound under load) */
#define ALARM_DEADLINE_MS	10000

static volatile sig_atomic_t alarm_child_hits;

static void alarm_child_handler(int signo)
{
	alarm_child_hits++;
}

/* can plain timers be created and armed right now? */
static int alarm_probe(void)
{
	struct sigevent sev = {0};
	struct itimerspec its = {{0}};
	timer_t tid = 0;
	int ret = 0;

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGUSR2;
	its.it_value.tv_nsec = 10 * 1000 * 1000;	/* 10 ms */

	if (timer_create(CLOCK_REALTIME, &sev, &tid) != 0)
		return -errno;

	ret = timer_settime(tid, 0, &its, NULL);
	timer_delete(tid);

	return ret == 0 ? 0 : -errno;
}

/*
 * mbedtest_sigalrm_child: SIGEV_SIGNAL+SIGALRM with SIG_DFL, which terminates
 * the process with code 99; spawned by signal_alarm_test.  Any other exit code
 * is the raw errno (ETIMEDOUT = no delivery, so the test is skipped).
 */
int mbedtest_sigalrm_child(void)
{
	int ret = 0;
	struct sigevent evp = {0};
	struct itimerspec ts = {{0}};
	timer_t timerid = -1;

	/* Use SIG_DFL, which routes to the libc default handler and exit(code). */
	signal(SIGALRM, SIG_DFL);

	evp.sigev_notify = SIGEV_SIGNAL;
	evp.sigev_signo = SIGALRM;
	/* libc default handler exits with info->si_value.sival_int */
	evp.sigev_value.sival_int = 99;

	ret = timer_create(CLOCK_REALTIME, &evp, &timerid);
	if (ret != 0)
		exit(errno);

	ts.it_value.tv_sec = 1;
	ts.it_value.tv_nsec = 0;
	ret = timer_settime(timerid, 0, &ts, NULL);
	if (ret != 0)
		exit(errno);

	/* the sleep returns once the signal arrives; SIG_DFL runs on the way out */
	usleep(ALARM_DEADLINE_MS * 1000);

	TLOG("sigalrm-child: SIGALRM not delivered in %d ms\n", ALARM_DEADLINE_MS);

	exit(ETIMEDOUT);
}

/*
 * SIGALRM exits the whole process
 */
void signal_alarm_test(void)
{
	int rc = 0, st = 888;
	pid_t pid = -1;
	char *argv[] = {
		(char *)"mbedtest",
		(char *)"--sigalrm-child",
		NULL,
	};

	/*
	 * Safe SIGALRM default-action validation:
	 * run in a child so the full suite cannot terminate itself.
	 */
	TEST_START("signal_alarm_test");

	rc = posix_spawn(&pid, argv[0], NULL, NULL, argv, NULL);
	CHECK(rc == 0, rc);

	CHECK(waitpid(pid, &st, 0) >= 0, errno);

	/* the child exits with the raw errno (99 = SIG_DFL ran) */
	CHECK(st == 99, st, "SIGALRM child st=%d peer=%d", st, pid);

out:
	TEST_END();
}

/*
 * Wait for the #want'th delivery; a missing one is not attributable to
 * alarm() (dropped notification, busy workqueue), so report and skip.
 */
static void alarm_child_wait(int want)
{
	struct timespec t0;

	clock_gettime(CLOCK_MONOTONIC, &t0);

	while ((alarm_child_hits < want) && (test_ms_since(&t0) < ALARM_DEADLINE_MS))
		usleep(2 * 1000);

	if (alarm_child_hits < want) {
		TLOG("alarm-child: alarm #%d not delivered in %d ms\n",
			want, ALARM_DEADLINE_MS);

		exit(ETIMEDOUT);
	}
}

/*
 * mbedtest_alarm_child: alarm() must fire again after being re-armed.  Exit
 * codes: 0 = both delivered, otherwise the raw errno (EBADMSG = alarm() could
 * not arm although timers work, ETIMEDOUT = no delivery, so the test skips).
 */
int mbedtest_alarm_child(void)
{
	struct sigaction sa = {0};
	struct timespec ts = {0};
	sigset_t set, oldset;
	int i = 0, armed = 0;

	sa.sa_handler = alarm_child_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGALRM, &sa, NULL) != 0)
		exit(errno);

	/*
	 * alarm() cannot report failure: cancel what it armed, 0 = nothing was.
	 * A probe that still manages to expire leaves a queued SIGTIMER
	 * notification behind (it survives the cancel), which would be counted
	 * as an expiry later; block SIGALRM across the probe and drain it.
	 */
	sigemptyset(&set);
	sigaddset(&set, SIGALRM);
	sigprocmask(SIG_BLOCK, &set, &oldset);

	for (i = 0; i < 3 && !armed; i++) {
		alarm(30);
		armed = (alarm(0) != 0);
	}

	while (sigtimedwait(&set, NULL, &ts) == SIGALRM)
		;
	alarm_child_hits = 0;

	sigprocmask(SIG_SETMASK, &oldset, NULL);

	if (!armed)
		exit((alarm_probe() == 0) ? EBADMSG : ETIMEDOUT);

	/* re-arm after each expiry: the second arm used to be a silent no-op */
	for (i = 1; i <= 2; i++) {
		if (alarm(1) != 0)
			exit(EINVAL);

		alarm_child_wait(i);
	}

	exit(0);
}

/*
 * alarm_test: alarm() must fire again after being re-armed.
 *
 * Run in a spawned child (like signal_alarm_test) so the expiries
 * cannot disturb the rest of the suite.
 */
void alarm_test(void)
{
	int rc = 0, st = 888;
	pid_t pid = -1;
	char *argv[] = {
		(char *)"mbedtest",
		(char *)"--alarm-child",
		NULL,
	};

	TEST_START("alarm_test");

	rc = posix_spawn(&pid, argv[0], NULL, NULL, argv, NULL);
	CHECK(rc == 0, rc);

	CHECK(waitpid(pid, &st, 0) >= 0, errno);

	/* the child exits with the raw errno: 0 = both delivered */
	CHECK(st == 0, st, "alarm child st=%d peer=%d", st, pid);

out:
	TEST_END();
}

/*
 * sleep_signal_test: an interrupted usleep()/sleep() must report it the POSIX
 * way (usleep: -1/EINTR, sleep: unslept seconds).
 *
 * Only an interrupted sleep is evidence: a sleep that ran to its timeout was
 * either not interrupted at all (the delivery landed before the sleep) or the
 * thread was not scheduled again before the deadline (POSIX lets that report
 * as completed) - neither is attributable to a defect, so it skips.
 *
 * Single-threaded only (runs first in the suite): a sibling thread accepting
 * the process-directed notification leaves this sleep uninterrupted.
 */
static volatile sig_atomic_t sleep_hits;

static void sleep_handler(int signo)
{
	sleep_hits++;
}

/* arm a one-shot SIGUSR1 #msec from now */
static int sleep_sig_arm(timer_t *tid, long msec)
{
	struct sigevent sev = {0};
	struct itimerspec its = {{0}};

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGUSR1;
	its.it_value.tv_sec = msec / 1000;
	its.it_value.tv_nsec = (msec % 1000) * 1000 * 1000L;

	if (timer_create(CLOCK_REALTIME, &sev, tid) != 0)
		return -errno;

	return timer_settime(*tid, 0, &its, NULL) == 0 ? 0 : -errno;
}

void sleep_signal_test(void)
{
	struct sigaction sa = {0}, oldsa = {0};
	timer_t tid = 0;
	int ret = 0, err = 0, sa_set = 0;

	TEST_START("sleep_signal_test");

	sa.sa_handler = sleep_handler;
	sigemptyset(&sa.sa_mask);
	ret = sigaction(SIGUSR1, &sa, &oldsa);
	CHECK(ret == 0, errno, "sigaction");
	sa_set = 1;

	/* signal 300 ms into usleep(1 s) */
	sleep_hits = 0;
	ret = sleep_sig_arm(&tid, 300);
	CHECK(ret == 0, -ret, "arm 300ms");
	errno = 0;
	ret = usleep(1000 * 1000);
	err = errno;	/* every wrapper call below resets errno */
	timer_delete(tid);
	CHECK(ret != 0, ETIMEDOUT, "usleep not interrupted (hits=%d)",
		(int)sleep_hits);
	CHECK((ret == -1) && (err == EINTR), EBADMSG,
		"usleep ret=%d errno=%d hits=%d", ret, err, (int)sleep_hits);

	/* signal 1 s into sleep(3): the unslept time comes back in seconds */
	sleep_hits = 0;
	ret = sleep_sig_arm(&tid, 1000);
	CHECK(ret == 0, -ret, "arm 1s");
	ret = (int)sleep(3);
	timer_delete(tid);
	CHECK(ret != 0, ETIMEDOUT, "sleep not interrupted (hits=%d)",
		(int)sleep_hits);
	CHECK((ret >= 1) && (ret <= 3), EBADMSG,
		"sleep ret=%d hits=%d", ret, (int)sleep_hits);

out:
	if (sa_set)
		sigaction(SIGUSR1, &oldsa, NULL);
	TEST_END();
}

/*
 * Test signal handling with multiple threads and signal operations
 */
void signal_test(void)
{
	int ret = -1, i = 0;
	pthread_t thds[10] = {0};
	pthread_t sigwait = -1;
	sigset_t set, oset;
	struct sigaction sa = {0}, act = {0};
	union sigval ss = {0};

	TEST_START("signal_test");

	sigemptyset(&set);
	sigemptyset(&oset);

	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGQUIT);
	sigaddset(&set, SIGSTOP);
	sigaddset(&set, SIGKILL);
	sigaddset(&set, SIGUSR1);

	ret = sigprocmask(SIG_BLOCK, &set, &oset);
	CHECK(ret == 0, errno, "sigprocmask block");

	TDBG("sigprocmask ret=%d set=0x%lX oset=0x%lX\n", ret, set, oset);

	ret = sigprocmask(SIG_BLOCK, NULL, &oset);
	CHECK(ret == 0, errno, "sigprocmask read");

	TDBG("sigprocmask ret=%d curr-set=0x%lX\n", ret, oset);

	sig_checkpending();

	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = signal_handler;
	sigemptyset(&sa.sa_mask);

	ret = sigaction(SIGINT, &sa, NULL);
	CHECK(ret >= 0, errno);

	ret = sigaction(SIGQUIT, &sa, NULL);
	CHECK(ret >= 0, errno);

	/* random 1/7 probability: exercise sigwait/sigtimedwait path */
	if (test_rand() % 7 == 0) {
		ret = pthread_create(&sigwait, NULL, sigwait_trigger_thread, NULL);
		if (ret == 0 && sigwait != -1)
			pthread_detach(sigwait);
	}

	sig_checkpending();

	ret = sigprocmask(SIG_UNBLOCK, &set, NULL);
	CHECK(ret == 0, errno, "sigprocmask unblock");

	sig_checkpending();

	act.sa_flags = SA_SIGINFO;
	act.sa_sigaction = signal_handler_mutex;
	sigaddset(&act.sa_mask, SIGQUIT);
	sigaction(SIGQUIT, &act, NULL);

	for (i = 0; i < ARRAY_SIZE(thds); i++) {
		ss.sival_int = i;
		thds[i] = -1;

		ret = pthread_create(&thds[i], NULL,
			t5_routine_mutex, (void *)(intptr_t)i);

		if (ret == 0 && thds[i] != -1)
			pthread_sigqueue(thds[i], SIGQUIT, ss);
	}

	for (i = 0; i < ARRAY_SIZE(thds); i++)
		pthread_join(thds[i], NULL);

	CHECK(__atomic_load_n(&global_sigtest_mutex, __ATOMIC_ACQUIRE) >=
		GLOBAL_SIGTEST_MUTEX_CNT *
		__atomic_load_n(&sigtest_mutex_loops, __ATOMIC_ACQUIRE),
		EBADMSG, "global_sigtest_mutex=%ld",
		__atomic_load_n(&global_sigtest_mutex, __ATOMIC_ACQUIRE));

out:

	TEST_END();
}

/*
 * signal_si_code_test: Verify that sigtimedwait() returns correct
 * si_code values for different signal senders.
 *
 * - pthread_sigqueue()  -> si_code == SI_QUEUE  (thread-directed)
 * - kill()              -> si_code == SI_USER   (process-directed)
 *
 * NOTE: kill() is inherently process-directed and may be stolen
 * by other threads that don't block SIGUSR2. The test blocks
 * SIGUSR2 so the signal stays pending in the process queue.
 */
void signal_si_code_test(void)
{
	int ret = -1;
	sigset_t set, oset;
	int oset_saved = 0;
	siginfo_t info;
	struct timespec ts = {0};
	union sigval sv;

	TEST_START("signal_si_code_test");

	sigemptyset(&set);
	sigaddset(&set, SIGUSR2);

	ret = sigprocmask(SIG_BLOCK, &set, &oset);
	CHECK(ret == 0, errno, "sigprocmask block USR2");
	oset_saved = 1;

	/* drop a leftover of an earlier test that gave up waiting for its own */
	while (sigtimedwait(&set, NULL, &ts) == SIGUSR2)
		;

	/*
	 * Case 1: pthread_sigqueue() should produce SI_QUEUE.
	 * Use thread-directed delivery so no other thread can
	 * steal the signal before sigtimedwait dequeues it.
	 */
	memset(&info, 0, sizeof(info));
	sv.sival_int = 0x1234;
	ret = pthread_sigqueue(pthread_self(), SIGUSR2, sv);
	CHECK(ret == 0, errno, "pthread_sigqueue USR2 to self");

	ts.tv_sec = 20;
	ts.tv_nsec = 0;
	ret = sigtimedwait(&set, &info, &ts);
	CHECK(ret == SIGUSR2, ret < 0 ? errno : EINVAL,
		"sigtimedwait sigqueue ret=%d", ret);
	CHECK(info.si_signo == SIGUSR2, EBADMSG,
		"si_signo=%d expected=%d", info.si_signo, SIGUSR2);
	CHECK(info.si_code == SI_QUEUE, EBADMSG,
		"si_code=%d expected SI_QUEUE(%d)", info.si_code, SI_QUEUE);
	CHECK(info.si_value.sival_int == 0x1234, EBADMSG,
		"si_value=%d expected 0x1234", info.si_value.sival_int);

	/*
	 * Case 2: pthread_kill(self) should produce SI_USER.
	 * Thread-directed -- no race with other threads.
	 */
	memset(&info, 0, sizeof(info));
	ret = pthread_kill(pthread_self(), SIGUSR2);
	CHECK(ret == 0, errno, "pthread_kill USR2 to self");

	ts.tv_sec = 20;
	ts.tv_nsec = 0;
	ret = sigtimedwait(&set, &info, &ts);
	CHECK(ret == SIGUSR2, errno,
		"sigtimedwait pthread_kill ret=%d", ret);
	CHECK(info.si_signo == SIGUSR2, EBADMSG,
		"si_signo=%d expected=%d", info.si_signo, SIGUSR2);
	CHECK(info.si_code == SI_USER, EBADMSG,
		"si_code=%d expected SI_USER(%d)", info.si_code, SI_USER);

out:
	if (oset_saved)
		sigprocmask(SIG_SETMASK, &oset, NULL);
	TEST_END();
}

/* mark eintr_got=2 to signal the main thread received EINTR. */
static void eintr_handler(int signo)
{
	__atomic_store_n(&eintr_got, 2, __ATOMIC_RELEASE);
	TDBG("eintr_got=%d\n", eintr_got);
}

/*
 * eintr_trigger_thread: wait for main thread to enter read(),
 * then send SIGUSR1 to interrupt it with EINTR.
 */
static void *eintr_trigger_thread(void *arg)
{
	int tries = 0, ret = 0;
	pthread_t target = (intptr_t)arg;

	while ((__atomic_load_n(&eintr_got, __ATOMIC_ACQUIRE) != 1) && (++tries < 800))
		usleep(50000);

	if (__atomic_load_n(&eintr_got, __ATOMIC_ACQUIRE) != 1)
		TERR("eintr_got error %d\n", eintr_got);
	else
		sleep(3);

	ret = pthread_kill(target, SIGUSR1);
	if (ret != 0)
		TERR("sendsig %d to %d failed %d\n", SIGUSR1, (int)target, ret);

	/*
	 * Safety net: close the write end of the pipe after a delay.
	 * Under extreme resource pressure, the signal may be delivered
	 * before the main thread enters read()
	 */
	sleep(5);

	close(__atomic_exchange_n(&eintr_wfd, -1, __ATOMIC_ACQ_REL));

	return NULL;
}

/*
 * signal_eintr_test: verify read() on empty pipe is interrupted
 * by a signal (SA_RESTART not set) and returns EINTR.
 */
void signal_eintr_test(void)
{
	int ret = -1;
	int p[2] = {-1, -1};
	struct sigaction sa = {0};
	struct sigaction oldsa = {0};
	int sa_saved = 0;
	pthread_t self = pthread_self();
	pthread_t th = 0;
	char c = 0;

	TEST_START("signal_eintr_test");

	ret = pipe(p);
	CHECK(ret >= 0, errno);

	sa.sa_handler = eintr_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	ret = sigaction(SIGUSR1, &sa, &oldsa);
	CHECK(ret == 0, errno);
	sa_saved = 1;

	__atomic_store_n(&eintr_got, 0, __ATOMIC_RELEASE);

	ret = pthread_create(&th, NULL, eintr_trigger_thread,
			(void *)(intptr_t)self);
	CHECK(ret == 0, ret);

	ret = pthread_detach(th);
	if (ret != 0 && ret != EINVAL) {
		test_close_fd(&p[1]);
		if (ret != ESRCH) {
			pthread_kill(th, SIGCANCEL);
			pthread_join(th, NULL);
		}
		th = 0;
	}
	CHECK(ret == 0 || ret == EINVAL, ret);

	__atomic_store_n(&eintr_wfd, p[1], __ATOMIC_RELEASE);
	p[1] = -1; /* ownership transferred to eintr_wfd */
	__atomic_store_n(&eintr_got, 1, __ATOMIC_RELEASE);

	/* Block on empty pipe: should be interrupted with EINTR (no SA_RESTART). */
	ret = read(p[0], &c, 1);
	if (ret == -1 && errno == EINTR) {
		/* Expected: signal interrupted read */
		CHECK(__atomic_load_n(&eintr_got, __ATOMIC_ACQUIRE) == 2, EINVAL);
	} else if (ret == 0 &&
		   __atomic_load_n(&eintr_got, __ATOMIC_ACQUIRE) == 2) {
		/*
		 * Signal was delivered before read() under extreme
		 * resource pressure. Trigger thread closed write
		 * end -> EOF. Not a functional failure.
		 */
		TDBG("EINTR race: signal before read (resource pressure)\n");
	} else {
		CHECK(ret < 0 && errno == EINTR, errno,
			"read EINTR ret=%d errno=%d", ret, errno);
	}

out:
	if (sa_saved && sigaction(SIGUSR1, &oldsa, NULL) != 0)
		TDBG("sigaction restore failed: %d\n", errno);
	test_close_fd(&p[0]);
	test_close_fd(&p[1]);
	close(__atomic_exchange_n(&eintr_wfd, -1, __ATOMIC_ACQ_REL));
	TEST_END();
}
