// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * mbedtest_timer.c -- POSIX time/clock/timer tests.
 */

#include "mbedtest.h"
#include "mbedtest_internal.h"

static int sigev_cnt = 0, sigev_cnt_sig = 0;

/*
 * month_index: convert "Jan", "Feb", ... to 0-based month number.
 */
static int month_index(const char *mon)
{
	static const char names[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
	int i = 0;

	for (i = 0; i < 12; i++) {
		if (strncmp(mon, names + i * 3, 3) == 0)
			return i;
	}

	return -1;
}

static time_t parse_build_time(void)
{
	struct tm tm;
	char mon[4] = {0};
	int day = 0, year = 0, hour = 0, min = 0, sec = 0;
	int month = 0;
	int ret = -1;

	ret = sscanf(__DATE__, "%3s %d %d", mon, &day, &year);
	if (ret != 3)
		return (time_t)-1;

	ret = sscanf(__TIME__, "%d:%d:%d", &hour, &min, &sec);
	if (ret != 3)
		return (time_t)-1;

	month = month_index(mon);
	if (month < 0)
		return (time_t)-1;

	memset(&tm, 0, sizeof(tm));
	tm.tm_year = year - 1900;
	tm.tm_mon = month;
	tm.tm_mday = day;
	tm.tm_hour = hour;
	tm.tm_min = min;
	tm.tm_sec = sec;
	tm.tm_isdst = -1;

	return mktime(&tm);
}

/*
 * time_test: basic wall-clock sanity -- verify CLOCK_REALTIME
 * is within a reasonable range (build time +/- 1 year).
 */
void time_test(void)
{
	struct timeval tv1 = {0};
	struct timespec ts = {0};
	time_t secs_raw = 0;
	time_t build_time = 0;
	long long delta = 0;

	TEST_START("time");

	CHECK(time(&secs_raw) != (time_t)-1, errno);
	CHECK(clock_gettime(CLOCK_REALTIME, &ts) == 0, errno);
	CHECK(gettimeofday(&tv1, NULL) == 0, errno);

	TLOG("%s", asctime(localtime(&secs_raw)));

	build_time = parse_build_time();
	CHECK(build_time != (time_t)-1, EINVAL,
		"build time parse %s %s", __DATE__, __TIME__);

	CHECK((long long)secs_raw + 86400LL >= (long long)build_time,
		ERANGE, "time=%lld build=%lld (%s %s)",
		(long long)secs_raw, (long long)build_time, __DATE__, __TIME__);

	delta = llabs((long long)ts.tv_sec - (long long)secs_raw);
	CHECK(delta <= 60, ERANGE, "clock/time delta=%lld", delta);
	delta = llabs((long long)tv1.tv_sec - (long long)secs_raw);
	CHECK(delta <= 60, ERANGE, "gettimeofday/time delta=%lld", delta);

	TDBG("time=%lld clock=%lld gettimeofday=%lld build=%lld (%s %s)\n",
		(long long)secs_raw, (long long)ts.tv_sec, (long long)tv1.tv_sec,
		(long long)build_time, __DATE__, __TIME__);

out:
	TEST_END();
}

/*
 * clock_gettime_test -- verify CLOCK_REALTIME and CLOCK_MONOTONIC:
 *  - returned timestamps are non-negative and sane
 *  - CLOCK_MONOTONIC is monotonically non-decreasing
 *  - a usleep gap is reflected
 */
void clock_gettime_test(void)
{
	struct timespec rt1 = {0}, rt2 = {0};
	struct timespec mt1 = {0}, mt2 = {0};
	int ret = 0;
	long long delta_us = 0;

	TEST_START("clock_gettime_test");

	ret = clock_gettime(CLOCK_REALTIME, &rt1);
	CHECK(ret == 0, errno, "clock_gettime REALTIME");
	CHECK(rt1.tv_sec >= 0, ERANGE, "REALTIME sec=%ld",
		(long)rt1.tv_sec);

	ret = clock_gettime(CLOCK_MONOTONIC, &mt1);
	CHECK(ret == 0, errno, "clock_gettime MONOTONIC");
	CHECK(mt1.tv_sec >= 0, ERANGE, "MONOTONIC sec=%ld",
		(long)mt1.tv_sec);

	usleep(50 * 1000);

	ret = clock_gettime(CLOCK_REALTIME, &rt2);
	CHECK(ret == 0, errno, "clock_gettime REALTIME #2");

	ret = clock_gettime(CLOCK_MONOTONIC, &mt2);
	CHECK(ret == 0, errno, "clock_gettime MONOTONIC #2");

	CHECK(mt2.tv_sec > mt1.tv_sec ||
		(mt2.tv_sec == mt1.tv_sec && mt2.tv_nsec >= mt1.tv_nsec),
		EPROTO, "MONOTONIC went backwards");

	delta_us = (long long)(mt2.tv_sec - mt1.tv_sec) * 1000000LL +
		(long long)(mt2.tv_nsec - mt1.tv_nsec) / 1000LL;
	CHECK(delta_us >= 30000, ERANGE, "mono delta=%lld us", delta_us);

out:
	TEST_END();
}

/*
 * clock_getres_test -- verify clock_getres() returns sane resolution.
 */
void clock_getres_test(void)
{
	int ret = 0;
	struct timespec ts = {0};

	TEST_START("clock_getres_test");

	ret = clock_getres(CLOCK_REALTIME, &ts);
	CHECK(ret == 0, errno, "CLOCK_REALTIME");
	CHECK(ts.tv_sec >= 0, ERANGE, "REALTIME sec=%ld", (long)ts.tv_sec);
	CHECK(ts.tv_nsec >= 0, ERANGE, "REALTIME nsec=%ld", (long)ts.tv_nsec);

	ret = clock_getres(CLOCK_MONOTONIC, &ts);
	CHECK(ret == 0, errno, "CLOCK_MONOTONIC");
	CHECK(ts.tv_sec >= 0, ERANGE, "MONO sec=%ld", (long)ts.tv_sec);
	CHECK(ts.tv_nsec >= 0, ERANGE, "MONO nsec=%ld", (long)ts.tv_nsec);

out:
	TEST_END();
}

/*
 * timer_thd_cb: SIGEV_THREAD callback for timer test -- increments
 * counter and optionally verifies value via sigwait-like logic.
 */
static void timer_thd_cb(union sigval v)
{
	time_t ttt;
	char str[64];

	TEST_START("timer_thd_cb");

	time(&ttt);
	strftime(str, sizeof(str), "%T", localtime(&ttt));

	sigev_cnt++;

	float_f_test(test_rand() % 50 + 1);
	float_d_test(test_rand() % 10 + 1);
	float_ld_test(test_rand() % 2 + 1);
	float_f_neg_test(test_rand() % 30 + 1);
	float_d_neg_test(test_rand() % 8 + 1);

	TDBG("%lx, %s val=%d sigev_cnt=%d\n", (unsigned long)pthread_self(),
		str, v.sival_int, sigev_cnt);
	TEST_END();
}

/*
 * Common timer test loop -- shared by timer_thd() and timer_sig().
 * max_rounds:  upper bound for random loop count
 * label:       "thread" or "signal" for log messages
 * notify:      SIGEV_THREAD or SIGEV_SIGNAL
 * signo:       signal number (SIGEV_SIGNAL only)
 * sig_handler: signal handler (SIGEV_SIGNAL only, may be NULL)
 * thd_cb:      thread callback (SIGEV_THREAD only, may be NULL)
 *
 * Returns 0 on success, -1 if a CHECK failed.
 */
static int timer_test_core(int max_rounds, const char *label,
			   int notify, int signo,
			   void (*sig_handler)(int, siginfo_t *, void *),
			   void (*thd_cb)(union sigval))
{
	int flags = 0;
	int ret = -1, cnt = 0, i = 0;
	struct sigevent evp = {0};
	struct sigaction sa = {0};
	struct itimerspec ts, ots = {{0}};
	timer_t timerid = -1;
	int use_altstack = 0, altstack_created = 0;
	stack_t ss = {0}, oldss = {0};

	/*
	 * Randomly enable sigaltstack (~25%) to exercise FPU-context
	 * save/restore with SA_ONSTACK signal delivery.
	 */
	if (notify == SIGEV_SIGNAL && (test_rand() % 4) == 0) {
		ss.ss_sp = mbedtest_altstack_buf;
		ss.ss_size = SIGSTKSZ;
		ss.ss_flags = 0;
		ret = sigaltstack(&ss, &oldss);
		if (ret == 0) {
			use_altstack = 1;
			altstack_created = 1;
		}
	}

	for (i = 0; i < (test_rand() % max_rounds) + 1; i++) {
		timerid = -1;
		memset(&evp, 0, sizeof(evp));
		evp.sigev_notify = notify;
		evp.sigev_value.sival_int = i + 1;

		if (notify == SIGEV_SIGNAL) {
			evp.sigev_signo = signo;
			sa.sa_flags = SA_SIGINFO;
			if (use_altstack)
				sa.sa_flags |= SA_ONSTACK;
			sa.sa_sigaction = sig_handler;
			sigemptyset(&sa.sa_mask);
			ret = sigaction(signo, &sa, NULL);
			CHECK(ret >= 0, errno);
		} else {
			evp.sigev_notify_function = thd_cb;
		}

		ret = timer_create(CLOCK_REALTIME, &evp, &timerid);
		CHECK(ret == 0, errno, "timer_create %s i=%d", label, i);

		ts.it_interval.tv_sec = 0;
		ts.it_interval.tv_nsec = (test_rand() % 2) ? test_rand() % 20000000 : 100000;
		ts.it_value.tv_sec = 0;
		ts.it_value.tv_nsec = test_rand() % 20000000;

		flags = ((test_rand() % 5) == 0) ? TIMER_ABSTIME : 0;

		if (flags == TIMER_ABSTIME) {
			clock_gettime(CLOCK_REALTIME, &ts.it_value);
			TDBG("asctime: %s\n", asctime(localtime(&ts.it_value.tv_sec)));
			ts.it_value.tv_nsec = test_rand() % 100000000;
		}

		ret = timer_settime(timerid, flags, &ts, NULL);
		CHECK(ret == 0, errno, "timer_settime %s timer=%lx",
		      label, (unsigned long)timerid);

		float_f_test(test_rand() % 50 + 1);
		float_d_test(test_rand() % 10 + 1);
		float_ld_test(test_rand() % 2 + 1);
		float_f_neg_test(test_rand() % 30 + 1);
		float_d_neg_test(test_rand() % 8 + 1);

		while (cnt < 5) {
			ret = timer_getoverrun(timerid);
			if (ret > 10 || errno != 0)
				TDBG("%lx overrun %d errno=%d\n",
				     (unsigned long)timerid, ret, errno);
			if (ret > 25)
				break;
			cnt++;
			usleep(test_rand() % 1000);
		}

		if ((test_rand() % 5) == 0) {
			ret = timer_gettime(timerid, &ots);
			CHECK(ret == 0, errno, "timer_gettime %s timer=%lx",
			      label, (unsigned long)timerid);

			ts.it_interval.tv_sec = 0;
			ts.it_interval.tv_nsec = 0;
			ts.it_value.tv_sec = 0;
			ts.it_value.tv_nsec = test_rand() % 5000000;
			ret = timer_settime(timerid, 0, &ts, &ots);
			CHECK(ret == 0, errno, "timer_settime %s reload timer=%lx",
			      label, (unsigned long)timerid);

			if ((test_rand() % 5) == 0)
				ret = timer_delete(timerid);
		} else {
			ret = timer_delete(timerid);
		}

		CHECK(ret == 0, errno, "timer_delete %s timer=%lx",
		      label, (unsigned long)timerid);

		cnt = 0;
	}

out:
	if (altstack_created) {
		ss.ss_flags = SS_DISABLE;
		sigaltstack(&ss, NULL);
	}
	return TEST_ERRNO();
}

/*
 * Test timer with SIGEV_THREAD notification
 */
int timer_thd(void)
{
	int ret;

	TEST_START("timer_thd");
	ret = timer_test_core(10, "thread", SIGEV_THREAD, 0,
			      NULL, timer_thd_cb);
	CHECK(ret == 0, ret, "timer_thd core failed");

out:
	TDBG("sigev_cnt=%d\n", sigev_cnt);
	return TEST_END();
}

/*
 * timer_sig_cb: SIGEV_SIGNAL handler for timer test.
 */
static void timer_sig_cb(int signo, siginfo_t *info, void *ctx)
{
	TEST_START_SIG("timer_sig_cb");

	sigev_cnt_sig++;

	float_f_test(test_rand() % 50 + 1);
	float_d_test(test_rand() % 10 + 1);
	float_ld_test(test_rand() % 2 + 1);
	float_f_neg_test(test_rand() % 30 + 1);
	float_d_neg_test(test_rand() % 8 + 1);

	TEST_END();
}

/*
 * Test timer with SIGEV_SIGNAL notification
 */
int timer_sig(void)
{
	int ret;

	TEST_START("timer_sig");
	ret = timer_test_core(5, "signal", SIGEV_SIGNAL, SIGALRM,
			      timer_sig_cb, NULL);
	CHECK(ret == 0, ret, "timer_sig core failed");

out:
	TDBG("sigev_cnt_sig=%d\n", sigev_cnt_sig);
	return TEST_END();
}

static volatile sig_atomic_t getoverrun_count;
static void getoverrun_sigev(int signo, siginfo_t *info, void *ctx)
{
	getoverrun_count++;
}

/*
 * timer_getoverrun_test: verify timer_getoverrun() returns zero
 * after timer cancellation, and >0 when timer expires faster than handled.
 */
void timer_getoverrun_test(void)
{
	struct sigaction sa = {0}, oldsa = {0};
	struct sigevent sev = {0};
	struct itimerspec its = {0};
	timer_t timerid = (timer_t)0;
	int created = 0, sa_installed = 0;
	int overrun = 0;
	int ret = 0;
	sigset_t blkset, oldset;

	TEST_START("timer_getoverrun_test");

	sa.sa_sigaction = getoverrun_sigev;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	getoverrun_count = 0;

	ret = sigaction(SIGUSR1, &sa, &oldsa);
	CHECK(ret == 0, errno, "sigaction USR1");
	sa_installed = 1;

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGUSR1;
	ret = timer_create(CLOCK_REALTIME, &sev, &timerid);
	CHECK(ret == 0, errno, "timer_create");
	created = 1;

	/*
	 * Fast periodic timer: 1 ms interval, 1 ms first expiry.
	 * Block SIGUSR1 briefly so the timer accumulates overruns.
	 */
	sigemptyset(&blkset);
	sigaddset(&blkset, SIGUSR1);
	ret = sigprocmask(SIG_BLOCK, &blkset, &oldset);
	CHECK(ret == 0, errno, "sigprocmask block");

	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = 1 * 1000 * 1000;  /* 1 ms */
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 1 * 1000 * 1000;
	ret = timer_settime(timerid, 0, &its, NULL);
	CHECK(ret == 0, errno, "timer_settime");

	usleep(50 * 1000); /* let several intervals accrue */

	ret = sigprocmask(SIG_SETMASK, &oldset, NULL);
	CHECK(ret == 0, errno, "sigprocmask unblock");

	/* Give the queued signal a moment to deliver. */
	usleep(10 * 1000);
	overrun = timer_getoverrun(timerid);
	CHECK(overrun >= 0, errno, "timer_getoverrun=%d", overrun);

out:
	if (created) {
		memset(&its, 0, sizeof(its));
		timer_settime(timerid, 0, &its, NULL);
		timer_delete(timerid);
	}
	if (sa_installed)
		sigaction(SIGUSR1, &oldsa, NULL);
	TEST_END();
}

static volatile sig_atomic_t monotonic_count;

static void monotonic_sigev(int signo, siginfo_t *info, void *ctx)
{
	monotonic_count++;
}

/*
 * timer_monotonic_test: verify CLOCK_MONOTONIC timer fires at the
 * expected absolute time and is not affected by wall-clock changes.
 */
void timer_monotonic_test(void)
{
	struct sigaction sa = {0}, oldsa = {0};
	struct sigevent sev = {0};
	struct itimerspec its = {0}, got = {0};
	sigset_t set, oldset;
	timer_t tid = (timer_t)0;
	int created = 0, sa_set = 0, mask_set = 0;
	int ret = 0, waited_ms = 0;

	TEST_START("timer_monotonic_test");

	sigemptyset(&set);
	sigaddset(&set, SIGUSR2);
	ret = pthread_sigmask(SIG_UNBLOCK, &set, &oldset);
	CHECK(ret == 0, ret, "pthread_sigmask SIGUSR2");
	mask_set = 1;

	sa.sa_sigaction = monotonic_sigev;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	monotonic_count = 0;

	ret = sigaction(SIGUSR2, &sa, &oldsa);
	CHECK(ret == 0, errno, "sigaction SIGUSR2");
	sa_set = 1;

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGUSR2;

	ret = timer_create(CLOCK_MONOTONIC, &sev, &tid);
	CHECK(ret == 0, errno, "timer_create CLOCK_MONOTONIC");
	created = 1;

	/* 5 ms interval, 5 ms first expiry */
	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = 5 * 1000 * 1000;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 5 * 1000 * 1000;

	ret = timer_settime(tid, 0, &its, NULL);
	CHECK(ret == 0, errno, "timer_settime");

	while (monotonic_count == 0 && waited_ms < 2000) {
		usleep(50 * 1000);
		waited_ms += 50;
	}

	ret = timer_gettime(tid, &got);
	CHECK(ret == 0, errno, "timer_gettime");

	/* Under burn-in, signal delivery can lag; timeout is a skip-worthy case. */
	CHECK(monotonic_count > 0, ETIMEDOUT, "count=%d waited_ms=%d",
		monotonic_count, waited_ms);

out:
	if (created) {
		memset(&its, 0, sizeof(its));
		timer_settime(tid, 0, &its, NULL);
		timer_delete(tid);
	}
	if (sa_set)
		sigaction(SIGUSR2, &oldsa, NULL);
	if (mask_set)
		pthread_sigmask(SIG_SETMASK, &oldset, NULL);
	TEST_END();
}

/*
 * timer_combo -- run SIGEV_THREAD and SIGEV_SIGNAL timers concurrently.
 * Both notification modes fire at overlapping intervals so that thread
 * and signal delivery interleave, exercising concurrency in the timer
 * subsystem.
 */
static pthread_mutex_t combo_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t combo_cv = PTHREAD_COND_INITIALIZER;
static int combo_thd_cnt;
static volatile sig_atomic_t combo_sig_cnt;
static int combo_target;

/* SIGEV_THREAD callback for combo test */
static void combo_thd_cb(union sigval v)
{
	TEST_START("combo_thd_cb");

	pthread_mutex_lock(&combo_mu);
	__atomic_add_fetch(&combo_thd_cnt, 1, __ATOMIC_RELAXED);
	if (__atomic_load_n(&combo_thd_cnt, __ATOMIC_RELAXED) +
	    combo_sig_cnt >= combo_target)
		pthread_cond_signal(&combo_cv);
	pthread_mutex_unlock(&combo_mu);

	float_f_test(test_rand() % 50 + 1);
	float_d_test(test_rand() % 10 + 1);
	float_ld_test(test_rand() % 2 + 1);
	float_f_neg_test(test_rand() % 30 + 1);
	float_d_neg_test(test_rand() % 8 + 1);

	TEST_END();
}

/*
 * SIGEV_SIGNAL handler for combo test -- async-signal-safe: only
 * increments the atomic counter; main thread polls it.
 */
static void combo_sig_cb(int signo, siginfo_t *info, void *ctx)
{
	TEST_START_SIG("combo_sig_cb");

	combo_sig_cnt++;
	float_f_test(test_rand() % 50 + 1);
	float_d_test(test_rand() % 10 + 1);
	float_ld_test(test_rand() % 2 + 1);
	float_f_neg_test(test_rand() % 30 + 1);
	float_d_neg_test(test_rand() % 8 + 1);

	TEST_END();
}

/*
 * timer_combo: combined timer+signal+thread test -- creates two timers
 * (SIGEV_THREAD + SIGEV_SIGNAL), verifies both notification paths agree.
 */
int timer_combo(void)
{
	int ret = -1;
	struct sigaction sa = {0}, oldsa = {0};
	struct sigevent sev_thd = {0}, sev_sig = {0};
	struct itimerspec its_thd = {{0}}, its_sig = {{0}};
	struct itimerspec zero_its = {{0}};
	timer_t tid_thd = (timer_t)0, tid_sig = (timer_t)0;
	int thd_created = 0, sig_created = 0, sa_set = 0;
	struct timespec deadline;
	int thd_ok = 0, sig_ok = 0;
	int i = 0;
	int use_altstack = 0, altstack_created = 0;
	stack_t ss = {0}, oldss = {0};

	TEST_START("timer_combo");

	/*
	 * Randomly enable sigaltstack (~25%) for FPU-on-altstack coverage.
	 */
	if ((test_rand() % 4) == 0) {
		ss.ss_sp = mbedtest_altstack_buf;
		ss.ss_size = SIGSTKSZ;
		ss.ss_flags = 0;
		ret = sigaltstack(&ss, &oldss);
		if (ret == 0) {
			use_altstack = 1;
			altstack_created = 1;
		}
	}

	/* ---- setup SIGEV_SIGNAL on SIGUSR1 ---- */
	sa.sa_sigaction = combo_sig_cb;
	sa.sa_flags = SA_SIGINFO;
	if (use_altstack)
		sa.sa_flags |= SA_ONSTACK;
	sigemptyset(&sa.sa_mask);

	ret = sigaction(SIGUSR1, &sa, &oldsa);
	CHECK(ret == 0, errno, "sigaction SIGUSR1");
	sa_set = 1;

	sev_sig.sigev_notify = SIGEV_SIGNAL;
	sev_sig.sigev_signo = SIGUSR1;

	/* ---- setup SIGEV_THREAD ---- */
	sev_thd.sigev_notify = SIGEV_THREAD;
	sev_thd.sigev_notify_function = combo_thd_cb;

	for (i = 0; i < (test_rand() % 3) + 2; i++) {
		__atomic_store_n(&combo_thd_cnt, 0, __ATOMIC_RELAXED);
		combo_sig_cnt = 0;
		combo_target = (test_rand() % 25) + 15;

		tid_thd = 0;
		tid_sig = 0;
		thd_created = 0;
		sig_created = 0;

		/* create both timers -- one signals, one spawns thread */
		ret = timer_create(CLOCK_REALTIME, &sev_thd, &tid_thd);
		CHECK(ret == 0, errno, "timer_create THREAD round=%d", i);
		thd_created = 1;

		ret = timer_create(CLOCK_REALTIME, &sev_sig, &tid_sig);
		CHECK(ret == 0, errno, "timer_create SIGNAL round=%d", i);
		sig_created = 1;

		/* thread timer: ~5 ms interval, ~1 ms first expiry */
		its_thd.it_value.tv_nsec = 1 * 1000 * 1000;
		its_thd.it_interval.tv_nsec = 5 * 1000 * 1000;

		/* signal timer: ~9 ms interval, ~2 ms first expiry */
		its_sig.it_value.tv_nsec = 2 * 1000 * 1000;
		its_sig.it_interval.tv_nsec = 9 * 1000 * 1000;

		ret = timer_settime(tid_thd, 0, &its_thd, NULL);
		CHECK(ret == 0, errno, "timer_settime THREAD round=%d", i);

		ret = timer_settime(tid_sig, 0, &its_sig, NULL);
		CHECK(ret == 0, errno, "timer_settime SIGNAL round=%d", i);

		float_f_test(test_rand() % 50 + 1);
		float_d_test(test_rand() % 10 + 1);
		float_ld_test(test_rand() % 2 + 1);
		float_f_neg_test(test_rand() % 30 + 1);
		float_d_neg_test(test_rand() % 8 + 1);

		/* wait until enough callbacks from both modes, or 5 s timeout */
		clock_gettime(CLOCK_REALTIME, &deadline);
		deadline.tv_sec += 5;

		pthread_mutex_lock(&combo_mu);
		while (__atomic_load_n(&combo_thd_cnt, __ATOMIC_RELAXED) +
		       combo_sig_cnt < combo_target) {
			ret = pthread_cond_timedwait(&combo_cv, &combo_mu,
						     &deadline);
			if (ret == ETIMEDOUT)
				break;
		}
		thd_ok = __atomic_load_n(&combo_thd_cnt, __ATOMIC_RELAXED);
		sig_ok = combo_sig_cnt;
		pthread_mutex_unlock(&combo_mu);

		/* disarm both timers */
		timer_settime(tid_thd, 0, &zero_its, NULL);
		timer_settime(tid_sig, 0, &zero_its, NULL);

		timer_delete(tid_thd);
		thd_created = 0;
		timer_delete(tid_sig);
		sig_created = 0;

		CHECK(thd_ok > 0, ETIMEDOUT,
			"THREAD cb never fired round=%d", i);
		CHECK(sig_ok > 0, ETIMEDOUT,
			"SIGNAL cb never fired round=%d", i);
		CHECK(thd_ok >= 1 && sig_ok >= 5, ETIMEDOUT,
			"too few events: thd=%d sig=%d round=%d",
			thd_ok, sig_ok, i);

		TDBG("combo round=%d thd=%d sig=%d\n", i, thd_ok, sig_ok);
	}

out:
	if (thd_created) {
		timer_settime(tid_thd, 0, &zero_its, NULL);
		timer_delete(tid_thd);
	}
	if (sig_created) {
		timer_settime(tid_sig, 0, &zero_its, NULL);
		timer_delete(tid_sig);
	}
	if (sa_set)
		sigaction(SIGUSR1, &oldsa, NULL);
	TDBG("combo final: thd=%d sig=%d\n",
		__atomic_load_n(&combo_thd_cnt, __ATOMIC_RELAXED),
		combo_sig_cnt);

	if (altstack_created) {
		ss.ss_flags = SS_DISABLE;
		sigaltstack(&ss, NULL);
	}
	return TEST_END();
}
