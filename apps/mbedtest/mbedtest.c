// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * mbedtest.c -- Unified test framework: lifecycle, assertions,
 * shared utilities (hex, I/O helpers, path/cleanup).
 */

#include "mbedtest.h"
#include "mbedtest_internal.h"

struct test_stats g_test_stats;

static pthread_key_t test_main_key;
static pthread_once_t test_main_key_once = PTHREAD_ONCE_INIT;
static int test_main_key_ready;

static pthread_key_t test_sig_key;
static pthread_once_t test_sig_key_once = PTHREAD_ONCE_INIT;
static int test_sig_key_ready;

static void test_vformat_msg(char *buf, size_t buflen,
			     const char *fmt, va_list ap)
{
	size_t len = 0;

	if (!buflen)
		return;

	buf[0] = '\0';
	if (!fmt || !fmt[0])
		return;

	vsnprintf(buf, buflen, fmt, ap);
	len = strlen(buf);
	while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
		buf[--len] = '\0';
}

static void test_main_key_init(void)
{
	if (pthread_key_create(&test_main_key, NULL) == 0)
		test_main_key_ready = 1;
	else
		TERR("test main key create FAIL\n");
}

static void test_sig_key_init(void)
{
	if (pthread_key_create(&test_sig_key, NULL) == 0)
		test_sig_key_ready = 1;
	else
		TERR("test sig key create FAIL\n");
}

/*
 * test_set_main -- store t on the main key, pre-create the sig-key entry.
 * Returns 0 on success, -errno on failure.
 */
static void test_set_main(struct test_ctx *t)
{
	pthread_once(&test_main_key_once, test_main_key_init);
	if (test_main_key_ready) {
		while (pthread_setspecific(test_main_key, t) == ENOMEM)
			usleep(20000);
	}

	pthread_once(&test_sig_key_once, test_sig_key_init);
	if (test_sig_key_ready && !pthread_getspecific(test_sig_key)) {
		while (pthread_setspecific(test_sig_key, (void *)1) == ENOMEM)
			usleep(20000);
		pthread_setspecific(test_sig_key, NULL);
	}
}

static void test_set_sig(struct test_ctx *t)
{
	pthread_once(&test_sig_key_once, test_sig_key_init);
	if (test_sig_key_ready)
		while (pthread_setspecific(test_sig_key, t) == ENOMEM)
			usleep(20000);
}

/*
 * test_current -- return the active test_ctx.
 *
 * Priority: sig key > main key > NULL.
 * NULL means no test context is active (no wild CHECKs exist).
 */
static struct test_ctx *test_current(void)
{
	struct test_ctx *t;

	pthread_once(&test_sig_key_once, test_sig_key_init);
	if (test_sig_key_ready) {
		t = pthread_getspecific(test_sig_key);
		if (t)
			return t;
	}

	pthread_once(&test_main_key_once, test_main_key_init);
	if (test_main_key_ready) {
		t = pthread_getspecific(test_main_key);
		if (t)
			return t;
	}

	return NULL;
}

int test_errno(void)
{
	return test_current()->err;
}

/*
 * test_begin -- start a top-level test (always on the main key).
 * If TLS setup fails, marks the test failed so TEST_END reports it.
 */
void test_begin(struct test_ctx *t, const char *name)
{
	memset(t, 0, sizeof(*t));
	t->name = name;

	__atomic_fetch_add(&g_test_stats.total_tests, 1,
		__ATOMIC_RELAXED);

	test_set_main(t);

	TLOG("TEST RUN  %s\n", t->name);
}

/*
 * test_begin_sig -- start a signal-handler test (always on the sig key).
 */
void test_begin_sig(struct test_ctx *t, const char *name)
{
	memset(t, 0, sizeof(*t));
	t->name = name;

	__atomic_fetch_add(&g_test_stats.total_tests, 1,
		__ATOMIC_RELAXED);

	test_set_sig(t);
}

/*
 * test_end -- finish a test.
 *
 * Key detection (sig vs main) is reliable because t's key was already
 * decided by test_begin/test_begin_sig. Sig-contexts suppress
 * PASS/SKIP log to avoid noise.
 */
int test_end(struct test_ctx *t)
{
	int sig = (pthread_getspecific(test_sig_key) == t);
	int checks = t->checks;

	__atomic_fetch_add(&g_test_stats.total_checks, checks,
		__ATOMIC_RELAXED);

	if (t->failed == 0) {
		__atomic_fetch_add(&g_test_stats.passed_tests, 1,
			__ATOMIC_RELAXED);
		if (!sig)
			TLOG("TEST PASS %s | checks=%d\n", t->name, checks);
	} else if (test_is_resource_error(t->err)) {
		__atomic_fetch_add(&g_test_stats.skipped_tests, 1,
			__ATOMIC_RELAXED);
		if (!sig)
			TLOG("TEST SKIP %s | L%04d | checks=%d | err=%d | expr=`%s`\n",
				t->name, t->line, checks, t->err, t->expr);
	} else {
		__atomic_fetch_add(&g_test_stats.failed_tests, 1,
			__ATOMIC_RELAXED);
		TERR("TEST FAIL %s | L%04d | checks=%d | err=%d | expr=`%s`%s\n",
			t->name, t->line, checks, t->err, t->expr,
			sig ? " [sig]" : "");
	}

	if (sig)
		test_set_sig(NULL);
	else
		test_set_main(NULL);

	return t->err ? -t->err : 0;
}

int test_check(const char *scope, int line, const char *expr, int ok,
	       int e, const char *fmt, ...)
{
	struct test_ctx *t = test_current();
	int sig = (pthread_getspecific(test_sig_key) == t);
	const char *tag = sig ? " [sig]" : "";
	va_list ap;

	t->checks++;

	if (ok)
		return 1;

	t->failed++;
	if (t->failed == 1) {
		t->err = e;
		t->line = line;
		t->expr = expr;
	}
	if (fmt) {
		va_start(ap, fmt);
		test_vformat_msg(t->msg, sizeof(t->msg), fmt, ap);
		va_end(ap);
	}

	if (!test_is_resource_error(e)) {
		TERR("CHECK FAIL %s | L%04d | err=%d | expr=`%s`%s\n",
			scope, line, e, expr, tag);
		if (t->msg[0]) {
			TERR("CHECK FAIL %s | L%04d | msg=`%s`%s\n",
				scope, line, t->msg, tag);
			t->msg[0] = 0;
		}
	}

	return 0;
}

int test_is_resource_error(int e)
{
	return e == EMFILE || e == ENFILE || e == ENOMEM ||
		e == ENOSPC || e == EDQUOT || e == EFAULT ||
		e == EINTR || e == ETIMEDOUT || e == ENOSYS ||
		e == ENOTSUP || e == EBUSY;
}

void test_summary(void)
{
	int total, pass, fail, skip, checks;

	total  = __atomic_load_n(&g_test_stats.total_tests,
		__ATOMIC_RELAXED);
	pass   = __atomic_load_n(&g_test_stats.passed_tests,
		__ATOMIC_RELAXED);
	fail   = __atomic_load_n(&g_test_stats.failed_tests,
		__ATOMIC_RELAXED);
	skip   = __atomic_load_n(&g_test_stats.skipped_tests,
		__ATOMIC_RELAXED);
	checks = __atomic_load_n(&g_test_stats.total_checks,
		__ATOMIC_RELAXED);

	TLOG("------------------------------------------------\n");
	if (!fail && !skip)
		TLOG("Results: %d passed (%d checks)\n", pass, checks);
	else if (!fail)
		TLOG("Results: %d passed, %d skipped (total %d, %d checks)\n",
			pass, skip, total, checks);
	else if (!skip)
		TLOG("Results: %d passed, %d failed (total %d, %d checks)\n",
			pass, fail, total, checks);
	else
		TLOG("Results: %d passed, %d failed, %d skipped "
			"(total %d, %d checks)\n",
			pass, fail, skip, total, checks);
	TLOG("------------------------------------------------\n");
}
