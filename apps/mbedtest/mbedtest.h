/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 *
 * mbedtest -- Unified Test Framework for MbedTEE
 *
 * Public test API:
 *
 *   TEST_START(name)              -- start a top-level test
 *   TEST_START_SIG(name)          -- start a signal-handler test (sub-key)
 *   CHECK(cond, err [,fmt, ...])  -- fatal: goto out if !cond
 *   TEST_ERRNO()                  -- 0 or negative errno/code from CHECK
 *   TEST_FAILED()                 -- non-zero after a failed CHECK
 *   TEST_END()                    -- end any test; returns 0 or -err
 *
 * Dual-key design:
 *   Two pthread TLS keys (main / sub) keep signal-handler and main-test
 *   contexts fully isolated.  TEST_START always uses the main key;
 *   TEST_START_SIG always uses the sub key.  TEST_END detects which key
 *   to clear by checking which key holds t.
 */

#ifndef _MBEDTEST_H
#define _MBEDTEST_H

#include <stddef.h>
#include <string.h>
#include <stdint.h>

struct test_stats {
	int total_tests;
	int passed_tests;
	int failed_tests;
	int skipped_tests;
	int total_checks;
};

extern struct test_stats g_test_stats;
#define TEST_MSG_LEN 192

struct test_ctx {
	const char *name;
	const char *expr;
	int checks;
	int failed;
	int err;
	int line;
	char msg[TEST_MSG_LEN];
};

int test_errno(void);
void test_summary(void);
int test_end(struct test_ctx *t);
int test_is_resource_error(int err);
void test_begin(struct test_ctx *t, const char *name);
void test_begin_sig(struct test_ctx *t, const char *name);
int test_check(const char *scope, int line,
	const char *expr, int ok, int err, const char *fmt, ...);

#define TEST_START(tname) \
	struct test_ctx __test; \
	test_begin(&__test, (tname))

#define TEST_FAILED() (__test.failed != 0)

#define TEST_ERRNO() test_errno()

#define TEST_END() test_end(&__test)

#define TEST_START_SIG(tname) \
	struct test_ctx __test; \
	test_begin_sig(&__test, (tname))

#define CHECK(cond, e, ...) do { \
	int test_check_ok_ = !!(cond); \
	int test_check_err_ = (e); \
	if (!test_check(__func__, __LINE__, #cond, test_check_ok_, \
		test_check_err_, ##__VA_ARGS__, NULL)) \
		goto out; \
} while (0)

#endif /* _MBEDTEST_H */
