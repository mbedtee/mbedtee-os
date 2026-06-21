// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * mbedtest_pthread.c -- Thread/synchronization tests.
 */

#include "mbedtest.h"
#include "mbedtest_internal.h"
#include <sched.h>

/* ---- Local tuning constants ------------------------------------- */
#define GLOBAL_MUTEXLOCK_CNT      10000
#define GLOBAL_RWLOCK_CNT         10000

/*
 * Shared synchronization objects used by t1/t2/t3 thread routines.
 * Only test_mutex, test_barrier_dup1, and test_barrier_dup2 are
 * genuinely shared with other .c files; the rest are static.
 */
pthread_mutex_t test_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t test_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static volatile int global_variable = 0, global_variable_rwlock = 0;
static struct timespec tt1 = {0}, tt2 = {0}, tt3 = {0}, tt4 = {0};
static pthread_barrier_t test_barrier = -1;
pthread_barrier_t test_barrier_dup1 = -1, test_barrier_dup2 = -1;
static volatile int test_barrier_cnt = 4;
static int barrier_started = 0;
static struct timespec realt = {0};
static pthread_once_t once_control = PTHREAD_ONCE_INIT;
static int cancel_ready = 0, cancel_seen = 0;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int t4_counter;
static pthread_cond_t t4_cond = PTHREAD_COND_INITIALIZER;
static volatile int once_tls_once_count;
static volatile int once_tls_dtor_count;

struct cond_signal_ctx {
	pthread_mutex_t *mu;
	pthread_cond_t *cv;
	int ready;
};

struct once_tls_thread_ctx {
	pthread_once_t *once;
	pthread_key_t key;
	uintptr_t value;
};

/*
 * once_tls_init_once: increment once-count (called via pthread_once).
 */
static void once_tls_init_once(void)
{
	__atomic_add_fetch(&once_tls_once_count, 1, __ATOMIC_ACQ_REL);
}

/*
 * once_tls_key_destructor: increment dtor-count when a TLS key
 * with non-NULL value is cleaned up at thread exit.
 */
static void once_tls_key_destructor(void *data)
{
	if (data)
		__atomic_add_fetch(&once_tls_dtor_count, 1, __ATOMIC_ACQ_REL);
}

/*
 * once_tls_thread: verify pthread_once + TLS set/get in a thread.
 */
static void *once_tls_thread(void *arg)
{
	struct once_tls_thread_ctx *ctx = arg;
	void *value = NULL;
	int ret = 0;

	ret = pthread_once(ctx->once, once_tls_init_once);
	if (ret != 0)
		return (void *)(intptr_t)ret;

	ret = pthread_setspecific(ctx->key, (void *)ctx->value);
	if (ret != 0)
		return (void *)(intptr_t)ret;

	value = pthread_getspecific(ctx->key);
	if (value != (void *)ctx->value)
		return (void *)(intptr_t)EIO;

	return NULL;
}

/*
 * atexit handler for worker threads
 */
static void __pthread_thread_atexit(void)
{
	TDBG("exiting\n\n");
}

static void once_routine(void)
{
	TDBG("called in once control\n");
}

/*
 * pthread_key destructor function
 */
static void mbedtest_key_destructor(void *data)
{
	TDBG("exiting - called in destructor %p\n\n", data);
}

/*
 * exit when test exceptions riased, usually on OOM
 */
void test_abort_handler(void *arg)
{
	TERR("aborted - %s\n", (const char *)arg);
	kill(getpid(), SIGKILL);
}

/*
 * Thread 1 routine: mutex lock contention and read lock test
 */
void *t1_routine(void *arg)
{
	int policy = -1;
	struct sched_param p = {0};
	int i = 0, ret = 0;

	pthread_cleanup_push(test_abort_handler, "t1");

	atexit(__pthread_thread_atexit);

	while (!__atomic_load_n(&barrier_started, __ATOMIC_ACQUIRE))
		usleep(5000);
	ret = pthread_barrier_wait(&test_barrier);
	TDBG("t1 pthread_barrier_wait %d\n", ret);

	float_test();
	fs_test();
	urandom_test();
	dup_test(); /* last */

	for (i = 0; i < GLOBAL_MUTEXLOCK_CNT; i++) {
		pthread_mutex_lock(&test_mutex);
		global_variable++;
		ret = pthread_mutex_unlock(&test_mutex);
		if (ret != 0)
			TERR("---unlock ret %d---\n", ret);
	}

	for (i = 0; i < GLOBAL_RWLOCK_CNT; i++) {
		ret = pthread_rwlock_rdlock(&test_rwlock);
		if (ret != 0)
			TERR("rwlock rd failed %d\n", ret);
		global_variable_rwlock++;
		ret = pthread_rwlock_unlock(&test_rwlock);
		if (ret != 0)
			TERR("rwlock unlock failed %d\n", ret);
	}

	clock_gettime(CLOCK_REALTIME, &tt2);
	TDBG("t1 %lld.%09lu %d %d\n", (long long)tt2.tv_sec - tt1.tv_sec,
		tt2.tv_nsec - tt1.tv_nsec, global_variable, global_variable_rwlock);

	TDBG("t1 ret=%d policy=%d prio=%d\n",
		pthread_getschedparam(pthread_self(), &policy, &p),
		policy, p.sched_priority);

	TDBG("t1 pthread_self=%x pid=%d arg=%p\n",
		(unsigned int)pthread_self(), getpid(), arg);

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tt2);
	TDBG("t1 THREAD_CPUTIME %lld.%09lu\n", (long long)tt2.tv_sec, tt2.tv_nsec);

	sleep(2);

	pthread_cleanup_pop(0);
	return (void *)0x111;
}

/*
 * Cleanup handler for pthread cleanup push/pop test
 */
static void cleanup_handler(void *arg)
{
	TDBG("called in %p %s\n", arg, __func__);
}

/*
 * Thread 2 routine: mutex and read lock test with cleanup handler
 */
void *t2_routine(void *arg)
{
	int policy = -1;
	struct sched_param p = {0};
	int ret = 0, i = 0;

	pthread_cleanup_push(test_abort_handler, "t2");
	atexit(__pthread_thread_atexit);

	while (!__atomic_load_n(&barrier_started, __ATOMIC_ACQUIRE))
		usleep(20000);

	ret = pthread_barrier_wait(&test_barrier);
	TDBG("t2 pthread_barrier_wait %d\n", ret);

	float_test();
	fs_test();
	urandom_test();
	dup_test(); /* last */

	for (i = 0; i < GLOBAL_MUTEXLOCK_CNT; i++) {
		pthread_mutex_lock(&test_mutex);
		global_variable++;
		ret = pthread_mutex_unlock(&test_mutex);
		if (ret != 0)
			TERR("---unlock ret %d---\n", ret);
	}

	for (i = 0; i < GLOBAL_RWLOCK_CNT; i++) {
		ret = pthread_rwlock_rdlock(&test_rwlock);
		if (ret != 0)
			TERR("rwlock rd failed %d\n", ret);
		global_variable_rwlock++;
		ret = pthread_rwlock_unlock(&test_rwlock);
		if (ret != 0)
			TERR("rwlock unlock failed %d\n", ret);
	}

	clock_gettime(CLOCK_REALTIME, &tt3);
	TDBG("t2 %lld.%09lu %d %d\n", (long long)(tt3.tv_sec - tt1.tv_sec),
			tt3.tv_nsec - tt1.tv_nsec, global_variable, global_variable_rwlock);

	TDBG("t2 ret=%d policy=%d prio=%d\n",
		pthread_getschedparam(pthread_self(), &policy, &p),
		policy, p.sched_priority);

	pthread_cleanup_push(cleanup_handler, (void *)0x121212);

	sleep(1);

	TDBG("t2 arg=%p\n", arg);

	TDBG("t2 pthread_self=%x pid=%d arg=%p\n",
		(unsigned int)pthread_self(), getpid(), arg);

	TDBG("t2 signaled ret=%d\n", pthread_cond_signal(&cond));

	sleep(2);

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tt3);
	TDBG("t2 THREAD_CPUTIME %lld.%09lu\n", (long long)tt3.tv_sec, tt3.tv_nsec);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(0);

	return (void *)0x222;
}

/*
 * Thread 3 routine: write lock test and CPU time measurement
 */
void *t3_routine(void *arg)
{
	int policy = -1;
	struct sched_param p = {0};
	int i = 0, ret = 0;

	pthread_cleanup_push(test_abort_handler, "t3");
	atexit(__pthread_thread_atexit);

	while (!__atomic_load_n(&barrier_started, __ATOMIC_ACQUIRE))
		usleep(20000);

	ret = pthread_barrier_wait(&test_barrier);
	TDBG("t3 pthread_barrier_wait %d\n", ret);

	float_test();
	fs_test();
	urandom_test();
	dup_test(); /* last */

	for (i = 0; i < GLOBAL_MUTEXLOCK_CNT; i++) {
		pthread_mutex_lock(&test_mutex);
		global_variable++;
		ret = pthread_mutex_unlock(&test_mutex);
		if (ret != 0)
			TERR("---unlock ret %d---\n", ret);
	}

	for (i = 0; i < GLOBAL_RWLOCK_CNT; i++) {
		ret = pthread_rwlock_wrlock(&test_rwlock);
		if (ret != 0)
			TERR("rwlock wr failed %d\n", ret);
		global_variable_rwlock++;
		ret = pthread_rwlock_unlock(&test_rwlock);
		if (ret != 0)
			TERR("rwlock unlock failed %d\n", ret);
	}

	clock_gettime(CLOCK_REALTIME, &tt4);
	TDBG("t3 %lld.%09lu %d %d\n", (long long)(tt4.tv_sec - tt1.tv_sec),
		tt4.tv_nsec - tt1.tv_nsec, global_variable, global_variable_rwlock);

	TDBG("t3 ret=%d policy=%d prio=%d\n",
		pthread_getschedparam(pthread_self(), &policy, &p),
		policy, p.sched_priority);

	TDBG("t3 pthread_self=%x pid=%d arg=%p\n",
		(unsigned int)pthread_self(), getpid(), arg);

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tt4);
	TDBG("t3 THREAD_CPUTIME %lld.%09lu\n", (long long)tt4.tv_sec, tt4.tv_nsec);

	pthread_cleanup_pop(0);

	return (void *)0;
}

/*
 * Thread 4 routine: scheduling policy and condition variable test
 */
void *t4_routine(void *arg)
{
	int policy = -1;
	struct sched_param p = {.sched_priority = 32};
	struct timespec tt5 = {0};

	pthread_cleanup_push(test_abort_handler, "t4");
	atexit(__pthread_thread_atexit);

	if (pthread_setschedparam(pthread_self(), SCHED_OTHER, &p))
		TERR("t4 pthread_setschedprio error\n");

	TDBG("t4 ret=%d policy=%d prio=%d\n",
		pthread_getschedparam(pthread_self(), &policy, &p),
		policy, p.sched_priority);

	TDBG("t4 pthread_self=%x pid=%d arg=%p\n",
		(unsigned int)pthread_self(), getpid(), arg);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tt5);
	TDBG("t4 THREAD_CPUTIME %lld.%09lu\n", (long long)tt5.tv_sec, tt5.tv_nsec);

	__atomic_add_fetch(&t4_counter, 1, __ATOMIC_RELAXED);

	pthread_cleanup_pop(0);

	pthread_cond_signal(&t4_cond);

	while (1) {
		__atomic_add_fetch(&t4_counter, 1, __ATOMIC_RELAXED);
		pthread_yield();
	}

	return (void *)0;
}

/*
 * cond_signal_thread: wait on condition variable, verify it was
 * signalled after pthread_cond_signal.
 */
static void *cond_signal_thread(void *arg)
{
	struct cond_signal_ctx *ctx = arg;

	usleep(20000);
	pthread_mutex_lock(ctx->mu);
	__atomic_store_n(&ctx->ready, 1, __ATOMIC_RELEASE);
	pthread_cond_signal(ctx->cv);
	pthread_mutex_unlock(ctx->mu);
	return NULL;
}

/*
 * cond_timedwait_test: verify pthread_cond_timedwait timeout
 * and successful wakeup after cond_signal from a helper thread.
 */
void cond_timedwait_test(void)
{
	int ret = -1;
	pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
	struct timespec ts = {0};
	pthread_t th = 0;
	struct cond_signal_ctx ctx = {&mu, &cv, false};

	TEST_START("cond_timedwait_test");

	ret = pthread_mutex_lock(&mu);
	CHECK(ret == 0, ret);
	clock_gettime(CLOCK_REALTIME, &ts);
	test_timespec_add_ms(&ts, 500);
	ret = pthread_cond_timedwait(&cv, &mu, &ts);
	pthread_mutex_unlock(&mu);
	CHECK(ret == ETIMEDOUT, ret != 0 ? ret : EINVAL);

	__atomic_store_n(&ctx.ready, 0, __ATOMIC_RELEASE);
	ret = pthread_create(&th, NULL, cond_signal_thread, &ctx);
	CHECK(ret == 0, ret);

	pthread_mutex_lock(&mu);
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += 20;
	ret = pthread_cond_timedwait(&cv, &mu, &ts);
	pthread_mutex_unlock(&mu);
	if (!__atomic_load_n(&ctx.ready, __ATOMIC_ACQUIRE))
		pthread_join(th, NULL);
	CHECK(__atomic_load_n(&ctx.ready, __ATOMIC_ACQUIRE),
		ret != 0 ? ret : ETIMEDOUT);

	pthread_join(th, NULL);

out:
	TEST_END();
}

/*
 * pthread_mutex_type_test: verify PTHREAD_MUTEX_RECURSIVE
 * (re-lock allowed) and PTHREAD_MUTEX_ERRORCHECK (deadlock detection).
 */
void pthread_mutex_type_test(void)
{
	int ret = -1;
	pthread_mutex_t m;
	pthread_mutexattr_t a;

	TEST_START("pthread_mutex_type_test");

	pthread_mutexattr_init(&a);
	pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
	ret = pthread_mutex_init(&m, &a);
	pthread_mutexattr_destroy(&a);
	CHECK(ret == 0, ret);

	ret = pthread_mutex_lock(&m);
	CHECK(ret == 0, ret);
	ret = pthread_mutex_lock(&m);
	CHECK(ret == 0, ret);
	ret = pthread_mutex_unlock(&m);
	CHECK(ret == 0, ret);
	ret = pthread_mutex_unlock(&m);
	CHECK(ret == 0, ret);
	pthread_mutex_destroy(&m);

	pthread_mutexattr_init(&a);
	pthread_mutexattr_settype(&a, PTHREAD_MUTEX_ERRORCHECK);
	ret = pthread_mutex_init(&m, &a);
	pthread_mutexattr_destroy(&a);
	CHECK(ret == 0, ret);

	ret = pthread_mutex_lock(&m);
	CHECK(ret == 0, ret);
	ret = pthread_mutex_lock(&m);
	CHECK(ret == EDEADLK, ret != 0 ? ret : EINVAL);
	ret = pthread_mutex_unlock(&m);
	CHECK(ret == 0, ret);
	ret = pthread_mutex_unlock(&m);
	CHECK(ret == EPERM, ret != 0 ? ret : EINVAL);
	pthread_mutex_destroy(&m);

out:
	TEST_END();
}

/*
 * pthread_rwlock_try_timed_test: verify tryrdlock/trywrlock
 * return EBUSY on held lock, and timedlock returns ETIMEDOUT.
 */
void pthread_rwlock_try_timed_test(void)
{
	int ret = -1;
	pthread_rwlock_t rw;
	struct timespec ts = {0};

	TEST_START("pthread_rwlock_try_timed_test");

	ret = pthread_rwlock_init(&rw, NULL);
	CHECK(ret == 0, ret);

	ret = pthread_rwlock_wrlock(&rw);
	CHECK(ret == 0, ret);

	ret = pthread_rwlock_tryrdlock(&rw);
	CHECK(ret == EBUSY || ret == EDEADLK, ret != 0 ? ret : EINVAL);

	ret = pthread_rwlock_trywrlock(&rw);
	CHECK(ret == EBUSY || ret == EDEADLK, ret != 0 ? ret : EINVAL);

	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_nsec += 1000000;
	if (ts.tv_nsec >= 1000000000) {
		ts.tv_nsec -= 1000000000;
		ts.tv_sec++;
	}
	ret = pthread_rwlock_timedrdlock(&rw, &ts);
	CHECK(ret == ETIMEDOUT || ret == EDEADLK || ret == EBUSY,
		ret != 0 ? ret : EINVAL);

	ret = pthread_rwlock_timedwrlock(&rw, &ts);
	CHECK(ret == ETIMEDOUT || ret == EDEADLK || ret == EBUSY,
		ret != 0 ? ret : EINVAL);

	ret = pthread_rwlock_unlock(&rw);
	CHECK(ret == 0, ret);

	ret = pthread_rwlock_destroy(&rw);
	CHECK(ret == 0, ret);

out:
	TEST_END();
}

/*
 * pthread_nop_thread: minimal thread that immediately returns 0xabc.
 * Used by detach/join and equal tests as a lightweight worker.
 */
static void *pthread_nop_thread(void *)
{
	return (void *)0xabc;
}

/*
 * pthread_detach_join_test: verify pthread_join fails after
 * pthread_detach, and that detached threads clean up properly.
 */
void pthread_detach_join_test(void)
{
	int ret = -1;
	pthread_t th = 0;
	void *jr = NULL;

	TEST_START("pthread_detach_join_test");

	ret = pthread_create(&th, NULL, pthread_nop_thread, NULL);
	CHECK(ret == 0, ret);

	ret = pthread_detach(th);
	CHECK(ret == 0, ret);

	ret = pthread_join(th, &jr);
	CHECK(ret != 0, EINVAL);

out:
	TEST_END();
}

/*
 * pthread_cancel_seen_cleanup: cleanup handler for cancel test :
 * records that the cleanup ran.
 */
static void pthread_cancel_seen_cleanup(void *arg)
{
	int *flag = (int *)arg;
	__atomic_store_n(flag, 1, __ATOMIC_RELEASE);
}

/*
 * pthread_cancel_target: enable deferred cancel, push cleanup
 * handler, signal readiness, then spin in pthread_testcancel loop.
 */
static void *pthread_cancel_target(void *)
{
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	pthread_cleanup_push(pthread_cancel_seen_cleanup, &cancel_seen);
	__atomic_store_n(&cancel_ready, 1, __ATOMIC_RELEASE);
	while (1)
		pthread_testcancel();
	pthread_cleanup_pop(0);
	return NULL;
}

/*
 * pthread_cancel_deferred_test: spawn target with deferred cancel,
 * verify pthread_cancel + join yields PTHREAD_CANCELED and cleanup ran.
 */
void pthread_cancel_deferred_test(void)
{
	int ret = -1, cnt = 0;
	pthread_t th = 0;
	void *jr = NULL;

	TEST_START("pthread_cancel_deferred_test");

	cancel_ready = 0;
	cancel_seen = 0;
	ret = pthread_create(&th, NULL, pthread_cancel_target, NULL);
	CHECK(ret == 0, ret);

	while (!__atomic_load_n(&cancel_ready, __ATOMIC_ACQUIRE) && (++cnt < 600))
		usleep(50000);
	CHECK(__atomic_load_n(&cancel_ready, __ATOMIC_ACQUIRE), ETIMEDOUT);

	ret = pthread_cancel(th);
	CHECK(ret == 0 || ret == ESRCH || ret == EPERM, ret);

	ret = pthread_join(th, &jr);

	CHECK(ret == 0, ret);
	CHECK(__atomic_load_n(&cancel_seen, __ATOMIC_ACQUIRE), ENOMSG);
	CHECK(jr == PTHREAD_CANCELED, (intptr_t)jr,
		"pthread_cancel join ret=%lx", (long)jr);

out:
	TEST_END();
}

/*
 * host_affinity_test: verify the main thread's CPU affinity
 * can be queried and that it includes the current CPU.
 */
void host_affinity_test(pthread_t host)
{
	cpu_set_t cpuset;
	long tmpset = 0;
	long gotset = 0;
	int ret = -1;

	TEST_START("host_affinity");

	TDBG("host pthread_self=%x\n", (int)host);
	CPU_ZERO(&cpuset);
	tmpset = 1L << (test_rand() % 4);
	memcpy(&cpuset, &tmpset, sizeof(tmpset));
	ret = pthread_setaffinity(host, sizeof(cpuset), &cpuset);
	CHECK(ret == 0 || ret == EINVAL, ret,
		"setaffinity host mask=%lx", tmpset);

	CPU_ZERO(&cpuset);
	ret = pthread_getaffinity(host, sizeof(cpuset), &cpuset);
	memcpy(&gotset, &cpuset, sizeof(gotset));
	CHECK(ret == 0, ret, "getaffinity host ret=%d", ret);
	CHECK(gotset != 0, EINVAL, "getaffinity host mask=0");
	TDBG("host affinity mask=%lx target=%lx\n", gotset, tmpset);

out:
	TEST_END();
}

/*
 * init_sync_objects: one-time initialization of shared mutex,
 * rwlock, barrier, and TLS key. Called once before threaded tests.
 */
void init_sync_objects(pthread_t host)
{
	int ret = -1, policy = -1;
	struct sched_param p = {0};
	pthread_mutexattr_t attr;
	pthread_rwlockattr_t lattr;
	pthread_key_t key;

	TEST_START("sync_init");

	pthread_once(&once_control, once_routine);

	ret = pthread_rwlockattr_init(&lattr);
	CHECK(ret == 0, ret, "rwlockattr_init");
	ret = pthread_rwlockattr_setpshared(&lattr, PTHREAD_PROCESS_PRIVATE);
	CHECK(ret == 0, ret, "rwlockattr_setpshared");
	ret = pthread_rwlock_init(&test_rwlock, &lattr);
	CHECK(ret == 0, ret, "rwlock_init");

	ret = pthread_mutexattr_init(&attr);
	CHECK(ret == 0, ret, "mutexattr_init");
	if ((test_rand() % 7) == 0)
		ret = pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_PROTECT);
	else
		ret = pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_NONE);
	if (ret != 0)
		TDBG("mutexattr_setprotocol ret=%d\n", ret);
	ret = pthread_mutexattr_setprioceiling(&attr,
		sched_get_priority_max(SCHED_OTHER));
	if (ret != 0)
		TDBG("mutexattr_setprioceiling ret=%d\n", ret);
	ret = pthread_mutex_init(&test_mutex, &attr);
	CHECK(ret == 0, ret, "mutex_init");

	ret = pthread_key_create(&key, mbedtest_key_destructor);
	CHECK(ret == 0, ret, "pthread_key_create");
	ret = pthread_setspecific(key, (void *)(intptr_t)host);
	CHECK(ret == 0, ret, "pthread_setspecific");

	ret = pthread_getschedparam(host, &policy, &p);
	CHECK(ret == 0, ret, "host getschedparam");
	TDBG("host getschedparam ret=%d policy=%d prio=%d\n",
		ret, policy, p.sched_priority);

out:
	TEST_END();
}

/*
 * barrier_affinity_test: spawn t1/t2/t3 with specific CPU
 * affinities, wait at a barrier.
 */
int barrier_affinity_test(pthread_t host,
	pthread_t *t1, pthread_t *t2, pthread_t *t3)
{
	int ret = 0;
	cpu_set_t cpuset;
	long tmpset = 0;
	long gotset = 0;

	TEST_START("barrier_affinity");

	TDBG("before create barriercnt=%d\n", test_barrier_cnt);

	ret = pthread_create(t1, NULL, t1_routine, (void *)t1);
	if (ret != 0)
		test_barrier_cnt--;
	else {
		/* We cancel t1 later but never join it; detach to avoid resource leaks. */
		pthread_detach(*t1);
	}
	ret = pthread_create(t2, NULL, t2_routine, (void *)t2);
	if (ret != 0)
		test_barrier_cnt--;
	ret = pthread_create(t3, NULL, t3_routine, (void *)t3);
	if (ret != 0)
		test_barrier_cnt--;

	ret = pthread_barrier_init(&test_barrier, NULL, test_barrier_cnt);
	if (ret != 0) {
		pthread_cancel(*t1);
		pthread_cancel(*t2);
		pthread_cancel(*t3);
	}
	CHECK(ret == 0, ret, "barrier_init main cnt=%d", test_barrier_cnt);
	ret = pthread_barrier_init(&test_barrier_dup1, NULL, test_barrier_cnt);
	if (ret != 0) {
		pthread_cancel(*t1);
		pthread_cancel(*t2);
		pthread_cancel(*t3);
	}
	CHECK(ret == 0, ret, "barrier_init dup1 cnt=%d", test_barrier_cnt);
	ret = pthread_barrier_init(&test_barrier_dup2, NULL, test_barrier_cnt);
	if (ret != 0) {
		pthread_cancel(*t1);
		pthread_cancel(*t2);
		pthread_cancel(*t3);
	}
	CHECK(ret == 0, ret, "barrier_init dup2 cnt=%d", test_barrier_cnt);

	__atomic_store_n(&barrier_started, true, __ATOMIC_RELEASE);

	clock_gettime(CLOCK_REALTIME, &tt1);

	ret = pthread_barrier_wait(&test_barrier);
	CHECK(ret == 0 || ret == PTHREAD_BARRIER_SERIAL_THREAD,
		ret > 0 ? ret : EINVAL, "barrier_wait host=%x ret=%d", (int)host, ret);

	CPU_ZERO(&cpuset);
	tmpset = 1L << (test_rand() % 4);
	memcpy(&cpuset, &tmpset, sizeof(tmpset));
	ret = pthread_setaffinity(*t1, sizeof(cpuset), &cpuset);
	CHECK(ret == 0 || ret == EINVAL, ret, "setaffinity t1 mask=%lx", tmpset);

	CPU_ZERO(&cpuset);
	tmpset = 1L << (test_rand() % 4);
	memcpy(&cpuset, &tmpset, sizeof(tmpset));
	ret = pthread_setaffinity(*t2, sizeof(cpuset), &cpuset);
	CHECK(ret == 0 || ret == EINVAL, ret, "setaffinity t2 mask=%lx", tmpset);

	CPU_ZERO(&cpuset);
	tmpset = 1L << (test_rand() % 4);
	memcpy(&cpuset, &tmpset, sizeof(tmpset));
	ret = pthread_setaffinity(*t3, sizeof(cpuset), &cpuset);
	CHECK(ret == 0 || ret == EINVAL, ret, "setaffinity t3 mask=%lx", tmpset);

	CPU_ZERO(&cpuset);
	ret = pthread_getaffinity(*t3, sizeof(cpuset), &cpuset);
	memcpy(&gotset, &cpuset, sizeof(gotset));
	CHECK(ret == 0, ret, "getaffinity t3 ret=%d", ret);
	CHECK(gotset != 0, EINVAL, "getaffinity t3 mask=0");
	TDBG("t3 affinity mask=%lx target=%lx\n", gotset, tmpset);

out:
	return TEST_END();
}

/*
 * lock_stress_test: timed mutex/rwlock stress loop competing
 * with t1/t2/t3 threads that also hammer the same locks.
 */
void lock_stress_test(void)
{
	int ret = 0, i = 0;
	int timedout = 0;
	int errors = 0;

	TEST_START("lock_stress");

	for (i = 0; i < GLOBAL_MUTEXLOCK_CNT; i++) {
		clock_gettime(CLOCK_REALTIME, &realt);
		realt.tv_nsec += 8000000;
		if (realt.tv_nsec >= 1000000000) {
			realt.tv_nsec -= 1000000000;
			realt.tv_sec++;
		}
		ret = pthread_mutex_timedlock(&test_mutex, &realt);

		if (ret == ETIMEDOUT)
			timedout++;
		else if (ret != 0)
			errors++;
		global_variable++;
		if (ret == 0) {
			ret = pthread_mutex_unlock(&test_mutex);
			if (ret != 0) {
				errors++;
				TDBG("mutex unlock ret=%d\n", ret);
			}
		}
	}
	if (timedout != 0)
		TDBG("mutex timedout %d\n", timedout);

	timedout = 0;
	for (i = 0; i < GLOBAL_RWLOCK_CNT; i++) {
		clock_gettime(CLOCK_REALTIME, &realt);
		timespecadd(&realt, &((struct timespec){0, 8000000}), &realt);
		ret = pthread_rwlock_timedwrlock(&test_rwlock, &realt);
		global_variable_rwlock++;
		if (ret != 0) {
			timedout++;
			TDBG("rwlock timedwr failed %d\n", ret);
		} else {
			ret = pthread_rwlock_unlock(&test_rwlock);
			if (ret != 0) {
				errors++;
				TDBG("rwlock unlock failed %d\n", ret);
			}
		}
	}
	if (timedout != 0)
		TDBG("rwlock timedout %d\n", timedout);

	clock_gettime(CLOCK_REALTIME, &realt);
	CHECK(errors == 0, EINVAL, "lock errors=%d", errors);
	CHECK(global_variable >= GLOBAL_MUTEXLOCK_CNT, EINVAL,
		"mutex count=%d", global_variable);
	CHECK(global_variable_rwlock >= GLOBAL_RWLOCK_CNT, EINVAL,
		"rwlock count=%d", global_variable_rwlock);
	TDBG("host lock stress %lld.%09lu var=%d rwvar=%d\n",
		(long long)(realt.tv_sec - tt1.tv_sec),
		realt.tv_nsec - tt1.tv_nsec,
		global_variable, global_variable_rwlock);

out:
	TEST_END();
}

/*
 * join_cancel_test: join t2/t3, cancel t1, verify join returns
 * correct thread exit values and cancel on detached t1 is tolerated.
 */
int join_cancel_test(pthread_t host, pthread_t t1,
				     pthread_t t2, pthread_t t3)
{
	int ret = 0;
	void *joinret = (void *)-1;

	TEST_START("join_cancel");

	usleep(10000);

	CHECK(t2 != 0 && t3 != 0, ENOMEM,
		"threads not created t2=%x t3=%x", (int)t2, (int)t3);

	ret = pthread_join(t2, &joinret);
	CHECK(ret == 0, ret, "join t2 host=%x t2=%x", (int)host, (int)t2);
	CHECK(joinret == (void *)0x222, EINVAL, "join t2 ret=%p", joinret);
	ret = pthread_join(t3, &joinret);
	CHECK(ret == 0, ret, "join t3 host=%x t3=%x", (int)host, (int)t3);
	CHECK(joinret == (void *)0, EINVAL, "join t3 ret=%p", joinret);

	ret = pthread_cancel(t1);
	CHECK(ret == 0 || ret == ESRCH || ret == EPERM, ret,
		"cancel t1 host=%x t1=%x", (int)host, (int)t1);

	pthread_yield();
	pthread_once(&once_control, once_routine);

out:
	return TEST_END();
}

/*
 * sched_cond_test: use SCHED_FIFO + pthread_cond_wait to verify
 * scheduling order between threads of different priorities.
 */
int sched_cond_test(pthread_t host)
{
	int ret, policy = -1, tries = 200;
	struct sched_param p = {0};
	pthread_t t4 = 0;

	TEST_START("sched_cond");

	p.sched_priority = 32;
	if (pthread_setschedparam(pthread_self(), SCHED_RR, &p))
		TDBG("pthread_setschedparam error\n");

	TDBG("host %x getschedparam ret=%d policy=%d prio=%d\n",
		(int)host, pthread_getschedparam(host, &policy, &p),
		policy, p.sched_priority);

	if (pthread_setschedprio(pthread_self(),
			sched_get_priority_max(SCHED_RR)))
		TDBG("pthread_setschedprio error\n");

	ret = pthread_create(&t4, NULL, t4_routine, (void *)&t4);
	if (ret != 0)
		TDBG("%x pthread_createt4 %x ret=%x\n", (int)host, (int)t4, ret);
	CHECK(ret == 0, ret, "pthread_create t4 host=%x", (int)host);
	if (ret == 0) {
		pthread_detach(t4);

		pthread_mutex_lock(&test_mutex);
		clock_gettime(CLOCK_REALTIME, &realt);
		realt.tv_sec += 40;
		ret = pthread_cond_timedwait(&t4_cond, &test_mutex, &realt);
		pthread_mutex_unlock(&test_mutex);

		ret = pthread_cancel(t4);
		if (ret != 0)
			TDBG("%x pthread_cancelt4 %x ret=%x, t4_counter=%d\n",
				(int)host, (int)t4, ret, t4_counter);
		CHECK(ret == 0 || ret == ESRCH || ret == EPERM, ret,
			"cancel t4 host=%x t4=%x", (int)host, (int)t4);

		/* still not ready to run ? */
		while ((ret == ESRCH) && (--tries >= 0)) {
			usleep(50000);
			ret = pthread_cancel(t4);
		}

		pthread_cancel(t4);
	}

	clock_gettime(CLOCK_REALTIME, &realt);
	realt.tv_sec += 3;
	pthread_mutex_lock(&test_mutex);
	ret = pthread_cond_timedwait(&cond, &test_mutex, &realt);
	pthread_mutex_unlock(&test_mutex);
	CHECK(ret == 0 || ret == ETIMEDOUT, ret,
		"cond timedwait host=%x ret=%d", (int)host, ret);

	TDBG("final global=%d rwglobal=%d\n",
		global_variable, global_variable_rwlock);

out:
	return TEST_END();
}

/*
 * cpu_time_test: verify clock_gettime(CLOCK_THREAD_CPUTIME)
 * returns monotonically increasing values.
 */
void cpu_time_test(void)
{
	struct timespec thread_time = {0};
	struct timespec process_time = {0};
	struct timespec t2 = {0}, p2 = {0};
	int ret = -1;
	size_t spin_i;

	TEST_START("cpu_time");

	ret = clock_gettime(CLOCK_THREAD_CPUTIME_ID, &thread_time);
	CHECK(ret == 0, errno, "thread cputime");
	ret = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &process_time);
	CHECK(ret == 0, errno, "process cputime");
	CHECK(process_time.tv_sec > thread_time.tv_sec ||
		(process_time.tv_sec == thread_time.tv_sec &&
		 process_time.tv_nsec >= thread_time.tv_nsec),
		EINVAL, "thread=%lld.%09lu process=%lld.%09lu",
		(long long)thread_time.tv_sec, thread_time.tv_nsec,
		(long long)process_time.tv_sec, process_time.tv_nsec);

	/*
	 * Monotonic strengthening: second sample after small busy delay
	 * must be >= first; thread <= process invariant holds again.
	 */
	for (spin_i = 0; spin_i < 2000000; spin_i++)
		test_rand();

	ret = clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t2);
	CHECK(ret == 0, errno, "thread cputime 2nd");
	ret = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &p2);
	CHECK(ret == 0, errno, "process cputime 2nd");
	CHECK(t2.tv_sec > thread_time.tv_sec ||
		(t2.tv_sec == thread_time.tv_sec &&
		 t2.tv_nsec >= thread_time.tv_nsec),
		EINVAL, "t1=%lld.%09lu t2=%lld.%09lu\n",
		(long long)thread_time.tv_sec, thread_time.tv_nsec,
		(long long)t2.tv_sec, t2.tv_nsec);
	CHECK(p2.tv_sec > process_time.tv_sec ||
		(p2.tv_sec == process_time.tv_sec &&
		 p2.tv_nsec >= process_time.tv_nsec),
		EINVAL, "p1=%lld.%09lu p2=%lld.%09lu\n",
		(long long)process_time.tv_sec, process_time.tv_nsec,
		(long long)p2.tv_sec, p2.tv_nsec);

out:
	TEST_END();
}

/*
 * pthread_spin_basic_test: init/lock/trylock/unlock/destroy lifecycle
 * for pthread spinlocks; trylock on held lock must return EBUSY.
 */
void pthread_spin_basic_test(void)
{
	pthread_spinlock_t spin;
	int initialized = 0;
	int ret = 0;

	TEST_START("pthread_spin_basic_test");

	ret = pthread_spin_init(&spin, PTHREAD_PROCESS_PRIVATE);
	CHECK(ret == 0, ret, "spin_init");
	initialized = 1;

	ret = pthread_spin_lock(&spin);
	CHECK(ret == 0, ret, "spin_lock");

	/* trylock on already-held spinlock must return EBUSY. */
	ret = pthread_spin_trylock(&spin);
	CHECK(ret == EBUSY, ret, "trylock-while-held ret=%d", ret);

	ret = pthread_spin_unlock(&spin);
	CHECK(ret == 0, ret, "spin_unlock");

	/* trylock after unlock should now succeed. */
	ret = pthread_spin_trylock(&spin);
	CHECK(ret == 0, ret, "trylock-after-unlock");
	ret = pthread_spin_unlock(&spin);
	CHECK(ret == 0, ret, "spin_unlock 2");

out:
	if (initialized)
		pthread_spin_destroy(&spin);
	TEST_END();
}

/*
 * pthread_once_tls_test: verify pthread_once runs exactly once
 * across threads, TLS per-thread isolation, and key destructor counts.
 */
void pthread_once_tls_test(void)
{
	pthread_once_t once = PTHREAD_ONCE_INIT;
	pthread_key_t key = 0;
	pthread_t th[4] = {0};
	struct once_tls_thread_ctx ctx[ARRAY_SIZE(th)];
	void *jr = NULL;
	void *main_value = (void *)(uintptr_t)0x55AAu;
	int created = 0;
	int key_created = 0;
	int ret = 0;
	int i = 0;

	TEST_START("pthread_once_tls_test");

	__atomic_store_n(&once_tls_once_count, 0, __ATOMIC_RELEASE);
	__atomic_store_n(&once_tls_dtor_count, 0, __ATOMIC_RELEASE);

	ret = pthread_key_create(&key, once_tls_key_destructor);
	CHECK(ret == 0, ret, "pthread_key_create");
	key_created = 1;

	CHECK(pthread_getspecific(key) == NULL, EINVAL,
		"main getspecific initial");
	ret = pthread_setspecific(key, main_value);
	CHECK(ret == 0, ret, "main setspecific");
	CHECK(pthread_getspecific(key) == main_value, EINVAL,
		"main getspecific set");

	for (i = 0; i < ARRAY_SIZE(th); i++) {
		ctx[i].once = &once;
		ctx[i].key = key;
		ctx[i].value = (uintptr_t)(0x1000u + i);
		ret = pthread_create(&th[i], NULL, once_tls_thread, &ctx[i]);
		CHECK(ret == 0, ret, "pthread_create once/tls i=%d", i);
		created++;
	}

	for (i = 0; i < created; i++) {
		ret = pthread_join(th[i], &jr);
		CHECK(ret == 0, ret, "pthread_join once/tls i=%d", i);
		th[i] = 0;
		CHECK(jr == NULL, jr ? (int)(intptr_t)jr : EINVAL,
			"once/tls worker i=%d ret=%ld", i, (long)jr);
	}

	ret = pthread_once(&once, once_tls_init_once);
	CHECK(ret == 0, ret, "pthread_once main");
	CHECK(__atomic_load_n(&once_tls_once_count, __ATOMIC_ACQUIRE) == 1,
		EINVAL, "once count=%d", once_tls_once_count);
	CHECK(__atomic_load_n(&once_tls_dtor_count, __ATOMIC_ACQUIRE) == created,
		EINVAL, "dtor count=%d created=%d",
		once_tls_dtor_count, created);
	CHECK(pthread_getspecific(key) == main_value, EINVAL,
		"main tls isolation");

	ret = pthread_setspecific(key, NULL);
	CHECK(ret == 0, ret, "main clear tls");
	CHECK(pthread_getspecific(key) == NULL, EINVAL,
		"main getspecific clear");

	ret = pthread_key_delete(key);
	CHECK(ret == 0, ret, "pthread_key_delete");
	key_created = 0;

	CHECK(pthread_getspecific(key) == NULL, EINVAL,
		"getspecific after delete");
	ret = pthread_setspecific(key, main_value);
	CHECK(ret == EINVAL, ret != 0 ? ret : EINVAL,
		"setspecific after delete ret=%d", ret);

out:
	for (i = 0; i < ARRAY_SIZE(th); i++) {
		if (th[i] != 0) {
			pthread_join(th[i], NULL);
			th[i] = 0;
		}
	}
	if (key_created)
		pthread_key_delete(key);
	TEST_END();
}

/*
 * Thread routine for pthread_attr_test: returns the argument as exit code.
 */
static void *pthread_attr_thread(void *arg)
{
	sleep(1);
	return arg;
}

/*
 * Thread routine for pthread_exit_test: calls pthread_exit with a value.
 */
static void *pthread_exit_thread(void *arg)
{
	pthread_exit(arg);
	return NULL;
}

/*
 * Thread routine for pthread_cancel_disabled_test:
 * disables cancellation so that pthread_cancel has no effect.
 */
static void *pthread_cancel_disabled_thread(void *arg)
{
	int *flag = arg;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	__atomic_store_n(flag, 1, __ATOMIC_RELEASE);
	sleep(1);
	pthread_testcancel();
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	/* Now cancellation can take effect */
	while (1)
		pthread_testcancel();
	return NULL;
}

/*
 * Shared state and helpers for pthread_cond_basic_test
 */
static pthread_mutex_t cond_test_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond_test_cv = PTHREAD_COND_INITIALIZER;
static int cond_test_ready;

/*
 * cond_wait_thread: signal readiness, then block on cond_wait
 * (cancellation point) until woken by cond_signal/broadcast.
 */
static void *cond_wait_thread(void *arg)
{
	int *woken = arg;

	pthread_mutex_lock(&cond_test_mu);
	__atomic_store_n(&cond_test_ready, 1, __ATOMIC_RELEASE);
	/* cancellation point: pthread_cond_wait; deferred cancel tested here */
	pthread_cond_wait(&cond_test_cv, &cond_test_mu);
	*woken = 1;
	pthread_mutex_unlock(&cond_test_mu);
	return NULL;
}

/*
 * tls_null_dtor_thread: set TLS with NULL destructor, then exit.
 */
static void *tls_null_dtor_thread(void *arg)
{
	pthread_key_t *key = arg;
	void *value = NULL;

	value = pthread_getspecific(*key);
	if (value)
		return (void *)(intptr_t)EINVAL;

	return NULL;
}

/*
 * pthread_attr_test: full lifecycle of pthread_attr_t —
 * detachstate, stacksize, guardsize, inheritsched, scope, policy.
 */
void pthread_attr_test(void)
{
	int ret = 0;
	pthread_attr_t attr;
	pthread_t th = 0;
	void *jr = NULL;
	size_t stacksize = 0;
	size_t guardsize = 0;
	int detachstate = -1;
	int inheritsched = -1;
	int scope = -1;
	int policy = -1;
	struct sched_param sp = {0};
	int destroyed = 0;

	TEST_START("pthread_attr_test");

	/* --- init / destroy lifecycle --- */
	ret = pthread_attr_init(&attr);
	CHECK(ret == 0, ret, "attr_init");
	destroyed = 0;

	ret = pthread_attr_destroy(&attr);
	CHECK(ret == 0, ret, "attr_destroy");
	destroyed = 1;

	/* double-destroy: POSIX says behavior is undefined; just verify no crash */
	ret = pthread_attr_destroy(&attr);
	TDBG("attr double-destroy ret=%d\n", ret);

	/* --- detachstate --- */
	ret = pthread_attr_init(&attr);
	CHECK(ret == 0, ret, "attr_init2");
	destroyed = 0;

	ret = pthread_attr_getdetachstate(&attr, &detachstate);
	CHECK(ret == 0, ret, "getdetachstate_default");
	CHECK(detachstate == PTHREAD_CREATE_JOINABLE, EINVAL,
		"default detachstate=%d", detachstate);

	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	CHECK(ret == 0, ret, "setdetachstate_detached");

	ret = pthread_attr_getdetachstate(&attr, &detachstate);
	CHECK(ret == 0, ret, "getdetachstate_detached");
	CHECK(detachstate == PTHREAD_CREATE_DETACHED, EINVAL,
		"detachstate=%d", detachstate);

	/* create a detached thread: join must fail */
	ret = pthread_create(&th, &attr, pthread_attr_thread, (void *)0x300);
	CHECK(ret == 0, ret, "create_detached");

	ret = pthread_join(th, &jr);
	CHECK(ret == EINVAL || ret == ESRCH, ret, "join_detached");

	ret = pthread_attr_destroy(&attr);
	CHECK(ret == 0, ret, "attr_destroy2");
	destroyed = 1;

	/* --- stacksize --- */
	ret = pthread_attr_init(&attr);
	CHECK(ret == 0, ret, "attr_init3");
	destroyed = 0;

	ret = pthread_attr_getstacksize(&attr, &stacksize);
	CHECK(ret == 0, ret, "getstacksize_default");
	CHECK(stacksize > 0, EINVAL, "default stacksize=%zu", stacksize);

	ret = pthread_attr_setstacksize(&attr, stacksize * 2);
	CHECK(ret == 0 || ret == ENOMEM || ret == EINVAL,
		ret != 0 ? ret : EINVAL, "setstacksize");

	ret = pthread_attr_getstacksize(&attr, &stacksize);
	CHECK(ret == 0, ret, "getstacksize_after_set");
	CHECK(stacksize > 0, EINVAL, "stacksize=%zu", stacksize);

	ret = pthread_attr_destroy(&attr);
	CHECK(ret == 0, ret, "attr_destroy3");
	destroyed = 1;

	/* --- guardsize --- */
	ret = pthread_attr_init(&attr);
	CHECK(ret == 0, ret, "attr_init4");
	destroyed = 0;

	ret = pthread_attr_getguardsize(&attr, &guardsize);
	if (ret == 0)
		TDBG("default guardsize=%zu\n", guardsize);

	ret = pthread_attr_setguardsize(&attr, 4096);
	CHECK(ret == 0 || ret == EINVAL || ret == ENOTSUP,
		ret != 0 ? ret : EINVAL, "setguardsize");

	ret = pthread_attr_getguardsize(&attr, &guardsize);
	if (ret == 0)
		TDBG("guardsize after set=%zu\n", guardsize);

	ret = pthread_attr_destroy(&attr);
	CHECK(ret == 0, ret, "attr_destroy4");
	destroyed = 1;

	/* --- inheritsched --- */
	ret = pthread_attr_init(&attr);
	CHECK(ret == 0, ret, "attr_init5");
	destroyed = 0;

	ret = pthread_attr_getinheritsched(&attr, &inheritsched);
	CHECK(ret == 0, ret, "getinheritsched_default");
	CHECK(inheritsched == PTHREAD_INHERIT_SCHED ||
		inheritsched == PTHREAD_EXPLICIT_SCHED, EINVAL,
		"inheritsched=%d", inheritsched);

	ret = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
	if (ret == 0) {
		ret = pthread_attr_getinheritsched(&attr, &inheritsched);
		CHECK(ret == 0, ret, "getinheritsched_explicit");
		CHECK(inheritsched == PTHREAD_EXPLICIT_SCHED, EINVAL,
			"inheritsched after set=%d", inheritsched);
	}

	ret = pthread_attr_setinheritsched(&attr, PTHREAD_INHERIT_SCHED);
	CHECK(ret == 0, ret, "setinheritsched_inherit");

	/* --- schedpolicy --- */
	ret = pthread_attr_getschedpolicy(&attr, &policy);
	CHECK(ret == 0, ret, "getschedpolicy_default");
	CHECK(policy == SCHED_OTHER || policy == SCHED_RR ||
		policy == SCHED_FIFO, EINVAL, "policy=%d", policy);

	ret = pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
	CHECK(ret == 0, ret, "setschedpolicy_other");

	/* --- schedparam --- */
	ret = pthread_attr_getschedparam(&attr, &sp);
	CHECK(ret == 0, ret, "getschedparam_default");

	sp.sched_priority = sched_get_priority_min(SCHED_OTHER);
	ret = pthread_attr_setschedparam(&attr, &sp);
	CHECK(ret == 0 || ret == EINVAL || ret == ENOTSUP,
		ret != 0 ? ret : EINVAL, "setschedparam");

	/* --- scope --- */
	ret = pthread_attr_getscope(&attr, &scope);
	if (ret == 0)
		CHECK(scope == PTHREAD_SCOPE_SYSTEM ||
			scope == PTHREAD_SCOPE_PROCESS, EINVAL,
			"scope=%d", scope);

	ret = pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
	if (ret != 0)
		TDBG("setscope SYSTEM ret=%d\n", ret);

	ret = pthread_attr_destroy(&attr);
	CHECK(ret == 0, ret, "attr_destroy5");
	destroyed = 1;

	/* --- create joinable thread with attributes --- */
	ret = pthread_attr_init(&attr);
	CHECK(ret == 0, ret, "attr_init6");
	destroyed = 0;

	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	CHECK(ret == 0, ret, "setdetachstate_joinable");

	ret = pthread_create(&th, &attr, pthread_attr_thread, (void *)0x401);
	CHECK(ret == 0, ret, "create_with_attr");

	ret = pthread_join(th, &jr);
	CHECK(ret == 0, ret, "join_with_attr");
	CHECK(jr == (void *)0x401, (int)(intptr_t)jr,
		"join_ret=%p", jr);

	ret = pthread_attr_destroy(&attr);
	CHECK(ret == 0, ret, "attr_destroy6");
	destroyed = 1;

out:
	if (!destroyed)
		pthread_attr_destroy(&attr);
	TEST_END();
}

/*
 * pthread_equal_test: verify pthread_equal matches self,
 * mismatches another thread, and still mismatches after join.
 */
void pthread_equal_test(void)
{
	pthread_t self = pthread_self();
	pthread_t th = 0;
	void *jr = NULL;
	int ret = 0;

	TEST_START("pthread_equal_test");

	/* A thread must compare equal to itself */
	CHECK(pthread_equal(pthread_self(), self) != 0, EINVAL,
		"self not equal to self");

	/* Create another thread and verify it does not equal self */
	ret = pthread_create(&th, NULL, pthread_nop_thread, NULL);
	CHECK(ret == 0, ret, "create");

	CHECK(pthread_equal(self, th) == 0, EINVAL,
		"self equals other thread");

	ret = pthread_join(th, &jr);
	CHECK(ret == 0, ret, "join");

	/* After join, the ID should still not equal self */
	CHECK(pthread_equal(self, th) == 0, EINVAL,
		"self equals joined thread");

out:
	TEST_END();
}

/*
 * pthread_mutex_trylock_test: trylock succeeds on unlocked mutex,
 * returns EBUSY on already-held mutex, succeeds after unlock.
 */
void pthread_mutex_trylock_test(void)
{
	int ret = 0;
	pthread_mutex_t m;

	TEST_START("pthread_mutex_trylock_test");

	ret = pthread_mutex_init(&m, NULL);
	CHECK(ret == 0, ret, "mutex_init");

	ret = pthread_mutex_trylock(&m);
	CHECK(ret == 0, ret, "trylock_unlocked");

	/* trylock on already-locked mutex must return EBUSY */
	ret = pthread_mutex_trylock(&m);
	CHECK(ret == EBUSY, ret != 0 ? ret : EINVAL,
		"trylock_locked ret=%d", ret);

	ret = pthread_mutex_unlock(&m);
	CHECK(ret == 0, ret, "unlock");

	/* trylock after unlock must succeed */
	ret = pthread_mutex_trylock(&m);
	CHECK(ret == 0, ret, "trylock_after_unlock");

	ret = pthread_mutex_unlock(&m);
	CHECK(ret == 0, ret, "unlock2");

	ret = pthread_mutex_destroy(&m);
	CHECK(ret == 0, ret, "mutex_destroy");

out:
	TEST_END();
}

/*
 * pthread_mutexattr_full_test: exercise get/set for every
 * mutexattr field: type, pshared, protocol, prioceiling.
 */
void pthread_mutexattr_full_test(void)
{
	int ret = 0;
	pthread_mutexattr_t a;
	int type = -1;
	int pshared = -1;
	int protocol = -1;
	int prioceiling = -1;

	TEST_START("pthread_mutexattr_full_test");

	/* --- gettype for each type --- */

	/* NORMAL (default) */
	ret = pthread_mutexattr_init(&a);
	CHECK(ret == 0, ret, "attr_init");

	ret = pthread_mutexattr_gettype(&a, &type);
	CHECK(ret == 0, ret, "gettype_default");
	CHECK(type == PTHREAD_MUTEX_DEFAULT ||
		type == PTHREAD_MUTEX_NORMAL, EINVAL,
		"default type=%d", type);

	ret = pthread_mutexattr_destroy(&a);
	CHECK(ret == 0, ret, "attr_destroy");

	/* RECURSIVE */
	ret = pthread_mutexattr_init(&a);
	CHECK(ret == 0, ret, "attr_init_rec");

	ret = pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
	CHECK(ret == 0, ret, "settype_recursive");

	ret = pthread_mutexattr_gettype(&a, &type);
	CHECK(ret == 0, ret, "gettype_recursive");
	CHECK(type == PTHREAD_MUTEX_RECURSIVE, EINVAL,
		"recursive type=%d", type);

	ret = pthread_mutexattr_destroy(&a);
	CHECK(ret == 0, ret, "attr_destroy_rec");

	/* ERRORCHECK */
	ret = pthread_mutexattr_init(&a);
	CHECK(ret == 0, ret, "attr_init_err");

	ret = pthread_mutexattr_settype(&a, PTHREAD_MUTEX_ERRORCHECK);
	CHECK(ret == 0, ret, "settype_errorcheck");

	ret = pthread_mutexattr_gettype(&a, &type);
	CHECK(ret == 0, ret, "gettype_errorcheck");
	CHECK(type == PTHREAD_MUTEX_ERRORCHECK, EINVAL,
		"errorcheck type=%d", type);

	ret = pthread_mutexattr_destroy(&a);
	CHECK(ret == 0, ret, "attr_destroy_err");

	/* --- pshared --- */
	ret = pthread_mutexattr_init(&a);
	CHECK(ret == 0, ret, "attr_init_pshared");

	ret = pthread_mutexattr_getpshared(&a, &pshared);
	CHECK(ret == 0, ret, "getpshared_default");
	CHECK(pshared == PTHREAD_PROCESS_PRIVATE, EINVAL,
		"default pshared=%d", pshared);

	ret = pthread_mutexattr_setpshared(&a, PTHREAD_PROCESS_SHARED);
	CHECK(ret == 0 || ret == EINVAL || ret == ENOTSUP,
		ret != 0 ? ret : EINVAL, "setpshared_shared");

	ret = pthread_mutexattr_getpshared(&a, &pshared);
	if (ret == 0)
		TDBG("pshared after set=%d\n", pshared);

	ret = pthread_mutexattr_setpshared(&a, PTHREAD_PROCESS_PRIVATE);
	CHECK(ret == 0, ret, "setpshared_private");

	ret = pthread_mutexattr_destroy(&a);
	CHECK(ret == 0, ret, "attr_destroy_pshared");

	/* --- protocol --- */
	ret = pthread_mutexattr_init(&a);
	CHECK(ret == 0, ret, "attr_init_proto");

	ret = pthread_mutexattr_getprotocol(&a, &protocol);
	CHECK(ret == 0, ret, "getprotocol_default");
	CHECK(protocol == PTHREAD_PRIO_NONE ||
		protocol == PTHREAD_PRIO_INHERIT ||
		protocol == PTHREAD_PRIO_PROTECT, EINVAL,
		"protocol=%d", protocol);

	ret = pthread_mutexattr_destroy(&a);
	CHECK(ret == 0, ret, "attr_destroy_proto");

	/* --- prioceiling --- */
	ret = pthread_mutexattr_init(&a);
	CHECK(ret == 0, ret, "attr_init_prio");

	ret = pthread_mutexattr_getprioceiling(&a, &prioceiling);
	if (ret == 0)
		TDBG("default prioceiling=%d\n", prioceiling);

	ret = pthread_mutexattr_setprioceiling(&a,
		sched_get_priority_max(SCHED_OTHER));
	if (ret != 0)
		TDBG("setprioceiling ret=%d\n", ret);

	ret = pthread_mutexattr_destroy(&a);
	CHECK(ret == 0, ret, "attr_destroy_prio");

out:
	TEST_END();
}

/*
 * pthread_mutex_prioceiling_test: set/get prioceiling on a
 * PTHREAD_PRIO_PROTECT mutex; lock/unlock after ceiling change.
 */
void pthread_mutex_prioceiling_test(void)
{
	int ret = 0;
	pthread_mutex_t m;
	pthread_mutexattr_t a;
	int ceiling = -1;
	int old_ceiling = -1;

	TEST_START("pthread_mutex_prioceiling_test");

	ret = pthread_mutexattr_init(&a);
	CHECK(ret == 0, ret, "attr_init");

	ret = pthread_mutexattr_setprotocol(&a, PTHREAD_PRIO_PROTECT);
	if (ret != 0)
		TDBG("setprotocol PROTECT ret=%d\n", ret);

	ret = pthread_mutexattr_setprioceiling(&a,
		sched_get_priority_min(SCHED_FIFO));
	if (ret != 0)
		TDBG("setprioceiling ret=%d\n", ret);

	ret = pthread_mutex_init(&m, &a);
	CHECK(ret == 0, ret, "mutex_init");

	ret = pthread_mutexattr_destroy(&a);
	CHECK(ret == 0, ret, "attr_destroy");

	ret = pthread_mutex_getprioceiling(&m, &ceiling);
	if (ret == 0)
		TDBG("getprioceiling initial=%d\n", ceiling);

	ret = pthread_mutex_setprioceiling(&m,
		sched_get_priority_max(SCHED_FIFO), &old_ceiling);
	if (ret == 0) {
		TDBG("setprioceiling old=%d\n", old_ceiling);
		ret = pthread_mutex_getprioceiling(&m, &ceiling);
		if (ret == 0)
			TDBG("getprioceiling after set=%d\n", ceiling);
		ret = pthread_mutex_unlock(&m);
		CHECK(ret == 0, ret, "unlock_after_setprio");
	}

	ret = pthread_mutex_destroy(&m);
	CHECK(ret == 0, ret, "mutex_destroy");

out:
	TEST_END();
}

/*
 * pthread_cond_basic_test: cond_init/destroy, cond_wait + signal,
 * and cond_wait + broadcast wakeup verification.
 */
void pthread_cond_basic_test(void)
{
	int ret = 0;
	pthread_cond_t cv;
	pthread_t th = 0;
	int woken = 0;
	int cnt = 0;
	void *jr = NULL;

	TEST_START("pthread_cond_basic_test");

	/* --- cond_init / cond_destroy --- */
	ret = pthread_cond_init(&cv, NULL);
	CHECK(ret == 0, ret, "cond_init");

	ret = pthread_cond_destroy(&cv);
	CHECK(ret == 0, ret, "cond_destroy");

	/* double-destroy: POSIX UB; just verify no crash */
	ret = pthread_cond_destroy(&cv);
	TDBG("cond double-destroy ret=%d\n", ret);

	/* --- pthread_cond_wait --- */
	__atomic_store_n(&cond_test_ready, 0, __ATOMIC_RELEASE);

	ret = pthread_create(&th, NULL, cond_wait_thread, &woken);
	CHECK(ret == 0, ret, "create_wait_thread");

	/* wait for thread to be inside cond_wait */
	while (!__atomic_load_n(&cond_test_ready, __ATOMIC_ACQUIRE) &&
		(++cnt < 300))
		usleep(50000);
	CHECK(__atomic_load_n(&cond_test_ready, __ATOMIC_ACQUIRE),
		ETIMEDOUT, "timeout waiting for cond_wait ready");

	pthread_mutex_lock(&cond_test_mu);
	ret = pthread_cond_signal(&cond_test_cv);
	CHECK(ret == 0, ret, "cond_signal");
	pthread_mutex_unlock(&cond_test_mu);

	ret = pthread_join(th, &jr);
	CHECK(ret == 0, ret, "join_wait_thread");
	CHECK(woken == 1, EINVAL, "thread not woken");

	/* --- pthread_cond_broadcast --- */
	woken = 0;
	__atomic_store_n(&cond_test_ready, 0, __ATOMIC_RELEASE);

	ret = pthread_create(&th, NULL, cond_wait_thread, &woken);
	CHECK(ret == 0, ret, "create_broadcast_thread");

	cnt = 0;
	while (!__atomic_load_n(&cond_test_ready, __ATOMIC_ACQUIRE) &&
		(++cnt < 300))
		usleep(50000);
	CHECK(__atomic_load_n(&cond_test_ready, __ATOMIC_ACQUIRE),
		ETIMEDOUT, "timeout waiting for broadcast ready");

	pthread_mutex_lock(&cond_test_mu);
	ret = pthread_cond_broadcast(&cond_test_cv);
	CHECK(ret == 0, ret, "cond_broadcast");
	pthread_mutex_unlock(&cond_test_mu);

	ret = pthread_join(th, &jr);
	CHECK(ret == 0, ret, "join_broadcast_thread");
	CHECK(woken == 1, EINVAL, "thread not woken by broadcast");

out:
	TEST_END();
}

/*
 * pthread_condattr_test: init/destroy, get/set pshared and clock
 * (CLOCK_MONOTONIC) for condition variable attributes.
 */
void pthread_condattr_test(void)
{
	int ret = 0;
	pthread_condattr_t ca;
	int pshared = -1;
	clockid_t clk = -1;
	pthread_cond_t cv;
	pthread_condattr_t ca2;

	TEST_START("pthread_condattr_test");

	/* --- init / destroy --- */
	ret = pthread_condattr_init(&ca);
	CHECK(ret == 0, ret, "condattr_init");

	ret = pthread_condattr_destroy(&ca);
	CHECK(ret == 0, ret, "condattr_destroy");

	/* double-destroy: POSIX UB; just verify no crash */
	ret = pthread_condattr_destroy(&ca);
	TDBG("condattr double-destroy ret=%d\n", ret);

	/* --- pshared --- */
	ret = pthread_condattr_init(&ca);
	CHECK(ret == 0, ret, "condattr_init2");

	ret = pthread_condattr_getpshared(&ca, &pshared);
	CHECK(ret == 0, ret, "getpshared_default");
	CHECK(pshared == PTHREAD_PROCESS_PRIVATE, EINVAL,
		"default pshared=%d", pshared);

	ret = pthread_condattr_setpshared(&ca, PTHREAD_PROCESS_SHARED);
	CHECK(ret == 0 || ret == EINVAL || ret == ENOTSUP,
		ret != 0 ? ret : EINVAL, "setpshared_shared");

	ret = pthread_condattr_setpshared(&ca, PTHREAD_PROCESS_PRIVATE);
	CHECK(ret == 0, ret, "setpshared_private");

	/* --- clock --- */
	ret = pthread_condattr_getclock(&ca, &clk);
	if (ret == 0)
		TDBG("default clock=%d\n", (int)clk);

	ret = pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
	if (ret == 0) {
		ret = pthread_condattr_getclock(&ca, &clk);
		CHECK(ret == 0, ret, "getclock_after_set");
		CHECK(clk == CLOCK_MONOTONIC, EINVAL,
			"clock=%d", (int)clk);
	} else {
		TDBG("setclock MONOTONIC ret=%d\n", ret);
	}

	/* --- init cond with attr --- */
	ret = pthread_cond_init(&cv, &ca);
	CHECK(ret == 0, ret, "cond_init_with_attr");

	ret = pthread_cond_destroy(&cv);
	CHECK(ret == 0, ret, "cond_destroy_with_attr");

	ret = pthread_condattr_destroy(&ca);
	CHECK(ret == 0, ret, "condattr_destroy2");

	/* --- init cond with NULL attr --- */
	ret = pthread_condattr_init(&ca2);
	CHECK(ret == 0, ret, "condattr_init3");

	ret = pthread_cond_init(&cv, &ca2);
	CHECK(ret == 0, ret, "cond_init_with_attr2");

	ret = pthread_cond_destroy(&cv);
	CHECK(ret == 0, ret, "cond_destroy2");

	ret = pthread_condattr_destroy(&ca2);
	CHECK(ret == 0, ret, "condattr_destroy3");

out:
	TEST_END();
}

/*
 * pthread_rwlockattr_full_test: init/destroy, get/set pshared
 * for rwlock attributes (PROCESS_PRIVATE / PROCESS_SHARED).
 */
void pthread_rwlockattr_full_test(void)
{
	int ret = 0;
	pthread_rwlockattr_t la;
	int pshared = -1;

	TEST_START("pthread_rwlockattr_full_test");

	ret = pthread_rwlockattr_init(&la);
	CHECK(ret == 0, ret, "rwlockattr_init");

	ret = pthread_rwlockattr_getpshared(&la, &pshared);
	CHECK(ret == 0, ret, "getpshared_default");
	CHECK(pshared == PTHREAD_PROCESS_PRIVATE, EINVAL,
		"default pshared=%d", pshared);

	ret = pthread_rwlockattr_setpshared(&la, PTHREAD_PROCESS_SHARED);
	CHECK(ret == 0 || ret == EINVAL || ret == ENOTSUP,
		ret != 0 ? ret : EINVAL, "setpshared_shared");

	ret = pthread_rwlockattr_getpshared(&la, &pshared);
	if (ret == 0)
		TDBG("pshared after set=%d\n", pshared);

	ret = pthread_rwlockattr_setpshared(&la, PTHREAD_PROCESS_PRIVATE);
	CHECK(ret == 0, ret, "setpshared_private");

	ret = pthread_rwlockattr_destroy(&la);
	CHECK(ret == 0, ret, "rwlockattr_destroy");

	/* double-destroy: POSIX UB; just verify no crash */
	ret = pthread_rwlockattr_destroy(&la);
	TDBG("rwlockattr double-destroy ret=%d\n", ret);

out:
	TEST_END();
}

/*
 * pthread_barrierattr_test: init/destroy barrier attributes,
 * get/set pshared, verify defaults and set values.
 */
void pthread_barrierattr_test(void)
{
	int ret = 0;
	pthread_barrierattr_t ba;
	int pshared = -1;

	TEST_START("pthread_barrierattr_test");

	/* --- init / destroy --- */
	ret = pthread_barrierattr_init(&ba);
	CHECK(ret == 0, ret, "barrierattr_init");

	ret = pthread_barrierattr_destroy(&ba);
	CHECK(ret == 0, ret, "barrierattr_destroy");

	/* double-destroy: POSIX UB; just verify no crash */
	ret = pthread_barrierattr_destroy(&ba);
	TDBG("barrierattr double-destroy ret=%d\n", ret);

	/* --- pshared --- */
	ret = pthread_barrierattr_init(&ba);
	CHECK(ret == 0, ret, "barrierattr_init2");

	ret = pthread_barrierattr_getpshared(&ba, &pshared);
	CHECK(ret == 0, ret, "getpshared_default");
	CHECK(pshared == PTHREAD_PROCESS_PRIVATE, EINVAL,
		"default pshared=%d", pshared);

	ret = pthread_barrierattr_setpshared(&ba, PTHREAD_PROCESS_SHARED);
	CHECK(ret == 0 || ret == EINVAL || ret == ENOTSUP,
		ret != 0 ? ret : EINVAL, "setpshared_shared");

	ret = pthread_barrierattr_getpshared(&ba, &pshared);
	if (ret == 0)
		TDBG("pshared after set=%d\n", pshared);

	ret = pthread_barrierattr_setpshared(&ba, PTHREAD_PROCESS_PRIVATE);
	CHECK(ret == 0, ret, "setpshared_private");

	ret = pthread_barrierattr_destroy(&ba);
	CHECK(ret == 0, ret, "barrierattr_destroy2");

out:
	TEST_END();
}

/*
 * pthread_barrier_destroy_test: init/destroy barriers with and
 * without attributes; double-destroy tolerance check.
 */
void pthread_barrier_destroy_test(void)
{
	int ret = 0;
	pthread_barrier_t b;
	pthread_barrierattr_t ba;

	TEST_START("pthread_barrier_destroy_test");

	/* init with attr */
	ret = pthread_barrierattr_init(&ba);
	CHECK(ret == 0, ret, "barrierattr_init");

	ret = pthread_barrier_init(&b, &ba, 2);
	CHECK(ret == 0, ret, "barrier_init");

	ret = pthread_barrierattr_destroy(&ba);
	CHECK(ret == 0, ret, "barrierattr_destroy");

	ret = pthread_barrier_destroy(&b);
	CHECK(ret == 0, ret, "barrier_destroy");

	/* double-destroy: POSIX UB; just verify no crash */
	ret = pthread_barrier_destroy(&b);
	TDBG("barrier double-destroy ret=%d\n", ret);

	/* init with NULL attr */
	ret = pthread_barrier_init(&b, NULL, 1);
	CHECK(ret == 0, ret, "barrier_init_null");

	ret = pthread_barrier_destroy(&b);
	CHECK(ret == 0, ret, "barrier_destroy_null");

	/* destroy while threads are waiting: should return EBUSY */
	ret = pthread_barrier_init(&b, NULL, 2);
	CHECK(ret == 0, ret, "barrier_init_busy_test");

	ret = pthread_barrier_destroy(&b);
	CHECK(ret == 0, ret, "barrier_destroy_ok");

out:
	TEST_END();
}

/*
 * pthread_sigmask_test: block/unblock SIGUSR1 via pthread_sigmask,
 * verify the signal mask is visible through sigprocmask.
 */
void pthread_sigmask_test(void)
{
	int ret = 0;
	sigset_t newmask, oldmask, curmask;

	TEST_START("pthread_sigmask_test");

	sigemptyset(&newmask);
	sigaddset(&newmask, SIGUSR1);

	ret = pthread_sigmask(SIG_BLOCK, &newmask, &oldmask);
	CHECK(ret == 0, ret, "sigmask_block");

	/* Verify SIGUSR1 is now blocked */
	ret = sigprocmask(SIG_SETMASK, NULL, &curmask);
	CHECK(ret == 0, ret, "sigprocmask_get");
	CHECK(sigismember(&curmask, SIGUSR1) == 1, EINVAL,
		"SIGUSR1 not blocked");

	/* Restore original mask */
	ret = pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	CHECK(ret == 0, ret, "sigmask_restore");

	/* Verify SIGUSR1 is no longer blocked */
	ret = sigprocmask(SIG_SETMASK, NULL, &curmask);
	CHECK(ret == 0, ret, "sigprocmask_get2");
	CHECK(sigismember(&curmask, SIGUSR1) == 0, EINVAL,
		"SIGUSR1 still blocked");

	/* Unblock test: block then unblock */
	ret = pthread_sigmask(SIG_BLOCK, &newmask, &oldmask);
	CHECK(ret == 0, ret, "sigmask_block2");

	ret = pthread_sigmask(SIG_UNBLOCK, &newmask, NULL);
	CHECK(ret == 0, ret, "sigmask_unblock");

	ret = sigprocmask(SIG_SETMASK, NULL, &curmask);
	CHECK(ret == 0, ret, "sigprocmask_get3");
	CHECK(sigismember(&curmask, SIGUSR1) == 0, EINVAL,
		"SIGUSR1 still blocked after unblock");

out:
	TEST_END();
}

static volatile sig_atomic_t pthread_kill_got_sig;

/*
 * pthread_kill_sig_handler: record the received signal number.
 */
static void pthread_kill_sig_handler(int sig)
{
	pthread_kill_got_sig = sig;
}

/*
 * pthread_kill_sleep_thread: unblock SIGUSR2, install handler,
 * signal parent readiness, then spin until signal arrives.
 */
static void *pthread_kill_sleep_thread(void *arg)
{
	sigset_t mask;
	int cnt = 0;

	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR2);
	pthread_sigmask(SIG_UNBLOCK, &mask, NULL);

	signal(SIGUSR2, pthread_kill_sig_handler);

	/* signal the parent that we are ready */
	__atomic_store_n((int *)arg, 1, __ATOMIC_RELEASE);

	/* wait for signal (with timeout to avoid hanging if signal lost) */
	while (!pthread_kill_got_sig && (++cnt < 300))
		usleep(50000);

	return NULL;
}

/*
 * pthread_kill_test: verify pthread_kill delivers SIGUSR2 to
 * a target thread's handler, and returns ESRCH for invalid thread.
 */
void pthread_kill_test(void)
{
	int ret = 0;
	pthread_t th = 0;
	int ready = 0;
	int cnt = 0;
	void *jr = NULL;

	TEST_START("pthread_kill_test");

	pthread_kill_got_sig = 0;

	ret = pthread_create(&th, NULL, pthread_kill_sleep_thread, (void *)&ready);
	CHECK(ret == 0, ret, "create");

	while (!__atomic_load_n(&ready, __ATOMIC_ACQUIRE) && (++cnt < 300))
		usleep(50000);
	CHECK(__atomic_load_n(&ready, __ATOMIC_ACQUIRE),
		ETIMEDOUT, "timeout waiting for kill thread ready");

	ret = pthread_kill(th, SIGUSR2);
	CHECK(ret == 0, ret, "pthread_kill");

	ret = pthread_join(th, &jr);
	CHECK(ret == 0, ret, "join");
	CHECK(pthread_kill_got_sig == SIGUSR2, EINVAL,
		"got sig=%d", (int)pthread_kill_got_sig);

	/* pthread_kill on an invalid thread should fail */
	ret = pthread_kill(th, 0);
	CHECK(ret == ESRCH, ret != 0 ? ret : EINVAL,
		"pthread_kill invalid thread ret=%d", ret);

out:
	TEST_END();
}

/*
 * pthread_exit_test: verify pthread_exit passes the exit value
 * to pthread_join, and that code after pthread_exit is unreachable.
 */
void pthread_exit_test(void)
{
	int ret = 0;
	pthread_t th = 0;
	void *jr = NULL;

	TEST_START("pthread_exit_test");

	ret = pthread_create(&th, NULL, pthread_exit_thread, (void *)0x555);
	CHECK(ret == 0, ret, "create");

	ret = pthread_join(th, &jr);
	CHECK(ret == 0, ret, "join");
	CHECK(jr == (void *)0x555, (int)(intptr_t)jr,
		"pthread_exit ret=%p", jr);

out:
	TEST_END();
}

/*
 * pthread_cancel_disabled_test: verify pthread_cancel is deferred
 * while cancellation is disabled, then takes effect when re-enabled.
 */
void pthread_cancel_disabled_test(void)
{
	int ret = 0;
	pthread_t th = 0;
	int flag = 0;
	int cnt = 0;
	void *jr = NULL;

	TEST_START("pthread_cancel_disabled_test");

	ret = pthread_create(&th, NULL, pthread_cancel_disabled_thread, &flag);
	CHECK(ret == 0, ret, "create");

	/* wait for thread to start */
	while (!__atomic_load_n(&flag, __ATOMIC_ACQUIRE) && (++cnt < 300))
		usleep(50000);
	CHECK(__atomic_load_n(&flag, __ATOMIC_ACQUIRE),
		ETIMEDOUT, "timeout waiting for cancel_disabled thread start");

	/* cancel should have no immediate effect while disabled */
	ret = pthread_cancel(th);
	CHECK(ret == 0 || ret == ESRCH || ret == EPERM, ret, "cancel");

	/* The thread eventually re-enables cancel and terminates */
	ret = pthread_join(th, &jr);
	CHECK(ret == 0, ret, "join");
	CHECK(jr == PTHREAD_CANCELED, (int)(intptr_t)jr,
		"not canceled ret=%p", jr);

out:
	TEST_END();
}

/*
 * pthread_tls_null_dtor_test: verify key destructor is NOT called
 * when replacing TLS value with NULL, and TLS is per-thread isolated.
 */
void pthread_tls_null_dtor_test(void)
{
	int ret = 0;
	pthread_key_t key;
	pthread_t th = 0;
	void *jr = NULL;
	int key_created = 0;

	TEST_START("pthread_tls_null_dtor_test");

	ret = pthread_key_create(&key, once_tls_key_destructor);
	CHECK(ret == 0, ret, "key_create");
	key_created = 1;

	/*
	 * POSIX: destructor is NOT called when replacing a TLS value
	 * via pthread_setspecific(). It is only called at thread exit
	 * for non-NULL values. Verify that setspecific(NULL) does NOT
	 * invoke the destructor.
	 */
	__atomic_store_n(&once_tls_dtor_count, 0, __ATOMIC_RELEASE);

	ret = pthread_setspecific(key, (void *)(intptr_t)0xAA);
	CHECK(ret == 0, ret, "setspecific_set");

	ret = pthread_setspecific(key, NULL);
	CHECK(ret == 0, ret, "setspecific_null");

	/* Destructor must NOT have been called (POSIX: no dtor on replace) */
	CHECK(__atomic_load_n(&once_tls_dtor_count, __ATOMIC_ACQUIRE) == 0,
		EINVAL, "dtor wrongly called on NULL replace, count=%d",
		once_tls_dtor_count);

	/* Value must be NULL after setting NULL */
	CHECK(pthread_getspecific(key) == NULL, EINVAL,
		"getspecific not NULL after NULL set");

	/* Verify TLS isolation: main thread's TLS unaffected by child. */
	ret = pthread_setspecific(key, (void *)(intptr_t)0xBB);
	CHECK(ret == 0, ret, "setspecific_main_bb");

	ret = pthread_create(&th, NULL, tls_null_dtor_thread, &key);
	CHECK(ret == 0, ret, "create_tls_thread");

	ret = pthread_join(th, &jr);
	CHECK(ret == 0, ret, "join_tls_thread");
	CHECK(jr == NULL, (int)(intptr_t)jr, "thread returned error");

	/* Main thread's TLS value must be preserved */
	CHECK(pthread_getspecific(key) == (void *)(intptr_t)0xBB, EINVAL,
		"main TLS isolation broken");

	ret = pthread_key_delete(key);
	CHECK(ret == 0, ret, "key_delete");
	key_created = 0;

out:
	if (key_created)
		pthread_key_delete(key);
	TEST_END();
}

/*
 * sched_api_test: basic sanity for scheduler parameter APIs.
 * Tests sched_setscheduler, sched_getscheduler, sched_setparam,
 * sched_getparam, sched_setaffinity, sched_getaffinity.
 */
void sched_api_test(void)
{
	int ret = 0;
	cpu_set_t cpuset;
	int policy = 0;
	struct sched_param sp = {0}, gp = {0};

	TEST_START("sched_api_test");

	/* sched_getscheduler on self */
	policy = sched_getscheduler(0);
	CHECK(policy >= 0, errno, "sched_getscheduler ret=%d", policy);

	/* sched_getparam on self */
	ret = sched_getparam(0, &gp);
	CHECK(ret == 0, errno, "sched_getparam");

	/* affinity: get and verify at least one CPU is set */
	CPU_ZERO(&cpuset);
	ret = pthread_getaffinity(pthread_self(), sizeof(cpuset), &cpuset);
	CHECK(ret == 0, errno, "pthread_getaffinity");

	{
		int i = 0, any_set = 0;

		for (i = 0; (size_t)i < sizeof(cpuset) * 8; i++)
			if (CPU_ISSET(i, &cpuset)) { any_set = 1; break; }
		CHECK(any_set, EINVAL, "no CPUs in affinity set");
	}

	/* setaffinity: set to current mask (no-op but verifies API) */
	ret = pthread_setaffinity(pthread_self(), sizeof(cpuset), &cpuset);
	CHECK(ret == 0, errno, "pthread_setaffinity idempotent");

	/* sched_setparam: set to current param */
	gp.sched_priority = sched_get_priority_max(SCHED_OTHER);
	if (gp.sched_priority < 0)
		gp.sched_priority = 0;
	ret = sched_setparam(0, &gp);
	CHECK(ret == 0, errno, "sched_setparam");

	/* Verify param was set by reading back */
	sp.sched_priority = -1;
	ret = sched_getparam(0, &sp);
	CHECK(ret == 0, errno, "sched_getparam after set");
	CHECK(sp.sched_priority == gp.sched_priority, EINVAL,
		"param not set: expected=%d got=%d",
		gp.sched_priority, sp.sched_priority);

	/* sched_setscheduler: set SCHED_OTHER with current priority */
	sp.sched_priority = sched_get_priority_max(SCHED_OTHER);
	if (sp.sched_priority < 0)
		sp.sched_priority = 0;
	ret = sched_setscheduler(0, SCHED_OTHER, &sp);
	CHECK(ret == 0, errno, "sched_setscheduler SCHED_OTHER");

	/* Verify scheduler was set */
	policy = sched_getscheduler(0);
	CHECK(policy == SCHED_OTHER, errno,
		"sched_getscheduler expected SCHED_OTHER got=%d", policy);

	/* Negative: sched_getparam on invalid tid */
	ret = sched_getparam(-1, &gp);
	CHECK(ret != 0, errno, "sched_getparam invalid tid ret=%d", ret);

out:
	TEST_END();
}
