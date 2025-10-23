/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 *
 * mbedtest internal header -- shared decls between mbedtest.c and
 * the per-subsystem mbedtest_<module>.c files. Not part of the public
 * TEST API (that lives in mbedtest.h).
 *
 * This header ONLY contains definitions that are genuinely shared
 * across multiple .c files. Subsystem-specific constants, structs,
 * and single-consumer externs belong in their respective .c files.
 */

#ifndef _MBEDTEST_INTERNAL_H
#define _MBEDTEST_INTERNAL_H

/* ---- Common system headers (used broadly across test files) ---- */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <mqueue.h>
#include <semaphore.h>
#include <defs.h>
#include <utrace.h>
#include <misc.h>
#include <spawn.h>
#include <waitpid.h>

/* ----- Logging shims (consistent across all files) ------------------- */
#ifndef TLOG
#define TLOG(...)  IMSG(__VA_ARGS__)
#endif
#ifndef TERR
#define TERR(...)  EMSG(__VA_ARGS__)
#endif
#ifndef TDBG
#define TDBG(...)  DMSG(__VA_ARGS__)
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

/* ----- Genuinely cross-file shared state ----------------------------- */

/* Defined in mbedtest_pthread.c, used by mbedtest_signal.c */
extern pthread_mutex_t test_mutex;

/* Defined in mbedtest_pthread.c, used by mbedtest_io.c */
extern pthread_barrier_t test_barrier_dup1;
extern pthread_barrier_t test_barrier_dup2;

/*
 * Shared test buffer -- only the altstack buffer (SIGSTKSZ) is shared
 * across files.  4K scratch buffers are local to each function.
 * Defined in mbedtest_misc.c.
 */
extern char mbedtest_altstack_buf[SIGSTKSZ];

/* ----- Shared utility helpers (defined in mbedtest_misc.c) ----------- */
void test_unlink(const char *path);
void test_rmdir(const char *path);
void test_shm_unlink(const char *path);
void test_mq_unlink(const char *path);
void test_sem_unlink(const char *path);
int  test_rand(void);
int  test_rng(void *ctx, uint8_t *out, size_t len);
ssize_t test_write_full(int fd, const void *buf, size_t len);
ssize_t test_read_full(int fd, void *buf, size_t len);
int  test_mkpath(char *buf, size_t buflen,
		 const char *dir, const char *suffix);

/* Add milliseconds to a timespec using the standard timespecadd macro. */
static inline void test_timespec_add_ms(
	struct timespec *ts, unsigned int ms)
{
	struct timespec delta;

	delta.tv_sec = ms / 1000;
	delta.tv_nsec = (ms % 1000) * 1000000L;
	timespecadd(ts, &delta, ts);
}

/* Resource-cleanup helper: close fd if open, set to -1, return close() result. */
static inline int test_close_fd(int *fd)
{
	int ret = 0;

	if (*fd >= 0) {
		ret = close(*fd);
		*fd = -1;
	}
	return ret;
}

/* Resource-cleanup helper: close mq descriptor, set to -1, return mq_close() result. */
static inline int test_close_mq_fd(mqd_t *fd)
{
	int ret = 0;

	if (*fd >= 0) {
		ret = mq_close(*fd);
		*fd = -1;
	}
	return ret;
}

/* Resource-cleanup helper: close semaphore, set to SEM_FAILED, return sem_close() result. */
static inline int test_close_sem(sem_t **sem)
{
	int ret = 0;

	if (*sem != SEM_FAILED) {
		ret = sem_close(*sem);
		*sem = SEM_FAILED;
	}
	return ret;
}

/*
 * TEST_POLL_OPEN -- poll until an open-like function succeeds or times out.
 */
#define TEST_POLL_OPEN(var, failval, open_call, timeout_ms)              \
	do {                                                                 \
		int _tpo_cnt = 0;                                                \
		int _tpo_max = (timeout_ms) / 20;                                \
		int _tpo_err = 0;                                                \
		(var) = (failval);                                               \
		while ((var) == (failval) && _tpo_cnt < _tpo_max) {              \
			(var) = (open_call);                                         \
			_tpo_err = errno;                                            \
			if ((var) == (failval)) {                                    \
				_tpo_cnt++;                                              \
				usleep(20000);                                           \
			}                                                            \
		}                                                                \
		if ((var) == (failval))                                          \
			errno = _tpo_err;                                            \
	} while (0)

/* ----- Process / pipeline helpers (defined in mbedtest_process.c) ---- */
int  pipeline_stdin_to_stdout(void);
int  pipeline_gen_bytes(size_t nbytes);
int  pipeline_sink_bytes(size_t expect);
void pipeline_redirect_chk(const char *path, int code);
int  proc_execve_probe_write(const char *path);
int  proc_execve_spawn_probe(const char *self, const char *probe_path);
void proc_spawn_waitpid_basic_test(void);

/* ----- Per-subsystem test entry points ------------------------------- */

/* float (mbedtest_float.c) */
void float_test(void);
void float_corner_test(void);
void float_convert_test(void);
int  float_f_test(int rounds);
int  float_d_test(int rounds);
int  float_ld_test(int rounds);
int  float_f_neg_test(int rounds);
int  float_d_neg_test(int rounds);

/* rand (mbedtest_rand.c) */
void urandom_test(void);

/* timer/time (mbedtest_timer.c) */
void time_test(void);
void clock_gettime_test(void);
void clock_getres_test(void);

/* io (mbedtest_io.c) */
void dup_test(void);
void dup_cloexec_test(void);
void poll_test(void);
void epoll_test1(void);
void epoll_test2(void);
void fcntl_flags_test(void);
void fcntl_dupfd_test(void);
void poll_invalid_fd_test(void);
void epoll_oneshot_test(void);
void epoll_hup_err_test(void);
void epoll_et_test(void);
void eventfd_basic_test(void);
void select_basic_test(void);
void pselect_basic_test(void);

/* pipe (mbedtest_pipe.c) */
void pipe_basic_test(void);
void pipe_2proc_send(void);
int  pipe_2proc_recv(const char *mq_name);
void pipe_wraparound_test(void);
void pipe_blocking_read_eof_on_close_test(void);
void pipe_blocking_write_epipe_on_close_test(void);
void pipe2_flags_test(void);
void pipe_epollout_backpressure_test(void);

/* signal (mbedtest_signal.c) */
void signal_test(void);
void signal_api_test(void);
void signal_alarm_test(void);
void signal_eintr_test(void);
void signal_altstack_test(void);
void signal_si_code_test(void);
int  mbedtest_sigalrm_child(void);

/* pthread (mbedtest_pthread.c) */
void cond_timedwait_test(void);
void pthread_mutex_type_test(void);
void pthread_rwlock_try_timed_test(void);
void pthread_detach_join_test(void);
void pthread_cancel_deferred_test(void);
void pthread_spin_basic_test(void);
void pthread_once_tls_test(void);
void pthread_attr_test(void);
void pthread_equal_test(void);
void pthread_mutex_trylock_test(void);
void pthread_mutexattr_full_test(void);
void pthread_mutex_prioceiling_test(void);
void pthread_cond_basic_test(void);
void pthread_condattr_test(void);
void pthread_rwlockattr_full_test(void);
void pthread_barrierattr_test(void);
void pthread_barrier_destroy_test(void);
void pthread_sigmask_test(void);
void pthread_kill_test(void);
void pthread_exit_test(void);
void pthread_cancel_disabled_test(void);
void pthread_tls_null_dtor_test(void);
void sched_api_test(void);
void lock_stress_test(void);
void cpu_time_test(void);
void host_affinity_test(pthread_t host);
void init_sync_objects(pthread_t host);
int  barrier_affinity_test(pthread_t host,
		pthread_t *t1, pthread_t *t2, pthread_t *t3);
int  join_cancel_test(pthread_t host, pthread_t t1,
		pthread_t t2, pthread_t t3);
int  sched_cond_test(pthread_t host);
void *t1_routine(void *arg);
void *t2_routine(void *arg);
void *t3_routine(void *arg);
void *t4_routine(void *arg);
void test_abort_handler(void *arg);

/* mq (mbedtest_mq.c) */
bool mq_test_peer_died(pid_t peer);
int  mq_receive_fd_timed(mqd_t mqdes, int *outfd, long timeout_ms);
int  mq_notify_thread(void);
int  mq_notify_signal(void);
int  mq_static_test(void);
int  mq_fd_2proc_send(void);
int  mq_fd_2proc_recv(const char *mq_name);
int  mq_2proc_send(void);
int  mq_2proc_recv(const char *mq_name);
void mq_setattr_nonblock_test(void);
void mq_priority_order_test(void);
void mq_notify_oneshot_thread_test(void);
void mq_notify_oneshot_signal_test(void);
void mq_timed_edges_test(void);

/* sem (mbedtest_sem.c) */
void sem_wait_eintr_test(void);
void sem_basic_test(void);
void sem_named_test(void);
void sem_named_2proc_send(void);
int  sem_named_2proc_recv(const char *tag);
void sem_pipe_handshake_test(void);
void sem_timedwait_test(void);

/* timer/time (mbedtest_timer.c) */
int  timer_thd(void);
int  timer_sig(void);
int  timer_combo(void);
void timer_getoverrun_test(void);
void timer_monotonic_test(void);

/* fs (mbedtest_fs.c) */
void fs_test(void);

#endif /* _MBEDTEST_INTERNAL_H */
