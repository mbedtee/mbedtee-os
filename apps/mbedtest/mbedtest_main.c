// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * mbedtest_main.c -- Entry point, CLI dispatch, and test orchestrator.
 */
#define _GNU_SOURCE
#include <getopt.h>

#include "mbedtest.h"
#include "mbedtest_internal.h"

__attribute__((weak)) int mbedcrypto_test(int perf)
{
	printf("mbedcrypto not included - CONFIG_MBEDTEST_CRYPTO\n");
	/* Distinct non-zero status: the suite did NOT run. */
	return ENOSYS;
}

/*
 * Top-level test orchestrator: sets up env and runs all sub-tests
 */
static void mbedtest(void)
{
	pthread_t t1 = 0, t2 = 0, t3 = 0;
	pthread_t host = 0;
	int ret = -1;

	pthread_cleanup_push(test_abort_handler, "main");

	/*
	 * Prepare required test directories.
	 */
	if (access("/test", R_OK)) {
		mkdir("/test", 0700);
		mkdir("/ree", 0700);
		mkdir("/user", 0700);
		mkdir("/shm/test", 0700);
	}

	/* ==== Setup ==== */
	time_test();

	host = pthread_self();
	host_affinity_test(host);
	init_sync_objects(host);

	/* ==== Timer & Clock ==== */
	/*
	 * Single-threaded phase: nothing above this point may have created a
	 * thread yet.  A sibling would accept the process-directed SIGUSR1
	 * instead (POSIX-legal), and these tests read per-notification state.
	 */
	timer_stale_signal_test();
	timer_getoverrun_test();
	sleep_signal_test();
	timer_ignored_pending_test();
	timer_sig();
	timer_thd();
	timer_combo();
	timer_monotonic_test();
	clock_gettime_test();
	clock_getres_test();
	cpuclockid_test();

	/* ==== I/O Multiplexing ==== */
	poll_test();
	poll_invalid_fd_test();
	epoll_test1();
	epoll_test2();
	epoll_create1_test();
	epoll_ctl_error_test();
	epoll_oneshot_test();
	epoll_hup_err_test();
	epoll_et_test();
	pipe_epollout_backpressure_test();
	fcntl_flags_test();
	fcntl_dupfd_test();
	ioctl_test();
	eventfd_basic_test();
	select_basic_test();
	pselect_basic_test();

	/* ==== Process Lifecycle ==== */
	proc_spawn_waitpid_basic_test();

	/* ==== Message Queues ==== */
	mq_fd_2proc_send();
	mq_2proc_send();
	mq_static_test();
	mq_notify_thread();
	mq_notify_signal();
	mq_setattr_nonblock_test();
	mq_priority_order_test();
	mq_notify_oneshot_thread_test();
	mq_notify_oneshot_signal_test();
	mq_timed_edges_test();
	mq_notify_error_test();
	mq_name_rule_test();

	/* ==== Signals ==== */
	signal_api_test();
	signal_alarm_test();
	alarm_test();
	signal_test();
	signal_eintr_test();
	signal_altstack_test();
	signal_si_code_test();

	/* ==== Pipes ==== */
	pipe_basic_test();
	pipe_wraparound_test();
	pipe_blocking_read_eof_on_close_test();
	pipe_blocking_write_epipe_on_close_test();
	pipe_2proc_send();
	pipe2_flags_test();

	/* ==== Semaphores ==== */
	sem_pipe_handshake_test();
	sem_basic_test();
	sem_named_test();
	sem_name_rule_test();
	sem_named_2proc_send();
	sem_wait_eintr_test();
	sem_timedwait_test();

	/* ==== Pthreads (standalone -- no barrier dependency) ==== */
	cond_timedwait_test();
	pthread_mutex_type_test();
	pthread_rwlock_try_timed_test();
	pthread_detach_join_test();
	pthread_cancel_deferred_test();
	pthread_attr_test();
	pthread_equal_test();
	pthread_mutex_trylock_test();
	pthread_mutexattr_full_test();
	pthread_mutex_prioceiling_test();
	pthread_cond_basic_test();
	pthread_condattr_test();
	pthread_rwlockattr_full_test();
	pthread_barrierattr_test();
	pthread_barrier_destroy_test();
	pthread_sigmask_test();
	pthread_kill_test();
	pthread_exit_test();
	pthread_cancel_disabled_test();
	pthread_tls_null_dtor_test();
	sched_api_test();
	gettid_max_test();

	/* ==== Barrier: spawn t1/t2/t3 worker threads ==== */
	ret = barrier_affinity_test(host, &t1, &t2, &t3);
	if (ret != 0)
		goto out;

	/* ==== Concurrent stress (main + t1/t2/t3 run in parallel) ==== */
	float_test();
	float_corner_test();
	fs_test();
	urandom_test();
	dup_test();
	dup_cloexec_test();
	pthread_spin_basic_test();
	pthread_once_tls_test();
	lock_stress_test();
	cpu_time_test();

	/* ==== Post-barrier (requires t1/t2/t3 handles) ==== */
	join_cancel_test(host, t1, t2, t3);
	sched_cond_test(host);

out:
	test_summary();
	pthread_cleanup_pop(0);
}

/*
 * mbedtest_run -- run the full suite and turn the summary into an exit
 * status: 0 when no test failed (skips alone do not fail the run),
 * 1 otherwise.
 */
static int mbedtest_run(void)
{
	mbedtest();
	return __atomic_load_n(&g_test_stats.failed_tests, __ATOMIC_RELAXED)
		? 1 : 0;
}

static int mbedtest_pipeline_dispatch(int argc, char *argv[])
{
	unsigned long long n = 0;
	char msg[32] = {0};
	int code = 0, fd = -1, len = 0;

	if (argc <= 0)
		return EINVAL;

	if (strcmp(argv[0], "exit") == 0) {
		if (argc != 2)
			return EINVAL;
		exit(atoi(argv[1]));
		return 0;
	}

	if (strcmp(argv[0], "exitfile") == 0) {
		if (argc != 3)
			return EINVAL;
		code = atoi(argv[2]);
		fd = open(argv[1], O_CREAT | O_TRUNC | O_WRONLY, 0644);
		if (fd < 0)
			return errno;
		len = snprintf(msg, sizeof(msg), "EXIT:%d\n", code);
		if (len > 0)
			write(fd, msg, len);
		close(fd);
		exit(code);
		return 0;
	}

	if (strcmp(argv[0], "redirchk") == 0) {
		if (argc != 3)
			return EINVAL;
		pipeline_redirect_chk(argv[1], atoi(argv[2]));
		return 0;
	}

	if (strcmp(argv[0], "cat") == 0) {
		if (argc != 1)
			return EINVAL;
		return pipeline_stdin_to_stdout();
	}

	if (strcmp(argv[0], "gen") == 0) {
		if (argc != 2)
			return EINVAL;
		n = strtoull(argv[1], NULL, 0);
		return pipeline_gen_bytes(n);
	}

	if (strcmp(argv[0], "sink") == 0) {
		if (argc != 2)
			return EINVAL;
		n = strtoull(argv[1], NULL, 0);
		return pipeline_sink_bytes(n);
	}

	return EINVAL;
}

static struct option long_options[] = {
	{"test",                  no_argument,       NULL, 't'},
	{"help",                  no_argument,       NULL, 'h'},
	{"crypto",                no_argument,       NULL, 'c'},
	{"crypto-perf",           no_argument,       NULL, 'C'},
	{"msgq",                  required_argument, NULL, 'm'},
	{"sendfd",                required_argument, NULL, 's'},
	{"namedsem",              required_argument, NULL, 'n'},
	{"pipe",                  required_argument, NULL, 'p'},
	{"pipeline",              no_argument,       NULL, 'P'},
	{"sigalrm-child",         no_argument,       NULL, 'a'},
	{"alarm-child",           no_argument,       NULL, 'A'},
	{"execve-probe",          required_argument, NULL, 'e'},
	{"execve-spawn-probe",    required_argument, NULL, 'E'},
	{0, 0, NULL, 0}
};

static int optarg_bad(const char *arg, int need_slash)
{
	if (!arg || arg[0] == '\0')
		return 1;
	if (need_slash && arg[0] != '/')
		return 1;
	return 0;
}

int main(int argc, char *argv[])
{
	int option_index = -1, opt = -1;
	int show_help = 0;

	if (argc < 2) {
		/* Backward compat: plain `mbedtest` runs the full test suite */
		return mbedtest_run();
	}

	while ((opt = getopt_long(argc, argv, "thcCm:s:n:p:P",
		long_options, &option_index)) != -1) {
		switch (opt) {
		case 't':
			return mbedtest_run();
		case 'c':
			return mbedcrypto_test(0);
		case 'C':
			return mbedcrypto_test(1);
		case 'm':
			if (optarg_bad(optarg, 1))
				goto bad_optarg;
			return mq_2proc_recv(optarg);
		case 's':
			if (optarg_bad(optarg, 1))
				goto bad_optarg;
			return mq_fd_2proc_recv(optarg);
		case 'n':
			if (optarg_bad(optarg, 0))
				goto bad_optarg;
			return sem_named_2proc_recv(optarg);
		case 'p':
			if (optarg_bad(optarg, 1))
				goto bad_optarg;
			return pipe_2proc_recv(optarg);
		case 'P':
			return mbedtest_pipeline_dispatch(argc - optind,
				argv + optind);
		case 'a':
			return mbedtest_sigalrm_child();
		case 'A':
			return mbedtest_alarm_child();
		case 'e':
			if (optarg_bad(optarg, 1))
				goto bad_optarg;
			return proc_execve_probe_write(optarg);
		case 'E':
			if (optarg_bad(optarg, 1))
				goto bad_optarg;
			return proc_execve_spawn_probe(argv[0], optarg);

		case 'h':
			show_help = 1;
			goto err;
		default:
			goto err;
		}
	}

	/* the option loop ended without selecting a mode (e.g. `mbedtest foo`) */
	printf("main: no test mode selected, see --help\n");
	return EINVAL;

bad_optarg:
	printf("main: ignoring bad optarg '%c'='%s'\n",
		opt, optarg ? optarg : "(null)");
	/* Non-zero: the requested mode did not run. */
	return EINVAL;

err:
	printf("help info:\n");
	printf("--test       run full automated test suite\n");
	printf("--crypto     run mbedcrypto test suite\n");
	printf("--crypto-perf run mbedcrypto perf benchmarks\n");
	printf("--msgq       message-queue 2-proc peer\n");
	printf("--sendfd     mq fd-passing 2-proc peer\n");
	printf("--namedsem   named semaphore 2-proc peer\n");
	printf("--pipe       pipe 2-proc peer\n");
	printf("--pipeline <subcmd> pipeline/spawn helpers\n");
	printf("  exit <code> | exitfile <path> <code>\n");
	printf("  redirchk <path> <code> | cat\n");
	printf("  gen <nbytes> | sink <nbytes>\n");
	printf("--execve-probe <path>\n");
	printf("--execve-spawn-probe <path>\n");
	return show_help ? 0 : EINVAL;
}
