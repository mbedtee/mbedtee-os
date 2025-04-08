// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 *
 * TA for testing the OS functionalities:
 *-------------------------------------------
 *  libc/pthread/shm/msgq/signal/timer
 *  file/fs/poll/epoll/dup/float etc..
 *-------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/syslimits.h>

#include <defs.h>
#include <mmap.h>
#include <math.h>
#include <poll.h>
#include <epoll.h>
#include <sched.h>
#include <utrace.h>
#include <mqueue.h>
#include <pthread.h>
#include <syscall.h>

#include <generated/autoconf.h>

#define GLOBAL_MUTEXLOCK_CNT 10000
#define GLOBAL_RWLOCK_CNT 10000
static pthread_mutex_t test_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t test_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static __volatile int global_variable;
static __volatile int global_variable_rwlock;
static struct timespec tt1 = {0};
static struct timespec tt2 = {0};
static struct timespec tt3 = {0};
static struct timespec tt4 = {0};
static pthread_barrier_t test_barrier = -1;
static pthread_barrier_t test_barrier_dup1 = -1;
static pthread_barrier_t test_barrier_dup2 = -1;
static __volatile int test_barrier_cnt = 4, barrier_started;
static struct timespec realt = {0};

static pthread_once_t once_control = PTHREAD_ONCE_INIT;
#define NOTIFY_TEST_BUF_SIZE 256
#define NOTIFY_TEST_ROUND 20
static __volatile int mqnotify_exit[NOTIFY_TEST_ROUND] = {0};
static __volatile mqd_t mqdes[NOTIFY_TEST_ROUND] = {0};
static char mq_notify_name[NOTIFY_TEST_ROUND][64] = {{0}};
#define MQ_2PROC_TESTRUNS (15)
static int sigev_cnt;
static int sigev_cnt_sig;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static __volatile int t4_counter;
static pthread_cond_t t4_cond = PTHREAD_COND_INITIALIZER;
static __volatile long global_sigtest_mutex;
#define GLOBAL_SIGTEST_MUTEX_CNT 1000
static __volatile int sigwait_step;
static int epollfds[10240] = {0}, epfd = -1;
#define MIGHT_EXIT {if ((rand()%23) == 0) \
	{IMSG("=========force exiting=========\n\n"); exit(0); }}

#define TRIGGER_EXCEPTION(err) do {	         \
	EMSG("mbedtest-oops 0x%x:\n", err);	 \
	*(__volatile int *)-1 = 0;               \
} while (0)

static __volatile double in_d1[4] = {
	1234.987673, 918124.673981, 67821.1203, 311891.067128,
};
static __volatile double in_d2[4] = {
	89914.181767, 17224.83985, 737821.0123, 73421.570345,
};

static __volatile double mul_d[4] = {
	111042906.110126358191, 15814550471.65618694285,
	50039847635.06607969, 22899531925.11556911916,
};
static __volatile double div_d[4] = {
	0.01373518224522464613132267108428, 53.302363445834882464814324529119,
	0.09192083062067057371063163471795, 4.2479487385308933765219374238379,
};
static __volatile double add_d[4] = {
	91149.16944, 935349.513831, 805642.1326, 385312.637473,
};

static __volatile float in_f1[4] = {
	24.6981, 1234.987673, 621.1203, 391.067128,
};
static __volatile float in_f2[4] = {
	12.83985, 814.181767, 7821.0123, 1.570345,
};
static __volatile float add_f[4] = {
	37.53795, 2049.16944, 8442.1326, 392.637473,
};
static __volatile float div_f[4] = {
	1.923550508767625790020911459246, 1.5168451604492882238666000487825,
	0.07941686781390178864697604426476, 249.03261894679194699253985589154,
};
static __volatile float mul_f[4] = {
	317.119899285, 1005504.445826358191, 4857789.50607969, 614.11030911916,
};

static __volatile long double in_ld1[4] = {
	1234.987673, 918124.673981, 67821.1203, 311891.067128,
};
static __volatile long double in_ld2[4] = {
	89914.181767, 17224.83985, 737821.0123, 73421.570345,
};

static __volatile long double mul_ld[4] = {
	111042906.110126358191, 15814550471.65618694285,
	50039847635.06607969, 22899531925.11556911916,
};
static __volatile long double div_ld[4] = {
	0.01373518224522464613132267108428, 53.302363445834882464814324529119,
	0.09192083062067057371063163471795, 4.2479487385308933765219374238379,
};
static __volatile long double add_ld[4] = {
	91149.16944, 935349.513831, 805642.1326, 385312.637473,
};
static __volatile long double sub_ld[4] = {
	-88679.194094, 900899.834131, -669999.892, 238469.496783,
};

static void __pthread_t1_atexit(void)
{
	IMSG("exiting\n\n");
}
static void __pthread_t2_atexit(void)
{
	IMSG("exiting\n\n");
}
static void __pthread_t3_atexit(void)
{
	IMSG("exiting\n\n");
}
static void __pthread_t4_atexit(void)
{
	IMSG("exiting\n\n");
}

static __noinline void float_f_test(void)
{
	int i = 0;
	int loops;
	void *refpp, *tmpp;
	float tmp, diff;

	for (loops = 0; loops < (rand()%500); loops++) {
		for (i = 0; i < ARRAY_SIZE(in_f1); i++) {
			tmp = in_f1[i] + in_f2[i];
			diff = fabs(tmp - add_f[i]);
			if (diff >= 0.00001) {
				refpp = (void *)&add_f[i];
				tmpp = (void *)&tmp;
				IMSG("%d add_f %f expect %f, but got %f [0x%x - 0x%x]\n",
					i, diff, add_f[i], tmp, *(unsigned int *)refpp,
					*(unsigned int *)tmpp);
				TRIGGER_EXCEPTION(i);
			}
		}

		for (i = 0; i < ARRAY_SIZE(in_f1); i++) {
			tmp = in_f1[i] * in_f2[i];

			if (loops % 3 == 0)
				usleep(1);

			diff = fabs(tmp - mul_f[i]);
			if (diff >= 0.0001) {
				refpp = (void *)&mul_f[i];
				tmpp = (void *)&tmp;
				IMSG("%d mul_f %f expect %f, but got %f [0x%x - 0x%x]\n",
					i, diff, mul_f[i], tmp, *(unsigned int *)refpp,
					*(unsigned int *)tmpp);
				TRIGGER_EXCEPTION(i);
			}
		}

		for (i = 0; i < ARRAY_SIZE(in_f1); i++) {
			tmp = in_f1[i] / in_f2[i];
			diff = fabs(tmp - div_f[i]);
			if (diff >= 0.0001) {
				refpp = (void *)&div_f[i];
				tmpp = (void *)&tmp;
				IMSG("%d div_f %f expect %f, but got %f [0x%x - 0x%x]\n",
					i, diff, div_f[i], tmp, *(unsigned int *)refpp,
					*(unsigned int *)tmpp);
				TRIGGER_EXCEPTION(i);
			}
		}
	}
}

static __noinline void float_d_test(void)
{
	int i = 0;
	int loops;
	void *refpp = NULL, *tmpp = NULL;
	double tmp[ARRAY_SIZE(in_d1) * 3] = {0}, diff[ARRAY_SIZE(in_d1) * 3] = {0};

	for (loops = 0; loops < (rand()%50); loops++) {

		tmp[0] = in_d1[0] + in_d2[0];
		tmp[1] = in_d1[1] + in_d2[1];
		tmp[2] = in_d1[2] + in_d2[2];
		tmp[3] = in_d1[3] + in_d2[3];

		tmp[4] = in_d1[0] * in_d2[0];
		tmp[5] = in_d1[1] * in_d2[1];
		tmp[6] = in_d1[2] * in_d2[2];
		tmp[7] = in_d1[3] * in_d2[3];

		usleep(1);

		tmp[8] = in_d1[0] / in_d2[0];
		tmp[9] = in_d1[1] / in_d2[1];
		tmp[10] = in_d1[2] / in_d2[2];
		tmp[11] = in_d1[3] / in_d2[3];

		diff[0] = fabs(tmp[0] - add_d[0]);
		diff[1] = fabs(tmp[1] - add_d[1]);
		diff[2] = fabs(tmp[2] - add_d[2]);
		diff[3] = fabs(tmp[3] - add_d[3]);

		diff[4] = fabs(tmp[4] - mul_d[0]);
		diff[5] = fabs(tmp[5] - mul_d[1]);
		diff[6] = fabs(tmp[6] - mul_d[2]);
		diff[7] = fabs(tmp[7] - mul_d[3]);

		diff[8] = fabs(tmp[8] - div_d[0]);
		diff[9] = fabs(tmp[9] - div_d[1]);
		diff[10] = fabs(tmp[10] - div_d[2]);
		diff[11] = fabs(tmp[11] - div_d[3]);

		for (i = 0; i < ARRAY_SIZE(in_d1); i++) {
			if (diff[i] >= 0.000001) {
				refpp = (void *)&add_d[i];
				tmpp = (void *)&tmp[i];
				IMSG("%d add_d expect %f, but got %f [0x%llx - 0x%llx]\n",
					i, add_d[i], tmp[i], *(unsigned long long *)refpp,
					*(unsigned long long *)tmpp);
				TRIGGER_EXCEPTION(i);
			}
		}

		for (i = 4; i < ARRAY_SIZE(in_d1) + 4; i++) {
			if (diff[i] >= 0.0001) {
				refpp = (void *)&mul_d[i-4];
				tmpp = (void *)&tmp[i];
				IMSG("%d mul_d expect %f, but got %f [0x%llx - 0x%llx]\n",
					i-4, mul_d[i-4], tmp[i], *(unsigned long long *)refpp,
					*(unsigned long long *)tmpp);
				TRIGGER_EXCEPTION(i);
			}
		}

		for (i = 8; i < ARRAY_SIZE(in_d1) + 8; i++) {
			if (diff[i] >= 0.00001) {
				refpp = (void *)&div_d[i-8];
				tmpp = (void *)&tmp[i];
				IMSG("%d div_d diff %f expect %f, but got %f [0x%llx - 0x%llx]\n",
					i-8, diff[i], div_d[i-8], tmp[i], *(unsigned long long *)refpp,
					*(unsigned long long *)tmpp);
				TRIGGER_EXCEPTION(i);
			}
		}
	}
}

static __noinline void float_ld_test(void)
{
	int i = 0;
	int loops;

	long double tmp[ARRAY_SIZE(in_ld1) * 4], diff[ARRAY_SIZE(in_ld1) * 4];

	for (loops = 0; loops < (rand()%5); loops++) {

		tmp[0] = in_ld1[0] + in_ld2[0];
		tmp[1] = in_ld1[1] + in_ld2[1];
		tmp[2] = in_ld1[2] + in_ld2[2];
		tmp[3] = in_ld1[3] + in_ld2[3];

		tmp[4] = in_ld1[0] * in_ld2[0];
		tmp[5] = in_ld1[1] * in_ld2[1];
		tmp[6] = in_ld1[2] * in_ld2[2];
		tmp[7] = in_ld1[3] * in_ld2[3];

		usleep(1);

		tmp[8] = in_ld1[0] / in_ld2[0];
		tmp[9] = in_ld1[1] / in_ld2[1];
		tmp[10] = in_ld1[2] / in_ld2[2];
		tmp[11] = in_ld1[3] / in_ld2[3];

		tmp[12] = in_ld1[0] - in_ld2[0];
		tmp[13] = in_ld1[1] - in_ld2[1];
		tmp[14] = in_ld1[2] - in_ld2[2];
		tmp[15] = in_ld1[3] - in_ld2[3];

		diff[0] = fabs(tmp[0] - add_ld[0]);
		diff[1] = fabs(tmp[1] - add_ld[1]);
		diff[2] = fabs(tmp[2] - add_ld[2]);
		diff[3] = fabs(tmp[3] - add_ld[3]);

		diff[4] = fabs(tmp[4] - mul_ld[0]);
		diff[5] = fabs(tmp[5] - mul_ld[1]);
		diff[6] = fabs(tmp[6] - mul_ld[2]);
		diff[7] = fabs(tmp[7] - mul_ld[3]);

		diff[8] = fabs(tmp[8] - div_ld[0]);
		diff[9] = fabs(tmp[9] - div_ld[1]);
		diff[10] = fabs(tmp[10] - div_ld[2]);
		diff[11] = fabs(tmp[11] - div_ld[3]);

		diff[12] = fabs(tmp[12] - sub_ld[0]);
		diff[13] = fabs(tmp[13] - sub_ld[1]);
		diff[14] = fabs(tmp[14] - sub_ld[2]);
		diff[15] = fabs(tmp[15] - sub_ld[3]);

		for (i = 0; i < ARRAY_SIZE(in_ld1); i++) {
			if (diff[i] >= 0.000001)
				TRIGGER_EXCEPTION(i);
		}

		for (i = 4; i < ARRAY_SIZE(in_ld1) + 4; i++) {
			if (diff[i] >= 0.00001)
				TRIGGER_EXCEPTION(i);
		}

		for (i = 8; i < ARRAY_SIZE(in_ld1) + 8; i++) {
			if (diff[i] >= 0.00001)
				TRIGGER_EXCEPTION(i);
		}

		for (i = 12; i < ARRAY_SIZE(in_ld1) + 12; i++) {
			if (diff[i] >= 0.000001)
				TRIGGER_EXCEPTION(i);
		}
	}
}

static void float_test(void)
{
	int i = 0;

	for (i = 0; i < rand() % 8; i++) {
		float_d_test();
		float_f_test();
		float_ld_test();
	}
}

static void dup_cleanup(void *name)
{
	int ret = unlink(name);
	int err = errno;

	if (ret && err != ENOENT) {
		EMSG("unlink %s failed %d\n", name, err);
		while (err == ENOMEM) {
			usleep(20000);
			unlink(name);
			err = errno;
		}
	}
}

static void dup_ok(int i)
{
	int fd = -1, fdcurrent = -1;
	int ret = -1, fddup = -1, fddup_curr = -1, err = -1;
	char buaff[128] = {0};
	char name[128] = {0};

	snprintf(name, 128, "%s/%04d_%d.%d.dup.txt",
		 "/test", gettid(), rand(), i);

	unlink(name);

	pthread_cleanup_push(dup_cleanup, name);

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	err = errno;
	if (err == ENOMEM || err == ENOSPC || err == EMFILE)
		goto out;
	if (fd <= STDERR_FILENO) {
		EMSG("fd %d %s errno %d\n", fd, name, err);
		TRIGGER_EXCEPTION(err);
	}

	ret = write(fd, "111", 3);
	err = errno;
	DMSG("write ret=%d errno=%d @ %s\n",
			ret, err, strerror(err));
	if (err == ENOMEM || err == ENOSPC)
		goto out;
	if (ret != 3)
		TRIGGER_EXCEPTION(err);

	fdcurrent = open("/dev/uart0", O_RDONLY | O_NONBLOCK);
	if (fdcurrent < 0)
		goto out;

	fddup_curr = dup2(fd, fdcurrent);
	if (fddup_curr < 0) {
		EMSG("dupcurr fdcurrent=%d fddup_curr=%d errno=%d\n",
			fdcurrent, fddup_curr, err);
		goto out;
	}
	lseek(fddup_curr, 0, SEEK_SET);
	ret = read(fddup_curr, buaff, sizeof(buaff));
	err = errno;
	close(fddup_curr);
	fddup_curr = -1;
	if (memcmp(buaff, "111", 4) != 0) {
		EMSG("dupcurr read %d ret=%d errno=%d @ %s\n",
			fddup_curr, ret, err, buaff);
		TRIGGER_EXCEPTION(err);
	}

	fddup = dup(fd);
	err = errno;
	if (err == ENOMEM || err == EBUSY || err == EMFILE)
		goto out;
	if (fddup <= STDERR_FILENO) {
		EMSG("dup fd=%d fddup=%d errno=%d @ %s\n",
			fd, fddup, err, strerror(err));
		TRIGGER_EXCEPTION(err);
	}

	ret = write(fddup, "222", 3);
	err = errno;
	DMSG("dup write ret=%d errno=%d\n", ret, err);
	if (err == ENOMEM || err == ENOSPC)
		goto out;
	if (ret != 3)
		TRIGGER_EXCEPTION(err);

	ret = lseek(fddup, 0, SEEK_SET);
	DMSG("dup lseek ret=%d errno=%d\n", ret, err);

	fddup = dup2(fddup, fddup);
	if (fddup <= STDERR_FILENO)
		TRIGGER_EXCEPTION(errno);

	memset(buaff, 0, sizeof(buaff));
	ret = read(fddup, buaff, sizeof(buaff));
	err = errno;
	if (err == ENOMEM)
		goto out;
	if (memcmp(buaff, "111222", 7) != 0) {
		EMSG("dup read %d ret=%d errno=%d @ %s\n",
				fddup, ret, err, buaff);
		TRIGGER_EXCEPTION(err);
	}
	memset(buaff, 0, sizeof(buaff));

	fdcurrent = open("/dev/uart0", O_RDONLY | O_NONBLOCK);
	if (fdcurrent < 0)
		goto out;

	fddup_curr = dup2(fddup, fdcurrent);
	err = errno;
	if (fddup_curr <= STDERR_FILENO) {
		EMSG("dupcurr2 fd=%d dup=%d errno=%d\n",
			fdcurrent, fddup_curr, err);
		goto out;
	}

	ret = read(fddup_curr, buaff, sizeof(buaff));
	err = errno;
	if (ret != 0) {
		EMSG("dupcurr2 read ret=%d errno=%d @ %s\n",
			ret, err, buaff);
		TRIGGER_EXCEPTION(err);
	}

	ret = lseek(fddup_curr, 0, SEEK_SET);
	ret = read(fddup_curr, buaff, sizeof(buaff));
	err = errno;
	if (err == ENOMEM)
		goto out;
	if (memcmp(buaff, "111222", 7) != 0) {
		EMSG("dupcurr2 %d read ret=%d errno=%d @ %s\n",
			fddup_curr, ret, err, buaff);
		TRIGGER_EXCEPTION(err);
	}

out:
	close(fd);
	close(fddup);
	close(fddup_curr);
	pthread_cleanup_pop(1);
}

static void dup_ng(int i)
{
	int fdcurrent = -1, fd = -1;
	int ret = -1, fddup = -1, err = -1;
	char buaff[128] = {0};
	char name[128] = {0};
	static int fddup_saved = -1;

	snprintf(name, 128, "%s/%04d_%d.%d.dupng.txt",
		 "/test", gettid(), rand(), i);

	unlink(name);

	pthread_cleanup_push(dup_cleanup, name);

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (fd < 0)
		goto out;

	ret = write(fd, "111", 3);
	err = errno;
	if ((ret < 0) && (err == ENOMEM || err == ENOSPC))
		goto out;

	fddup = dup(fd);
	err = errno;
	if (err == ENOMEM || err == EBUSY)
		goto out;
	if (fddup < 0)
		goto out;

	ret = write(fddup, "222", 3);
	err = errno;
	if (err == ENOMEM || err == ENOSPC)
		goto out;

	ret = lseek(fddup, 0, SEEK_SET);
	ret = read(fddup, buaff, sizeof(buaff));
	err = errno;
	if (err == ENOMEM)
		goto out;

	memset(buaff, 0, sizeof(buaff));

	fdcurrent = open("/dev/uart0", O_RDONLY | O_NONBLOCK);
	if (fdcurrent < 0)
		goto out;

	ret = dup2(fddup, fdcurrent);

	if (fddup_saved < 0)
		fddup_saved = fdcurrent;

	ret = dup2(fddup, fddup_saved);

	ret = read(fddup_saved, buaff, sizeof(buaff));
	ret = lseek(fddup_saved, -1, SEEK_CUR);
	ret = read(fddup_saved, buaff, sizeof(buaff));

out:
	close(fd);
	close(fddup);
	pthread_cleanup_pop(1);
}

static void dup_test(void)
{
	int i = 0, max = rand()%300;

	pthread_barrier_wait(&test_barrier_dup1);

	for (i = 0; i < max; i++)
		dup_ok(i);

	pthread_barrier_wait(&test_barrier_dup2);

	for (i = 0; i < max; i++)
		dup_ng(i);
}

static void once_routine(void)
{
	IMSG("called in once control\n");
}

static void key_destr(void *data)
{
	IMSG("called in destr %p\n\n", data);
}

static void __fs_test_cleanup(void *arg)
{
	int ret = -1, err = 0;

	char *name = arg + 128;
	char *name2 = name + 128;
	char *dir = name2 + 128;
	char *dir2 = dir + 128;
	char *nameatdir = dir2 + 128;

	ret = unlink(nameatdir);
	err = errno;
	if (ret && err != ENOENT) {
		EMSG("unlink %s failed %d\n", nameatdir, err);
		while (err == ENOMEM) {
			usleep(20000);
			unlink(nameatdir);
			err = errno;
		}
	}

	ret = unlink(name);
	err = errno;
	if (ret && err != ENOENT) {
		EMSG("unlink %s failed %d\n", name, err);
		while (err == ENOMEM) {
			usleep(20000);
			unlink(name);
			err = errno;
		}
	}

	ret = unlink(name2);
	err = errno;
	if (ret && err != ENOENT) {
		EMSG("unlink %s failed %d\n", name2, err);
		while (err == ENOMEM) {
			usleep(20000);
			unlink(name2);
			err = errno;
		}
	}

	ret = rmdir(dir);
	err = errno;
	if (ret && err != ENOENT) {
		EMSG("rmdir %s failed %d\n", dir, err);
		while (err == ENOMEM) {
			usleep(20000);
			rmdir(dir);
			err = errno;
		}
	}

	ret = rmdir(dir2);
	err = errno;
	if (ret && err != ENOENT) {
		EMSG("rmdir %s failed %d\n", dir2, err);
		while (err == ENOMEM) {
			usleep(20000);
			rmdir(dir2);
			err = errno;
		}
	}

	free(arg);
}

static void __fs_test(const char *rootdir)
{
#define FS_BIGBUFF_SIZE 8192

	int i = 0;
	char *bigbuff = NULL;
	int fd = -1;
	int ret = -1, fd_rd = -1, fd_wr = -1, err = -1, retrycnt = 0;

	char *namestr = calloc(1, 1024);
	if (namestr == NULL)
		return;

	char *buaff = namestr;
	char *name = buaff + 128;
	char *name2 = name + 128;
	char *dir = name2 + 128;
	char *dir2 = dir + 128;
	char *nameatdir = dir2 + 128;

	snprintf(name, 128, "%s/%04d.%dfs.txt", rootdir, gettid(), rand());
	snprintf(name2, 128, "%s/%04d-rename-%dfs.txt", rootdir, gettid(), rand());
	snprintf(dir, 128, "%s/dir_%04d_%dfs", rootdir, gettid(), rand());
	snprintf(dir2, 128, "%s/dir2_%04d_%dfs", rootdir, gettid(), rand());
	strcpy(nameatdir, dir);
	snprintf(nameatdir+strlen(dir), 128, "/aa_%04d.%dfs.txt", gettid(), rand());

	pthread_cleanup_push(__fs_test_cleanup, namestr);

	fd = open(name, O_RDWR | O_CREAT, 0666);

	err = errno;
	if (err == ENOMEM || err == ENOSPC || err == EMFILE)
		goto out;

	if (fd < 0) {
		EMSG("create %s fd %d errno %d\n", name, fd, err);
		TRIGGER_EXCEPTION(err);
	}

	ret = lseek(fd, 0x1000, SEEK_SET);
	err = errno;
	if ((err == ENOMEM || err == ENOSPC) ||
		(ret > 0 && ret < 0x1000))
		goto out;

	if (ret != 0x1000)
		TRIGGER_EXCEPTION(err);

	ret = write(fd, "bbb", 3);
	err = errno;
	DMSG("write ret=%d errno=%d\n", ret, err);
	if (err == ENOMEM || err == ENOSPC)
		goto out;
	if (ret != 3)
		TRIGGER_EXCEPTION(err);

retry_fd_rd:
	fd_rd = open(name, O_RDONLY);
	err = errno;
	DMSG("open4rd %s fd=%d errno=%d\n", name, fd_rd, errno);
	if (++retrycnt > 3) {
		DMSG("timeout retried\n");
		goto out;
	}
	if (err == ENOMEM || err == ENOSPC || err == EMFILE) {
		usleep(2000);
		goto retry_fd_rd;
	}
	if (fd_rd < 0)
		TRIGGER_EXCEPTION(err);

	ret = lseek(fd_rd, 0x1000, SEEK_SET);
	if (ret != 0x1000)
		TRIGGER_EXCEPTION(errno);
	ret = read(fd_rd, buaff, 4);
	err = errno;
	DMSG("read ret=%d errno=%d @ %s\n", ret, err, buaff);
	if (err == ENOMEM) {
		close(fd_rd);
		goto out;
	}
	if (ret != 3)
		TRIGGER_EXCEPTION(err);
	if (memcmp(buaff, "bbb", 4) != 0)
		TRIGGER_EXCEPTION(err);

	retrycnt = 0;
retry_fd_wr:
	fd_wr = open(name, O_WRONLY);
	err = errno;
	DMSG("open4wr %s fd %d errno=%d\n", name, fd_wr, errno);
	if (++retrycnt > 3) {
		DMSG("timeout retried\n");
		goto out;
	}
	if (err == ENOMEM || err == ENOSPC || err == EMFILE) {
		usleep(2000);
		goto retry_fd_wr;
	}
	if (fd_wr < 0)
		TRIGGER_EXCEPTION(err);

	close(fd_rd);
	if (errno)
		TRIGGER_EXCEPTION(errno);

	close(fd_wr);
	if (errno)
		TRIGGER_EXCEPTION(errno);

	retrycnt = 0;
retry_mkdir:
	ret = mkdir(dir, 0600);
	if (ret != 0)
		ret = errno;
	DMSG("mkdir %s errno=%d\n", dir, errno);
	if (++retrycnt > 3) {
		DMSG("timeout retried\n");
		goto out;
	}
	if (ret == ENOMEM || ret == ENOSPC) {
		usleep(2000);
		goto retry_mkdir;
	}
	if (ret && (ret != EEXIST))
		TRIGGER_EXCEPTION(ret);

	ret = rmdir("/");
	err = errno;
	DMSG("rmdir %s ret=%d errno=%d @ %s\n", "/",
		ret, err, strerror(errno));
	if (!ret)
		TRIGGER_EXCEPTION(err);

	ret = rmdir(rootdir);
	err = errno;
	DMSG("rmdir %s ret=%d errno=%d @ %s\n",
			rootdir, ret, err, strerror(err));
	if (!ret)
		TRIGGER_EXCEPTION(err);

	char dir3[128] = {0};

	snprintf(dir3, 128, "%s/ac", rootdir);

	ret = rename(rootdir, dir3);
	err = errno;
	DMSG("rename %s->%s ret=%d errno=%d @ %s\n",
		rootdir, dir3, ret, err, strerror(err));
	if (!ret)
		TRIGGER_EXCEPTION(err);

	ret = rename(name, name2);
	DMSG("rename %s->%s ret=%d errno=%d @ %s\n",
		name, name2, ret, errno, strerror(errno));
	if (ret)
		goto out;

	ret = rename(dir, dir2);
	DMSG("rename %s->%s ret=%d errno=%d @ %s\n",
		dir, dir2, ret, errno, strerror(errno));
	if (ret)
		goto out;

	ret = rename(dir2, dir);
	DMSG("rename %s->%s ret=%d errno=%d @ %s\n",
		dir2, dir, ret, errno, strerror(errno));
	if (ret)
		goto out;

	retrycnt = 0;
retry2:
	ret = write(fd, "111", 3);
	err = errno;
	DMSG("write ret=%d errno=%d @ %s\n",
		ret, errno, strerror(errno));
	if (++retrycnt > 3) {
		DMSG("timeout retried\n");
		goto out;
	}
	if (err == ENOMEM || err == ENOSPC) {
		usleep(2000);
		goto retry2;
	}
	if (ret != 3)
		TRIGGER_EXCEPTION(err);
	ret = lseek(fd, 0x1000, SEEK_SET);
	if (ret != 0x1000)
		TRIGGER_EXCEPTION(ret);
	ret = read(fd, buaff, 7);
	err = errno;
	DMSG("read ret=%d errno=%d @ %s\n", ret, errno, buaff);
	if (err == ENOMEM)
		goto out;
	if (memcmp(buaff, "bbb111", 7) != 0)
		TRIGGER_EXCEPTION(err);

	int fd2 = open(name, O_RDONLY);

	if (errno == 0)
		TRIGGER_EXCEPTION(fd2);

	retrycnt = 0;
retry_open_name2_rdonly:
	fd2 = open(name2, O_RDONLY);
	err = errno;
	DMSG("open fd2=%d errno=%d @ %s\n", fd2, errno, strerror(errno));
	if (++retrycnt > 3) {
		DMSG("timeout retried\n");
		goto out;
	}
	if (err == ENOMEM || err == EMFILE) {
		usleep(2000);
		goto retry_open_name2_rdonly;
	}
	memset(buaff, 0, 128);
	ret = lseek(fd2, 0x1000, SEEK_SET);
	ret = read(fd2, buaff, 7);
	err = errno;
	DMSG("read ret=%d errno=%d @ %s\n", ret, errno, strerror(errno));
	if (err == ENOMEM)
		goto out;
	if (memcmp(buaff, "bbb111", 7) != 0)
		TRIGGER_EXCEPTION(err);

	ret = lseek(fd, 0, SEEK_SET);
	if (ret)
		TRIGGER_EXCEPTION(errno);

	bigbuff = malloc(FS_BIGBUFF_SIZE);
	if (bigbuff == NULL)
		goto out;

	memset(bigbuff, 0x5a, FS_BIGBUFF_SIZE);
	ret = write(fd, bigbuff, FS_BIGBUFF_SIZE);
	err = errno;
	DMSG("write %d ret=%d errno=%d @ %s\n", (int)FS_BIGBUFF_SIZE,
		ret, errno, strerror(errno));
	if ((err == ENOMEM || err == ENOSPC) ||
		(ret > 0 && ret < FS_BIGBUFF_SIZE)) {
		goto out;
	}
	if (ret != FS_BIGBUFF_SIZE)
		TRIGGER_EXCEPTION(err);

	int fd3 = open(name2, O_WRONLY);

	err = errno;
	DMSG("open %s fd3=%d errno=%d @ %s\n",
		name2, fd3, errno, strerror(errno));
	if (err == ENOMEM || err == EMFILE)
		goto out;
	if (fd3 < 0)
		TRIGGER_EXCEPTION(err);
	ret = close(fd);
	DMSG("close %s ret=%d errno=%d @ %s\n",
		name, ret, errno, strerror(errno));
	if (ret)
		TRIGGER_EXCEPTION(err);
	close(fd3);

	fd3 = open(name2, O_RDWR);
	err = errno;
	DMSG("open %s %d errno=%d @ %s\n",
		name2, fd3, err, strerror(err));
	if (err == ENOMEM || err == EMFILE)
		goto out;
	if (fd3 < 0)
		TRIGGER_EXCEPTION(err);

	ret = close(fd2);
	err = errno;
	DMSG("close %s ret=%d errno=%d @ %s\n",
		name2, ret, err, strerror(err));
	if (ret)
		TRIGGER_EXCEPTION(err);

	ret = unlink(name2);
	err = errno;
	DMSG("unlink %s ret=%d errno=%d @ %s\n",
		name2, ret, err, strerror(err));
	if (ret)
		goto out;

	int fd4 = open(name2, O_RDONLY);

	err = errno;
	DMSG("open %s %d errno=%d @ %s\n",
		name2, fd4, err, strerror(err));
	if (fd4 > 0)
		TRIGGER_EXCEPTION(err);

	int pos = 0;

	memset(bigbuff, 0, FS_BIGBUFF_SIZE);
	while (pos < FS_BIGBUFF_SIZE) {
		ret = read(fd3, bigbuff + pos, FS_BIGBUFF_SIZE - pos);
		err = errno;
		DMSG("read after unlink ret=%d errno=%d\n", ret, err);
		if (ret > 0)
			pos += ret;
		else
			usleep(5000);
	}

	if (pos != FS_BIGBUFF_SIZE)
		TRIGGER_EXCEPTION(pos);
	for (i = 0; i < pos; i++)
		if (bigbuff[i] != 0x5a)
			TRIGGER_EXCEPTION(bigbuff[i]);

	ret = write(fd3, bigbuff, FS_BIGBUFF_SIZE);
	err = errno;
	DMSG("write after unlink ret=%d errno=%d\n", ret, errno);
	if ((err == ENOMEM || err == ENOSPC) ||
		(ret > 0 && ret < FS_BIGBUFF_SIZE)) {
		goto out;
	}
	if (ret != FS_BIGBUFF_SIZE)
		TRIGGER_EXCEPTION(err);
	close(fd3);

	fd4 = creat(nameatdir, 0666);
	err = errno;
	DMSG("creat %s errno=%d\n", nameatdir, err);
	if (err == ENOMEM || err == ENOSPC || err == EMFILE)
		goto out;
	if (fd4 < 0)
		TRIGGER_EXCEPTION(err);

	DIR *dd = opendir(dir);

	DMSG("opendir %s dd=%p errno=%d\n", dir, dd, errno);
	if (dd == NULL) {
		close(fd4);
		goto out;
	}

	ret = rmdir(dir);
	err = errno;
	DMSG("rmdir %s ret=%d errno=%d\n", dir, ret, err);
	if (!ret)
		TRIGGER_EXCEPTION(err);
	struct dirent *dddd = readdir(dd);

	DMSG("readdir %s dddd=%p file=%s errno=%d @ %s\n", dir, dddd,
		dddd->d_name, errno, strerror(errno));
	rewinddir(dd);

	ret = unlink(nameatdir);
	DMSG("unlink %s ret=%d errno=%d\n", name, ret, errno);

	ret = rmdir(dir);
	DMSG("rmdir %s ret=%d errno=%d\n", dir, ret, errno);
	if (ret)
		goto out;

	dddd = readdir(dd);
	DMSG("readdir %s dddd=%p file=%s errno=%d\n", dir, dddd,
		dddd ? dddd->d_name : "null", errno);

	close(fd4);
	closedir(dd);

out:
	free(bigbuff);
	pthread_cleanup_pop(1);
}

static void shmfs_mmap_cleanup(void *name)
{
	int ret = shm_unlink(name);
	int err = errno;

	if (ret && err != ENOENT) {
		EMSG("shm_unlink %s failed %d\n", name, err);
		while (err == ENOMEM) {
			usleep(20000);
			shm_unlink(name);
			err = errno;
		}
	}
}

static void shmfs_mmap1(const char *rootdir)
{
	int ret = -1, fd = -1, err = -1;
	char name[128] = {0};
	char *ptr1 = NULL;

	snprintf(name, 128, "/%d%dshm1.txt", gettid(), getpid());

	shm_unlink(name);

	pthread_cleanup_push(shmfs_mmap_cleanup, name);

	if (rand()%2)
		fd = shm_open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	else
		fd = shm_open(name, O_RDWR | O_CREAT, 0666);
	err = errno;
	DMSG("shm_open %s fd = %d error=%d, strerror = %s\n",
		name, fd, err, strerror(err));
	if (err == ENOMEM || err == ENOSPC || err == EMFILE)
		goto out;
	if (fd < 0) {
		EMSG("shm_open %s fd = %d error=%d, strerror = %s\n",
			name, fd, err, strerror(err));
		TRIGGER_EXCEPTION(err);
	}

	if (rand()%2) {
		ret = write(fd, "1as1as11", 8);
		DMSG("write %d, errno=%d, strerror = %s\n",
			ret, errno, strerror(errno));
	}

	ptr1 = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	err = errno;
	if (err == ENOMEM || err == EINTR)
		goto out;

	if (ptr1 == NULL || ptr1 == MAP_FAILED) {
		EMSG("mmap %p, errno=%d\n", ptr1, err);
		TRIGGER_EXCEPTION(err);
	}

	ret = write(fd, "1as1as11", 8);
	err = errno;
	DMSG("write %d, errno=%d\n", ret, err);
	if (err == ENOMEM)
		goto out;

	if (ret != 8)
		TRIGGER_EXCEPTION(err);

	DMSG("mmap-get string = %s\n", ptr1);
	if (memcmp(ptr1, "1as1as11", 8) != 0)
		TRIGGER_EXCEPTION(-1);

	ret = close(fd);
	fd = -1;
	err = errno;
	DMSG("close %d, errno=%d\n", ret, err);
	if (ret < 0)
		TRIGGER_EXCEPTION(err);

	if (rand()%3 == 0) {
		ret = munmap(ptr1, 1024);
		err = errno;
		DMSG("munmap %d, errno=%d\n", ret, err);
		if (ret < 0)
			TRIGGER_EXCEPTION(err);
	}

out:
	if (fd >= 0) {
		ret = close(fd);
		err = errno;
		DMSG("close %d, errno=%d\n", ret, err);
		if (ret < 0)
			TRIGGER_EXCEPTION(err);
		if (rand()%2 == 0)
			munmap(ptr1, 1024);
	}

	pthread_cleanup_pop(1);
}

static void shmfs_mmap2(const char *rootdir)
{
	int ret = -1, fd = -1, err = -1, offset = 0;
	char name[128] = {0};
	char *ptr1 = NULL;

	snprintf(name, 128, "/%04d%04dshm2.txt", gettid(), getpid());

	shm_unlink(name);

	pthread_cleanup_push(shmfs_mmap_cleanup, name);

	if (rand()%2)
		fd = shm_open(name, O_RDWR | O_CREAT | O_TRUNC, 0666);
	else
		fd = shm_open(name, O_RDWR | O_CREAT, 0666);
	err = errno;
	DMSG("shm_open %s fd = %d error=%d %s\n",
		name, fd, err, strerror(err));
	if (err == ENOMEM || err == ENOSPC || err == EMFILE)
		goto out;
	if (fd < 0) {
		EMSG("shm_open %s fd = %d error=%d %s\n",
			name, fd, err, strerror(err));
		TRIGGER_EXCEPTION(err);
	}

	ptr1 = mmap(NULL, 1024*1024, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	err = errno;
	DMSG("mmap %p, errno=%d\n", ptr1, err);
	if (err == ENOMEM)
		goto out;

	if (ptr1 == NULL || ptr1 == MAP_FAILED)
		TRIGGER_EXCEPTION(err);

	offset = rand() % (1024*1024);
	offset -= 17;
	if (offset < 0)
		offset = 0;
	ret = lseek(fd, offset, SEEK_SET);
	err = errno;
	if (ret < 0) {
		DMSG("lseek %d ret=%d, errno=%d\n",
			offset, ret, err);
		goto out;
	}

	ret = write(fd, "2222222233333333\0", 17);
	err = errno;
	DMSG("offset %d write %d, errno=%d %s\n",
			offset, ret, err, strerror(err));
	if (err == ENOMEM)
		goto out;

	if (ret != 17)
		TRIGGER_EXCEPTION(err);

	DMSG("mmap-get offset %d string = %s\n", offset, ptr1 + offset);
	if (memcmp(ptr1 + offset, "2222222233333333\0", 17) != 0)
		TRIGGER_EXCEPTION(-1);

	ret = close(fd);
	fd = -1;
	err = errno;
	DMSG("close %d, errno=%d\n", ret, err);
	if (ret < 0)
		TRIGGER_EXCEPTION(err);

	if (rand()%3 == 0) {
		ret = munmap(ptr1, 1024*1024);
		err = errno;
		DMSG("munmap %d, errno=%d, strerror = %s\n",
			ret, err, strerror(err));
		if (ret < 0)
			TRIGGER_EXCEPTION(err);
	}

out:
	if (fd >= 0) {
		ret = close(fd);
		err = errno;
		DMSG("close %d, errno=%d, strerror = %s\n",
			ret, err, strerror(err));
		if (ret < 0)
			TRIGGER_EXCEPTION(err);
		if (rand()%2 == 0)
			munmap(ptr1, 1024*1024);
	}

	pthread_cleanup_pop(1);
}

static void mqnotify_sigev(int signo, siginfo_t *info, void *ctx)
{
	struct mq_attr attr;
	ssize_t nr;
	void *buf = NULL;
	char dftbuf[NOTIFY_TEST_BUF_SIZE];
	int idx = info->si_value.sival_int;

	DMSG("mq_notify signo %d i=%d mqdes %d\n", signo, idx, mqdes[idx]);

	/* Determine maximum msg size; allocate buffer to receive msg */

	if (mq_getattr(mqdes[idx], &attr) == -1) {
		EMSG("mq_getattr %d errno %d\n", mqdes[idx], errno);
		goto out;
	}

	buf = malloc(attr.mq_msgsize);

	if (buf == NULL)
		buf = dftbuf;

	nr = mq_receive(mqdes[idx], buf, attr.mq_msgsize, NULL);
	if (nr == -1) {
		EMSG("mq_receive %d errno %d\n", mqdes[idx], errno);
		goto out;
	}

	DMSG("Read %ld bytes from message queue\n", (long) nr);

out:
	if (buf != dftbuf)
		free(buf);

	mqnotify_exit[idx] = true;
}

static void mqnotify_thd(union sigval sv)
{
	siginfo_t info;

	info.si_signo = -1;
	info.si_value = sv;
	info.si_code = SI_MESGQ;
	mqnotify_sigev(info.si_signo, &info, NULL);
}

static void mq_notify_thread(void)
{
	int ret = -1, i = 0, cnt = 0;
	struct sigevent not;
	struct mq_attr attr = {0};

	attr.mq_maxmsg = 100;
	attr.mq_msgsize = NOTIFY_TEST_BUF_SIZE;

	for (i = 0; i < NOTIFY_TEST_ROUND/2; i++) {
		snprintf(mq_notify_name[i], sizeof(mq_notify_name[i]),
			"/%04d.msgq.notify%d", gettid(), i);
		mqdes[i] = mq_open(mq_notify_name[i], O_CREAT | O_RDWR, 0666, &attr);
		DMSG("mq_open, mqdes %d errno %d\n", mqdes[i], errno);
		if (mqdes[i] == (mqd_t) -1)
			continue;

		not.sigev_notify = SIGEV_THREAD;
		not.sigev_notify_function = mqnotify_thd;
		not.sigev_notify_attributes = NULL;
		not.sigev_value.sival_int = i;	 /* Arg. to thread func. */
		if (mq_notify(mqdes[i], &not) == -1) {
			if (errno != EBUSY) {
				EMSG("mq_notify, error %d\n", errno);
				TRIGGER_EXCEPTION(mqdes[i]);
			}
		}

		ret = mq_send(mqdes[i], (void *)mq_notify_name,
			rand() % 256, rand() % (MQ_PRIO_MAX - 1));
		DMSG("mq_send %d, errno=%d, strerror = %s\n",
			ret, errno, strerror(errno));
		if (ret != 0)
			goto out;

		while (!mqnotify_exit[i] && (++cnt < 50)) {
			usleep(5000);
			DMSG("wating tfunc_exit i=%d\n", i);
		}

out:
		ret = mq_close(mqdes[i]);
		if (ret < 0) {
			EMSG("mq_close errno=%d\n", errno);
			TRIGGER_EXCEPTION(mqdes[i]);
		}

		mqdes[i] = -1;
		ret = mq_unlink(mq_notify_name[i]);
		if (ret < 0)
			DMSG("mq_unlink %s %d, errno=%d\n", mq_notify_name[i],
			 ret, errno);
		cnt = 0;
	}
}

static void mq_notify_signal(void)
{
	int ret = -1, i = 0, cnt = 0;
	struct sigevent evp;
	struct mq_attr attr = {0};

	attr.mq_maxmsg = 100;
	attr.mq_msgsize = NOTIFY_TEST_BUF_SIZE;

	for (i = NOTIFY_TEST_ROUND/2; i < NOTIFY_TEST_ROUND; i++) {
		snprintf(mq_notify_name[i], sizeof(mq_notify_name[i]),
			"/%04d.msgq.notify%d", gettid(), i);
		mqdes[i] = mq_open(mq_notify_name[i], O_CREAT | O_RDWR, 0666, &attr);
		DMSG("mq_open, mqdes %d errno %d\n", mqdes[i], errno);
		if (mqdes[i] == (mqd_t) -1)
			continue;

		evp.sigev_notify = SIGEV_SIGNAL;
		evp.sigev_signo = SIGUSR1;
		evp.sigev_value.sival_int = i;/* Arg. to func for idx. */
		signal(SIGUSR1, (void *)mqnotify_sigev);

		if (mq_notify(mqdes[i], &evp) == -1) {
			if (errno != EBUSY) {
				EMSG("mq_notify, error %d\n", errno);
				TRIGGER_EXCEPTION(mqdes[i]);
			}
		}

		ret = mq_send(mqdes[i], (void *)mq_notify_name,
			rand() % 256, rand() % (MQ_PRIO_MAX - 1));
		DMSG("mq_send %d, errno=%d, strerror = %s\n",
			ret, errno, strerror(errno));
		if (ret != 0)
			goto out;

		while (!mqnotify_exit[i] && (++cnt < 20)) {
			usleep(5000);
			DMSG("wating tfunc_exit i=%d\n", i);
		}

out:
		ret = mq_close(mqdes[i]);
		if (ret < 0) {
			EMSG("mq_close errno=%d\n", errno);
			TRIGGER_EXCEPTION(mqdes[i]);
		}

		mqdes[i] = -1;
		ret = mq_unlink(mq_notify_name[i]);
		if (ret < 0)
			DMSG("mq_unlink %s %d, errno=%d\n", mq_notify_name[i],
			 ret, errno, strerror(errno));
		cnt = 0;
	}
}

static void mq_static_test(void)
{
	static char mqbigbuff[16384] = {0};

	int ret = -1, fd = -1, err = 0, retrycnt = 0;
	char name[256] = {0};

	snprintf(name, 256, "/%04d.msg", gettid());
	unsigned int prio = 0;
	struct mq_attr attr = {0};

	attr.mq_maxmsg = 100;
	attr.mq_msgsize = sizeof(mqbigbuff);

	mq_unlink(name);

retry0:
	fd = mq_open(name, O_RDWR | O_CREAT | O_NONBLOCK, 0666, &attr);
	err = errno;
	DMSG("mq_open %s fd = %d error=%d %s\n",
			name, fd, errno, strerror(errno));
	if (++retrycnt > 20) {
		DMSG("timeout retrycnt %d\n", retrycnt);
		return;
	}
	if (err == ENOMEM || err == EMFILE) {
		usleep(2000);
		goto retry0;
	}
	if (fd < 0)
		TRIGGER_EXCEPTION(err);
retry1:
	ret = mq_send(fd, "11111111", 9, rand() % (MQ_PRIO_MAX - 1));
	err = errno;
	DMSG("mq_send %d, errno=%d %s\n",
			ret, errno, strerror(errno));
	if (++retrycnt > 40) {
		DMSG("timeout retrycnt %d\n", retrycnt);
		goto out;
	}
	if (err == ENOMEM) {
		usleep(2000);
		goto retry1;
	}
	if (ret != 0)
		TRIGGER_EXCEPTION(err);
retry2:
	ret = mq_send(fd, "22222222", 9, rand() % (MQ_PRIO_MAX - 1));
	err = errno;
	DMSG("mq_send %d, errno=%d %s\n",
			ret, errno, strerror(errno));
	if (++retrycnt > 60) {
		DMSG("timeout retrycnt %d\n", retrycnt);
		goto out;
	}
	if (err == ENOMEM) {
		usleep(2000);
		goto retry2;
	}
	if (ret != 0)
		TRIGGER_EXCEPTION(err);
retry3:
	ret = mq_send(fd, "33333333", 9, rand() % (MQ_PRIO_MAX - 1));
	err = errno;
	DMSG("mq_send %d, errno=%d %s\n",
			ret, errno, strerror(errno));
	if (++retrycnt > 80) {
		DMSG("timeout retrycnt %d\n", retrycnt);
		goto out;
	}
	if (err == ENOMEM || err == ENOSPC) {
		usleep(2000);
		goto retry3;
	}
	if (ret != 0)
		TRIGGER_EXCEPTION(err);

	ret = mq_receive(fd, mqbigbuff, sizeof(mqbigbuff), &prio);
	err = errno;
	DMSG("mq_receive %d, errno=%d, strerror = %s\n",
			ret, errno, strerror(errno));
	if (ret != 9)
		TRIGGER_EXCEPTION(err);
	DMSG("msg = %s, prio = %d\n", mqbigbuff, prio);

	ret = mq_receive(fd, mqbigbuff, sizeof(mqbigbuff), &prio);
	err = errno;
	DMSG("mq_receive %d, errno=%d, strerror = %s\n",
			ret, errno, strerror(errno));
	if (ret != 9)
		TRIGGER_EXCEPTION(err);
	DMSG("msg = %s, prio = %d\n", mqbigbuff, prio);

	ret = mq_receive(fd, mqbigbuff, sizeof(mqbigbuff), &prio);
	err = errno;
	DMSG("mq_receive %d, errno=%d, strerror = %s\n",
			ret, errno, strerror(errno));
	if (ret != 9)
		TRIGGER_EXCEPTION(err);
	DMSG("msg = %s, prio = %d\n", mqbigbuff, prio);

out:
	ret = mq_close(fd);
	err = errno;
	DMSG("close %d, errno=%d, strerror = %s\n",
			ret, errno, strerror(errno));
	if (ret < 0)
		TRIGGER_EXCEPTION(err);

	ret = mq_unlink(name);
	if (ret < 0)
		DMSG("mq_unlink %s %d, errno=%d %s\n", name,
		 ret, errno, strerror(errno));
}

static void mq_test_kill_peer(int peer)
{
	int ret = -1, killretry = 0;

	do {
		ret = kill(peer, SIGKILL);
		if (ret) {
			EMSG("kill %04d ret = %d error=%d\n", peer, ret, errno);
			sleep(1);
		}
	} while (ret != 0 && (++killretry < 10));
}

static void mq_fd_2proc_send(void)
{
	int peer = -1;
	int ret = -1, fd = -1, mqdes = -1;
	char name[128] = {0};
	char fdtestfile[128] = {0};
	char *argv[3] = {"mbedtest", "--sendfd", NULL};

	peer = execve("mbedtest", argv, NULL);
	IMSG("execve - errno %d peer %04d\n", errno, peer);
	if (peer < 0)
		return;

	snprintf(name, sizeof(name), "/mq_2procfd_%04d.msg", peer);

	snprintf(fdtestfile, sizeof(fdtestfile),
			"/shm/mq_2procfd_%04d.txt", peer);

	mq_unlink(name);
	unlink(fdtestfile);

	ret = rand()%2 ? kill(peer, SIGSTOP) :
		rand()%2 ? pthread_kill(peer, SIGSTOP) :
		rand()%2 ? pthread_sigqueue(peer, SIGSTOP, (union sigval)(0)) :
		sigqueue(peer, SIGSTOP, (union sigval)(0));

	IMSG("FDSIGSTOP %04d ret %d, errno=%d\n", peer, ret, errno);

	mqdes = mq_open(name, O_RDWR | O_CREAT, 0666, NULL);
	IMSG("mq_open %s mqdes = %d error=%d, strerror = %s\n",
		name, mqdes, errno, strerror(errno));
	if (mqdes < 0)	{
		mq_test_kill_peer(peer);
		mq_unlink(name);
		return;
	}

	fd = open(fdtestfile, O_RDWR | O_CREAT);
	if (fd < 0)	{
		mq_test_kill_peer(peer);
		mq_close(mqdes);
		mq_unlink(name);
		return;
	}

	write(fd, "1234a55a", 9);
	lseek(fd, 0, SEEK_SET);

	ret = mq_send_fd(mqdes, fd);
	IMSG("mq_send_fd fd = %d ret = %d error=%d %s\n",
		fd, ret, errno, strerror(errno));
	close(fd);
	if (ret < 0) {
		mq_test_kill_peer(peer);
		mq_close(mqdes);
		mq_unlink(name);
		unlink(fdtestfile);
		return;
	}

	sleep(1);
	ret = rand()%2 ? kill(peer, SIGCONT) :
		rand()%2 ? pthread_kill(peer, SIGCONT) :
		rand()%2 ? pthread_sigqueue(peer, SIGCONT, (union sigval)(0)) :
		sigqueue(peer, SIGCONT, (union sigval)(0));
	IMSG("FDSIGCONT %04d ret %d, errno=%d\n", peer, ret, errno);
	if (ret != 0) {
		mq_test_kill_peer(peer);
		mq_close(mqdes);
		mq_unlink(name);
		unlink(fdtestfile);
		return;
	}

	ret = mq_close(mqdes);
	if (ret < 0) {
		EMSG("close %d, errno=%d %s\n", ret, errno, strerror(errno));
		TRIGGER_EXCEPTION(mqdes);
	}
}

static void mq_fd_2proc_recv(void)
{
	int ret = -1, fd = -1, mqdes = -1, err = -1;
	char buaff[64] = {0};
	char name[128] = {0};
	char fdtestfile[128] = {0};
	int retrycnt = 0;

	sprintf(fdtestfile, "/shm/mq_2procfd_%04d.txt", getpid());
	sprintf(name, "/mq_2procfd_%04d.msg", getpid());

retrymqopen:
	mqdes = mq_open(name, O_RDONLY);
	if (mqdes < 0 && ++retrycnt < 1000) {
		usleep(5000);
		goto retrymqopen;
	}

	if (mqdes < 0) {
		unlink(fdtestfile);
		mq_unlink(name);
		return;
	}

	ret = mq_receive_fd(mqdes, &fd);
	err = errno;
	IMSG("mq_receive_fd fd = %d ret = %d error=%d\n",
			fd, ret, err);
	if (fd < 0 && err != ENOMEM)
		TRIGGER_EXCEPTION(mqdes);

	read(fd, buaff, 9);
	IMSG("received %s\n", buaff);
	close(fd);
	ret = unlink(fdtestfile);
	DMSG("unlink %s ret %d, errno=%d\n", fdtestfile, ret, errno);

	ret = mq_close(mqdes);
	if (ret < 0) {
		EMSG("close %d, errno=%d\n", ret, errno);
		TRIGGER_EXCEPTION(mqdes);
	}

	mq_unlink(name);
}

static void mq_2proc_send(void)
{
	static char mqbigbuff[16384] = {0};

	int ret = -1, fd = -1, i = 0, peer = -1, err = 0;
	char name[128] = {0};
	struct mq_attr attr = {0};
	struct timespec ts = {0};
	char *argv[3] = {"mbedtest", "--msgq", NULL};

	peer = execve("mbedtest", argv, NULL);
	IMSG("execve - errno %d peer %04d\n", errno, peer);
	if (peer < 0)
		return;

	ret = rand()%2 ? kill(peer, SIGSTOP) :
		rand()%2 ? pthread_kill(peer, SIGSTOP) :
		rand()%2 ? pthread_sigqueue(peer, SIGSTOP, (union sigval)(0)) :
		sigqueue(peer, SIGSTOP, (union sigval)(0));

	IMSG("SIGSTOP %04d ret %d, errno=%d\n", peer, ret, errno);

	sprintf(name, "/mq_2proc_%04d.msg\n", peer);

	attr.mq_maxmsg = MQ_2PROC_TESTRUNS;
	attr.mq_msgsize = sizeof(mqbigbuff) >> (rand()%8);

	mq_unlink(name);

	fd = mq_open(name, O_RDWR | O_CREAT, 0666, &attr);
	DMSG("mq_open %s fd = %d error=%d\n", name, fd, errno);
	if (fd < 0)	{
		mq_test_kill_peer(peer);
		return;
	}

	for (i = 0; i < MQ_2PROC_TESTRUNS; i++) {
		snprintf(mqbigbuff, sizeof(mqbigbuff), "%d", i);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 1;
		ret = mq_timedsend(fd, mqbigbuff, attr.mq_msgsize, i, &ts);
		err = errno;
		DMSG("mq_send i=%d ret=%d, errno=%d\n",
			i, ret, errno);
		if (ret < 0) {
			if ((err == EAGAIN) || (err == ENOMEM))
				break;
			TRIGGER_EXCEPTION(err);
		}
	}

	IMSG("send %d msgs\n", i);

	sleep(1);
	ret = rand()%2 ? kill(peer, SIGCONT) :
		rand()%2 ? pthread_kill(peer, SIGCONT) :
		rand()%2 ? pthread_sigqueue(peer, SIGCONT, (union sigval)(0)) :
		sigqueue(peer, SIGCONT, (union sigval)(0));

	IMSG("SIGCONT %04d ret %d, errno=%d\n", peer, ret, errno);

	sleep(1);
	ret = mq_getattr(fd, &attr);
	if (ret < 0)
		TRIGGER_EXCEPTION(errno);

	if (attr.mq_curmsgs == i) {
		ret = kill(peer, SIGCONT);
		if (ret)
			EMSG("kill SIGCONT %04d ret = %d error=%d\n", peer, ret, errno);
		sleep(1);
	}

	ret = mq_getattr(fd, &attr);
	if (ret < 0)
		TRIGGER_EXCEPTION(errno);

	ret = mq_close(fd);
	DMSG("close %d, errno=%d\n", ret, errno);
	if (ret < 0)
		TRIGGER_EXCEPTION(errno);

	if (attr.mq_curmsgs == i)
		mq_unlink(name);
}

static void mq_2proc_recv(void)
{
	static char mqbigbuff[16384] = {0};

	int ret = -1, fd = -1, i = 0, err = 0, rnum = MQ_2PROC_TESTRUNS;
	char name[128] = {0};
	unsigned int prio = 0;
	struct timespec ts = {0};
	int retrycnt = 0;

	sprintf(name, "/mq_2proc_%04d.msg\n", getpid());

retryopen:
	fd = mq_open(name, O_RDONLY);
	if (fd < 0 && ++retrycnt < 1000) {
		usleep(5000);
		goto retryopen;
	}

	if (fd < 0)
		goto out;

	for (i = 0; i < rnum + 1; i++) {
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 2;
		ret = mq_timedreceive(fd, mqbigbuff, sizeof(mqbigbuff), &prio, &ts);
		err = errno;
		DMSG("mq_receive i=%d, ret=%d, prio=%d, msg=%s errno=%d\n",
			i, ret, prio, mqbigbuff, errno);

		if (ret < 0) {
			if ((err == EAGAIN) || (err == ENOMEM) || (err == ETIMEDOUT))
				break;
			TRIGGER_EXCEPTION(err);
		}
		if (rnum == MQ_2PROC_TESTRUNS)
			rnum = prio;
	}

	IMSG("received %d msgs\n", i);

	ret = mq_close(fd);
	DMSG("close %d, errno=%d\n", ret, errno);
	if (ret < 0)
		TRIGGER_EXCEPTION(errno);

out:
	mq_unlink(name);
}

static void timer_thd_sigev(union sigval v)
{
	time_t ttt;
	char str[64];

	time(&ttt);
	strftime(str, sizeof(str), "%T", localtime(&ttt));

	float_d_test();

	sigev_cnt++;

	LMSG("%x, %s val = %d sigev_cnt %d\n", (int)pthread_self(),
		str, v.sival_int, sigev_cnt);
}

static int timer_thd(void)
{
	int flags = 0;
	int ret = -1, cnt = 0, i = 0, err = -1;

	struct sigevent evp = {0};
	struct itimerspec ts, ots = {{0}};
	timer_t timerid = -1;

	for (i = 0; i < rand() % 5; i++) {
		timerid = -1;
		evp.sigev_notify = SIGEV_THREAD;
		evp.sigev_notify_function = timer_thd_sigev;
		evp.sigev_value.sival_int = i + 1;

		ret = timer_create(CLOCK_REALTIME, &evp, &timerid);
		err = errno;
		IMSG("timer_create %d, timerid %lx, errno=%d\n",
				ret, timerid, err);
		if (err == ENOMEM)
			continue;

		if (ret)
			TRIGGER_EXCEPTION(err);

		ts.it_interval.tv_sec = 0;
		ts.it_interval.tv_nsec = (rand() % 2) ? rand() % 50000000 : 10000;
		ts.it_value.tv_sec = 0;
		ts.it_value.tv_nsec = rand() % 50000000;

		flags = ((rand() % 5) == 0) ? TIMER_ABSTIME : 0;

		if (flags == TIMER_ABSTIME) {
			clock_gettime(CLOCK_REALTIME, &ts.it_value);
			IMSG("asctime: %s\n", asctime(localtime(&ts.it_value.tv_sec)));
			ts.it_value.tv_nsec = rand() % 100000000;
		}

		ret = timer_settime(timerid, flags, &ts, NULL);
		float_test();

		IMSG("%lx timer_settime %d, errno=%d, strerror = %s\n",
			(long)timerid, ret, errno, strerror(errno));
		if (ret)
			TRIGGER_EXCEPTION(ret);

		while (cnt < 5) {
			ret = timer_getoverrun(timerid);
			if (ret > 10 || errno)
				IMSG("%lx overrun %d\n", (long)timerid, ret);
			if (ret > 25)
				break;
			cnt++;
			usleep(rand() % 1000);
		}

		if ((rand() % 5) == 0) {
			ret = timer_gettime(timerid, &ots);
			IMSG("%lx ots.interval %ld:%ld val %ld:%ld errno=%d\n",
				(long)timerid, (long)ots.it_interval.tv_sec,
				(long)ots.it_interval.tv_nsec, (long)ots.it_value.tv_sec,
				(long)ots.it_value.tv_nsec, errno);
			if (ret)
				TRIGGER_EXCEPTION(ret);

			ts.it_interval.tv_sec = 0;
			ts.it_interval.tv_nsec = 0;
			ts.it_value.tv_sec = 0;
			ts.it_value.tv_nsec = rand() % 5000000;
			ret = timer_settime(timerid, 0, &ts, &ots);
			IMSG("%lx ots.interval %ld:%ld val %ld:%ld errno=%d\n",
				(long)timerid, (long)ots.it_interval.tv_sec,
				(long)ots.it_interval.tv_nsec, (long)ots.it_value.tv_sec,
				(long)ots.it_value.tv_nsec, errno);
			if (ret)
				TRIGGER_EXCEPTION(ret);

			if ((rand() % 5) == 0)
				ret = timer_delete(timerid);
		} else
			ret = timer_delete(timerid);

		if (ret)
			TRIGGER_EXCEPTION(ret);

		cnt = 0;
	}

	IMSG("sigev_cnt = %d\n", sigev_cnt);
	return 0;
}

static void timer_sigev(int signo, siginfo_t *info, void *ctx)
{
	time_t ttt;
	char str[64];

	LMSG("signal %d-%d code: %d, val: %p, sp-%p, ctx-%p\n", signo,
		info->si_signo, info->si_code, info->si_value.sival_ptr, &str, ctx);

	float_f_test();

	time(&ttt);
	strftime(str, sizeof(str), "%T", localtime(&ttt));

	sigev_cnt_sig++;
}

static int timer_sig(void)
{
	int flags = 0;
	int ret = -1, cnt = 0, i = 0, err = -1;
	struct sigevent evp = {0};
	struct itimerspec ts, ots = {{0}};
	timer_t timerid = -1;

	for (i = 0; i < rand() % 10; i++) {
		timerid = -1;
		evp.sigev_notify = SIGEV_SIGNAL;
		evp.sigev_signo = SIGALRM;
		evp.sigev_value.sival_int = i + 1;
		signal(SIGALRM, (void *)timer_sigev);

		ret = timer_create(CLOCK_REALTIME, &evp, &timerid);
		err = errno;
		IMSG("timer_create %d, timerid %lx, errno=%d\n",
			ret, timerid, err);
		if (err == ENOMEM)
			continue;

		if (ret)
			TRIGGER_EXCEPTION(ret);

		ts.it_interval.tv_sec = 0;
		ts.it_interval.tv_nsec = (rand() % 2) ? rand() % 50000000 : 10000;
		ts.it_value.tv_sec = 0;
		ts.it_value.tv_nsec = rand() % 50000000;

		flags = ((rand() % 5) == 0) ? TIMER_ABSTIME : 0;

		if (flags == TIMER_ABSTIME) {
			clock_gettime(CLOCK_REALTIME, &ts.it_value);
			IMSG("asctime: %s\n", asctime(localtime(&ts.it_value.tv_sec)));
			ts.it_value.tv_nsec = rand() % 100000000;
		}

		ret = timer_settime(timerid, flags, &ts, NULL);
		float_test();
		IMSG("%lx timer_settime %d, errno=%d, strerror = %s\n",
			(long)timerid, ret, errno, strerror(errno));
		if (ret)
			TRIGGER_EXCEPTION(ret);

		while (cnt < 5) {
			ret = timer_getoverrun(timerid);
			if (ret > 10 || errno)
				IMSG("%lx overrun %d\n", (long)timerid, ret);
			if (ret > 25)
				break;
			cnt++;
			usleep(rand() % 1000);
		}

		if ((rand() % 5) == 0) {
			ret = timer_gettime(timerid, &ots);
			IMSG("%lx ots.interval %ld:%ld val %ld:%ld errno=%d\n",
				(long)timerid, (long)ots.it_interval.tv_sec,
				(long)ots.it_interval.tv_nsec, (long)ots.it_value.tv_sec,
				(long)ots.it_value.tv_nsec, errno);
			if (ret)
				TRIGGER_EXCEPTION(ret);

			ts.it_interval.tv_sec = 0;
			ts.it_interval.tv_nsec = 0;
			ts.it_value.tv_sec = 0;
			ts.it_value.tv_nsec = rand() % 5000000;
			ret = timer_settime(timerid, 0, &ts, &ots);
			IMSG("%lx ots.interval %ld:%ld val %ld:%ld errno=%d\n",
				(long)timerid, (long)ots.it_interval.tv_sec,
				(long)ots.it_interval.tv_nsec, (long)ots.it_value.tv_sec,
				(long)ots.it_value.tv_nsec, errno);
			if (ret)
				TRIGGER_EXCEPTION(ret);

			if ((rand() % 5) == 0)
				ret = timer_delete(timerid);
		} else
			ret = timer_delete(timerid);

		if (ret)
			TRIGGER_EXCEPTION(ret);

		cnt = 0;
	}

	IMSG("sigev_cnt_sig = %d\n", sigev_cnt_sig);
	return 0;
}

void fs_test(void)
{
	int i = 0;

	for (i = 0; i < 10; i++) {
		if (rand() % 2 == 0)
			__fs_test("/");
		else
			__fs_test("/user");

		shmfs_mmap1("/shm/test");
		if (i < 2)
			__fs_test("/test");
		if (rand() % 7 == 0)
			shmfs_mmap2("/shm");
		__fs_test("/ree");
		shmfs_mmap1("/shm");
		__fs_test("/shm");
		if (rand() % 23 == 0)
			shmfs_mmap2("/shm/test");
		__fs_test("/shm/test");
		shmfs_mmap1("/shm/test");
	}
}

void urandom_test(void)
{
	int ret = -1, i = 0;
	char buffer[256] = {0};

	int rngfd = open("/dev/urandom", O_RDONLY);

	if (rngfd < 0)
		IMSG("open /dev/urandom failed %d\n", errno);
	else {
		for (i = 0; i < 2; i++) {
			ret = read(rngfd, buffer, sizeof(buffer));
			if (ret <= 0) {
				IMSG("read /dev/urandom failed %d\n", errno);
				continue;
			}
			udump("rng", buffer, sizeof(buffer));
		}
		close(rngfd);
	}
}

static void *t1_routine(void *arg)
{
	int policy = -1;
	struct sched_param p = {0};
	int i = 0, ret = 0;

	atexit(__pthread_t1_atexit);

	while (!barrier_started)
		usleep(1000);
	ret = pthread_barrier_wait(&test_barrier);
	IMSG("t1 pthread_barrier_wait %d\n", ret);

	MIGHT_EXIT;

	float_test();
	fs_test();
	urandom_test();
	dup_test(); /* last */

	for (i = 0; i < GLOBAL_MUTEXLOCK_CNT; i++) {
		pthread_mutex_lock(&test_mutex);
		global_variable++;
		ret = pthread_mutex_unlock(&test_mutex);
		if (ret)
			EMSG("---unlock ret %d---\n", ret);
	}

	for (i = 0; i < GLOBAL_RWLOCK_CNT; i++) {
		ret = pthread_rwlock_rdlock(&test_rwlock);
		if (ret)
			EMSG("rwlock rd failed %d\n", ret);
		global_variable_rwlock++;
		ret = pthread_rwlock_unlock(&test_rwlock);
		if (ret)
			EMSG("rwlock unlock failed %d\n", ret);
	}

	MIGHT_EXIT;

	clock_gettime(CLOCK_REALTIME, &tt2);
	IMSG("t1 %lld.%09lu %d %d\n", (long long)tt2.tv_sec - tt1.tv_sec,
		tt2.tv_nsec - tt1.tv_nsec, global_variable, global_variable_rwlock);

	IMSG("t1 ret = %d, policy=%d, prio=%d\n",
		pthread_getschedparam(pthread_self(), &policy, &p),
		policy, p.sched_priority);

	IMSG("t1 pthread_self = %x @ pid%d, arg=%p\n",
		(unsigned int)pthread_self(), getpid(), arg);

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tt2);
	IMSG("t1 THREAD_CPUTIME %lld.%09lu\n", (long long)tt2.tv_sec,
		tt2.tv_nsec);

	sleep(2);
	MIGHT_EXIT;

	return (void *)0x111;
}

static void cleanup_handler(void *arg)
{
	IMSG("called in %p %s\n", arg, __func__);
}

static void *t2_routine(void *arg)
{
	int policy = -1;
	struct sched_param p = {0};
	int ret = 0;
	int i = 0;

	atexit(__pthread_t2_atexit);

	MIGHT_EXIT;

	while (!barrier_started)
		usleep(1000);

	ret = pthread_barrier_wait(&test_barrier);
	IMSG("t2 pthread_barrier_wait %d\n", ret);

	float_test();
	fs_test();
	urandom_test();
	dup_test(); /* last */

	for (i = 0; i < GLOBAL_MUTEXLOCK_CNT; i++) {
		pthread_mutex_lock(&test_mutex);
		global_variable++;
		ret = pthread_mutex_unlock(&test_mutex);
		if (ret)
			EMSG("---unlock ret %d---\n", ret);
	}

	for (i = 0; i < GLOBAL_RWLOCK_CNT; i++) {
		ret = pthread_rwlock_rdlock(&test_rwlock);
		if (ret)
			EMSG("rwlock rd failed %d\n", ret);
		global_variable_rwlock++;
		ret = pthread_rwlock_unlock(&test_rwlock);
		if (ret)
			EMSG("rwlock unlock failed %d\n", ret);
	}

	MIGHT_EXIT;

	clock_gettime(CLOCK_REALTIME, &tt3);
	IMSG("t2 %lld.%09lu %d %d\n", (long long)(tt3.tv_sec - tt1.tv_sec),
			tt3.tv_nsec - tt1.tv_nsec, global_variable, global_variable_rwlock);

	IMSG("t2 ret = %d, policy=%d, prio=%d\n",
		pthread_getschedparam(pthread_self(), &policy, &p),
		policy, p.sched_priority);

	MIGHT_EXIT;

	pthread_cleanup_push(cleanup_handler, (void *)0x121212);

	sleep(1);

	IMSG("t2 arg=%p\n", arg);

	IMSG("t2 pthread_self = %x @ pid%d, arg=%p\n",
		(unsigned int)pthread_self(), getpid(), arg);

	IMSG("t2 signaled ret = %d\n", pthread_cond_signal(&cond));

	sleep(2);

	MIGHT_EXIT;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tt3);
	IMSG("t2 THREAD_CPUTIME %lld.%09lu\n", (long long)tt3.tv_sec,
		tt3.tv_nsec);

	pthread_cleanup_pop(1);

	return (void *)0x222;
}

static void *t3_routine(void *arg)
{
	int policy = -1;
	struct sched_param p = {0};
	int i = 0, ret = 0;

	atexit(__pthread_t3_atexit);

	MIGHT_EXIT;

	while (!barrier_started)
		usleep(1000);

	ret = pthread_barrier_wait(&test_barrier);
	IMSG("t3 pthread_barrier_wait %d\n", ret);

	MIGHT_EXIT;

	float_test();
	fs_test();
	urandom_test();
	dup_test(); /* last */

	for (i = 0; i < GLOBAL_MUTEXLOCK_CNT; i++) {
		pthread_mutex_lock(&test_mutex);
		global_variable++;
		ret = pthread_mutex_unlock(&test_mutex);
		if (ret)
			EMSG("---unlock ret %d---\n", ret);
	}

	for (i = 0; i < GLOBAL_RWLOCK_CNT; i++) {
		ret = pthread_rwlock_wrlock(&test_rwlock);
		if (ret)
			EMSG("rwlock wr failed %d\n", ret);
		global_variable_rwlock++;
		ret = pthread_rwlock_unlock(&test_rwlock);
		if (ret)
			EMSG("rwlock unlock failed %d\n", ret);
	}

	clock_gettime(CLOCK_REALTIME, &tt4);
	IMSG("t3 %lld.%09lu %d %d\n", (long long)(tt4.tv_sec - tt1.tv_sec),
		tt4.tv_nsec - tt1.tv_nsec, global_variable, global_variable_rwlock);

	IMSG("t3 ret = %d, policy=%d, prio=%d\n",
		pthread_getschedparam(pthread_self(), &policy, &p),
		policy, p.sched_priority);

	IMSG("t3 pthread_self = %x @ pid%d, arg=%p\n",
		(unsigned int)pthread_self(), getpid(), arg);

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tt4);
	IMSG("t3 THREAD_CPUTIME %lld.%09lu\n", (long long)tt4.tv_sec,
		tt4.tv_nsec);

	MIGHT_EXIT;

	return (void *)0;
}

static void *t4_routine(void *arg)
{
	int policy = -1;
	struct sched_param p = {.sched_priority = 32};
	struct timespec tt5 = {0};

	atexit(__pthread_t4_atexit);

	if (pthread_setschedparam(pthread_self(), SCHED_RR, &p))
		IMSG("t4 pthread_setschedprio error\n");

	IMSG("t4 ret = %d, policy=%d, prio=%d\n",
		pthread_getschedparam(pthread_self(), &policy, &p),
		policy, p.sched_priority);

	IMSG("t4  pthread_self = %x @ pid%d, arg=%p\n",
		(unsigned int)pthread_self(), getpid(), arg);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tt5);
	IMSG("t4 THREAD_CPUTIME %lld.%09lu\n", (long long)tt5.tv_sec,
		tt5.tv_nsec);

	t4_counter++;

	pthread_cond_signal(&t4_cond);

	while (1)
		t4_counter++;

	return (void *)0;
}

static void signal_handler(int signo, siginfo_t *info, void *ctx)
{
	int i = 0;
	unsigned int aaaa[1] = {0};

	IMSG("signal %d-%d code: %d, val: %p, sp-%p, ctx-%p\n", signo,
		info->si_signo, info->si_code, info->si_value.sival_ptr, &aaaa, ctx);

	for (i = 0; i < 5; i++) {
		IMSG("recv %d %d\n", signo, i);
		usleep(500000);
	}
}

static void signal_handler_mutex(int signo, siginfo_t *info, void *ctx)
{
	int i = 0;

	IMSG("recv %d idx=%d\n", signo, info->si_value.sival_int);

	for (i = 0; i < GLOBAL_SIGTEST_MUTEX_CNT; i++) {
		pthread_mutex_lock(&test_mutex);
		global_sigtest_mutex++;
		pthread_mutex_unlock(&test_mutex);
	}

	IMSG("idx=%ld done\n", (intptr_t)info->si_value.sival_int);
}

static void *t5_routine_mutex(void *arg)
{
	int i = 0;

	IMSG("idx=%ld\n", (intptr_t)arg);

	for (i = 0; i < GLOBAL_SIGTEST_MUTEX_CNT; i++) {
		pthread_mutex_lock(&test_mutex);
		global_sigtest_mutex++;
		pthread_mutex_unlock(&test_mutex);
	}

	return (void *)0;
}

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
	IMSG("sigprocmask: ret %d set-0x%lX oset-0x%lX\n", ret, set, oset);
	if (ret != 0)
		return NULL;

	IMSG("wating SIGINT\n");
	sigwait_step = 0;

	sigemptyset(&set);
	sigaddset(&set, SIGINT);

	sigwait_step = 1;
	clock_gettime(CLOCK_REALTIME, &t1);
	ret = sigwait(&set, &signo);
	IMSG("sigwait ret=%d errno %d signo %d\n", ret, errno, signo);
	clock_gettime(CLOCK_REALTIME, &t2);
	IMSG("sigwait %lld.%09lu\n", (long long)(t2.tv_sec - t1.tv_sec),
			t2.tv_nsec - t1.tv_nsec);

	sigwait_step = 2;
	ts.tv_sec = 5;
	ts.tv_nsec = 0;
	clock_gettime(CLOCK_REALTIME, &t1);
	ret = sigtimedwait(&set, &info, &ts);
	IMSG("sigtimedwait ret=%d errno %d signo %d\n", ret, errno, info.si_signo);
	clock_gettime(CLOCK_REALTIME, &t2);
	IMSG("sigtimedwait %lld.%09lu\n", (long long)(t2.tv_sec - t1.tv_sec),
			t2.tv_nsec - t1.tv_nsec);

	ret = sigprocmask(SIG_SETMASK, &oset, NULL);
	sigwait_step = 3;
	ret = pause();
	IMSG("pause ret=%d errno %d\n", ret, errno);

	sigwait_step = 4;
	ret = sigsuspend(&set);
	IMSG("sigsuspend ret=%d errno %d\n", ret, errno);

	sigwait_step = 5;
	return NULL;
}

static void *sigwaittest_trigger(void *arg)
{
	int ret = -1, cnt = 0;
	pthread_t sigwait = -1;

	pthread_create(&sigwait, NULL, sigwait_test, (void *)0);

	if (sigwait == -1)
		return NULL;

	while (sigwait_step != 1 && (++cnt % 300 != 0))
		usleep(2000);

	if (sigwait_step != 1) {
		pthread_cancel(sigwait);
		return NULL;
	}
	IMSG("sigwait %04d\n", sigwait & 0xfff);

	do { /* sigwait */
		ret = pthread_sigqueue(sigwait, SIGQUIT, (union sigval)(-1));
		sleep(1);
		ret |= pthread_sigqueue(sigwait, SIGINT, (union sigval)(-2));
		if (ret == 0)
			break;
		if (ret == ESRCH || ret == EPERM)
			return NULL;
		usleep(5000);
	}  while (1);
	while (sigwait_step < 2)
		usleep(5000);

	usleep(200000);
	do { /* sigtimedwait */
		ret = pthread_sigqueue(sigwait, SIGINT, (union sigval)(-3));
		if (ret == 0)
			break;
		if (ret == ESRCH || ret == EPERM)
			return NULL;
		usleep(5000);
	}  while (1);
	while (sigwait_step < 3)
		usleep(5000);

	usleep(200000);
	do { /* pause */
		ret = pthread_sigqueue(sigwait, SIGINT, (union sigval)(-4));
		if (ret == 0)
			break;
		if (ret == ESRCH || ret == EPERM)
			return NULL;
		usleep(5000);
	}  while (1);
	while (sigwait_step < 4)
		usleep(5000);

	usleep(200000);
	do { /* sigsuspend */
		ret = pthread_sigqueue(sigwait, SIGQUIT, (union sigval)(-5));
		if (ret == 0)
			break;
		if (ret == ESRCH || ret == EPERM)
			return NULL;
		usleep(5000);
	}  while (1);
	while (sigwait_step < 5)
		usleep(5000);

	return NULL;
}

static void sig_checkpending(void)
{
	int i = 0, ret = -1;
	sigset_t pset;

	ret = sigpending(&pset);
	IMSG("Get sigpending: ret %d %lX\n", ret, pset);

	for (i = 0; i < NSIG; i++) {
		if (sigismember(&pset, i))
			IMSG("%d pending\n", i);
	}
}

static void sigtest(void)
{
	int ret = -1, i = 0;
	pthread_t thds[10] = {0};
	pthread_t sigwait = -1;
	sigset_t set, oset;

	if (rand() % 5 == 0) {
		signal(SIGALRM, (void *)SIG_DFL);
		alarm(1);
		sleep(2);
	}

	sigemptyset(&set);
	sigemptyset(&oset);

	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGQUIT);
	sigaddset(&set, SIGSTOP);
	sigaddset(&set, SIGKILL);
	sigaddset(&set, SIGUSR1);

	ret = sigprocmask(SIG_BLOCK, &set, &oset);

	IMSG("sigprocmask: ret %d set-0x%lX oset-0x%lX\n", ret, set, oset);

	ret = sigprocmask(SIG_BLOCK, NULL, &oset);

	IMSG("sigprocmask: ret %d curr-set-0x%lX\n", ret, oset);

	sig_checkpending();

	signal(SIGINT, (void *)signal_handler);
	signal(SIGQUIT, (void *)signal_handler);

	if (rand() % 7 == 0) {
		pthread_create(&sigwait, NULL, sigwaittest_trigger, NULL);
		/* pthread_join(sigwait, NULL); */
	}

	sig_checkpending();

	ret = sigprocmask(SIG_UNBLOCK, &set, NULL);

	sig_checkpending();

	struct sigaction act = {0};

	act.sa_flags = SA_SIGINFO;
	act.sa_sigaction = signal_handler_mutex;
	sigaddset(&act.sa_mask, SIGQUIT);
	sigaction(SIGQUIT, &act, NULL);

	union sigval ss = {0};

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

	IMSG("global_sigtest_mutex=%ld\n", global_sigtest_mutex);
}

static void poll_test(void)
{
	int ret = -1, i = 0;
	int nr = rand() % 10240 + 1;
	char str[256] = {0};

	int _fd = open("/dev/uart1", O_RDWR | O_NONBLOCK);
	if (_fd < 0) {
		if (!(rand() % 3))
			_fd = open("/dev/null", O_RDWR | O_NONBLOCK);
		else
			_fd = open("/dev/uart0", O_RDWR | O_NONBLOCK);
	}
	if (_fd < 0)
		return;

	struct pollfd *fds = malloc(nr * sizeof(struct pollfd));

	if (fds) {
		for (i = 0; i < nr; i++) {
			fds[i].fd = _fd/*STDIN_FILENO*/;
			fds[i].events = POLLIN;
		}
		ret = poll(fds, nr, 3000);
		if (ret > 0)
			read(_fd, str, sizeof(str) - 1);

		IMSG("poll ret = %d errno %d str %s\n", ret, errno, str);

		free(fds);
	}

	ret = close(_fd);

	IMSG("close ret = %d errno %d\n", ret, errno);
}

static void *epdel_routine(void *arg)
{
	int fd = (intptr_t)arg;
	int randx = rand();

	usleep(randx % 200000);
	LMSG("async fd %d\n", fd);
	if (randx % 3)
		epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
	else
		close(fd);

	return NULL;
}

static void epoll_test1(void)
{
	int ret = -1, i = 0, n = -1, nrevts = 0, _fd = -1;
	int nr = rand() % ARRAY_SIZE(epollfds) + 1;
	char str[256] = {0};
	struct epoll_event *evts = NULL, evt = {0};
	int randx = rand();

	_fd = open("/dev/uart1", O_RDWR | O_NONBLOCK);
	if (_fd < 0) {
		if (!(rand() % 3))
			_fd = open("/dev/null", O_RDWR | O_NONBLOCK);
		else
			_fd = open("/dev/uart0", O_RDWR | O_NONBLOCK);
	}
	if (_fd < 0)
		return;

	memset(epollfds, -1, sizeof(epollfds));

	epfd = epoll_create(0);
	if (epfd < 0)
		goto out;

	evt.events = EPOLLIN;
	evt.data.u64 = 0x6a5612341177ffaa;

	evts = malloc(nr * sizeof(struct epoll_event));
	if (evts) {
		ret = epoll_wait(epfd, evts, nr, 0);
		IMSG("epoll_wait maxnr=%d ret = %d errno %d\n", nr, ret, errno);

		ret = epoll_ctl(epfd, EPOLL_CTL_DEL, epfd, NULL);
		IMSG("EPOLL_CTL_DEL ret = %d errno %d\n", ret, errno);

		ret = epoll_ctl(epfd, EPOLL_CTL_ADD, _fd, &evt);
		IMSG("EPOLL_CTL_ADD 1ret = %d errno %d\n", ret, errno);
		ret = epoll_ctl(epfd, EPOLL_CTL_ADD, _fd, NULL);
		IMSG("EPOLL_CTL_ADD 2ret = %d errno %d\n", ret, errno);
		ret = epoll_ctl(epfd, EPOLL_CTL_ADD, _fd, &evt);
		IMSG("EPOLL_CTL_ADD 3ret = %d errno %d\n", ret, errno);

		ret = epoll_wait(epfd, evts, nr, rand() % 5000);
		IMSG("epoll_wait nrevts = %d errno %d\n", ret, errno);
		IMSG("epoll_wait 0xa55a12341177ff33 REVENTS %d DATA:0x%llx\n",
			evts[0].events, (long long)evts[0].data.u64);

		for (i = 0; i < nr; i++) {
			epollfds[i] = open("/dev/uart1", O_RDWR | O_NONBLOCK);
			if (epollfds[i] < 0) {
				if (!(rand() % 3))
					epollfds[i] = open("/dev/null", O_RDWR | O_NONBLOCK);
				else
					epollfds[i] = open("/dev/uart0", O_RDWR | O_NONBLOCK);
			}
			if (epollfds[i] < 0)
				break;

			randx = rand();

			evt.events = EPOLLIN | ((randx % 2) ? EPOLLET : 0) |
						(((rand() % 5) == 0) ? EPOLLONESHOT : 0);

			evt.data.fd = epollfds[i];
			ret = epoll_ctl(epfd, EPOLL_CTL_ADD, epollfds[i], &evt);
			if (ret != 0)
				break;
		}

		nrevts = epoll_wait(epfd, evts, nr, randx % 4000);
		IMSG("epoll_wait nrevts = %d[%d] errno %d\n", nrevts, nr, errno);

		for (n = 0; n < nrevts; n++) {
			ret = read(evts[n].data.fd, str, sizeof(str) - 1);
			if (strlen(str))
				IMSG("fd %d revent %d readret = %d errno %d str %s\n",
					(int)evts[n].data.fd, (int)evts[n].events, ret, errno, str);
			epoll_ctl(epfd, EPOLL_CTL_DEL, evts[n].data.fd, NULL);
		}

		for (i = 0; i < nr; i++) {
			if (epollfds[i] <= 0)
				continue;
			if (i >= nrevts)
				epoll_ctl(epfd, EPOLL_CTL_DEL, epollfds[i], NULL);
			close(epollfds[i]);
		}
	}

out:
	free(evts);
	ret = close(_fd);
	ret = close(epfd);
	epfd = -1;
}

static void epoll_test2(void)
{
	int ret = -1, i = 0, n = -1, nrevts = 0, _fd = -1;
	int nr = rand() % ARRAY_SIZE(epollfds) + 1;
	char str[256] = {0};
	struct epoll_event *evts = NULL, evt = {0};
	int randx = rand(), del_routine = 0;
	pthread_t epdel;

	_fd = open("/dev/uart1", O_RDWR | O_NONBLOCK);
	if (_fd < 0) {
		if (!(rand() % 3))
			_fd = open("/dev/null", O_RDWR | O_NONBLOCK);
		else
			_fd = open("/dev/uart0", O_RDWR | O_NONBLOCK);
	}
	if (_fd < 0)
		return;

	memset(epollfds, -1, sizeof(epollfds));

	epfd = epoll_create(0);
	if (epfd < 0)
		goto out;

	evt.events = EPOLLIN;
	evt.data.u64 = 0xa55a12341177ff33;

	evts = malloc(nr * sizeof(struct epoll_event));
	if (evts) {
		ret = epoll_wait(epfd, evts, nr, 0);
		IMSG("epoll_wait maxnr=%d ret = %d errno %d\n", nr, ret, errno);

		ret = epoll_ctl(epfd, EPOLL_CTL_DEL, epfd, NULL);
		IMSG("EPOLL_CTL_DEL ret = %d errno %d\n", ret, errno);

		ret = epoll_ctl(epfd, EPOLL_CTL_ADD, _fd, &evt);
		IMSG("EPOLL_CTL_ADD 1ret = %d errno %d\n", ret, errno);
		ret = epoll_ctl(epfd, EPOLL_CTL_ADD, _fd, NULL);
		IMSG("EPOLL_CTL_ADD 2ret = %d errno %d\n", ret, errno);
		ret = epoll_ctl(epfd, EPOLL_CTL_ADD, _fd, &evt);
		IMSG("EPOLL_CTL_ADD 3ret = %d errno %d\n", ret, errno);

		ret = epoll_wait(epfd, evts, nr, rand() % 5000);
		IMSG("epoll_wait nrevts = %d errno %d\n", ret, errno);
		IMSG("epoll_wait 0xa55a12341177ff33 REVENTS %d DATA:0x%llx\n",
			evts[0].events, (long long)evts[0].data.u64);

		for (i = 0; i < nr; i++) {
			epollfds[i] = open("/dev/uart1", O_RDWR | O_NONBLOCK);
			if (epollfds[i] < 0) {
				if (!(rand() % 3))
					epollfds[i] = open("/dev/null", O_RDWR | O_NONBLOCK);
				else
					epollfds[i] = open("/dev/uart0", O_RDWR | O_NONBLOCK);
			}
			if (epollfds[i] < 0)
				break;

			randx = rand();

			evt.events = EPOLLIN | ((randx % 2) ? EPOLLET : 0) |
						(((rand() % 5) == 0) ? EPOLLONESHOT : 0);

			evt.data.fd = epollfds[i];
			ret = epoll_ctl(epfd, EPOLL_CTL_ADD, epollfds[i], &evt);
			if (ret != 0)
				break;
			if ((randx % 23) == 0 && (++del_routine < 10)) {
				pthread_create(&epdel, NULL, epdel_routine,
					(void *)(intptr_t)epollfds[i]);
				epollfds[i] = 0;
			}
		}

		nrevts = epoll_wait(epfd, evts, nr, randx % 4000);
		IMSG("epoll_wait nrevts = %d[%d] errno %d\n", nrevts, nr, errno);

		for (n = 0; n < nrevts; n++) {
			ret = read(evts[n].data.fd, str, sizeof(str) - 1);
			if (strlen(str))
				IMSG("fd %d revent %d readret = %d errno %d str %s\n",
					(int)evts[n].data.fd, (int)evts[n].events, ret, errno, str);
			epoll_ctl(epfd, EPOLL_CTL_DEL, evts[n].data.fd, NULL);
		}

		for (i = 0; i < nr; i++) {
			if (epollfds[i] <= 0)
				continue;
			if (rand() % 2 == 0)
				close(epollfds[i]);
		}
	}

out:
	free(evts);
	if (rand() % 2 == 0)
		ret = close(_fd);
	if (randx % 2)
		ret = close(epfd);
}

static void mbedtest(void)
{
	pthread_t t1 = 0, t2 = 0, t3 = 0, t4 = 0, host = 0;
	int ret = -1, i = 0;
	void *joinret = (void *)-1;
	int policy = -1;
	struct sched_param p = {0};
	pthread_mutexattr_t attr;
	pthread_rwlockattr_t lattr;
	pthread_key_t key;
	struct timeval tv1;
	time_t secs_raw;
	struct tm *info;
	int timedout = 0;

	if (access("/test", R_OK)) {
		IMSG("creating test folders\n");
		mkdir("/", 0700); /* create the "/mbedtest" */
		mkdir("/test", 0700); /* create the "/mbedtest/test" */
		mkdir("/user", 0700); /* create the "/user/mbedtest" if user-space enabled*/
		mkdir("/ree", 0700); /* create the "/ree/mbedtest" if ree-fs enabled*/
		mkdir("/shm/test", 0700); /* create the "/shm/test" */
	}

	time(&secs_raw);
	clock_gettime(CLOCK_REALTIME, &tt1);
	gettimeofday(&tv1, NULL);

	info = localtime(&secs_raw);
	IMSG("current date: %s", asctime(info));

	secs_raw = tt1.tv_sec;
	info = localtime(&secs_raw);
	IMSG("current date: %s", asctime(info));

	info = localtime(&tv1.tv_sec);
	IMSG("current date: %s", asctime(info));

	IMSG("current date: %s", ctime(&secs_raw));

	cpu_set_t cpuset; long tmpset;

	CPU_ZERO(&cpuset);
	tmpset = rand() % 31;
	memcpy(&cpuset, &tmpset, sizeof(tmpset));
	ret = pthread_setaffinity(host, sizeof(cpuset), &cpuset);
	IMSG("pthread_setaffinity host ret %d\n", ret);

	timer_sig();
	timer_thd();
	poll_test();
	epoll_test1();
	epoll_test2();

	mq_fd_2proc_send();
	mq_2proc_send();
	mq_static_test();
	mq_notify_thread();
	mq_notify_signal();

	pthread_once(&once_control, once_routine);

	pthread_rwlockattr_init(&lattr);
	pthread_rwlockattr_setpshared(&lattr, PTHREAD_PROCESS_PRIVATE);
	pthread_rwlock_init(&test_rwlock, &lattr);

	pthread_mutexattr_init(&attr);
	if ((rand() % 7) == 0)
		pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_PROTECT);
	else
		pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_NONE);
	pthread_mutexattr_setprioceiling(&attr,
			sched_get_priority_max(SCHED_OTHER));
	pthread_mutex_init(&test_mutex, &attr);

	if (pthread_key_create(&key, key_destr))
		IMSG("pthread_key_create failed\n");
	pthread_setspecific(key, (void *)(intptr_t)pthread_self());

	host = pthread_self();

	IMSG("host pthread_self =%x\n", (int)host);

	IMSG("host getschedparam ret = %d, policy=%d, prio=%d\n",
		pthread_getschedparam(pthread_self(), &policy, &p),
		policy, p.sched_priority);

	IMSG("before create barriercnt=%d\n", test_barrier_cnt);

	ret = pthread_create(&t1, NULL, t1_routine, (void *)&t1);
	if (ret)
		test_barrier_cnt--;
	ret = pthread_create(&t2, NULL, t2_routine, (void *)&t2);
	if (ret)
		test_barrier_cnt--;
	ret = pthread_create(&t3, NULL, t3_routine, (void *)&t3);
	if (ret)
		test_barrier_cnt--;

	ret = pthread_barrier_init(&test_barrier, NULL, test_barrier_cnt);
	IMSG("pthread_barrier_init cnt=%d ret=%d\n", test_barrier_cnt, ret);
	ret |= pthread_barrier_init(&test_barrier_dup1, NULL, test_barrier_cnt);
	ret |= pthread_barrier_init(&test_barrier_dup2, NULL, test_barrier_cnt);
	if (ret)
		TRIGGER_EXCEPTION(ret);

	barrier_started = true;

	clock_gettime(CLOCK_REALTIME, &tt1);

	ret = pthread_barrier_wait(&test_barrier);
	IMSG("%x pthread_barrier_wait %d\n", (int)host, ret);

	CPU_ZERO(&cpuset);
	tmpset = rand() % 31;
	memcpy(&cpuset, &tmpset, sizeof(tmpset));
	ret = pthread_setaffinity(t1, sizeof(cpuset), &cpuset);
	IMSG("pthread_setaffinity t1 ret %d\n", ret);

	CPU_ZERO(&cpuset);
	tmpset = rand() % 31;
	memcpy(&cpuset, &tmpset, sizeof(tmpset));
	ret = pthread_setaffinity(t2, sizeof(cpuset), &cpuset);
	IMSG("pthread_setaffinity t2 ret %d\n", ret);

	CPU_ZERO(&cpuset);
	tmpset = rand() % 31;
	memcpy(&cpuset, &tmpset, sizeof(tmpset));
	ret = pthread_setaffinity(t3, sizeof(cpuset), &cpuset);

	ret = pthread_getaffinity(t3, sizeof(cpuset), &cpuset);
	IMSG("getaffinity t3 ret %d affinity %lx\n", ret, *(long *)&cpuset);

	sigtest();

	float_test();
	fs_test();
	urandom_test();
	dup_test();

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
		else if (ret)
			EMSG("---timedlock %d---\n", ret);
		global_variable++;
		if (ret == 0) {
			ret = pthread_mutex_unlock(&test_mutex);
			if (ret)
				EMSG("---unlock ret %d---\n", ret);
		}
	}
	if (timedout)
		IMSG("---timedout %d---\n", timedout);

	timedout = 0;
	for (i = 0; i < GLOBAL_RWLOCK_CNT; i++) {
		clock_gettime(CLOCK_REALTIME, &realt);
		timespecadd(&realt, &((struct timespec){0, 8000000}), &realt);
		ret = pthread_rwlock_timedwrlock(&test_rwlock, &realt);
		global_variable_rwlock++;
		if (ret) {
			timedout++;
			DMSG("rwlock timedwr failed %d\n", ret);
		} else {
			ret = pthread_rwlock_unlock(&test_rwlock);
			if (ret)
				EMSG("rwlock unlock failed %d\n", ret);
		}
	}
	if (timedout)
		IMSG("---rwlock timedout %d---\n", timedout);

	clock_gettime(CLOCK_REALTIME, &realt);
	IMSG("host %lld.%09lu var=%d rwvar=%d\n",
		(long long)(realt.tv_sec - tt1.tv_sec),
		realt.tv_nsec - tt1.tv_nsec,
		global_variable, global_variable_rwlock);

	usleep(10000);

	ret = pthread_join(t2, &joinret);
	IMSG("%x pthread_joint2 %x ret=%d joinret2=%p\n",
			(int)host, (int)t2, ret, joinret);
	ret = pthread_join(t3, &joinret);
	IMSG("%x pthread_joint3 %x ret=%d joinret3=%p\n",
			(int)host, (int)t3, ret, joinret);

	ret = pthread_cancel(t1);
	IMSG("%x pthread_cancelt1 %x ret=%d\n", (int)host, (int)t1, ret);
	if (ret && (ret != ESRCH) && (ret != EPERM))
		TRIGGER_EXCEPTION(ret);

	pthread_yield();
	pthread_once(&once_control, once_routine);

	p.sched_priority = 32;
	if (pthread_setschedparam(pthread_self(), SCHED_RR, &p))
		IMSG("pthread_setschedparam error\n");

	IMSG("host %x getschedparam ret = %d, policy=%d, prio=%d\n",
		(int)host, pthread_getschedparam(host, &policy, &p),
		policy, p.sched_priority);

	ret = pthread_create(&t4, NULL, t4_routine, (void *)&t4);
	if (ret != 0)
		IMSG("%x pthread_createt4 %x ret=%x\n", (int)host, (int)t4, ret);

	if (ret == 0) {
		if (pthread_setschedprio(pthread_self(),
				sched_get_priority_max(SCHED_RR)))
			IMSG("pthread_setschedprio error\n");

		pthread_yield();
		pthread_mutex_lock(&test_mutex);
		clock_gettime(CLOCK_REALTIME, &realt);
		realt.tv_sec += 30;
		ret = pthread_cond_timedwait(&t4_cond, &test_mutex, &realt);
		pthread_mutex_unlock(&test_mutex);

		ret = pthread_cancel(t4);
		IMSG("%x pthread_cancelt4 %x ret=%x, t4_counter= %d\n",
			(int)host, (int)t4, ret, t4_counter);
		if (ret && (ret != ESRCH) && (ret != EPERM))
			TRIGGER_EXCEPTION(ret);

		while (ret == ESRCH) {
			usleep(1000);/* t4 may be not ready to run */
			ret = pthread_cancel(t4);
		}
	}

	clock_gettime(CLOCK_REALTIME, &realt);
	realt.tv_sec += 3;
	pthread_mutex_lock(&test_mutex);
	ret = pthread_cond_timedwait(&cond, &test_mutex, &realt);
	pthread_mutex_unlock(&test_mutex);
	IMSG("%x pthread_cond_timedwait ret=%d\n", (int)host, ret);

	IMSG("----------final global=%d %d----------\n",
		global_variable, global_variable_rwlock);

	struct timespec cusumed_t;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cusumed_t);
	IMSG("host THREAD_CPUTIME %lld.%09lu\n", (long long)cusumed_t.tv_sec,
		cusumed_t.tv_nsec);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cusumed_t);
	IMSG("host PROCESS_CPUTIME %lld.%09lu\n", (long long)cusumed_t.tv_sec,
		cusumed_t.tv_nsec);
}

static struct option long_options[] = {
	{"test",			no_argument,	NULL, 't'},
	{"help",			no_argument,	NULL, 'h'},
	{"msgq",			no_argument,	NULL, 'm'},
	{"sendfd",			no_argument,	NULL, 's'},
	{0, 0, NULL, 0}
};

int main(int argc, char *argv[])
{
	int ret = -EINVAL;
	int option_index = -1, opt = -1;

	if (argc < 2)
		goto err;

	while ((opt = getopt_long(argc, argv, "thms",
		long_options, &option_index)) != -1) {
		switch (opt) {
		case 'm':
			mq_2proc_recv();
			return 0;
		case 's':
			mq_fd_2proc_recv();
			return 0;
		case 't':
			mbedtest();
			return 0;

		case 'h': /* help information */
			ret = 0;
			goto err;
		default:
			goto err;
		}
	}

err:
	if (ret == -EINVAL) {
		printf("help info:\n");
		printf("--test to run test()\n");
	}
	return ret;
}
