// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * POSIX scheduler functions
 */

#include <sched.h>
#include <cpuset.h>
#include <utrace.h>
#include <syscall.h>

#include <__pthread.h>

int sched_get_priority_max(int policy)
{
	static int prio_max = -1;

	if (prio_max < 0) {
		prio_max = syscall1(SYSCALL_SCHED_GET_PRIORITY_MAX, policy);
		errno = 0;
	}

	return prio_max;
}

int sched_get_priority_min(int policy)
{
	static int prio_min = -1;

	if (prio_min < 0) {
		prio_min = syscall1(SYSCALL_SCHED_GET_PRIORITY_MIN, policy);
		errno = 0;
	}
	return prio_min;
}

int sched_setscheduler(pid_t id, int policy,
	const struct sched_param *param)
{
	int ret = -1;

	ret = syscall3(SYSCALL_SCHED_SETSCHEDULER, id, policy, param);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int sched_getscheduler(pid_t id)
{
	int ret = -1;

	ret = syscall1(SYSCALL_SCHED_GETSCHEDULER, id);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int sched_setparam(pid_t id,
	const struct sched_param *param)
{
	int ret = -1;

	ret = syscall2(SYSCALL_SCHED_SETPARAM, id, param);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int sched_getparam(pid_t id,
	struct sched_param *param)
{
	int ret = -1;

	ret = syscall2(SYSCALL_SCHED_GETPARAM, id, param);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int sched_setaffinity(pid_t id,
	size_t cpusetsize, const cpu_set_t *cpuset)
{
	int ret = -1;

	ret = syscall3(SYSCALL_SCHED_SETAFFINITY, id, cpusetsize, cpuset);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int sched_getaffinity(pid_t id,
	size_t cpusetsize, cpu_set_t *cpuset)
{
	int ret = -1;

	ret = syscall3(SYSCALL_SCHED_GETAFFINITY, id, cpusetsize, cpuset);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int sched_yield(void)
{
	syscall0(SYSCALL_SCHED_YIELD);
	errno = 0;
	return 0;
}

int sched_getcpu(void)
{
	return __pthread_self->cpuid;
}
