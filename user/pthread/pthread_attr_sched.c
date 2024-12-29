// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread scheduler attributes
 */

#define _GNU_SOURCE
#include <cpuset.h>
#include <sched.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <syscall.h>

#include <__pthread.h>

int	pthread_attr_setscope(pthread_attr_t *attr, int scope)
{
	switch (scope) {
	case PTHREAD_SCOPE_SYSTEM:
		attr->contentionscope = scope;
		return 0;

	case PTHREAD_SCOPE_PROCESS:
		return ENOTSUP;

	default:
		return EINVAL;
	}
}

int	pthread_attr_getscope(const pthread_attr_t *attr, int *scope)
{
	*scope = attr->contentionscope;
	return 0;
}

int	pthread_attr_setinheritsched(pthread_attr_t *attr,
	int inheritsched)
{
	if (inheritsched != PTHREAD_INHERIT_SCHED &&
		inheritsched != PTHREAD_EXPLICIT_SCHED)
		return EINVAL;

	attr->inheritsched = inheritsched;

	return 0;
}

int	pthread_attr_getinheritsched(const pthread_attr_t *attr,
	int *inheritsched)
{
	*inheritsched = attr->inheritsched;

	return 0;
}

int	pthread_attr_setschedpolicy(
	pthread_attr_t *attr,
	int policy)
{
	if (policy != SCHED_OTHER &&
		policy != SCHED_RR &&
		policy != SCHED_FIFO)
		return EINVAL;

	attr->schedpolicy = policy;

	return 0;
}

int	pthread_attr_getschedpolicy(
	const pthread_attr_t *attr,
	int *policy)
{
	*policy = attr->schedpolicy;
	return 0;
}

int	pthread_attr_setschedparam(
	pthread_attr_t *attr,
	const struct sched_param *param)
{
	if (!param || (param->sched_priority >
		sched_get_priority_max(SCHED_RR)) ||
		(param->sched_priority <
		sched_get_priority_min(SCHED_RR)))
		return EINVAL;

	memcpy(&attr->schedparam, param,
		sizeof(struct sched_param));
	return 0;
}

int	pthread_attr_getschedparam(
	const pthread_attr_t *attr,
	struct sched_param *param)
{
	memcpy(param, &attr->schedparam,
		sizeof(struct sched_param));
	return 0;
}

/* Direct Scheduling Parameters Getting */
int	pthread_getschedparam(pthread_t pthread,
	int *policy, struct sched_param *param)
{
	int ret = -1;

	ret = sched_getscheduler(tid_of(pthread));
	if (ret < 0)
		return errno;
	*policy = ret;

	sched_getparam(tid_of(pthread), param);
	return errno;
}

/* Direct Scheduling Parameters Setting */
int	pthread_setschedparam(pthread_t pthread,
	int policy, struct sched_param *param)
{
	sched_setscheduler(tid_of(pthread),
			policy, param);
	return errno;
}

/* Direct Scheduling Parameters Setting */
int	pthread_setschedprio(pthread_t pthread, int prio)
{
	struct sched_param p = {.sched_priority = prio};

	sched_setparam(tid_of(pthread), &p);
	return errno;
}

/* Direct Scheduling Affinity Setting */
int	pthread_setaffinity(pthread_t pthread,
	size_t cpusetsize, const cpu_set_t *cpuset)
{
	int ret = -1;

	ret = sched_setaffinity(tid_of(pthread), cpusetsize, cpuset);
	if (ret < 0)
		return errno;

	return 0;
}

/* Direct Scheduling Parameters Setting */
int	pthread_getaffinity(pthread_t pthread,
	size_t cpusetsize, cpu_set_t *cpuset)
{
	int ret = -1;

	ret = sched_getaffinity(tid_of(pthread), cpusetsize, cpuset);
	if (ret < 0)
		return errno;

	return 0;
}

void pthread_yield(void)
{
	sched_yield();
}
