// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread attributes
 */

#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <__pthread.h>

static const DECLARE_DEFAULT_PTHREAD_ATTR(lattr);

int	pthread_attr_init(pthread_attr_t *attr)
{
	memcpy(attr, &lattr, sizeof(lattr));

	return 0;
}

int	pthread_attr_destroy(pthread_attr_t *attr)
{
	return 0;
}

int	pthread_attr_setstack(pthread_attr_t *attr,
	void *stackaddr, size_t stacksize)
{
	if (pthread_attr_setstacksize(attr, stacksize))
		return EINVAL;

	return pthread_attr_setstackaddr(attr, stackaddr);
}

int	pthread_attr_getstack(const pthread_attr_t *attr,
	void **stackaddr, size_t *stacksize)
{
	*stackaddr = attr->stackaddr;
	*stacksize = attr->stacksize;

	return 0;
}

int	pthread_attr_getstacksize(
	const pthread_attr_t *attr,
	size_t *stacksize)
{
	*stacksize = attr->stacksize ? attr->stacksize
				: PTHREAD_STACK_DEFAULT;

	return 0;
}

int	pthread_attr_setstacksize(
	pthread_attr_t *attr,
	size_t stacksize)
{
	if (stacksize < PTHREAD_STACK_MIN)
		return EINVAL;

	attr->stacksize = stacksize;

	return 0;
}

int	pthread_attr_getstackaddr(
	const pthread_attr_t *attr,
	void **stackaddr)
{
	*stackaddr = attr->stackaddr;

	return 0;
}

int	pthread_attr_setstackaddr(
	pthread_attr_t *attr,
	void *stackaddr)
{
	attr->stackaddr = stackaddr;

	return 0;
}

int	pthread_attr_getdetachstate(
	const pthread_attr_t *attr,
	int *detachstate)
{
	*detachstate = attr->detachstate;

	return 0;
}

int	pthread_attr_setdetachstate(
	pthread_attr_t *attr,
	int detachstate)
{
	if ((detachstate == PTHREAD_CREATE_DETACHED) ||
		(detachstate == PTHREAD_CREATE_JOINABLE)) {
		attr->detachstate = detachstate;
		return 0;
	}

	return EINVAL;
}

int	pthread_attr_getguardsize(
	const pthread_attr_t *attr,
	size_t *guardsize)
{
	return ENOTSUP;
}

int	pthread_attr_setguardsize(
	pthread_attr_t *attr,
	size_t guardsize)
{
	return ENOTSUP;
}
