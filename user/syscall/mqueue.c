// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Message Queue
 */

#include <errno.h>
#include <syscall.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <mqueue.h>
#include <stdarg.h>
#include <pthread.h>

#include <sys/syslimits.h>

mqd_t mq_open(const char *name, int oflag, ...)
{
	int ret = -1;
	mode_t mode = 0;
	struct mq_attr *attr = NULL;
	size_t namelen = 0;
	char mq_name[NAME_MAX + 7] = "/msgq/";
	va_list ap;

	if (oflag & O_CREAT) {
		va_start(ap, oflag);
		mode = va_arg(ap, mode_t);
		attr = va_arg(ap, struct mq_attr *);
		va_end(ap);
	}

	while (*name == '/')
		++name;

	namelen = strlen(name) + 1;
	if (namelen >= NAME_MAX || namelen <= 1) {
		errno = EINVAL;
		return -1;
	}

	strlcpy(mq_name + 6, name, NAME_MAX);

	ret = syscall4(SYSCALL_MQ_OPEN, mq_name, oflag, mode, attr);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int mq_close(mqd_t mqdes)
{
	return close(mqdes);
}

int mq_unlink(const char *name)
{
	char mq_name[NAME_MAX + 7] = "/msgq/";
	size_t namelen = 0;

	while (*name == '/')
		++name;

	namelen = strlen(name) + 1;
	if (namelen >= NAME_MAX || namelen <= 1) {
		errno = EINVAL;
		return -1;
	}

	strlcpy(mq_name + 6, name, NAME_MAX);

	return unlink(mq_name);
}

int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
	unsigned int msg_prio, const struct timespec *abstime)
{
	int ret = -1;

	pthread_testcancel();

	ret = syscall5(SYSCALL_MQ_TIMEDSEND, mqdes,
		msg_ptr, msg_len, msg_prio, abstime);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

ssize_t mq_timedreceive(mqd_t mqdes, char *msg_ptr,
	size_t msg_len, unsigned int *msg_prio,
	const struct timespec *abstime)
{
	ssize_t ret = -1;

	pthread_testcancel();

	ret = syscall5(SYSCALL_MQ_TIMEDRECEIVE, mqdes,
		msg_ptr, msg_len, msg_prio, abstime);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int mq_send(mqd_t mqdes, const char *msg_ptr,
	size_t msg_len, unsigned int msg_prio)
{
	return mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, NULL);
}

ssize_t mq_receive(mqd_t mqdes, char *msg_ptr,
	size_t msg_len, unsigned int *msg_prio)
{
	return mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio, NULL);
}

int mq_send_fd(mqd_t mqdes, int fd)
{
	int ret = -1;

	pthread_testcancel();

	ret = syscall2(SYSCALL_MQ_SENDFD, mqdes, fd);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int mq_receive_fd(mqd_t mqdes, int *pfd)
{
	int ret = -1;

	pthread_testcancel();

	ret = syscall2(SYSCALL_MQ_RECEIVEFD, mqdes, pfd);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int mq_setattr(mqd_t mqdes, const struct mq_attr *mqstat, struct mq_attr *omqstat)
{
	int ret = -1;

	ret = syscall3(SYSCALL_MQ_GETSETATTR, mqdes, mqstat, omqstat);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}

int mq_getattr(mqd_t mqdes, struct mq_attr *mqstat)
{
	return mq_setattr(mqdes, NULL, mqstat);
}

int mq_notify(mqd_t mqdes, const struct sigevent *notification)
{
	int ret = -1;

	ret = syscall2(SYSCALL_MQ_NOTIFY, mqdes, notification);

	errno = syscall_errno(ret);
	return syscall_retval(ret);
}
