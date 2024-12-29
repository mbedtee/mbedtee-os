/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Message Queue
 */

#ifndef _MQUEUE_H
#define _MQUEUE_H

#include <time.h>
#include <signal.h>

#define MQ_PRIO_MAX 1024

typedef int mqd_t;

struct mq_attr {
	long mq_flags;    /* Message queue flags */
	long mq_maxmsg;   /* Maximum number of messages */
	long mq_msgsize;  /* Maximum message size */
	long mq_curmsgs;  /* Number of messages currently queued */
};

mqd_t mq_open(const char *name, int oflag, ...);

int mq_close(mqd_t mqdes);

int mq_unlink(const char *name);

int mq_send(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio);

ssize_t mq_receive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio);

int mq_notify(mqd_t mqdes, const struct sigevent *notification);

int mq_getattr(mqd_t mqdes, struct mq_attr *mqstat);

int mq_setattr(mqd_t mqdes, const struct mq_attr *mqstat, struct mq_attr *omqstat);

int mq_timedsend(mqd_t mqdes, const char *__restrict msg_ptr, size_t msg_len,
	unsigned int msg_prio, const struct timespec *abstime);

ssize_t mq_timedreceive(mqd_t mqdes, char *__restrict msg_ptr,
	size_t msg_len, unsigned *__restrict msg_prio,
	const struct timespec *__restrict abstime);

int mq_send_fd(mqd_t mqdes, int fd);

int mq_receive_fd(mqd_t mqdes, int *pfd);

#endif
