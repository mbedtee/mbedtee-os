/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * eventpoll (epoll) definitions
 */

#ifndef _EVENTPOLL_H
#define _EVENTPOLL_H

#include <stdint.h>
#include <limits.h>

#define EPOLLIN          0x0001 /* available for read operations */
#define EPOLLPRI         0x0002
#define EPOLLOUT         0x0004 /* available for write operations */
#define EPOLLERR         0x0008
#define EPOLLHUP         0x0010
#define EPOLLNVAL        0x0020

#define EPOLLRDNORM      0x0040 /* Equivalent to EPOLLIN */
#define EPOLLRDBAND      0x0080
#define EPOLLWRNORM      0x0100 /* Equivalent to EPOLLOUT */
#define EPOLLWRBAND      0x0200
#define EPOLLMSG         0x0400
#define EPOLLRDHUP       0x2000

#define EPOLLONESHOT     (1u << 30)
#define EPOLLET          (1u << 31)
#define EPOLLHIGHMASK    (0xffu << 24)

#define EPOLL_CTL_ADD    1
#define EPOLL_CTL_DEL    2
#define EPOLL_CTL_MOD    3

struct epoll_event {
	uint32_t events;
	union epoll_data {
	  void *ptr;
	  int fd;
	  uint32_t u32;
	  uint64_t u64;
	} data;
};

#define EPOLL_MAXEVENTS (INT_MAX >> 4)

int epoll_create(int size);

int epoll_create1(int flags);

int epoll_ctl(int epfd, int op, int fd,
		      struct epoll_event *event);

int epoll_wait(int epfd, struct epoll_event *events,
		       int maxevents, int timemsecs);

#endif
