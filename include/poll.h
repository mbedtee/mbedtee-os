/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * poll() definitions
 */

#ifndef _POLL_H
#define _POLL_H

#define POLLIN          0x0001 /* available for read operations */
#define POLLPRI         0x0002
#define POLLOUT         0x0004 /* available for write operations */
#define POLLERR         0x0008
#define POLLHUP         0x0010
#define POLLNVAL        0x0020

#define POLLRDNORM      0x0040 /* Equivalent to POLLIN */
#define POLLRDBAND      0x0080
#define POLLWRNORM      0x0100 /* Equivalent to POLLOUT */
#define POLLWRBAND      0x0200
#define POLLMSG         0x0400
#define POLLREMOVE      0x1000
#define POLLRDHUP       0x2000

#define POLL_BUSY_LOOP  0x8000

struct pollfd {
	int fd;           /* file descriptor */
	short events;     /* requested events */
	short revents;    /* returned events */
};

typedef unsigned int nfds_t;

int poll(struct pollfd *fds, nfds_t nfds, int timemsecs);

#endif
