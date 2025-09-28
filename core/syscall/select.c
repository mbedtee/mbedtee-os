// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2026 Xing Loong <xing.xl.loong@gmail.com>
 * select() / pselect() kernel implementation on top of poll().
 *
 * Handles fd_set copy_from_user / copy_to_user here (like
 * do_syscall_poll in poll.c), so syscall.c stays a thin wrapper.
 */

#include <errno.h>
#include <uaccess.h>
#include <sys/select.h>
#include <poll.h>
#include <ksignal.h>
#include <file.h>

#include "fops.h"

/* Kernel-space poll() — defined in poll.c, uses memcpy. */
extern int poll(struct pollfd *fds, nfds_t nfds, int timemsecs);

/*
 * do_syscall_select -- kernel select/pselect implementation.
 *
 * r_u / w_u / e_u : user-space fd_set pointers (may be NULL).
 * tsp              : kernel timespec for timeout (NULL = infinite).
 * usigmask         : user-space sigset_t for pselect (NULL = no mask).
 *
 * Copies fd_sets from user space, converts to pollfd, calls kernel
 * poll(), converts revents back to fd_set, and copies results out.
 */
long do_syscall_select(int nfds,
		       fd_set *r_u, fd_set *w_u, fd_set *e_u,
		       struct timespec *tsp,
		       const sigset_t *usigmask)
{
	struct pollfd pfds[FD_SETSIZE];
	fd_set r_in, w_in, e_in;
	sigset_t oldset = 0;
	int i = 0, n = 0, ret = 0;

	if (nfds < 0 || nfds > FD_SETSIZE)
		return -EINVAL;
	if (!IS_ENABLED(CONFIG_POLL))
		return -ENOSYS;

	/* ---- copy fd_sets from user space ---- */
	if (r_u && copy_from_user(&r_in, r_u, sizeof(r_in)))
		return -EFAULT;
	if (w_u && copy_from_user(&w_in, w_u, sizeof(w_in)))
		return -EFAULT;
	if (e_u && copy_from_user(&e_in, e_u, sizeof(e_in)))
		return -EFAULT;

	/* ---- optionally install caller's signal mask (pselect) ---- */
	if (usigmask) {
		sigset_t mask = 0;

		if (copy_from_user(&mask, usigmask, sizeof(mask)))
			return -EFAULT;
		sigprocmask(SIG_SETMASK, &mask, &oldset);
	}

	/* ---- fd_set -> pollfd ---- */
	for (i = 0; i < nfds; i++) {
		pfds[n].fd = i;
		pfds[n].events = 0;
		pfds[n].revents = 0;

		if (r_u && FD_ISSET(i, &r_in))
			pfds[n].events |= POLLIN;
		if (w_u && FD_ISSET(i, &w_in))
			pfds[n].events |= POLLOUT;
		if (e_u && FD_ISSET(i, &e_in))
			pfds[n].events |= POLLERR;

		if (pfds[n].events)
			n++;
	}

	/* ---- call kernel-space poll ---- */
	ret = poll(pfds, n, tsp ? (int)(tsp->tv_sec * 1000 +
			tsp->tv_nsec / 1000000) : -1);

	/* ---- restore signal mask ---- */
	if (usigmask)
		sigprocmask(SIG_SETMASK, &oldset, NULL);

	if (ret < 0)
		return ret;

	/* ---- pollfd revents -> fd_set ---- */
	if (r_u)
		FD_ZERO(&r_in);
	if (w_u)
		FD_ZERO(&w_in);
	if (e_u)
		FD_ZERO(&e_in);

	ret = 0;
	for (i = 0; i < n; i++) {
		int fd = pfds[i].fd;

		if ((pfds[i].revents & (POLLIN | POLLHUP | POLLERR)) &&
		    r_u) {
			FD_SET(fd, &r_in);
			ret++;
		}
		if ((pfds[i].revents & POLLOUT) && w_u) {
			FD_SET(fd, &w_in);
			if (!(pfds[i].revents & (POLLIN | POLLHUP | POLLERR)))
				ret++;
		}
		if ((pfds[i].revents & POLLERR) && e_u)
			FD_SET(fd, &e_in);
	}

	/* ---- copy fd_sets back to user space ---- */
	if (r_u && copy_to_user(r_u, &r_in, sizeof(r_in)))
		return -EFAULT;
	if (w_u && copy_to_user(w_u, &w_in, sizeof(w_in)))
		return -EFAULT;
	if (e_u && copy_to_user(e_u, &e_in, sizeof(e_in)))
		return -EFAULT;

	return ret;
}

