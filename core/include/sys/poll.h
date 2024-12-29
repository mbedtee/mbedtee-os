/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * poll() stubs in kernel
 */

#ifndef _SYS_POLL_H
#define _SYS_POLL_H

#include <wait.h>
#include <poll.h>
#include <file.h>

struct poll_table {
	void (*waitfn)(struct file *filp,
		struct waitqueue *wq, struct poll_table *pt);
};

static inline void poll_wait(struct file *filp,
	struct waitqueue *wq, struct poll_table *pt)
{
	if (pt->waitfn)
		pt->waitfn(filp, wq, pt);
}

#endif
