// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Suspend to RAM
 * Suspend/Resume framework
 */

#include <wait.h>
#include <sched.h>
#include <kthread.h>
#include <device.h>
#include <spinlock.h>
#include <trace.h>
#include <str.h>

static int warmboot;

void str_suspend(void)
{
	int ret = -1;
	struct str_declaration *op = NULL;
	struct str_declaration *start = NULL;
	struct str_declaration *end = NULL;

	warmboot = true;

	fs_suspend();

	start = (void *)__str_start();
	end = (void *)__str_end();

	for (op = end - 1; op >= start; op--) {
		if (op->suspend == NULL)
			continue;

		IMSG("%s\n", op->name);
		ret = op->suspend(op->data);
		if (ret)
			EMSG("%s error\n", op->name);
	}
}

static void str_post_resume(void *arg)
{
	fs_resume();
}

void str_resume(void)
{
	int ret = -1;
	pid_t id = -1;
	struct str_declaration *op = NULL;
	struct str_declaration *start = NULL;
	struct str_declaration *end = NULL;
	struct sched_param p = {.sched_priority = SCHED_PRIO_MAX};

	if (!warmboot)
		return;

	warmboot = false;

	start = (void *)__str_start();
	end = (void *)__str_end();

	for (op = start; op < end; op++) {
		if (op->resume == NULL)
			continue;

		IMSG("%s\n", op->name);
		ret = op->resume(op->data);
		if (ret)
			EMSG("%s error\n", op->name);
	}

	id = kthread_run(str_post_resume, NULL, "resume");
	assert(id > 0);

	/* set to top priority */
	sched_setscheduler(id, SCHED_FIFO, &p);

	/* never return */
	schedule();
}
