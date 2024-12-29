// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * simple shell initialization
 */

#include <fs.h>
#include <string.h>
#include <trace.h>
#include <file.h>
#include <thread.h>
#include <kmalloc.h>
#include <device.h>
#include <kthread.h>

#include <shell.h>

extern void shell_kthread(void *data);

static void __init shell_init(void)
{
#ifdef CONFIG_KERN_SHELL
	int id = 0;

	id = __kthread_create(shell_kthread, NULL,
		PAGE_SIZE * (sizeof(long)/sizeof(int)), "kshell");
	if (id < 0)
		EMSG("create shell failed %d\n", id);
	else
		sched_ready(id);
#elif defined(CONFIG_USER_SHELL)
	int id = 0;

	id = process_run("shell", NULL);
	if (id < 0)
		EMSG("run shell failed %d\n", id);
#endif
}

MODULE_INIT_LATE(shell_init);
