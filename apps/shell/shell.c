// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
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

extern long shell_kthread(void *data);

static void __init shell_init(void)
{
	int id = 0;

#if defined(CONFIG_KERN_SHELL)
	id = kthread_run(shell_kthread, NULL, "kshell");
#elif defined(CONFIG_USER_SHELL)
	id = process_run("shell", NULL);
#endif
	if (id < 0)
		EMSG("run shell failed %d\n", id);
}

MODULE_INIT_LATE(shell_init);
