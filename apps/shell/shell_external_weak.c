// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * fallback (and generic default) for external process support.
 *
 * These are intentionally minimal and return -ENOTSUP so that pure kernel-mode
 * builds never depend on userspace process APIs.
 */

#include <shell.h>

__weak_symbol int shell_ext_runapp_argv(struct shell *, char *const [])
{
	return -ENOTSUP;
}

__weak_symbol int shell_ext_spawnapp_argv(struct shell *, char *const [], pid_t *pid_out)
{
	if (pid_out)
		*pid_out = -1;
	return -ENOTSUP;
}

__weak_symbol int shell_ext_spawn_pipeline_stage(pid_t *pid_out, int, int,
	char *const [])
{
	if (pid_out)
		*pid_out = -1;
	return -ENOTSUP;
}
