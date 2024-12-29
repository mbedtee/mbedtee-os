/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * simple shell
 */

#ifndef _SHELL_H
#define _SHELL_H

#include <generated/autoconf.h>

#define CMD_MAX_LEN			256
#define CMD_HISTORY_NUM		9
#define CMD_DFTARGV_NUM		32

struct cmd_history {
	char cmd[CMD_MAX_LEN];
	int cmd_pos;
};

struct ring_print {
	int fd; /* output fd */
	int pos; /* current print position */
	char ringbuf[1024-8];  /* ring buffer */
};

struct shell {
	/* for uart port */
	int fd;

	int cursor_pos;

	/* received msg length */
	int key_len;
	/* receive msg buffer */
	char key[CMD_MAX_LEN];

	/* command */
	char cmd[CMD_MAX_LEN];
	int cmd_pos;

	/* argv, if argv num less than default, use the default array */
	int argc;
	char **argv;
	char *dft_argv[CMD_DFTARGV_NUM];

	struct ring_print ringprint;
	/* command history */
	struct cmd_history history[CMD_HISTORY_NUM];
	int history_rec_pos;
	int history_show_pos;
};

typedef void (*key_handler)(struct shell *);

struct key_code {
	key_handler func;
	char raw_key[8];
	int raw_key_size;
};

typedef void (*cmd_handler)(struct shell *);

struct shell_cmd {
	const char *cmd;
	const char *help;
	cmd_handler func;
};

static inline unsigned long long __pow(
	unsigned long long x, int y)
{
	int i = 0;
	unsigned long long res = 1;

	for (i = 0; i < y; i++)
		res = res * x;

	return res;
}


#endif
