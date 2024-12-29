/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * GlobalPlatform Misc functions
 */

#ifndef _GLOBALPLATFORM_H
#define _GLOBALPLATFORM_H

#include <tee_api_defines.h>
#include <tee_api_types.h>

struct globalplatform_open_session {
	TEE_UUID *uid;    /* dst's uuid */
	uint32_t timeout; /* microseconds */
	uint32_t type;
	TEE_Param *param;
};

struct globalplatform_invoke_session {
	pid_t tid;          /* invoke which session-id */
	uint32_t cmd;     /* invoke with CMD */
	uint32_t timeout; /* microseconds */
	uint32_t type;
	TEE_Param *param;
};

struct globalplatform_memacc {
	void *va;
	size_t size;
	uint32_t flags;
};

/* ioctl cmds */
#define GLOBALPLATFORM_CMD_OPEN_SESSION    0xdeff01
#define GLOBALPLATFORM_CMD_INVOKE_SESSION  0xdeff02
#define GLOBALPLATFORM_CMD_CLOSE_SESSION   0xdeff03
#define GLOBALPLATFORM_CMD_GET_REETIME     0xdeff04
#define GLOBALPLATFORM_CMD_CHECK_MEMACC    0xdeff05

#endif
