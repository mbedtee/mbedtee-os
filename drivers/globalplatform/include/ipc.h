/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * IPC Call Implementation (GlobalPlatform Style TA<->TA)
 */

#ifndef _IPC_H
#define _IPC_H

#include <tee_api_types.h>

int ipc_session_open(TEE_UUID *uuid,
	uint32_t timeout, uint32_t types, void *param);

int ipc_session_invoke(pid_t tid, uint32_t timeout,
	uint32_t cmd, uint32_t types, void *params);

int ipc_session_close(pid_t tid);

#endif
