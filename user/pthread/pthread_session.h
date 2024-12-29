/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread session APIs for RPC/IPC (GlobalPlatform Style)
 */

#ifndef _PTHREAD_SESS_H
#define _PTHREAD_SESS_H

#include <stdint.h>
#include <stddef.h>
#include <__pthread.h>

#include <tee_api_types.h>

#include "pthread_auxiliary.h"

/* session stat or lifecycle */
#define SESS_CREATED		0
#define SESS_PREPARED		1
#define SESS_ENTER_APP		2
#define SESS_LEAVE_APP		3
#define SESS_DONE			4

struct pthread_session {
	/* session stat */
	uint8_t stat;

	/* Cancellation mask */
	bool cancel_mask;
	/* Cancellation flag */
	bool cancel_flag;
	/* parameter types */
	void *session;
	/* parameter types */
	uint32_t types;
	/* parameters */
	TEE_Param params[4];
	/* peer request cmd */
	uint32_t cmd;
};

#define PTHREAD_SESSION_OFFSET (PTHREAD_AUX_OFFSET + sizeof(struct __pthread_aux))

#define __pthread_sess \
	((struct pthread_session *)((long)__pthread_self + \
		PTHREAD_SESSION_OFFSET))

bool pthread_session_cancel_flag(void);
bool pthread_session_cancel_unmask(void);
bool pthread_session_cancel_mask(void);

#endif
