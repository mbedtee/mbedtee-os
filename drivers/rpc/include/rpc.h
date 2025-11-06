/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RPC Caller (TEE->REE)
 */

#ifndef _RPC_H
#define _RPC_H

#include <unistd.h>
#include <stddef.h>
#include <rpc/rpc.h>

/*
 * rpc callback to REE, asynchronous mode
 *
 * @id   - function id of callee
 * @data - buffer sending to REE (input)
 * @size - buffer size (Max. PAGE_SIZE)
 * @return - 0 on callback msg has been sent successfully.
 */
int rpc_call(unsigned int id, void *data, size_t size);

/*
 * rpc callback to REE, synchronous mode
 *
 * @id   - function id of callee
 * @data - buffer sending to REE (inout)
 * @size - buffer size (Max. RPC SHM Size)
 * @return - 0 on callback msg has been sent/ack successfully.
 */
int rpc_call_sync(unsigned int id, void *data, size_t size);

/*
 * return if the callee ready or not
 */
int rpc_test_callee(void);

/*
 * return the callee's hartid or mpid
 */
int rpc_calleeid(void);

/*
 * complete the execution of rpc_call_sync()
 *
 * @tid - thread id which is doing rpc_call_sync()
 */
int rpc_complete(pid_t tid);

/*
 * allocate rpc shared-memory
 */
void *rpc_shm_alloc(size_t size);

/*
 * free rpc shared-memory
 */
void rpc_shm_free(void *addr);

#endif
