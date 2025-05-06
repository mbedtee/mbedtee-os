/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Inter-Processor-Interrupt
 */

#ifndef _IPI_H
#define _IPI_H

#include <unistd.h>
#include <stddef.h>
#include <sched.h>

#define IPI_MSG_MAX_SIZE 128u

/*
 * defines the __typeof__ the ipi callee function handler.
 * @data - shared memory buffer from the ipi caller.
 * @size - the data size of this shared memory buffer.
 */
typedef void (*ipi_func_t)(void *data, size_t size);

/*
 * percpu ipi structure init.
 */
void ipi_init(void);

/*
 * For CPU Hot-Plug
 * free the ipi resource (ring buffer)
 */
void ipi_down(void);

/*
 * ipi call, asynchronous mode
 *
 * @func - function of callee
 * @cpu  - send to which CPU
 * @data - buffer sending to callee (input)
 * @size - buffer size (Max. #IPI_MSG_MAX_SIZE)
 *
 * @return - 0 on caller msg has been sent successfully.
 */
int ipi_call(void *func, unsigned int cpu, const void *data, size_t size);

/*
 * ipi call, synchronous mode
 *
 * @func - function of callee
 * @cpu  - send to which CPU
 * @data - buffer sending to callee (inout)
 * @size - buffer size
 *
 * @return - 0 on caller msg has been sent/ack successfully.
 */
int ipi_call_sync(void *func, unsigned int cpu, void *data, size_t size);

#endif
