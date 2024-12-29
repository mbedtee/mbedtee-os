/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Inter-Processor-Interrupt
 */

#ifndef _IPI_H
#define _IPI_H

#include <unistd.h>
#include <stddef.h>

#define IPI_SCHED        0
#define IPI_TLB          1u
#define IPI_ICACHE       2u
#define IPI_NR           3u

#define IPI_MSG_MAX_SIZE 128u

/*
 * defines the __typeof__ the ipi callee function handler.
 * @data - shared memory buffer from the ipi caller.
 * @size - the data size of this shared memory buffer.
 */
typedef void (*ipi_func_t)(void *data, size_t size);

/*
 * register the ipi callee func.
 * @id   - function id of callee
 * @return - 0 on success. Else negative num.
 */
int ipi_register(unsigned int id, ipi_func_t func);

/*
 * unregister the callee @id.
 */
void ipi_unregister(unsigned int id);

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
 * @id   - function id of callee
 * @cpu  - send to which CPU
 * @data - buffer sending to callee (input)
 * @size - buffer size (Max. #IPI_MSG_MAX_SIZE)
 *
 * @return - 0 on caller msg has been sent successfully.
 */
int ipi_call(unsigned int id, unsigned int cpu, const void *data, size_t size);

/*
 * ipi call, synchronous mode
 *
 * @id   - function id of callee
 * @cpu  - send to which CPU
 * @data - buffer sending to callee (inout)
 * @size - buffer size
 *
 * @return - 0 on caller msg has been sent/ack successfully.
 */
int ipi_call_sync(unsigned int id, unsigned int cpu, void *data, size_t size);

/*
 * ipi call to trigger schedule() (on the specified #cpu)
 */
static inline void ipi_call_sched(unsigned int cpu)
{
	ipi_call(IPI_SCHED, cpu, NULL, 0);
}

#endif
