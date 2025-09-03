/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * RPC Callee (GlobalPlatform Style REE->TA)
 */

#ifndef _RPC_CALLEE_H
#define _RPC_CALLEE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ctx.h>
#include <rpc.h>
#include <page.h>
#include <rpc/rpc.h>

/* handler for fast calls */
long rpc_fastcall_handler(unsigned long fn,
	unsigned long a0, unsigned long a1, unsigned long a2);

/* handler for yield calls */
long rpc_yield_handler(unsigned long fn, unsigned long remote);

/*
 * Legacy callee handler: reads fn and args from the rpc_cmd
 * at @remote.  Used by RISC-V (ring buffer based) path.
 */
static inline long rpc_callee_handler(unsigned long remote)
{
	long ret = -ENXIO;
	struct rpc_cmd *rpc = NULL;

	/*
	 * this remote PAGE must within REE memory
	 */
	if (mem_in_secure(remote) || (remote & 3)) {
		EMSG("rpc remote error %lx\n", remote);
		return -EFAULT;
	}

	rpc = phys_to_virt(remote);

	if (IS_ENABLED(CONFIG_MMU) && !access_kern_ok(
		(void *)rpc, sizeof(*rpc), PG_RW)) {
		EMSG("rpc remote badaddr %lx\n", remote);
		return -EFAULT;
	}

	if (MBEDTEE_RPC_IS_FASTCALL(rpc->id)) {
		ret = rpc_fastcall_handler(rpc->id,
			(unsigned long)rpc->data[0],
			(unsigned long)rpc->data[1],
			(unsigned long)rpc->data[2]);
		rpc->ret = ret;
		if (rpc->waiter_id) {
			uint64_t wire_waiter_id = rpc->waiter_id;

			rpc_call(MBEDTEE_RPC_COMPLETE_REE, &wire_waiter_id,
				 sizeof(wire_waiter_id));
		}
	} else {
		if (IS_ENABLED(CONFIG_RPC_YIELD))
			ret = rpc_yield_handler(rpc->id, remote);
		rpc->ret = ret;
	}

	return ret;
}

/*
 * SMCCC yield handler: fn comes directly from SMC r0,
 * @remote is the rpc_cmd physical address from SMC r1.
 * Used by ARM/ARM64 SMCCC-compatible path.
 */
static inline long rpc_callee_handler_yield(
	unsigned long fn, unsigned long remote)
{
	long ret = -ENXIO;
	struct rpc_cmd *rpc = NULL;

	if (mem_in_secure(remote) || (remote & 3)) {
		EMSG("rpc remote error %lx\n", remote);
		return -EFAULT;
	}

	rpc = phys_to_virt(remote);

	if (IS_ENABLED(CONFIG_MMU) && !access_kern_ok(
		(void *)rpc, sizeof(*rpc), PG_RW)) {
		EMSG("rpc remote badaddr %lx\n", remote);
		return -EFAULT;
	}

	if (IS_ENABLED(CONFIG_RPC_YIELD))
		ret = rpc_yield_handler(fn, remote);
	rpc->ret = ret;

	return ret;
}

int rpc_gpshm_register(struct rpc_memref *r);

int rpc_gpshm_unregister(struct rpc_memref *r);

void *rpc_gpshm_map(struct process *proc,
	struct rpc_memref *mr, unsigned long flags);

int rpc_gpshm_unmap(uint64_t id);

#ifdef __cplusplus
}
#endif

#endif
