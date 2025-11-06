/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RPC Callee (GlobalPlatform Style REE->TA)
 */

#ifndef _RPC_CALLEE_H
#define _RPC_CALLEE_H

#include <ctx.h>
#include <rpc.h>
#include <page.h>
#include <rpc/rpc.h>

/* handler for fast calls */
long rpc_fastcall_handler(unsigned long fn,
	unsigned long a0, unsigned long a1, unsigned long a2);

/* handler for yield calls */
long rpc_yield_handler(unsigned long fn, unsigned long remote);

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

	if (RPC_IS_FASTCALL(rpc->id)) {
		ret = rpc_fastcall_handler(rpc->id,
			rpc->data[0], rpc->data[1], rpc->data[2]);
		rpc->ret = ret;
		if (rpc->waiter)
			rpc_call(RPC_COMPLETE_REE, &remote, sizeof(remote));
	} else {
		if (IS_ENABLED(CONFIG_RPC_YIELD))
			ret = rpc_yield_handler(rpc->id, remote);
		rpc->ret = ret;
	}

	return ret;
}

int rpc_gpshm_register(struct rpc_memref *r);

int rpc_gpshm_unregister(struct rpc_memref *r);

void *rpc_gpshm_map(struct process *proc,
	struct rpc_memref *mr, unsigned long flags);

int rpc_gpshm_unmap(uint64_t id);

#endif
