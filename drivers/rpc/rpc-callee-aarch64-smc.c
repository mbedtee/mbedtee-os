// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RPC Callee (REE->TEE) - SMC handler
 */

#include <trace.h>
#include <percpu.h>

#include <rpc_callee.h>

void *smc_handler(struct thread_ctx *unused)
{
	struct percpu *pc = thiscpu;
	struct thread_ctx *rregs = pc->rctx;

	rregs->r[RET_REG] = rpc_callee_handler(rregs->r[ARG_REG]);

	return unused;
}
