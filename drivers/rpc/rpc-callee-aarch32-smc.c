// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RPC Callee (REE->TEE) - SMC handler
 */

#include <trace.h>
#include <sched.h>
#include <percpu.h>

#include <rpc_callee.h>

void *smc_handler(struct thread_ctx *regs)
{
#ifdef CONFIG_REE_THREAD
	long ret = -1;
	struct percpu *pc = thiscpu;

	pc->in_interrupt = true;
	pc->int_ctx = regs;

	ret = rpc_callee_handler(regs->r[ARG_REG]);

	if (pc->is_ns)
		regs->r[RET_REG] = ret;
	else
		sched_client_retval(ret);

	pc->int_ctx = NULL;
	pc->in_interrupt = false;

	return regs;
#else
	struct percpu *pc = thiscpu;
	struct thread_ctx *rregs = (void *)&pc->rctx;

	pc->in_interrupt = true;
	pc->int_ctx = regs;

	rregs->r[RET_REG] = rpc_callee_handler(rregs->r[ARG_REG]);

	pc->int_ctx = NULL;
	pc->in_interrupt = false;

	return regs;
#endif
}
