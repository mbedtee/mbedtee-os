// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * RPC Callee (REE->TEE) - SMC handler
 *
 * SMCCC-compatible calling convention:
 *   Fast call  : r0 = function ID (bit 31 set), r1-r3 = args, return in r0.
 *   Yield call : r0 = function ID (bit 31 clear), r1 = phys(rpc_cmd),
 *                return 0 in r0 (actual result via async completion).
 *
 * Standard PSCI calls (service type 0x04, e.g. 0x84000003) are accepted
 * alongside MbedTEE calls (service type 0x00, e.g. 0x80000003).
 */

#include <trace.h>
#include <sched.h>
#include <percpu.h>

#include <rpc_callee.h>

/*
 * Convert standard PSCI function IDs (0x84xxxxxx) to
 * MbedTEE format (0x80xxxxxx) so the existing switch
 * table in rpc_fastcall_handler() works unchanged.
 */
static inline unsigned long psci_to_mbedtee(unsigned long fn)
{
	unsigned int svc = (fn >> 24) & 0x3F;

	/* Standard Secure Service (0x04) -> map to MbedTEE (0x00) */
	if (svc == 0x04)
		return (fn & 0x0000FFFF) | MBEDTEE_RPC_FASTCALL;

	return fn;
}

void *smc_handler(struct thread_ctx *regs)
{
	struct percpu *pc = thiscpu;
	struct thread_ctx *rregs = (void *)&pc->rctx;
	unsigned long fn = rregs->r[0];

	pc->in_interrupt = true;
	pc->int_ctx = regs;

	if (MBEDTEE_RPC_IS_FASTCALL(fn)) {
		/*
		 * SMCCC fast call: fn in r0, args in r1-r3, return in r0.
		 * Handles both standard PSCI (0x84xxxxxx) and MbedTEE
		 * custom fast calls (0x80xxxxxx).
		 */
		fn = psci_to_mbedtee(fn);
		rregs->r[0] = rpc_fastcall_handler(fn,
			rregs->r[1], rregs->r[2], rregs->r[3]);
	} else {
		/*
		 * SMCCC yield call: fn in r0, rpc_cmd phys in r1.
		 * The rpc_cmd carries session parameters and waiter_id
		 * for async completion notification.
		 */
		rregs->r[0] = rpc_callee_handler_yield(
			fn, rregs->r[1]);
	}

	pc->int_ctx = NULL;
	pc->in_interrupt = false;

	return regs;
}
