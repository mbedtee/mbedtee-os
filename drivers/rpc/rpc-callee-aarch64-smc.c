// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * RPC Callee (REE->TEE) - SMC handler
 *
 * SMCCC-compatible calling convention:
 *   Fast call  : x0 = function ID (bit 31 set), x1-x3 = args, return in x0.
 *   Yield call : x0 = function ID (bit 31 clear), x1 = phys(rpc_cmd),
 *                return 0 in x0 (actual result via async completion).
 *
 * Standard PSCI calls (service type 0x04, e.g. 0xC4000003) are accepted
 * alongside MbedTEE calls (service type 0x00, e.g. 0x80000003).
 */

#include <trace.h>
#include <percpu.h>

#include <rpc_callee.h>

/*
 * Convert standard PSCI function IDs to MbedTEE format
 * so the existing switch table works unchanged.
 */
static inline unsigned long psci_to_mbedtee(unsigned long fn)
{
	unsigned int svc = (fn >> 24) & 0x3F;

	/* Standard Secure Service (0x04) -> map to MbedTEE (0x00) */
	if (svc == 0x04)
		return (fn & 0x0000FFFF) | MBEDTEE_RPC_FASTCALL;

	return fn;
}

void *smc_handler(struct thread_ctx *unused)
{
	struct percpu *pc = thiscpu;
	struct thread_ctx *rregs = pc->rctx;
	unsigned long fn = rregs->r[0];

	if (MBEDTEE_RPC_IS_FASTCALL(fn)) {
		fn = psci_to_mbedtee(fn);
		rregs->r[0] = rpc_fastcall_handler(fn,
			rregs->r[1], rregs->r[2], rregs->r[3]);
	} else {
		rregs->r[0] = rpc_callee_handler_yield(
			fn, rregs->r[1]);
	}

	return unused;
}
