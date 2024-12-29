/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Structures for AArch64 context save/restore
 */

#ifndef _CTX_H
#define _CTX_H

/* x0 offset @ struct thread_ctx.r[] */
#define ARG_REG             (0)
#define RET_REG             (0)

/*
 * context registers for per-thread
 */
struct thread_ctx {
	/* link register (x30) of the thread */
	unsigned long lr;

	/* generic regs x0 - x29 */
	unsigned long r[30];

	unsigned long contextidr_el1;

	unsigned long tpidr_el0;

	unsigned long ttbr0_el1;

	/* Stack pointer of the thread -- EL1_SP0 or EL0_SP0 */
	unsigned long sp;

	/* Saved program status register */
	unsigned long spsr;

	unsigned long tpidrro_el0;

	/*
	 * pc of the thread before enter the exception
	 */
	unsigned long pc;

	/*
	 * FP/SIMD state/control regs
	 */
	unsigned long fpsr;
	unsigned long fpcr;
	/*
	 * FP/SIMD registers, here aligned to 32-bytes
	 */
	__uint128_t vr[32];
};

/*
 * only a information for monitor EL3, not really in use
 */
struct thread_ctx_el3 {
	/* link register (x30) of the thread */
	unsigned long lr;

	/* generic regs x0 - x29 */
	unsigned long r[30];

	unsigned long contextidr_el1;

	unsigned long tpidr_el0;

	unsigned long ttbr0_el1;

	/* Stack pointer of the thread -- EL1_SP0 or EL0_SP0 */
	unsigned long sp;

	/* Saved program status register */
	unsigned long spsr;

	unsigned long tpidrro_el0;

	/*
	 * pc of the thread before enter the exception
	 */
	unsigned long pc;



	/* Saved EL1 program status register */
	unsigned long spsr_el1;

	/* EL1 link register of the thread */
	unsigned long elr_el1;

	/*
	 * s/ns world per-cpu registers
	 */
	unsigned long vbar_el1;
	unsigned long ttbr1_el1;
	unsigned long tcr_el1;
	unsigned long mair_el1;
	unsigned long sctlr_el1;
	unsigned long sp_el1;
	unsigned long esr_el1;
	unsigned long far_el1;
	unsigned long cpacr_el1;
	unsigned long csselr_el1;
	unsigned long par_el1;
	unsigned long tpidr_el1;

	unsigned long cntkctl_el1;
	unsigned long cntp_ctl_el0;
	unsigned long cntp_cval_el0;
	unsigned long cntv_ctl_el0;
	unsigned long cntv_cval_el0;

	unsigned long actlr_el1;

	unsigned long afsr0_el1;
	unsigned long afsr1_el1;

	/*
	 * FP/SIMD state/control regs
	 */
	unsigned long fpsr;
	unsigned long fpcr;
	/*
	 * FP/SIMD registers, here aligned to 32-bytes
	 */
	__uint128_t vr[32];
};

#endif

