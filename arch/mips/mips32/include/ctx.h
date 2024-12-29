/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Structure for MIPS32 context save/restore
 */

#ifndef _CTX_H
#define _CTX_H

/* a0/v0 offset @ struct thread_ctx.r[] */
#define ARG_REG				(4)
#define RET_REG				(2)

/*
 * context registers for per-thread
 */
struct thread_ctx {
	/* 32 generic regs */
	unsigned long r[28];
	unsigned long gp; // r28
	unsigned long sp; // r29
	unsigned long r30;
	unsigned long lr; // r31 - ra

	/* hi/lo registers for div/mul */
	unsigned long hi;
	unsigned long lo;

	/* cp0_status */
	unsigned long stat;

	/* cp0_epc
	 * pc of the thread before
	 * enter the exception
	 */
	unsigned long pc;

	/* cp0_cause */
	unsigned long cause;
	/* UserLocal */
	unsigned long userlocal;
};

#endif

