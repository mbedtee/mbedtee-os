/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Structure for MIPS32 context save/restore
 */

#ifndef _CTX_H
#define _CTX_H

#include <generated/autoconf.h>

#ifdef __cplusplus
extern "C" {
#endif

/* a0/v0 offset @ struct thread_ctx.r[] */
#define ARG_REG				(4)
#define RET_REG				(2)

/*
 * context registers for per-thread
 */
struct thread_ctx {
	/* 32 generic regs */
	unsigned long r[28];
	unsigned long gp; /* r28 */
	unsigned long sp; /* r29 */
	unsigned long r30;
	unsigned long lr; /* r31 - ra */

	/* hi/lo registers for div/mul */
	unsigned long hi;
	unsigned long lo;

	/* cp0_status */
	unsigned long stat;

	/*
	 * cp0_epc
	 * pc of the thread before
	 * enter the exception
	 */
	unsigned long pc;

	/* cp0_cause */
	unsigned long cause;
	/* UserLocal */
	unsigned long userlocal;

#if defined(CONFIG_FPU)
	/*
	 * FPU (CP1) state - located at GPR_CTX_SIZE offset.
	 * Exception frames allocate only GPR_CTX_SIZE bytes;
	 * FPU state lives in sched->regs and is lazily restored.
	 */
	unsigned long fcsr;          /* FP Control/Status Register */
	unsigned long __fpu_pad;     /* align f[] to 8 bytes */
	unsigned long long f[16];    /* f0/f1 .. f30/f31 as 16 doubles */
#endif
} __attribute__((aligned(8)));

/*
 * GPR_CTX_SIZE: byte size of the GPR-only portion.
 * Exception frames are compressed to this size; FPU state
 * resides only in sched->regs (lazily saved/restored).
 */
#if defined(CONFIG_FPU)
#define GPR_CTX_SIZE	offsetof(struct thread_ctx, fcsr)
#define FPU_CTX_SIZE	(sizeof(struct thread_ctx) - GPR_CTX_SIZE)
#else
#define GPR_CTX_SIZE	sizeof(struct thread_ctx)
#define FPU_CTX_SIZE	0
#endif

#if defined(CONFIG_FPU)
/* low-level save/restore functions for FPU context @ ASM */
extern void save_fpu_ctx(struct thread_ctx *ctx);
extern void restore_fpu_ctx(struct thread_ctx *ctx);
#endif

#ifdef __cplusplus
}
#endif

#endif

