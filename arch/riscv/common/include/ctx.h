/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RISCV32/RISCV64 context structure
 */

#ifndef _CTX_H
#define _CTX_H

#include <sys/cdefs.h>

/* a0 offset @ struct thread_ctx.r[]
 * supposed to be x10, but the struct thread_ctx.r[]
 * counts from x5, so the val is 10 - 5 = 5
 */
#define ARG_REG             (5)
#define RET_REG             (5)

/*
 * context registers for per-thread
 */
struct thread_ctx {
	/* 32 generic regs */
	unsigned long zr;	 // x0 - zero
	unsigned long lr;    // x1 - ra
	unsigned long sp;    // x2 - stack
	unsigned long gp;    // x3 - gp
	unsigned long tp;    // x4 - current
	unsigned long r[27]; // x5 ~ x31

	/* CSR_STATUS */
	unsigned long stat;

	/* CSR_EPC
	 * pc of the thread before
	 * enter the exception
	 */
	unsigned long pc;

	/* CSR_CAUSE */
	unsigned long cause;

	/* current process's SATP for MMU Translation
	 * Table Base (pointer of PTDs) + ASID
	 */
	unsigned long satp;

#if defined(__riscv_flen)

#if   __riscv_flen == 32
	unsigned int f[32];
#elif __riscv_flen == 64
	unsigned long long f[32];
#endif

	unsigned int fcsr;
/* restore-flags when backing to userspace or kernel ctx switch */
	unsigned char fusersaved;
	unsigned short fcpu;
#endif
} __aligned(8);

/* low level save/restore functions for fpu context @ ASM */
extern void save_fpu_ctx(struct thread_ctx *regs);
extern void restore_fpu_ctx(struct thread_ctx *regs);

/* higher level save/restore functions @ sched_riscv */
extern void __sched_save_fabtctx(void *thread);
extern void __sched_restore_fuerctx(struct thread_ctx *regs);
extern void __sched_reset_fuserctx(void *thread, struct thread_ctx *regs);

#endif

