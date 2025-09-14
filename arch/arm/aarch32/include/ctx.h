/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Structures for AArch32 context save/restore
 */

#ifndef _CTX_H
#define _CTX_H

/* r0 offset @ struct thread_ctx.r[] */
#define ARG_REG             (0)
#define RET_REG             (0)

/*
 * Padding between the last GPR field (lr) and fpscr, and
 * between fpscr and d[]. For ARM32 AAPCS, va_arg(ap, uint64_t)
 * requires the stack pointer (SP) aligned to 8 bytes, and since
 * SP is adjusted by GPR_CTX_SIZE, GPR_CTX_SIZE must be 8-byte
 * aligned. The same padding value also aligns d[] to 8 bytes.
 */
#define PADDING_LENGTH		(4)

#if !defined(__ASSEMBLY__)

#ifdef __cplusplus
extern "C" {
#endif

/*
 * context registers for per-thread @ EL1
 */
struct thread_ctx {
	/* generic regs r0 - r12 */
	unsigned long r[13];
	/*
	 * pc of the thread before
	 * enter the exception
	 */
	unsigned long pc;
	/* saved program status register */
	unsigned long spsr;

	/* TPIDRURW to store the userspace's __builtin_thread_pointer */
	unsigned long tpidrurw;
	/* TPIDRURO to store the kernel's current thread pointer */
	unsigned long tpidruro;
	/* TTBR for user space */
	unsigned long ttbr0;
	/* ASID */
	unsigned long context_id;

	/* Stack pointer of the thread */
	unsigned long sp;
	/* link register of the thread */
	unsigned long lr;

	/* padding: align GPR_CTX_SIZE to 8 bytes */
	unsigned long __gpr_pad;

	/*
	 * VFP/NEON state
	 */
	unsigned long fpscr;
	/* padding: align d[] to 8 bytes */
	unsigned long __fpu_pad;
#if defined(VFP_D32)
	unsigned long long d[32]; /* D0-D31 */
#else
	unsigned long long d[16]; /* D0-D15 only */
#endif
};

/* Byte sizes of GPR and FPU portions of struct thread_ctx */
#define GPR_CTX_SIZE	offsetof(struct thread_ctx, fpscr)
#define FPU_CTX_SIZE	(sizeof(struct thread_ctx) - GPR_CTX_SIZE)

/* low level save/restore functions for FPU context @ ASM */
extern void save_fpu_ctx(struct thread_ctx *ctx);
extern void restore_fpu_ctx(struct thread_ctx *ctx);

/*
 * context registers for per-cpu
 */
struct percpu_ctx {
	unsigned long spsr_svc;
	unsigned long sp_svc;
	unsigned long lr_svc;
	unsigned long spsr_irq;
	unsigned long sp_irq;
	unsigned long lr_irq;
	unsigned long spsr_abt;
	unsigned long sp_abt;
	unsigned long lr_abt;
	unsigned long spsr_undef;
	unsigned long sp_undef;
	unsigned long lr_undef;
	/* VFP/NEON state - NOT banked between Secure/Non-Secure */
	unsigned long fpexc;
	unsigned long fpscr;
#if defined(VFP_D32)
	unsigned long long d[32]; /* D0-D31 */
#else
	unsigned long long d[16]; /* D0-D15 only */
#endif
	/* CPACR - NOT banked between Secure/Non-Secure */
	unsigned long cpacr;
};

/*
 * context registers for per-thread @ EL3
 */
struct thread_ctx_el3 {
	struct thread_ctx thread_ctx;
	struct percpu_ctx cpu_ctx;
};


#ifdef __cplusplus
}
#endif

#endif

#endif
