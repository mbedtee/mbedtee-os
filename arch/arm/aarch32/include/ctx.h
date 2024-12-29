/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Structures for AArch32 context save/restore
 */

#ifndef _CTX_H
#define _CTX_H

/* r0 offset @ struct thread_ctx.r[] */
#define ARG_REG             (0)
#define RET_REG             (0)

/*
 * context registers for per-thread
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
};

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
};

/*
 * context registers for per-thread
 */
struct thread_ctx_el3 {
	/* generic regs r0 - r12 */
	unsigned long r[13];
	/*
	 * pc of the thread before
	 * enter the exception
	 */
	unsigned long pc;
	/* saved program status register */
	unsigned long spsr;

	/* TPIDRURW to store the __builtin_thread_pointer */
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

	struct percpu_ctx cpu_ctx;
};

#endif

