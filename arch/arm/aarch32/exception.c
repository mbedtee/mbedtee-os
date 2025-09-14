// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * AArch32 data/instruction/undefined abort exceptions
 */

#include <trace.h>
#include <ctx.h>
#include <cpu.h>
#include <string.h>
#include <thread.h>
#include <sys/mmap.h>
#include <uaccess.h>
#include <ksyscall.h>

#if defined(CONFIG_USER)
#include <elf_proc.h>
#endif

#define STATUS_MASK1 (0xF)
#define STATUS_MASK2 (0x1)
#define STATUS_MASK2_SHIFT (10)

#define DFSR_SECT_FAULT 5
#define DFSR_PAGE_FAULT 7
#define DFSR_WNR 11

/*
 * VMSA Fault Status Register Encodings
 *
 * in architecture reference manual
 * table B3-23 Short-descriptor format FSR encodings
 */
static const char * const fault_encodings[] = {
	"Reserved",
	"Alignment fault", /* data fault only */
	"Watchpoint debug event",
	"Access flag fault - first level",
	"Instruction cache maintenance fault", /* data fault only */
	"Translation fault - first level",
	"Access flag fault - second level",
	"Translation fault - Second level",
	"Synchronous external abort",
	"Domain fault - first level",
	"Reserved",
	"Domain fault - second level",
	"Synchronous external abort on translation table walk - first level",
	"Permission fault - first level",
	"Synchronous external abort on translation table walk - second level",
	"Permission fault - second level",
	"TLB conflict abort",
	"Reserved",
	"Reserved",
	"Reserved",
	"IMPLEMENTATION DEFINED - Lockdown",
	"Reserved",
	"Asynchronous external abort", /* data fault only */
	"Reserved",
	"Asynchronous parity error on memory access", /* data fault only */
	"Synchronous parity error on memory access",
	"IMPLEMENTATION DEFINED - Coprocessor abort",
	"Reserved",
	"Synchronous parity error on translation table walk - first level",
	"Reserved",
	"Synchronous parity error on translation table walk - second level",
	"Reserved",
};

static inline unsigned long __df_addr(void)
{
	unsigned long addr = 0;

	/* read DFAR */
	asm volatile (
		"mrc p15, 0, %0, c6, c0, 0\n"
		: "=r" (addr)
		:
		: "memory", "cc");

	return addr;
}

static inline unsigned long __dfsr(void)
{
	unsigned long status = 0;

	/* read DFSR */
	asm volatile (
		"mrc p15, 0, %0, c5, c0, 0\n"
		: "=r" (status)
		:
		: "memory", "cc");

	return status;
}

static inline int __dfsr_fs(unsigned long dfsr)
{
	unsigned long ext = STATUS_MASK2 << STATUS_MASK2_SHIFT;

	return (dfsr & STATUS_MASK1) |
		((dfsr & ext) ? (STATUS_MASK2 << 4) : 0);
}

static inline unsigned long __if_addr(void)
{
	unsigned long addr = 0;

	/* read IFAR */
	asm volatile (
		"mrc p15, 0, %0, c6, c0, 2\n"
		: "=r" (addr)
		:
		: "memory", "cc");

	return addr;
}

static inline unsigned long __if_status(void)
{
	unsigned long status = 0;
	unsigned long ext = STATUS_MASK2 << STATUS_MASK2_SHIFT;

	/* read IFSR */
	asm volatile (
		"mrc p15, 0, %0, c5, c0, 1\n"
		: "=r" (status)
		:
		: "memory", "cc");

	return (status & STATUS_MASK1) |
		((status & ext) ? (STATUS_MASK2 << 4) : 0);
}

static void __prefetch_oops(void)
{
	int s = __if_status();

	EMSG("address: 0x%lx\n", __if_addr());
	EMSG("status: %d\n", s);
	EMSG("encoding: %s\n", fault_encodings[s]);
}

static void __undefined_oops(void)
{
	int s = __if_status();

	EMSG("address: 0x%lx\n", __if_addr());
	EMSG("status: %d\n", s);
	EMSG("encoding: %s\n", fault_encodings[s]);
}

static void __data_oops(void)
{
	unsigned long dfsr = __dfsr();
	int s = __dfsr_fs(dfsr);

	EMSG("address: 0x%lx\n", __df_addr());
	EMSG("status: %d\n", s);
	EMSG("encoding: %s\n", fault_encodings[s]);
}

static inline int vm_fault_handler(struct thread *t,
	unsigned long dfsr)
{
	void *addr = (void *)(__df_addr() & PAGE_MASK);
	int flags = (dfsr & (1U << DFSR_WNR)) ? PG_RW : PG_RO;

	return vm_fault(t->proc, addr, flags);
}

static inline void __register_dump(struct thread_ctx *regs)
{
	int i = 0;

	for (i = 0; i < 12; i += 4)
		printk("r[%02d~%02d] %08lx %08lx %08lx %08lx\n",
			i, i + 3, regs->r[i], regs->r[i+1],
			regs->r[i+2], regs->r[i+3]);

	printk("r[12] %08lx\n\n", regs->r[12]);
}

static __nosprot void __oops(struct thread *t, struct thread_ctx *regs)
{
	const char *symstr = NULL;
	unsigned long offset = 0;
	struct process *proc = NULL;

	EMSG("sp 0x%lx\n", regs->sp);
	EMSG("spsr 0x%lx\n", regs->spsr);
	EMSG("ttbr0 0x%lx\n", regs->ttbr0);
	EMSG("tpidrurw 0x%lx\n", regs->tpidrurw);
	EMSG("context_id 0x%lx\n", regs->context_id);

	proc = t->proc;

	EMSG("oops@%s asid %d sig %d\n",
		t->name, proc->pt->asid, sighandling(t));

	EMSG("usp(0x%x@%p) ksp(0x%x@%p)\n",
		t->ustack_size, t->ustack_uva,
		t->kstack_size, t);

#if defined(CONFIG_USER)

	symstr = elf_proc_funcname(proc, regs->pc, &offset);
	EMSG("pc 0x%lx (%s + %lx)\n", regs->pc, symstr ? symstr : "null", offset);
	offset = 0;
	symstr = elf_proc_funcname(proc, regs->lr, &offset);
	EMSG("lr 0x%lx (%s + %lx)\n\n", regs->lr, symstr ? symstr : "null", offset);
#else
	symstr = ksymname_of(regs->pc, &offset);
	EMSG("pc 0x%lx (%s + %lx)\n", regs->pc, symstr ? symstr : "null", offset);
	offset = 0;
	symstr = ksymname_of(regs->lr, &offset);
	EMSG("lr 0x%lx (%s + %lx)\n\n", regs->lr, symstr ? symstr : "null", offset);
#endif

	__register_dump(regs);
}

void *irq_forward(struct thread_ctx *regs)
{
	/*
	 * In case of AArch32@ARMV7-A:
	 *
	 * Due to TEE is using FIQ instead of the IRQ
	 * and the IRQ may happen during TEE execution,
	 * so TEE needs to forward the IRQ to REE in case
	 * of the IRQ happened when CPU state is secure (TEE).
	 *
	 * If the CONFIG_IRQ_FORWARD is not set, this handler
	 * should never be called.
	 */

#if !defined(CONFIG_IRQ_FORWARD)
	WMSG("Forwarding IRQ when CONFIG_IRQ_FORWARD isn't set\n");
#endif

	sched_exec_ree(regs);

	return regs;
}

__nosprot void *data_abort(struct thread_ctx *regs)
{
	struct thread *t = current;

#if defined(CONFIG_USER)
	unsigned long dfsr = __dfsr();
	int fs = __dfsr_fs(dfsr);

	/* handle low-level page fault */
	if ((fs == DFSR_PAGE_FAULT || fs == DFSR_SECT_FAULT) &&
		((regs->spsr & 0xF) == 0)) {
		if (vm_fault_handler(t, dfsr) == 0)
			return regs;
	}
#endif

	__data_oops();

	__oops(t, regs);

	sched_abort(regs);

	return regs;
}

__nosprot void *prefetch_abort(struct thread_ctx *regs)
{
	struct thread *t = current;

	__prefetch_oops();

	__oops(t, regs);

	sched_abort(regs);

	return regs;
}

__nosprot void *undefined_abort(struct thread_ctx *regs)
{
	unsigned long cpacr = 0;

	asm volatile("mrc p15, 0, %0, c1, c0, 2"
		: "=r" (cpacr) : : "memory", "cc");

	/*
	 * Lazy FPU trap: when CPACR restricts user-mode VFP access
	 * (cp10/cp11 = 01, privileged only), a user-mode VFP instruction
	 * causes an undefined instruction exception. Detect this and
	 * lazily restore the FPU context.
	 */
	if ((regs->spsr & 0x1F) == USR_MODE) {
		/* cp10/cp11 = 01 (privileged only) -> FPU trap from user */
		if ((cpacr & 0xF00000) == 0x500000) {
			struct thread *t = current;

			/* Restore current thread's FPU from sched->regs */
			restore_fpu_ctx(t->sched_ctx);
			thiscpu->fpu_owner = t;

			/* Enable full VFP access (cp10/cp11 = 11) */
			cpacr |= 0xF00000;
			asm volatile("mcr p15, 0, %0, c1, c0, 2\n\tisb"
				: : "r" (cpacr) : "memory");
			return regs;
		}
	}

	__undefined_oops();

	__oops(current, regs);

	sched_abort(regs);

	return regs;
}

/*
 * Syscall handler
 */
__nosprot void *sys_handler(struct thread_ctx *regs)
{
#if defined(CONFIG_SYSCALL)
	return syscall_handler(regs);
#else
	__oops(current, regs);
	deadloop();
	return regs;
#endif
}
