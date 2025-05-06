// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Handle MIPS32 Exceptions
 */

#include <ctx.h>
#include <trace.h>
#include <thread.h>
#include <uaccess.h>
#include <syscall.h>
#include <interrupt.h>
#include <sys/mmap.h>
#include <mips32-tlb.h>

#define MIPS32_CAUSE_MASK (0x1F)
#define MIPS32_CAUSE ((regs->cause >> 2) & MIPS32_CAUSE_MASK)

typedef void *(*exc_fn)(struct thread_ctx *);

static const char * const fault_encodings[] = {
	"Interrupt",
	"Store, but page marked as read-only in the TLB",
	"Load or fetch, but page marked as invalid in the TLB",
	"Store, but page marked as invalid in the TLB",
	"Address error on load/fetch respectively, wrongly aligned or a privilege violation",
	"Address error on store respectively, wrongly aligned or a privilege violation", /* 5 */
	"Bus error signaled on instruction fetch",
	"Bus error signaled on load/store (imprecise)",
	"System call, i.e. syscall instruction executed",
	"Breakpoint, i.e. break instruction executed",
	"Instruction code not recognized (or not legal)",  /* 10 */
	"Instruction code was for a co-processor which is not enabled in StatusCU3-0",
	"Overflow from a trapping variant of integer arithmetic instructions",
	"Condition met on one of the conditional trap instructions teq etc",
	"Reserved",
	"Floating point unit exception, more details in the FPU control/status registers", /* 15 */
	"Reverved",
	"Reverved",
	"Reverved",
	"Reverved",
	"Reverved", /* 20 */
	"Reverved",
	"Reverved",
	"Instruction or data reference matched a watchpoint",
	"Machine check",
	"Reverved",	/* 25 */
	"Tried to run an instruction from the MIPS DSP ASE, not enabed",
	"Reverved",
	"Reverved",
	"Reverved",
	"Cache Error", /* 30 */
	"Reverved"
};

/* register names under MIPS oabi 32 */
static const char *__register_name[32] = {
	"zr", "at", "v0", "v1", "a0", "a1", "a2", "a3",
	"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
	"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
	"t8", "t9", "k0", "k1", "gp", "sp", "s8", "ra",
};

static inline void __register_dump(struct thread_ctx *regs)
{
	int i = 0;

	for (i = 0; i < ARRAY_SIZE(regs->r); i += 4)
		printk("r[%02d~%02d] (%s)%08lx (%s)%08lx (%s)%08lx (%s)%08lx\n",
			i, i + 3, __register_name[i], regs->r[i],
			__register_name[i+1], regs->r[i+1],
			__register_name[i+2], regs->r[i+2],
			__register_name[i+3], regs->r[i+3]);

	printk("\n");
}

static inline unsigned long __bad_addr(void)
{
	/* read BadVAddr */
	return read_cp0_register(C0_BADVADDR);
}

static __nosprot void __oops(struct thread *t, struct thread_ctx *regs)
{
	const char *symstr = NULL;
	unsigned long offset = 0;
	struct process *proc = NULL;
	unsigned long addr = __bad_addr();

	EMSG("address: 0x%lx\n", addr);
	EMSG("gp 0x%lx s8 0x%lx\n", regs->gp, regs->r30);
	EMSG("sp 0x%lx pc 0x%lx ra 0x%lx\n", regs->sp, regs->pc, regs->lr);
	EMSG("stat 0x%lx, cause 0x%lx\n", regs->stat, regs->cause);
	EMSG("encoding: %s\n", fault_encodings[MIPS32_CAUSE]);

	proc = t->proc;

	EMSG("oops@%s asid %d sig %d\n",
		t->name, proc->pt->asid, sighandling(t));

	EMSG("usp(0x%x@%p) ksp(0x%x@%p)\n",
		t->ustack_size, t->ustack_uva,
		t->kstack_size, t);

#if defined(CONFIG_USER)
#include <elf_proc.h>

	symstr = elf_proc_funcname(proc, regs->pc, &offset);
	EMSG("pc 0x%lx (%s + %lx)\n", regs->pc, symstr ? symstr : "null", offset);
	offset = 0;
	symstr = elf_proc_funcname(proc, regs->lr, &offset);
	EMSG("ra 0x%lx (%s + %lx)\n\n", regs->lr, symstr ? symstr : "null", offset);
#else
	symstr = ksymname_of(regs->pc, &offset);
	EMSG("pc 0x%lx (%s + %lx)\n", regs->pc, symstr ? symstr : "null", offset);
	offset = 0;
	symstr = ksymname_of(regs->lr, &offset);
	EMSG("ra 0x%lx (%s + %lx)\n\n", regs->lr, symstr ? symstr : "null", offset);
#endif

	__register_dump(regs);
}

/*
 * Generic abort handler
 */
static __nosprot void *abort_handler(struct thread_ctx *regs)
{
	struct thread *t = current;

	__oops(t, regs);

	sched_abort(regs);

	return regs;
}

/*
 * Syscall handler
 */
static __nosprot void *sys_handler(struct thread_ctx *regs)
{
#if defined(CONFIG_SYSCALL)
	extern void *syscall_handler(struct thread_ctx *);

	regs->pc += BYTES_PER_INT;

	return syscall_handler(regs);
#else
	__oops(current, regs);
	deadloop();
	return regs;
#endif
}

/*
 * case 1: it refills the TLB entry
 * case 2: it handles the user-space MM Read fault
 */
static __nosprot void *tlbr_handler(struct thread_ctx *regs)
{
#if defined(CONFIG_MMU)
	struct thread *t = current;
	struct pt_struct *pt = kpt();
	unsigned long va = __bad_addr() & PAGE_MASK;

	if (t && user_addr(va))
		pt = t->proc->pt;

	thiscpu->asid = pt->asid;

	if (tlb_refill(pt, va, PG_RO) == 0)
		return regs;
#endif

#if defined(CONFIG_USER)
	if (((regs->stat & STAT_KU_MASK) == STAT_USER) &&
		(vm_fault(t->proc, (void *)va, PG_RO) == 0))
		return regs;
#endif

	return abort_handler(regs);
}

/*
 * case 1: it refills the TLB entry
 * case 2: it handles the user-space MM Write fault
 */
static __nosprot void *tlbw_handler(struct thread_ctx *regs)
{
#if defined(CONFIG_MMU)
	struct thread *t = current;
	struct pt_struct *pt = kpt();
	unsigned long va = __bad_addr() & PAGE_MASK;

	if (t && user_addr(va))
		pt = t->proc->pt;

	thiscpu->asid = pt->asid;

	if (tlb_refill(pt, va, PG_RW) == 0)
		return regs;
#endif

#if defined(CONFIG_USER)
	if (((regs->stat & STAT_KU_MASK) == STAT_USER) &&
		(vm_fault(t->proc, (void *)va, PG_RW) == 0))
		return regs;
#endif

	return abort_handler(regs);
}

/*
 * case 1: it handles the user-space rdhwr fault
 * (e.g. rdhwr not work @ part of the qemu malta boards!!)
 *
 * case 2:
 */
static __nosprot void *instr_abort_handler(struct thread_ctx *regs)
{
	struct thread *t = current;
	unsigned long instr = 0;

#define OPCODE         0xfc000000
#define SPEC3          0x7c000000
#define RD             0x0000f800
#define RT             0x001f0000
#define FUNC           0x0000003f
#define RDHWR          0x0000003b
#define RDHWR_RD_VAL   29

	if (!user_addr(regs->pc))
		return abort_handler(regs);

	instr = *((unsigned long *)regs->pc);
	if (((instr & FUNC) == RDHWR) &&
		((instr & OPCODE) == SPEC3) &&
		((instr & RD) >> 11) == RDHWR_RD_VAL) {
		regs->pc += BYTES_PER_LONG;
		regs->r[(instr & RT) >> 16] = (long)t->tuser_uva;
		return regs;
	}

	return abort_handler(regs);
}

static const exc_fn exception_routines[] = {
	irq_handler, abort_handler, tlbr_handler, tlbw_handler,
	abort_handler, abort_handler, abort_handler, abort_handler,
	sys_handler, abort_handler, instr_abort_handler, abort_handler,
	abort_handler, abort_handler, abort_handler, abort_handler,
	abort_handler, abort_handler, abort_handler, abort_handler,
	abort_handler, abort_handler, abort_handler, abort_handler,
	abort_handler, abort_handler, abort_handler, abort_handler,
	abort_handler, abort_handler, abort_handler, abort_handler
};

__nosprot void *exception_handler(struct thread_ctx *regs)
{
	/*
	 * Switch to kernel mode
	 */
	write_cp0_register(C0_STATUS, regs->stat & (~STAT_MASK));

	return exception_routines[MIPS32_CAUSE](regs);
}
