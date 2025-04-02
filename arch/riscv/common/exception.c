// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Handle RISCV Exceptions
 */

#include <ctx.h>
#include <trace.h>
#include <thread.h>
#include <uaccess.h>
#include <syscall.h>
#include <ksyscall.h>
#include <interrupt.h>
#include <sys/mmap.h>
#include <riscv-mmu.h>

#define RISCV_CAUSE(c) ((c) & 0xF)
#define IS_INTERRUPT(c) ((c) & BIT(BITS_PER_LONG - 1))

typedef void *(*exc_fn)(struct thread_ctx *);

static const char * const fault_encodings[] = {
	"Instruction address misaligned",
	"Instruction access fault",
	"Illegal instruction",
	"Breakpoint",
	"Load address misaligned",
	"Load access fault", /* 5 */
	"Store/AMO address misaligned",
	"Store/AMO access fault",
	"Environment call from U-mode",
	"Environment call from S-mode",
	"Reserved",  /* 10 */
	"Environment call from M-mode",
	"Instruction page fault",
	"Load page fault",
	"Reserved",
	"Store/AMO page fault", /* 15 */
};

/* register names under RISCV ilp32d/lp64d ABI */
static const char *__register_name[32] = {
	"zr", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
	"s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
	"a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
	"s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
};

static inline void __register_dump(struct thread_ctx *regs)
{
	int i = 0;
	unsigned long *r = (void *)regs;
	int cpu = percpu_id();

#if defined(CONFIG_64BIT)
	for (i = 0; i < ARRAY_SIZE(__register_name); i += 4)
		printk("[ERR-%04u|%04u@CPU%02u] r<%02d~%02d> (%s)%016lx\t(%s)%016lx\t(%s)%016lx\t(%s)%016lx\n",
			current_id, current->proc->id, cpu,
			i, i + 3, __register_name[i], r[i],
			__register_name[i+1], r[i+1],
			__register_name[i+2], r[i+2],
			__register_name[i+3], r[i+3]);
#else
	for (i = 0; i < ARRAY_SIZE(__register_name); i += 4)
		printk("[ERR-%04u|%04u@CPU%02u] r<%02d~%02d> (%s)%08lx\t(%s)%08lx\t(%s)%08lx\t(%s)%08lx\n",
			current_id, current->proc->id, cpu,
			i, i + 3, __register_name[i], r[i],
			__register_name[i+1], r[i+1],
			__register_name[i+2], r[i+2],
			__register_name[i+3], r[i+3]);
#endif

	printk("\n");
}

static inline unsigned long __bad_addr(void)
{
	/* read badaddr */
	return read_csr(CSR_TVAL);
}

static __nosprot void __oops(struct thread *t, struct thread_ctx *regs)
{
	const char *symstr = NULL;
	unsigned long offset = 0;
	struct process *proc = t->proc;
	unsigned long addr = __bad_addr();
	unsigned long cause = regs->cause;

	EMSG("oops@%s asid %d usp(0x%x@%p) ksp(0x%x@%p) sp(0x%lx) sig %d\n",
		t->name, proc->pt->asid,
		t->ustack_size, t->ustack_uva,
		t->kstack_size, t, regs->sp, sighandling(t));

	EMSG("stat 0x%lx\n", regs->stat);
	EMSG("satp 0x%lx\n", regs->satp);
	EMSG("cause 0x%lx\n", cause);
	EMSG("address: 0x%lx\n", addr);
	EMSG("encoding: %s\n", fault_encodings[RISCV_CAUSE(cause)]);

#ifdef CONFIG_USER
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

static __nosprot void *page_fault(struct thread_ctx *regs, int flags)
{
#ifdef CONFIG_USER
	struct process *proc = current->proc;
	unsigned long addr = __bad_addr() & PAGE_MASK;

	/* came from user-space */
	if ((regs->stat & SR_PP) == 0) {
		if (user_addr(addr) && vm_fault(proc,
				(void *)addr, flags) == 0)
			return regs;
	} else {
	/* came from kernel-space */
		if (pt_sync(proc->pt, addr))
			return regs;
	}
#endif

	return abort_handler(regs);
}

static __nosprot void *page_fault_load(struct thread_ctx *regs)
{
	return page_fault(regs, PG_RO);
}

static __nosprot void *page_fault_store(struct thread_ctx *regs)
{
	return page_fault(regs, PG_RW);
}

/*
 * Syscall handler
 */
static __nosprot void *ecall_handler(struct thread_ctx *regs)
{
#if defined(CONFIG_SYSCALL)
	regs->pc += BYTES_PER_INT;

#if defined(__riscv_flen)
	regs->fusersaved = false;
	regs = syscall_handler(regs);

	__sched_restore_fuerctx(regs);
#else
	regs = syscall_handler(regs);
#endif

	return regs;
#else
	__oops(current, regs);
	deadloop();
	return regs;
#endif
}

static __nosprot void *instr_handler(struct thread_ctx *regs)
{
#define OPCODE_MASK    0x7f
#define OPCODE_LOAD    0x07
#define OPCODE_STORE   0x27
#define OPCODE_MADD    0x43
#define OPCODE_MSUB    0x47
#define OPCODE_NMSUB   0x4B
#define OPCODE_NMADD   0x4f
#define OPCODE_FP      0x53

#define OPCODE_CSR     0x73

#if defined(__riscv_flen)
	unsigned int is_fpu = false;
	unsigned int instr = *(unsigned int *)regs->pc;
	unsigned int opcode = instr & OPCODE_MASK;

	/* only check and handle the FPU instruction fault */
	if ((regs->stat & SR_FS) != SR_FS_OFF)
		return abort_handler(regs);

	switch (opcode) {
	case OPCODE_FP:
	case OPCODE_LOAD:
	case OPCODE_STORE:
	case OPCODE_MADD:
	case OPCODE_MSUB:
	case OPCODE_NMSUB:
	case OPCODE_NMADD:
		is_fpu = true;
		break;
	default:
		break;
	}

	if (!is_fpu) {
		if (opcode == OPCODE_CSR) {
			if ((((instr >> 12) & 3) != 0) &&
				(((instr >> 20)) != 0) &&
				(((instr >> 20) & ~3ul) == 0))
				is_fpu = true;
		} else {
#if defined(__riscv_compressed)
			if (((instr & 1) == 0) &&
				(((instr >> 13) & 1) != 0))
#if defined(CONFIG_64BIT)
				if (((instr >> 13) & 2) == 0)
#endif
					is_fpu = true;
#endif
		}
	}

	if (is_fpu) {
		/* check and save the unsaved user or kernel fpu-ctx */
		__sched_save_fabtctx(current);
		/* clear fpu-ctx - avoid to leak kernel info */
		__sched_reset_fuserctx(current, regs);
		return regs;
	}
#endif

	return abort_handler(regs);
}

static const exc_fn exception_routines[] = {
	abort_handler, abort_handler, instr_handler, abort_handler,
	abort_handler, abort_handler, abort_handler, abort_handler,
	ecall_handler, abort_handler, abort_handler, abort_handler,
	abort_handler, page_fault_load, abort_handler, page_fault_store,
};

__nosprot void *exception_handler(struct thread_ctx *regs)
{
	unsigned long cause = regs->cause;

	assert((cause & LONG_MAX) < ARRAY_SIZE(exception_routines));

	if (IS_INTERRUPT(cause)) {
		regs = irq_handler(regs);
		/* helps to check if there is any timer expired */
		tevent_isr();
	} else
		regs = exception_routines[RISCV_CAUSE(cause)](regs);

	return regs;
}
