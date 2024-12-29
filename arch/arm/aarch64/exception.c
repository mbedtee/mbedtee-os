// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch64 exception routine
 */

#include <cpu.h>
#include <trace.h>
#include <string.h>
#include <uaccess.h>
#include <thread.h>
#include <sys/mmap.h>
#include <__pthread.h>

extern void *syscall_handler(struct thread_ctx *);

#define ESR_EC_UNKNOWN        (0x00) /* Unknown reason */
#define ESR_EC_WFI_WFE        (0x01) /* Trapped WFE, WFI, WFET or WFIT instruction execution */
#define ESR_EC_CP15_MCR_MRC   (0x03)
#define ESR_EC_CP15_MCRR_MRRC (0x04)
#define ESR_EC_CP14_MCR_MRC   (0x05)
#define ESR_EC_CP14_LDC_STC   (0x06)
#define ESR_EC_SVE_SIMD_FP    (0x07)
#define ESR_EC_CP10_VMRS      (0x08) /* Trapped VMRS access to MVFR0, MVFR1, MVFR2, or FPSID. */
#define ESR_EC_PAUTH          (0x09) /* Trapped access to an FEAT_PAuth instruction */
#define ESR_EC_LD64B_ST64B    (0x0A) /* Trapped execution of an LD64B, ST64B, ST64BV, or ST64BV0 instruction */
#define ESR_EC_CP14_MRRC      (0x0C)
#define ESR_EC_ILL_STATE      (0x0E) /* Illegal Execution state */
#define ESR_EC_SVC32          (0x11) /* AArch32 */
#define ESR_EC_HVC32          (0x12) /* AArch32 EL2 */
#define ESR_EC_SMC32          (0x13) /* AArch32 */
#define ESR_EC_SVC64          (0x15) /* AArch64 */
#define ESR_EC_HVC64          (0x16) /* AArch64 EL2 only */
#define ESR_EC_SMC64          (0x17) /* AArch64 */
#define ESR_EC_MSR_MRS        (0x18) /* AArch64 */
#define ESR_EC_SVE            (0x19)
#define ESR_EC_ERET           (0x1A) /* AArch64 EL2 only */
#define ESR_EC_PAUTH_FAIL     (0x1C) /* AArch64 */
#define ESR_EC_IMP_DEF        (0x1F) /* IMPLEMENTATION DEFINED exception taken to EL3 */
#define ESR_EC_IABT_LOW       (0x20) /* Instruction Abort from a lower Exception level */
#define ESR_EC_IABT_CUR       (0x21) /* Instruction Abort from current Exception level */
#define ESR_EC_PC_ALIGN       (0x22) /* PC alignment fault */
#define ESR_EC_DABT_LOW       (0x24) /* Data Abort from a lower Exception level */
#define ESR_EC_DABT_CUR       (0x25) /* Data Abort from current Exception level */
#define ESR_EC_SP_ALIGN       (0x26) /* SP alignment fault */
#define ESR_EC_FP32           (0x28) /* Trapped floating-point exception taken from AArch32 state */
#define ESR_EC_FP64           (0x2C) /* Trapped floating-point exception taken from AArch64 state */
#define ESR_EC_SERROR         (0x2F)
#define ESR_EC_BREAKP_LOW     (0x30) /* Breakpoint exception from a lower Exception level (EL012) */
#define ESR_EC_BREAKP_CUR     (0x31) /* Breakpoint exception from current Exception level (EL012) */
#define ESR_EC_SOFTSTEP_LOW   (0x32) /* Software Step exception from a lower Exception level (EL012) */
#define ESR_EC_SOFTSTEP_CUR   (0x33) /* Software Step exception from current Exception level (EL012) */
#define ESR_EC_WATCHP_LOW     (0x34) /* Watchpoint exception from a lower Exception level (EL012) */
#define ESR_EC_WATCHP_CUR     (0x35) /* Watchpoint exception from a lower Exception level (EL012) */
#define ESR_EC_BKPT32         (0x38) /* BKPT instruction execution in AArch32 state (EL2 only) */
#define ESR_EC_VECTOR32       (0x3A) /* Vector Catch exception from AArch32 state (EL2 only) */
#define ESR_EC_BRK64          (0x3C) /* BRK instruction execution in AArch64 state */
#define ESR_EC_MAX            (0x3F)

#define ESR_EC_SHIFT          (26)
#define ESR_EC_MASK           (0x3F)
#define ESR_EC(esr)           (((esr) >> ESR_EC_SHIFT) & ESR_EC_MASK)

#define ESR_ISS_CM            (8)
#define ESR_ISS_WNR           (6)

static const char * const ec_encodings[] = {
	[0 ... ESR_EC_MAX]          = "Undefined",
	[ESR_EC_UNKNOWN]            = "Unknown",
	[ESR_EC_WFI_WFE]            = "WFI/WFE",
	[ESR_EC_CP15_MCR_MRC]       = "CP15 MCR/MRC",
	[ESR_EC_CP15_MCRR_MRRC]     = "CP15 MCRR/MRRC",
	[ESR_EC_CP14_MCR_MRC]       = "CP14 MCR/MRC",
	[ESR_EC_CP14_LDC_STC]       = "CP14 LDC/STC",
	[ESR_EC_SVE_SIMD_FP]        = "SVE/SIMD/FP",
	[ESR_EC_CP10_VMRS]          = "CP10 VMRS",
	[ESR_EC_PAUTH]              = "PAuth Access",
	[ESR_EC_LD64B_ST64B]        = "LD64B/ST64B",
	[ESR_EC_CP14_MRRC]          = "CP14 MRRC",
	[ESR_EC_ILL_STATE]          = "Ill PSTATE.IL",
	[ESR_EC_SVC32]              = "SVC (AArch32)",
	[ESR_EC_HVC32]              = "HVC (AArch32)",
	[ESR_EC_SMC32]              = "SMC (AArch32)",
	[ESR_EC_SVC64]              = "SVC (AArch64)",
	[ESR_EC_HVC64]              = "HVC (AArch64)",
	[ESR_EC_SMC64]              = "SMC (AArch64)",
	[ESR_EC_MSR_MRS]            = "MSR/MRS",
	[ESR_EC_SVE]                = "SVE",
	[ESR_EC_ERET]               = "ERET",
	[ESR_EC_PAUTH_FAIL]         = "PAuth AuthFail",
	[ESR_EC_IMP_DEF]            = "IMP DEF @ EL3",
	[ESR_EC_IABT_LOW]           = "IABT (lower EL)",
	[ESR_EC_IABT_CUR]           = "IABT (current EL)",
	[ESR_EC_PC_ALIGN]           = "PC Alignment",
	[ESR_EC_DABT_LOW]           = "DABT (lower EL)",
	[ESR_EC_DABT_CUR]           = "DABT (current EL)",
	[ESR_EC_SP_ALIGN]           = "SP Alignment",
	[ESR_EC_FP32]               = "FP (AArch32)",
	[ESR_EC_FP64]               = "FP (AArch64)",
	[ESR_EC_SERROR]             = "SError",
	[ESR_EC_BREAKP_LOW]         = "Breakpoint (lower EL)",
	[ESR_EC_BREAKP_CUR]         = "Breakpoint (current EL)",
	[ESR_EC_SOFTSTEP_LOW]       = "Software Step (lower EL)",
	[ESR_EC_SOFTSTEP_CUR]       = "Software Step (current EL)",
	[ESR_EC_WATCHP_LOW]         = "Watchpoint (lower EL)",
	[ESR_EC_WATCHP_CUR]         = "Watchpoint (current EL)",
	[ESR_EC_BKPT32]             = "BKPT (AArch32)",
	[ESR_EC_VECTOR32]           = "Vector catch (AArch32)",
	[ESR_EC_BRK64]              = "BRK (AArch64)",
};

static inline int is_write_abort(unsigned long esr)
{
	return (esr & (1 << ESR_ISS_WNR)) &&
		 !(esr & (1 << ESR_ISS_CM));
}

static inline unsigned long __esr(void)
{
	unsigned long esr = 0;

	asm volatile ("mrs %0, esr_el1\n"
		: "=r" (esr) : : "memory", "cc");

	return esr;
}

static inline unsigned long __far(void)
{
	unsigned long addr = 0;

	asm volatile ("mrs %0, far_el1\n"
		: "=r" (addr) : : "memory", "cc");

	return addr;
}

static inline int vm_fault_handler(struct thread *t,
	unsigned long esr)
{
	void *addr = (void *)(__far() & PAGE_MASK);
	int flags = is_write_abort(esr) ? PG_RW : PG_RO;

	return vm_fault(t->proc, addr, flags);
}

static inline void __register_dump(struct thread_ctx *regs)
{
	int i = 0;

	for (i = 0; i < 28; i += 4)
		printk("x[%02d~%02d] %016lx %016lx %016lx %016lx\n",
			i, i + 3, regs->r[i], regs->r[i+1],
			regs->r[i+2], regs->r[i+3]);

	printk("x[28~29] %016lx %016lx\n\n", regs->r[28], regs->r[29]);
}

static __nosprot void __oops(struct thread *t, struct thread_ctx *regs)
{
	const char *symstr = NULL;
	unsigned long offset = 0;
	struct process *proc = NULL;
	unsigned long esr = __esr();
	unsigned long addr = __far();
	unsigned long ec = ESR_EC(esr);

	EMSG("address: 0x%lx\n", addr);
	EMSG("sp 0x%lx\n", regs->sp);
	EMSG("spsr 0x%lx\n", regs->spsr);
	EMSG("exception class: 0x%lx\n", ec);
	EMSG("exception iss: 0x%lx\n", esr & 0xffffff);
	EMSG("encoding: %s\n", ec_encodings[ec]);

	proc = t->proc;

	EMSG("oops@%s asid %d usp(0x%x@%p) ksp(0x%x@%p) sig %d\n",
		t->name, proc->pt->asid,
		t->ustack_size, t->ustack_uva,
		t->kstack_size, t, sighandling(t));

#ifdef CONFIG_USER
#include <elf_proc.h>

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

__nosprot void *exception_handler(struct thread_ctx *regs)
{
	struct thread *t = current;

#ifdef CONFIG_USER
	unsigned long esr = __esr();
	unsigned long ec = ESR_EC(esr);

	/* handle low-level syscall */
	if (ec == ESR_EC_SVC64)
		return syscall_handler(regs);

	/* handle low-level page fault */
	if (ec == ESR_EC_DABT_LOW) {
		if (vm_fault_handler(t, esr) == 0)
			return regs;
	}
#endif

	__oops(t, regs);

	sched_abort(regs);

	return regs;
}
