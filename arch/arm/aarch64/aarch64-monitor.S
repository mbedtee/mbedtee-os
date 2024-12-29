/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * EL3 - Secure Monitor
 * SMC/FIQ routines for TEE/REE world ctx switching
 */

#include "aarch64-ctx.h"
#include "aarch64-mmu.h"

.text
.section ".head.text", "ax"

/*
 * 1008 bytes for Context - refer to struct thread_ctx_el3. align to 1024..
 * so the stack size is 2048 + 64 - (1024 * 2) = 64 (64B is enough)
 * get from tpidr_el3
 */
#define CONTEXT_SIZE (1024)
#define BUFFER_SIZE (2048 + 64)

/*
 * EL3 -> EL1 SMC call info (to share the rctx pointer with EL1 SMC routine)
 * get from tpidr_el1 -> rctx/sgi
 * when received NS SMC, monitor will trigger SGI, EL1 responses this SGI
 */
#define SMC_SGI_ID (15)

/* save S world per-cpu context */
.macro save_s_context
	/* temp save lr / x0 to monitor's stack */
	stp	x30, x0, [sp, #-16]!
	mrs x0, tpidr_el3
	add x0, x0, #(CONTEXT_SIZE)
	bl save_percpu_ctx
	ldp	x30, x1, [sp], #16
	/* save lr / x0 to pre-defined buffer */
	stp	x30, x1, [x0, #16 * 0]
.endm

/* save NS world per-cpu context */
.macro save_ns_context
	/* temp save lr / x0 to monitor's stack*/
	stp	x30, x0, [sp, #-16]!
	mrs x0, tpidr_el3
	bl save_percpu_ctx
	ldp	x30, x1, [sp], #16
	/* save lr / x0 to pre-defined buffer */
	stp	x30, x1, [x0, #16 * 0]
.endm

/* restore S world per-cpu context */
.macro restore_s_context
	mrs x0, tpidr_el3
	add x0, x0, #(CONTEXT_SIZE)
	bl restore_percpu_ctx
	/* restore the lr and x0 */
	ldp	x30, x0, [x0, #16 * 0]
.endm

/* restore NS world per-cpu context */
.macro restore_ns_context
	mrs x0, tpidr_el3
	bl restore_percpu_ctx
	/* restore the lr and x0 */
	ldp	x30, x0, [x0, #16 * 0]
.endm

.global _start
_start:
	unset_nsbit x7
	/* FIQ IRQ ASYNC, DEBUG exceptions are all masked */
	msr daifset, #(0xF)
	ldr x1, =MPIDR_BITMASK
	mrs x0, mpidr_el1
	and x0, x0, x1
	adr lr, cpu_setup_el3
	cbnz x0, secondary_cpu_wait

cpu_setup_el3:
	bl _cpu_init_el3
	bl _stack_init_el3
#	bl _mmu_init_el3
	bl _tpidr_init_el3

	/* Switch to EL1 */
	adr x8, cpu_setup
	msr	elr_el3, x8
	ldr x8, =(SPSR_MODE_EL1T | SPSR_DAIF_MASK)
	msr spsr_el3, x8
	mrs x1, tpidr_el3 /* rctx */
	ldr x2, =SMC_SGI_ID
	eret

/*
 * Setup EL3 Stack
 */
_stack_init_el3:
	mov x1, #(BUFFER_SIZE)
	adr_l x2, __el3_buffer
	add	x2, x2, x1
	madd x2, x0, x1, x2
	mov sp, x2
	ret

/*
 * setup tpidr_el3 to store s/ns world ctx pointer
 */
_tpidr_init_el3:
	mov x1, #(BUFFER_SIZE)
	adr_l x2, __el3_buffer
	madd x2, x0, x1, x2
	msr tpidr_el3, x2
	isb
	ret

_cpu_init_el3:
	/*
	 * SCTLR
	 * disable MMU/cache/BP/AlignCheck,  use Little EE
	 * [6] Non-aligned access for several instructions
	 */
	mov x1, #(1 << 6)
	msr sctlr_el3, x1
	isb

	/* Set Monitor VBAR */
	adr_l x1, monitor_vectors
	msr vbar_el3, x1
	isb

	/*
	 * Set SCR
	 * 02: Set the FIQ bit so as to route FIQs to monitor mode
	 * 08: HVC instructions are enabled at EL3, EL2, and EL1
	 * 09: Secure state instruction fetches from Non-secure memory are not permitted
	 * 10: low EL is aarch64
	 * 11: Secure EL1 access Counter-timer Physical Secure timer register not to be trapped.
	 * 26: Enable Accesses at EL1 and EL2 to GCR_EL1, RGSR_EL1, TFSR_EL1, TFSR_EL2 or TFSRE0_EL1
	 */
	ldr x1, =((1 << 2) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 26))
	msr scr_el3, x1
	isb

	/* Set the GenericTimer Counter FRQ */
	adr_l x1, __cntfrq
	ldr x1, [x1]
	msr cntfrq_el0, x1
	isb

	/*
	 * trap nothing to el3
	 */
	ldr x1, =(1 << 8)
	msr cptr_el3, x1
	isb

	/*
	 * Set MDCR - Disable Secure self-hosted debugs
	 * SDD (1 << 16), SPD32 [15:14]
	 */
	ldr x1, =((1 << 16) | (2 << 14))
	msr mdcr_el3, x1
	isb

	/*
	 * Set CPUECTLR.SMPEN
	 * SMP enables coherent requests to the processors
	 */
	smp_enable

	mov x25, lr
	adr lr, 2f

	/*
	 * invalidate tlb, icache and dcache
	 */
	cbz  x0, invalidate_cache_all
	cbnz x0, invalidate_cache_l1

	/*
	 * SCTLR -- enable I/D caches for EL3
	 */
2:	mrs x1, sctlr_el3
	orr x1, x1, #(1 << 2)
	orr x1, x1, #(1 << 12)
	msr sctlr_el3, x1
	isb

	/*
	 * GIC SRE is enabled for EL3 (bit0)
	 * icc_sre_el2 / icc_sre_el1 access is enabled (bit3)
	 * FIQ(bit1)/IRQ(bit2) bypass is disabled
	 */
	ldr x1, =((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3))
	msr icc_sre_el3, x1
	isb

	br x25


/* x6 holds the flags */
__mmu_enable_el3:
	dsb ishst
	mrs x7, sctlr_el3
	orr x7, x7, x6
	msr sctlr_el3, x7
	isb
	ret

__mmu_early_init_el3:
	mov x25, lr

	/*
	 *	MT_NORMAL                   0
	 *	MT_DEVICE_nGnRnE            1
	 *
	 *	MAIR_ATTR_DEVICE_nGnRnE     (0x00UL)
	 *	MAIR_ATTR_NORMAL            (0xffUL)
	 */
	ldr x6, =MAIR_VAL
	msr mair_el3, x6
	isb

	/* set TTBR0 */
	adr_l x5, __kern_pgtbl_el3
	msr ttbr0_el3, x5
	isb

	/* set TCR, TTBR0 has 512GB (depends on VA_BITS) address space */
	ldr x6, =TCR_VAL_EL3
	msr tcr_el3, x6
	isb

	/* The gap of virt_to_phys is 0 */
	adr_l x8, _start /* Get the physical address */
	/* x8 hold the phys PMD index of _start */
	mov x8, x8, lsr #(SECTION_SHIFT)

	/* x13 holds the PTD flags */
	adr_l x11, __kern_ptd_el3
	ldr x13, =(PTD_TYPE_TABLE)
	orr x13, x13, x11

	/* x14 hold the PMD flags */
	ldr x14, =(SECTION_MAP_FLAGS)

	/* Get the virtual address, virtual==phys */
	adr_l x12, _start
	mov x12, x12, lsr #(SECTION_SHIFT) /* PMD index - start */

	/* Map the whole kernel virtual memory space */
	mov x7, x12, lsr #(PTD_SHIFT - SECTION_SHIFT)
	str	x13, [x5, x7, lsl #3] /* PTD */

1:	orr x7, x14, x8, lsl #(SECTION_SHIFT)
	and x10, x12, #(PMDS_PER_PTD - 1)
	str	x7, [x11, x10, lsl #3] /* PMD */
	add x8, x8, #1
	add x12, x12, #1
	cmp	x10, #(PMDS_PER_PTD - 1) /* within a PTD */
	blo	1b

	/* set SCTLR to turn on the MMU, without WXN */
	ldr x6, =(SCTLR_VAL_EL3)
	bl __mmu_enable_el3
	br x25

__mmu_secondary_init_el3:
	mov x25, lr

	/*
	 *	MT_NORMAL                   0
	 *	MT_DEVICE_nGnRnE            1
	 *
	 *	MAIR_ATTR_DEVICE_nGnRnE     (0x00UL)
	 *	MAIR_ATTR_NORMAL            (0xffUL)
	 */
	ldr x6, =MAIR_VAL
	msr mair_el3, x6
	isb

	/* set TCR, TTBR0 has 512GB (depends on VA_BITS) address space */
	ldr x6, =TCR_VAL_EL3
	msr tcr_el3, x6

	/* set TTBR0 */
	adr_l x5, __kern_pgtbl_el3
	msr ttbr0_el3, x5
	isb

	/* set SCTLR to turn on the MMU, without WXN */
	ldr x6, =(SCTLR_VAL_EL3)
	bl __mmu_enable_el3
	br x25

_mmu_init_el3:
	/* only CPU-0 setups the early pgtbl at the first time,
	secondary-cores or secondary-times calls __mmu_secondary_init_el3 */

	cbnz x0, __mmu_secondary_init_el3
	b __mmu_early_init_el3

/* the lr / x0 are saved before this func */
.type save_percpu_ctx, %function
save_percpu_ctx:
	# struct thread_ctx_el3

	/* save x1-x28 */
	stp	x1, x2, [x0, #16 * 1]
	stp	x3, x4, [x0, #16 * 2]
	stp	x5, x6, [x0, #16 * 3]
	stp	x7, x8, [x0, #16 * 4]
	stp	x9, x10, [x0, #16 * 5]
	stp	x11, x12, [x0, #16 * 6]
	stp	x13, x14, [x0, #16 * 7]
	stp	x15, x16, [x0, #16 * 8]
	stp	x17, x18, [x0, #16 * 9]
	stp	x19, x20, [x0, #16 * 10]
	stp	x21, x22, [x0, #16 * 11]
	stp	x23, x24, [x0, #16 * 12]
	stp	x25, x26, [x0, #16 * 13]
	stp	x27, x28, [x0, #16 * 14]

	mrs x10, contextidr_el1

	/* save x29/contextidr_el1 */
	stp	x29, x10, [x0, #16 * 15]

	mrs x11, tpidr_el0
	mrs x12, ttbr0_el1
	mrs x13, sp_el0
	mrs x14, spsr_el3

	/* save tpidr_el0 and ttbr0_el1 */
	stp	x11, x12, [x0, #16 * 16]
	/* save sp and spsr */
	stp	x13, x14, [x0, #16 * 17]

	mrs x11, tpidrro_el0
	mrs	x12, elr_el3
	mrs x13, spsr_el1
	mrs	x14, elr_el1

	/* save tpidrro_el0 and pc */
	stp	x11, x12, [x0, #16 * 18]
	/* save spsr_el1 and elr_el1 */
	stp	x13, x14, [x0, #16 * 19]

	/* save s/ns world per-cpu registers */
	mrs x10, vbar_el1
	mrs	x11, ttbr1_el1
	mrs x12, tcr_el1
	mrs	x13, mair_el1
	mrs	x14, sctlr_el1
	mrs x15, sp_el1
	stp	x10, x11, [x0, #16 * 20]
	stp	x12, x13, [x0, #16 * 21]
	stp	x14, x15, [x0, #16 * 22]

	mrs x10, esr_el1
	mrs	x11, far_el1
	mrs x12, cpacr_el1
	mrs	x13, csselr_el1
	mrs	x14, par_el1
	mrs x15, tpidr_el1
	stp	x10, x11, [x0, #16 * 23]
	stp	x12, x13, [x0, #16 * 24]
	stp	x14, x15, [x0, #16 * 25]

	mrs x10, cntkctl_el1
	mrs	x11, cntp_ctl_el0
	mrs x12, cntp_cval_el0
	mrs	x13, cntv_ctl_el0
	mrs	x14, cntv_cval_el0
	mrs x15, actlr_el1
	stp	x10, x11, [x0, #16 * 26]
	stp	x12, x13, [x0, #16 * 27]
	stp	x14, x15, [x0, #16 * 28]

	mrs x10, afsr0_el1
	mrs x11, afsr1_el1
	stp	x10, x11, [x0, #16 * 29]

	/* FP/SIMD registers */
	mrs	x10, fpsr
	mrs	x11, fpcr
	stp	x10, x11, [x0, #16 * 30]

	stp	q0, q1, [x0, #16 * 31]
	stp	q2, q3, [x0, #16 * 33]
	stp	q4, q5, [x0, #16 * 35]
	stp	q6, q7, [x0, #16 * 37]
	stp	q8, q9, [x0, #16 * 39]
	stp	q10, q11, [x0, #16 * 41]
	stp	q12, q13, [x0, #16 * 43]
	stp	q14, q15, [x0, #16 * 45]
	stp	q16, q17, [x0, #16 * 47]
	stp	q18, q19, [x0, #16 * 49]
	stp	q20, q21, [x0, #16 * 51]
	stp	q22, q23, [x0, #16 * 53]
	stp	q24, q25, [x0, #16 * 55]
	stp	q26, q27, [x0, #16 * 57]
	stp	q28, q29, [x0, #16 * 59]
	stp	q30, q31, [x0, #16 * 61]

	ret
.size save_percpu_ctx, .-save_percpu_ctx

/* the lr / x0 are restored outside this func */
.type restore_percpu_ctx, %function
restore_percpu_ctx:

	# struct thread_ctx_el3

	/* restore the x29 and contextidr_el1 */
	ldp	x29, x9, [x0, #16 * 15]
	msr contextidr_el1, x9

	/* restore tpidr_el0 and ttbr0_el1 */
	ldp	x10, x11, [x0, #16 * 16]
	msr tpidr_el0, x10
	msr ttbr0_el1, x11

	/* restore sp and spsr */
	ldp	x12, x13, [x0, #16 * 17]
	msr sp_el0, x12
	msr spsr_el3, x13

	/* restore tpidrro_el0 and pc */
	ldp	x14, x15, [x0, #16 * 18]
	msr tpidrro_el0, x14
	msr elr_el3, x15

	/* restore spsr_el1 and elr_el1 */
	ldp	x12, x13, [x0, #16 * 19]
	msr spsr_el1, x12
	msr elr_el1, x13

	/* save s/ns world per-cpu registers */
	ldp	x10, x11, [x0, #16 * 20]
	ldp	x12, x13, [x0, #16 * 21]
	ldp	x14, x15, [x0, #16 * 22]
	msr vbar_el1, x10
	msr	ttbr1_el1, x11
	msr tcr_el1, x12
	msr	mair_el1, x13
	msr	sctlr_el1, x14
	msr sp_el1, x15

	ldp	x10, x11, [x0, #16 * 23]
	ldp	x12, x13, [x0, #16 * 24]
	ldp	x14, x15, [x0, #16 * 25]
	msr esr_el1, x10
	msr	far_el1, x11
	msr cpacr_el1, x12
	msr	csselr_el1, x13
	msr	par_el1, x14
	msr tpidr_el1, x15

	ldp	x10, x11, [x0, #16 * 26]
	ldp	x12, x13, [x0, #16 * 27]
	ldp	x14, x15, [x0, #16 * 28]
	msr cntkctl_el1, x10
	msr	cntp_ctl_el0, x11
	msr cntp_cval_el0, x12
	msr	cntv_ctl_el0, x13
	msr	cntv_cval_el0, x14
	msr actlr_el1, x15

	ldp	x11, x12, [x0, #16 * 29]
	msr	afsr0_el1, x11
	msr	afsr1_el1, x12

	/* restore FP/SIMD state/ctrl */
	ldp	x14, x15, [x0, #16 * 30]
	msr	fpsr, x14
	msr	fpcr, x15
	isb

	/* restore the x1 ~ x28 */
	ldp	x1, x2, [x0, #16 * 1]
	ldp	x3, x4, [x0, #16 * 2]
	ldp	x5, x6, [x0, #16 * 3]
	ldp	x7, x8, [x0, #16 * 4]
	ldp	x9, x10, [x0, #16 * 5]
	ldp	x11, x12, [x0, #16 * 6]
	ldp	x13, x14, [x0, #16 * 7]
	ldp	x15, x16, [x0, #16 * 8]
	ldp	x17, x18, [x0, #16 * 9]
	ldp	x19, x20, [x0, #16 * 10]
	ldp	x21, x22, [x0, #16 * 11]
	ldp	x23, x24, [x0, #16 * 12]
	ldp	x25, x26, [x0, #16 * 13]
	ldp	x27, x28, [x0, #16 * 14]

	/* restore FP/SIMD registers */
	ldp	q0, q1, [x0, #16 * 31]
	ldp	q2, q3, [x0, #16 * 33]
	ldp	q4, q5, [x0, #16 * 35]
	ldp	q6, q7, [x0, #16 * 37]
	ldp	q8, q9, [x0, #16 * 39]
	ldp	q10, q11, [x0, #16 * 41]
	ldp	q12, q13, [x0, #16 * 43]
	ldp	q14, q15, [x0, #16 * 45]
	ldp	q16, q17, [x0, #16 * 47]
	ldp	q18, q19, [x0, #16 * 49]
	ldp	q20, q21, [x0, #16 * 51]
	ldp	q22, q23, [x0, #16 * 53]
	ldp	q24, q25, [x0, #16 * 55]
	ldp	q26, q27, [x0, #16 * 57]
	ldp	q28, q29, [x0, #16 * 59]
	ldp	q30, q31, [x0, #16 * 61]

	ret
.size restore_percpu_ctx, .-restore_percpu_ctx

/*
 * TEE2Monitor calls:
 * x0 == 1: set GeneriTimer Counter FRQ
 * x0 == 2: secondary_cpu_restart
 */
smc_handling_for_s:
	cmp x0, #1
	beq set_cntfrq
	cmp x0, #2
	beq secondary_cpu_restart
	b .
set_cntfrq:
	/* Set the GenericTimer Counter FRQ @ x1 */
	msr cntfrq_el0, x1
	/* save it to global for secondary CPUs */
	adr_l x15, __cntfrq
	str x1, [x15]
	eret

/*
 * x0 == 0: resume NS
 * x0 == others: TEE2Monitor calls
 */
smc_called_from_s:
	cbz x0, 1f
	b smc_handling_for_s
1:	save_s_context
	set_nsbit x15
	restore_ns_context
	clrex
	eret

smc_called_from_ns:
	save_ns_context
	unset_nsbit x15
/* trigger a IPI call for notifying S world -------- start */
	/* fill the SGIR_VAL */
	ldr x13, =(SMC_SGI_ID) /* GIC SGI 15 */
	lsl x13, x13, #24

	ldr x9, =0xff
	mrs x14, mpidr_el1
	and x15, x9, x14
	ldr x10, =1
	lsl x15, x10, x15
	orr x15, x13, x15

	and x10, x9, x14, lsr #32
	and x11, x9, x14, lsr #16
	and x12, x9, x14, lsr #8

	orr x15, x15, x10, lsl #48
	orr x15, x15, x11, lsl #32
	orr x15, x15, x12, lsl #16

	/* icc_write_sgi1r */
	dsb ishst
	msr S3_0_C12_C11_5, x15
/* trigger a IPI call for notifying S world ---------- end */
	restore_s_context
	clrex
	eret

fiq_called_from_s:
	save_s_context
	set_nsbit x15
	restore_ns_context
	clrex
	eret

.align 11
monitor_vectors:
/* Current EL with SP0 */
	b .
	.align 7
	b .
	.align 7
	b .
	.align 7
	b .
	.align 7
/* Current EL with SPx */
monitor_synchronous_el3:
	b .
	.align 7
monitor_irq_el3:
	b .
	.align 7
monitor_fiq_el3:
	b .
	.align 7
monitor_serror_el3:
	b .
	.align 7
/* Lower EL using AArch64 */
monitor_synchronous:
	is_nsbit_unset x15
	beq smc_called_from_s
	bne smc_called_from_ns
	.align 7
monitor_irq:
	b .
	.align 7
monitor_fiq:
	is_nsbit_unset x15
	beq fiq_called_from_s
	save_ns_context
	unset_nsbit x15
	restore_s_context
	clrex
	eret
	.align 7

monitor_serror:
	b .
	.align 7
/* Lower EL using AArch32 */
	b .
	.align 7
	b .
	.align 7
	b .
	.align 7
	b .
	.align 7
	b .

	.data
	.align	3
__cntfrq:
	.dword 1000000000 /* Default 1 GHz */

	.bss
	.align 6
__el3_buffer:
	.fill BUFFER_SIZE * CONFIG_NR_CPUS, 1, 0

	.data
	.align PAGE_SHIFT
__kern_pgtbl_el3:
	.fill PTDS_PER_PT, BYTES_PER_LONG, 0

	.align PAGE_SHIFT
__kern_ptd_el3:
	.fill PMDS_PER_PTD, BYTES_PER_LONG, 0
