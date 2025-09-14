/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * save/restore AArch32@ARMV7-A based exception ctx
 */
#include "ctx.h"
#include "aarch32-ctx.h"

/*
 *	save context for per thread @ r12
 *	r12 - points to thread_ctx struct
 */
FUNC_START save_thread_ctx
	# struct thread_ctx
	/* save the sys/user mode's r0-r11 */
	stmia r12!, {r0 - r11}
	/* pop the original r12 and lr */
	pop	{r0, r1}
	/* save original r12 */
	stmia r12!, {r0}

	mrs r2, spsr

	/* read the tpidrurw / tpidruro / ttbr0 / context-id */
	mrc p15, 0, r8,  c13, c0, 2 /* tpidrurw */
	mrc p15, 0, r9,  c13, c0, 3 /* tpidruro */
	mrc p15, 0, r10, c2,  c0, 0 /* ttbr0 */
	mrc p15, 0, r11, c13, c0, 1 /* context-id */

	/* <<<<<<<<<<<<<< patch FIQ not to be masked issue >>>>>>>>>>>>>> */
	/*
	 * save svc/irq/abort mode spsr/lr
	 * in case of FIQ may happen at the beginning of
	 * the "exception_vectors" execution,
	 * FIQ occurs before the handlers call "cpsid aif".
	 */
	mrc p15, 0, r3, c1, c1, 0
	tst r3, #(SCR_NS_BIT)
	bne from_ns

	and r3, r2, #(SYS_MODE)

	cmp r3, #(USR_MODE)
	beq from_sys_user
	cmp r3, #(SYS_MODE)
	beq from_sys_user

	mrs r4, cpsr

 	cmp r3, #(SVC_MODE)
	msreq cpsr_c, #(SVC_MODE | IRQ_MASK | FIQ_MASK)
	beq from_svc_irq_abt

	cmp r3, #(IRQ_MODE)
	msreq cpsr_c, #(IRQ_MODE | IRQ_MASK | FIQ_MASK)
	beq from_svc_irq_abt

	cmp r3, #(UND_MODE)
	msreq cpsr_c, #(UND_MODE | IRQ_MASK | FIQ_MASK)
	beq from_svc_irq_abt

	msr cpsr_c, #(ABT_MODE | IRQ_MASK | FIQ_MASK)
	sub lr, lr, #(BYTES_PER_LONG)

from_svc_irq_abt:
 	mrs r2, spsr
	sub r1, lr, #(BYTES_PER_LONG)
	msr cpsr_c, r4
	isb
	/* <<<<<<<<<<<<<< patch FIQ not to be masked issue >>>>>>>>>>>>>> */

from_ns:
from_sys_user:
	/* save the pc */
	stmia r12!, {r1}
	/* save the spsr */
	stmia r12!, {r2}
	/* save the tpidrurw / tpidruro / ttbr0 / context-id */
	stmia r12!, {r8, r9, r10, r11}
	/* save the sys/user mode's sp and lr */
	stmia r12, {sp, lr}^
	/* advance r12 past sp, lr, padding, and FPU area to end of struct */
	add r12, r12, #(BYTES_PER_LONG * 2 + PADDING_LENGTH + THREAD_CTX_SIZE - GPR_CTX_SIZE)

	bx lr
FUNC_END save_thread_ctx

/*
 *	save context for per thread @ r0
 *	r0 - points to thread_ctx struct
 */
FUNC_START restore_thread_ctx
	# struct thread_ctx
	push {lr}
	/* navigate to sp/lr area within GPR portion */
	add r0, r0, #(GPR_CTX_SIZE - BYTES_PER_LONG - PADDING_LENGTH)

	/* restore the sys/user mode's sp and lr */
	ldmda r0, {sp, lr}^
	sub r0, r0, #(2 * BYTES_PER_LONG)

	/* restore the tpidrurw / tpidruro / ttbr0 / context-id */
	ldmda r0!, {r9, r10, r11, r12}
	mcr p15, 0, r9,  c13, c0, 2 /* tpidrurw */
	mcr p15, 0, r10, c13, c0, 3 /* tpidruro */
	mov r8, #0
	mcr p15, 0, r8,  c13, c0, 1 /* context-id */
	isb
	mcr p15, 0, r11, c2,  c0, 0 /* ttbr0 */
	isb
	mcr p15, 0, r12, c13, c0, 1 /* context-id */
	isb

	/* restore the spsr */
	ldmda r0!, {r1}
	msr spsr_cxsf, r1

	/* restore the pc */
	ldmda r0!, {lr}

	/* restore the sys/user mode's r0-r12 */
	ldmda r0!, {r1-r12}
	ldmda r0, {r0}

	pop {pc}
FUNC_END restore_thread_ctx

/*
 *	save context for per CPU @ r12
 *	r12 - points to register context
 */
FUNC_START save_percpu_ctx
	# struct percpu_ctx
	/* save svc mode spsr/sp/lr */
	cps #(SVC_MODE)
	mrs r11, spsr
	stmia r12!, {r11, sp, lr}

	/* save IRQ mode spsr/sp/lr */
	cps #(IRQ_MODE)
	mrs	r11, spsr
	stmia r12!, {r11, sp, lr}

	/* save abort mode spsr/sp/lr */
	cps #(ABT_MODE)
	mrs	r11, spsr
	stmia r12!, {r11, sp, lr}

	/* save undefined mode spsr/sp/lr */
	cps #(UND_MODE)
	mrs r11, spsr
	stmia r12!, {r11, sp, lr}

	/*
	 * VFP (D0-D31, FPSCR, FPEXC) - always save.
	 *
	 * Physical VFP registers are shared hardware between Secure
	 * and Non-secure worlds. NS (Linux/REE) uses VFP/NEON and
	 * will overwrite them; when S resumes it needs its values
	 * back.
	 */
	mrc p15, 0, r10, c1, c0, 2	/* original CPACR */
	orr r8, r10, #(0x00500000)	/* force cp10/cp11 = 01 (privileged) */
	mcr p15, 0, r8, c1, c0, 2
	isb
	vmrs r11, fpexc			/* CPACR already set to enable the access to FPEXC */
	stmia r12!, {r11}
	orr r9, r11, #(1 << 30)	/* force FPEXC.EN=1 to unlock FPSCR/D-regs */
	vmsr fpexc, r9
	vmrs r11, fpscr
	stmia r12!, {r11}
	vstm_vfp r12
	/* Save original CPACR - NOT banked between S/NS */
	stmia r12!, {r10}

	/* switch back to original monitor mode */
	cps #(MON_MODE)
	bx lr
FUNC_END save_percpu_ctx

/*
 *	restore context for per CPU @ r12
 *	r12 - core context pointer
 *
 *  always been called from monitor mode
 */
FUNC_START restore_percpu_ctx
	# struct percpu_ctx
	/* restore SVC mode spsr/sp/lr */
	cps #(SVC_MODE)
	ldmia r12!, {r11, sp, lr}
	msr spsr_cxsf, r11

	/* restore IRQ mode spsr/sp/lr */
	cps #(IRQ_MODE)
	ldmia r12!, {r11, sp, lr}
	msr	spsr_cxsf, r11

	/* restore abort mode spsr/sp/lr */
	cps #(ABT_MODE)
	ldmia r12!, {r11, sp, lr}
	msr	spsr_cxsf, r11

	/* restore undefined mode spsr/sp/lr */
	cps #(UND_MODE)
	ldmia r12!, {r11, sp, lr}
	msr	spsr_cxsf, r11

	/*
	 * VFP - always restore. NS overwrote the physical
	 * registers; S needs its saved values back.
	 */
	mrc p15, 0, r8, c1, c0, 2	/* current CPACR (may block VFP) */
	orr r8, r8, #(0x00500000)	/* force cp10/cp11 = 01 (privileged) */
	mcr p15, 0, r8, c1, c0, 2
	isb
	ldr r10, [r12, #(PERCPU_CTX_VFP_SIZE)]	/* saved CPACR */
	ldmia r12!, {r11}		/* saved FPEXC */
	orr r9, r11, #(1 << 30)	/* force FPEXC.EN=1 to unlock FPSCR/D-regs */
	vmsr fpexc, r9
	ldmia r12!, {r9}		/* saved FPSCR */
	vmsr fpscr, r9
	vldm_vfp r12
	vmsr fpexc, r11			/* restore original FPEXC */
	/* Restore original CPACR - NOT banked between S/NS */
	mcr p15, 0, r10, c1, c0, 2
	isb

	/* switch back to original monitor mode */
	cps #(MON_MODE)
	bx lr
FUNC_END restore_percpu_ctx

/*
 * save_fpu_ctx(struct thread_ctx *ctx)
 *
 * Save VFP/NEON state (FPSCR, D0-D31) from physical
 * registers to the FPU area of struct thread_ctx.
 */
FUNC_START save_fpu_ctx
	vmrs r1, fpscr
	str r1, [r0, #(GPR_CTX_SIZE)]
	add r1, r0, #(GPR_CTX_SIZE + BYTES_PER_LONG + PADDING_LENGTH)
	vstm_vfp r1
	dsb
	bx lr
FUNC_END save_fpu_ctx

/*
 * restore_fpu_ctx(struct thread_ctx *ctx)
 *
 * Restore VFP/NEON state (FPSCR, D0-D31) from the
 * FPU area of struct thread_ctx to physical registers.
 */
FUNC_START restore_fpu_ctx
	ldr r1, [r0, #(GPR_CTX_SIZE)]
	vmsr fpscr, r1
	add r1, r0, #(GPR_CTX_SIZE + BYTES_PER_LONG + PADDING_LENGTH)
	vldm_vfp r1
	bx lr
FUNC_END restore_fpu_ctx

/*
 * save_fpu_ctx_eager
 *
 * Eagerly save FPU state when entering kernel.
 * If fpu_owner is set, save D0-D31/FPSCR to owner->sched_ctx,
 * clear fpu_owner, and enable the user VFP trap.
 *
 * Called from save_thread_context macro.
 * save_fpu_ctx only clobbers r0, r1 - r2, r3 are preserved.
 */
FUNC_START save_fpu_ctx_eager
	mrc	p15, 0, r2, c13, c0, 4
	ldr	r1, [r2, #PERCPU_FPU_OWNER]
	cmp	r1, #0
	bxeq	lr
	mov	r3, lr
	ldr	r0, [r1, #THREAD_SCHED_CTX]
	bl	save_fpu_ctx
	mov	r0, #0
	str	r0, [r2, #PERCPU_FPU_OWNER]
	mov	r0, #0x00500000		/* CPACR_VFP_TRAP_USR */
	mcr	p15, 0, r0, c1, c0, 2
	isb
	bx	r3
FUNC_END save_fpu_ctx_eager
