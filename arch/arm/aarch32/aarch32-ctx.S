/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * save/restore AArch32@ARMV7-A based exception ctx
 */

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
	add r12, r12, #(BYTES_PER_LONG * 2)

	bx lr
FUNC_END save_thread_ctx

/*
 *	save context for per thread @ r0
 *	r0 - points to thread_ctx struct
 */
FUNC_START restore_thread_ctx
	# struct thread_ctx
	push {lr}
	add r0, r0, #(THREAD_CTX_SIZE - BYTES_PER_LONG)

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
 *	restore context for per CPU @ r12
 *	r12 - points to register context
 */
FUNC_START save_precpu_ctx
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

	/* save undefine mode spsr/sp/lr */
	cps #(UND_MODE)
	mrs r11, spsr
	stmia r12!, {r11, sp, lr}

	/* switch back to original monitor mode */
	cps #(MON_MODE)
	bx lr
FUNC_END save_precpu_ctx

/*
 *	restore context for per CPU @ r12
 *	r12 - core context pointer
 *
 *  always been called from monitor mode
 */
FUNC_START restore_precpu_ctx
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

	/* restore undefine mode spsr/sp/lr */
	cps #(UND_MODE)
	ldmia r12!, {r11, sp, lr}
	msr	spsr_cxsf, r11

	/* switch back to original monitor mode */
	cps #(MON_MODE)
	bx lr
FUNC_END restore_precpu_ctx
