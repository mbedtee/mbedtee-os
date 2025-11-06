/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Definitions related to AArch64 CPU
 */

#ifndef _CPU_H
#define _CPU_H

#include <defs.h>
#include <stdbool.h>
#include <generated/autoconf.h>

#define BYTES_PER_INT		(4)
#define BYTES_PER_LONG		(8)
#define BITS_PER_LONG		(BYTES_PER_LONG * 8)
#define BITS_PER_INT		(BYTES_PER_INT * 8)

#define BIT_SHIFT_PER_INT	(5)
#define BIT_MASK_PER_INT	(BITS_PER_INT - 1)
#define BIT_SHIFT_PER_LONG	(6)
#define BIT_MASK_PER_LONG	(BITS_PER_LONG - 1)

#define STACK_SIZE			UL(8192)

#define SPSR_MODE_EL0T		(0) /* use SP_EL0 for Exception level EL0 */
#define SPSR_MODE_EL1T		(4) /* use SP_EL0 for Exception level EL1 */
#define SPSR_MODE_EL1H		(5) /* use SP_EL1 for Exception level EL1 */
#define SPSR_MODE_EL2T		(8) /* use SP_EL0 for Exception level EL2 */
#define SPSR_MODE_EL2H		(9) /* use SP_EL2 for Exception level EL2 */
#define SPSR_DEBUG_MASK		(1 << 9)
#define SPSR_ASYNC_MASK		(1 << 8)
#define SPSR_IRQ_MASK		(1 << 7)
#define SPSR_FIQ_MASK		(1 << 6)
#define SPSR_DAIF_MASK		(SPSR_DEBUG_MASK | SPSR_ASYNC_MASK | \
							SPSR_IRQ_MASK | SPSR_FIQ_MASK)

#define MPIDR_AFFINITY_MASK		UL(0xFF)
#define MPIDR_AFFINITY_0(mpidr)	(mpidr & MPIDR_AFFINITY_MASK)
#define MPIDR_AFFINITY_1(mpidr)	((mpidr >> 8) & MPIDR_AFFINITY_MASK)
#define MPIDR_AFFINITY_2(mpidr)	((mpidr >> 16) & MPIDR_AFFINITY_MASK)
#define MPIDR_AFFINITY_3(mpidr)	((mpidr >> 32) & MPIDR_AFFINITY_MASK)
#define MPIDR_BITMASK			UL(0xff00ffffff)

#ifndef __ASSEMBLY__
#include <limits.h>
#include <sys/cdefs.h>

#define read_system_reg(reg) ({				\
	unsigned long __v = 0;					\
	asm volatile (							\
		 "mrs %0,"#reg						\
		 : "=r" (__v) : : "memory", "cc");	\
	__v;									\
})

#define write_system_reg(reg, v) ({			\
	unsigned long __v = (long)(v);			\
	asm volatile (							\
		"msr "#reg", %0\n"					\
		"isb"								\
		: : "r" (__v) : "memory", "cc");	\
})

#define write_system_reg_imm(reg, imm) ({	\
	asm volatile (							\
		"msr "#reg", "#imm"\n"				\
		"isb"								\
		: : : "memory", "cc");				\
})

static __always_inline struct thread *get_current(void)
{
	struct thread *curr = NULL;

	asm("mrs %0, tpidrro_el0" : "=r" (curr));

	return curr;
}

static __always_inline void set_current(void *curr)
{
	write_system_reg(tpidrro_el0, curr);
}

static __always_inline bool cpu_has_security_extn(void)
{
	unsigned long id_aa64pfr0_el1 = 0;

	id_aa64pfr0_el1 = read_system_reg(id_aa64pfr0_el1);

	return ((id_aa64pfr0_el1 >> 12) & 0xf) ? true : false;
}

static __always_inline bool is_security_extn_ena(void)
{
	bool gic_has_security_extn(void);

	return cpu_has_security_extn() && gic_has_security_extn();
}

static __always_inline void local_irq_restore(unsigned long flags)
{
	write_system_reg(daif, flags);
}

static __always_inline void local_irq_disable(void)
{
	write_system_reg_imm(daifset, 15);
}

static __always_inline void local_irq_enable(void)
{
	write_system_reg_imm(daifclr, 3);
}

static __always_inline long irqs_disabled(void)
{
	unsigned long flags = read_system_reg(daif);

	return flags & SPSR_IRQ_MASK;
}

static __always_inline unsigned long arch_irq_save(void)
{
	unsigned long flags = read_system_reg(daif);

	write_system_reg_imm(daifset, 15);

	return flags;
}

static inline unsigned long smc_call(
	unsigned long arg0, unsigned long arg1,
	unsigned long arg2, unsigned long arg3)
{
	unsigned long ret = 0;

	register long x0 asm ("x0") = arg0;
	register long x1 asm ("x1") = arg1;
	register long x2 asm ("x2") = arg2;
	register long x3 asm ("x3") = arg3;

	asm volatile("smc #0" : "=r" (ret)
				: "r" (x0), "r" (x1), "r" (x2), "r" (x3)
				: "memory", "cc");

	return ret;
}

#define local_irq_save(flags)									\
	do {														\
		BUILD_ERROR_ON(!TYPE_COMPATIBLE(flags, unsigned long)); \
		flags = arch_irq_save();								\
	} while (0)

#endif
#endif
