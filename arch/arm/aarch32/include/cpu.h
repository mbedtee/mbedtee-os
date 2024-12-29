/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Definitions related to AArch32@ARMV7-A CPU
 */

#ifndef _CPU_H
#define _CPU_H

#include <defs.h>
#include <stdbool.h>
#include <generated/autoconf.h>

#define BYTES_PER_INT       (4)
#define BYTES_PER_LONG      (4)
#define BITS_PER_LONG       (BYTES_PER_LONG * 8)
#define BITS_PER_INT        (BYTES_PER_INT * 8)

#define BIT_SHIFT_PER_INT   (5)
#define BIT_MASK_PER_INT    (BITS_PER_INT - 1)
#define BIT_SHIFT_PER_LONG  (5)
#define BIT_MASK_PER_LONG   (BITS_PER_LONG - 1)

#define STACK_SIZE          UL(4096)

#define USR_MODE            UL(0x10)
#define FIQ_MODE            UL(0x11)
#define IRQ_MODE            UL(0x12)
#define SVC_MODE            UL(0x13)
#define MON_MODE            UL(0x16)
#define ABT_MODE            UL(0x17)
#define UND_MODE            UL(0x1B)
#define SYS_MODE            UL(0x1F)

#define ASYNC_ABT_MASK      (UL(1) << 8)
#define IRQ_MASK            (UL(1) << 7)
#define FIQ_MASK            (UL(1) << 6)

#define VALID_CPUID(x)      ((unsigned int)(x) < CONFIG_NR_CPUS)

#define MPIDR_BITMASK       UL(0x00ffffff)

#define MPIDR_AFFINITY_MASK UL(0xFF)

#ifndef __ASSEMBLY__
#include <limits.h>
#include <sys/cdefs.h>

static __always_inline struct thread *get_current(void)
{
	struct thread *curr = NULL;

	asm("mrc p15, 0, %0, c13, c0, 3" : "=r" (curr));

	return curr;
}

static __always_inline void set_current(void *curr)
{
	asm volatile("mcr p15, 0, %0, c13, c0, 3" : : "r" (curr) : "memory", "cc");
}

static __always_inline void local_irq_restore(unsigned long flags)
{
	asm volatile("msr cpsr_c, %0" : : "r" (flags) : "memory", "cc");
}

static __always_inline void local_irq_disable(void)
{
	asm volatile("cpsid aif" : : : "memory", "cc");
}

static __always_inline void local_irq_enable(void)
{
#ifdef CONFIG_IRQ_FORWARD
	asm volatile("cpsie aif" : : : "memory", "cc");
#else
	asm volatile("cpsie af" : : : "memory", "cc");
#endif
}

static __always_inline long irqs_disabled(void)
{
	unsigned long flags = 0;

	asm volatile("mrs %0, cpsr" : "=r" (flags) : : "memory", "cc");

	return flags & FIQ_MASK;
}

static __always_inline unsigned long arch_irq_save(void)
{
	unsigned long flags = 0;

	asm volatile("mrs %0, cpsr\n"
				 "cpsid aif" : "=r" (flags) : : "memory", "cc");

	return flags;
}

static inline unsigned long smc_call(
	unsigned long arg0, unsigned long arg1,
	unsigned long arg2, unsigned long arg3)
{
	unsigned long ret = 0;

	register long r0 asm ("r0") = arg0;
	register long r1 asm ("r1") = arg1;
	register long r2 asm ("r2") = arg2;
	register long r3 asm ("r3") = arg3;

	asm volatile(".arch_extension sec\n"
				"smc #0" : "=r" (ret)
				: "r" (r0), "r" (r1), "r" (r2), "r" (r3)
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
