/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Definitions related to MIPS32 based CPU
 */

#ifndef _CPU_H
#define _CPU_H

#include <defs.h>
#include <stdbool.h>

#include <generated/autoconf.h>

#define BYTES_PER_INT		(4)
#define BYTES_PER_LONG		(4)
#define BITS_PER_LONG		(BYTES_PER_LONG * 8)
#define BITS_PER_INT		(BYTES_PER_INT * 8)

#define BIT_SHIFT_PER_INT		(5)
#define BIT_MASK_PER_INT		(BITS_PER_INT - 1)
#define BIT_SHIFT_PER_LONG      (5)
#define BIT_MASK_PER_LONG       (BITS_PER_LONG - 1)

#define STACK_SIZE			UL(4096)

#define KSEG0				UL(0x80000000)
#define KSEG1				UL(0xA0000000)
#define KSEG2				UL(0xC0000000)

#define KSEG0_REGION(x)	(((unsigned long)(x) >= KSEG0) && \
		((unsigned long)(x) < KSEG1))
#define KSEG1_REGION(x)	(((unsigned long)(x) >= KSEG1) && \
		((unsigned long)(x) < KSEG2))

#define C0_INDEX         $0    /* Index into TLB Array */
#define C0_RANDOM        $1    /* Random Index into TLB Array */
#define C0_TLBLO0        $2    /* physical (output) side of a TLB entry low */
#define C0_TLBLO1        $3    /* physical (output) side of a TLB entry low */
#define C0_CONTEXT       $4
#define C0_PAGEMASK      $5
#define C0_WIRED         $6
#define C0_HWRENA        $7
#define C0_BADVADDR      $8     /* Bad Virtual Address */
#define C0_COUNT         $9     /* Timer Counter */
#define C0_TLBHI         $10    /* High-order Portion of TLB Entry */
#define C0_COMPARE       $11    /* Timer Compare */
#define C0_STATUS        $12    /* Status Register */
#define C0_CAUSE         $13    /* Cause Register */
#define C0_EPC           $14    /* Exception Program Counter */
#define C0_PRID          $15    /* Processor Revision Identifire */
#define C0_EBASE         $15, 1 /* Exception base */
#define C0_CONFIG        $16    /* Device Configuration Information. Read ONLY    */
#define C0_CALG          $17    /* Cache Attributes */
#define C0_WATCHLO       $18    /* Intruction breakpoint VAddr */
#define C0_WATCHHI       $19    /* Data breakpoint VAddr */
#define C0_XCONTEXT      $20
#define C0_FRAMEMASK     $21
#define C0_DIAGNOSTIC    $22
#define C0_DEBUG         $23    /* Debug Register for DSU */
#define C0_DEPC          $24    /* Debug Exception PC for DSU */
#define C0_PERFORMANCE   $25
#define C0_ECC           $26    /* S-cache ECC and Primary Parity */
#define C0_CACHEERR      $27    /* Cache Error and Status register */
#define C0_TAGLO         $28
#define C0_TAGHI         $29
#define C0_ERROREPC      $30    /* Error Exception Program Counter */
#define C0_DESAVE        $31    /* Debug Save Register for DSU */

#define STAT_USER		(UL(1) << 4)
#define STAT_ERL		(UL(1) << 2)
#define STAT_EXL		(UL(1) << 1)
#define STAT_IE			(UL(1) << 0)
#define STAT_KU_MASK	(UL(0x18))
#define STAT_MASK		(UL(0x1F))

#define REG_STR(x) #x

#define read_cp0_register(reg) ({				\
	long __v = 0;								\
	asm volatile(								\
		"mfc0 %0,"REG_STR(reg)					\
		: "=r" (__v) : : "memory", "cc");		\
	__v;										})

#define read_cp0_register_ex(reg, ex) ({		\
	long __v = 0;								\
	asm volatile(								\
		"mfc0 %0,"REG_STR(reg)","REG_STR(ex)	\
		: "=r" (__v) : : "memory", "cc");		\
	__v;										})

#define write_cp0_register(reg, v) ({			\
	asm volatile(								\
		"mtc0 %0,"REG_STR(reg)"\n"				\
		"ehb"									\
		: : "r" (v) : "memory", "cc");			})

#define write_cp0_register_ex(reg, ex, v) ({	\
	asm volatile(								\
		"mtc0 %0,"REG_STR(reg)","REG_STR(ex)"\n"\
		"ehb"									\
		: : "r" (v) : "memory", "cc");			})


#ifndef __ASSEMBLY__
#include <limits.h>
#include <sys/cdefs.h>
#include <percpu.h>

static __always_inline struct thread *get_current(void)
{
	struct thread *curr = NULL;

/* rdhwr not work @ part of the qemu malta boards!!
 *	asm(".set push\n"
		".set noreorder\n"
		".set mips32r2\n"
		"rdhwr %0, $29\n"
		".set pop\n"
		: "=r" (curr));
*/

	curr = thiscpu->current_thread;
	return curr;
}

static __always_inline void set_current(void *curr)
{
	thiscpu->current_thread = curr;
}

static __always_inline void local_irq_disable(void)
{
	asm volatile(
		".set push\n"
		".set noreorder\n"
		"di\n"
		"ehb\n"
		".set pop\n"
		: : : "memory", "cc");
}

static __always_inline void local_irq_enable(void)
{
	asm volatile(
		".set push\n"
		".set noreorder\n"
		"ei\n"
		"ehb\n"
		".set pop\n"
		: : : "memory", "cc");
}

static __always_inline void local_irq_restore(unsigned long flags)
{
	asm volatile(
		".set push\n"
		".set noreorder\n"
		"beqz %0, 1f\n"
		"nop\n"
		"ei\n"
		"1: ehb\n"
		".set pop\n"
		: : "r" (flags) : "memory", "cc");
}

static __always_inline long irqs_disabled(void)
{
	unsigned long flags = 0;

	asm volatile(
		".set push\n"
		".set noreorder\n"
		"mfc0 %0, $12\n"
		".set pop\n"
		: "=r" (flags) : : "memory", "cc");

	return !(flags & STAT_IE);
}

static __always_inline unsigned long arch_irq_save(void)
{
	unsigned long flags = 0;

	asm volatile(
		".set push\n"
		".set noreorder\n"
		"di %0\n"
		"andi %0, 1\n"
		"ehb\n"
		".set pop\n"
		: "=r" (flags) : : "memory", "cc");

	return flags;
}

#define local_irq_save(flags)									\
	do {														\
		BUILD_ERROR_ON(!TYPE_COMPATIBLE(flags, unsigned long)); \
		flags = arch_irq_save();								\
	} while (0)

#endif
#endif
