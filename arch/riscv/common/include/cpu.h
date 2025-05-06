/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Definitions related to RISCV32 based CPU
 */

#ifndef _CPU_H
#define _CPU_H

#include <defs.h>
#include <stdbool.h>

#include <generated/autoconf.h>

#define BYTES_PER_INT       (4)
#define BITS_PER_INT        (BYTES_PER_INT * 8)
#define BIT_SHIFT_PER_INT   (5)
#define BIT_MASK_PER_INT    (BITS_PER_INT - 1)

#if defined(CONFIG_64BIT)
#define BYTES_PER_LONG      (8)
#define BITS_PER_LONG       (BYTES_PER_LONG * 8)
#define BIT_SHIFT_PER_LONG  (6)
#define BIT_MASK_PER_LONG   (BITS_PER_LONG - 1)
#define STACK_SIZE          UL(8192)
#else
#define BYTES_PER_LONG      (4)
#define BITS_PER_LONG       (BYTES_PER_LONG * 8)
#define BIT_SHIFT_PER_LONG  (5)
#define BIT_MASK_PER_LONG   (BITS_PER_LONG - 1)
#define STACK_SIZE          UL(4096)
#endif

#if defined(CONFIG_RISCV_S_MODE)

#define CSR_STATUS        sstatus          /* Global status register */
#define CSR_SCRATCH       sscratch         /* Scratch register */
#define CSR_EPC           sepc             /* Exception program counter */
#define CSR_IE            sie              /* Interrupt enable register */
#define CSR_IP            sip              /* Interrupt pending register */
#define CSR_CAUSE         scause           /* Interrupt cause register */
#define CSR_TVAL          stval            /* Trap value register */
#define CSR_TVEC          stvec            /* Trap vector base addr register */

#define CSR_TIME          time
#define CSR_TIMEH         timeh
#define CSR_STIMECMP      stimecmp
#define CSR_STIMECMPH     stimecmph

#define CSR_TOPEI         stopei
#define CSR_ISELECT       siselect
#define CSR_IREG          sireg

#define SR_IE		      (UL(1) << 1)
#define SR_PIE	          (UL(1) << 5)
#define SR_PP		      (UL(1) << 8)

#define IE_TIE            (UL(1) << 5)

#define eret              sret

#else

#define CSR_STATUS        mstatus          /* Global status register */
#define CSR_SCRATCH       mscratch         /* Scratch register */
#define CSR_EPC           mepc             /* Exception program counter */
#define CSR_IE            mie              /* Interrupt enable register */
#define CSR_IP            mip              /* Interrupt pending register */
#define CSR_CAUSE         mcause           /* Interrupt cause register */
#define CSR_TVAL          mtval            /* Trap value register */
#define CSR_TVEC          mtvec            /* Trap vector base addr register */

#define CSR_TOPEI         mtopei
#define CSR_ISELECT       miselect
#define CSR_IREG          mireg

#define SR_IE		      (UL(1) << 3)
#define SR_PIE	          (UL(1) << 7)
#define SR_PP		      (UL(3) << 11)

#define IE_TIE            (UL(1) << 7)

#define eret              mret

#endif

#define SR_SUM	          (UL(1) << 18)
#define SR_MXR	          (UL(1) << 19)
#define SR_SD	          (UL(1) << 31)
#define SR_FS	          (UL(3) << 13)
#define SR_FS_OFF	      (UL(0) << 13)
#define SR_FS_INIT	      (UL(1) << 13)
#define SR_FS_CLEAN	      (UL(2) << 13)
#define SR_FS_DIRTY	      (UL(3) << 13)

#define ECALL_RDTIME      0x51110618 /* Read time */
#define ECALL_WRTIME      0x51110619 /* Set time */
#define ECALL_SENDIPI     0x51110620 /* Send IPI */
#define ECALL_APLIC_D     0x51110621 /* APLIC delegation */
#define ECALL_APLIC_MSI   0x51110622 /* APLIC MSIAddrCfg */

#define REG_STR(x) #x
#define read_csr(reg) ({					\
	unsigned long __v = 0;					\
	asm volatile(							\
		"csrr %0, " REG_STR(reg)			\
		: "=r" (__v) : : "memory", "cc");	\
	__v;									})

#define write_csr(reg, v)  ({				\
	unsigned long __v = (v);				\
	asm volatile(							\
		"csrw " REG_STR(reg) ", %0"			\
		: : "rK" (__v) : "memory", "cc");	})

#define set_csr(reg, val)	({				\
	unsigned long __v = (val);				\
	asm volatile(							\
		"csrs " REG_STR(reg) ", %0"			\
		: : "rK" (__v) : "memory", "cc");	})

#define clear_csr(reg, val)  ({				\
	unsigned long __v = (val);				\
	asm volatile(							\
		"csrc " REG_STR(reg) ", %0"			\
		: : "rK" (__v) : "memory", "cc");	})

#define read_set_csr(reg, val) ({			\
	unsigned long __v = 0;					\
	asm volatile(							\
		"csrrs %0, " REG_STR(reg) ", %1"	\
		: "=r" (__v) : "rK" (val) :			\
		"memory", "cc");					\
	__v;									})

#define read_clear_csr(reg, val) ({			\
	unsigned long __v = 0;					\
	asm volatile(							\
		"csrrc %0, " REG_STR(reg) ", %1"	\
		: "=r" (__v) : "rK" (val) :			\
		"memory", "cc");					\
	__v;									})

#define swap_csr(reg, v) ({			        \
	unsigned long __v = (v);				\
	asm volatile(							\
		"csrrw %0, " REG_STR(reg) ", %1"	\
		: "=r" (__v) : "rK" (__v) :		    \
		"memory", "cc");					\
	__v;									})

#ifndef __ASSEMBLY__
#include <limits.h>
#include <sys/cdefs.h>

extern unsigned long __misa;

bool is_io_readable(void *addr);

static __always_inline bool sstc_supported(void)
{
	extern bool __sstc_supported;
	return __sstc_supported;
}

static __always_inline unsigned int supervisor_bmap(void)
{
	extern unsigned int __supervisor_bmap;
	return __supervisor_bmap;
}

static __always_inline struct thread *get_current(void)
{
	register struct thread *curr asm("tp");

	return curr;
}

static __always_inline void set_current(void *curr)
{
	asm volatile("mv tp, %0" :: "r" (curr) : "memory", "cc");
}

static __always_inline void local_irq_disable(void)
{
	clear_csr(CSR_STATUS, SR_IE);
}

static __always_inline void local_irq_enable(void)
{
	set_csr(CSR_STATUS, SR_IE);
}

static __always_inline void local_irq_restore(unsigned long flags)
{
	set_csr(CSR_STATUS, flags & SR_IE);
}

static __always_inline long irqs_disabled(void)
{
	return !(read_csr(CSR_STATUS) & SR_IE);
}

static __always_inline unsigned long arch_irq_save(void)
{
	return read_clear_csr(CSR_STATUS, SR_IE);
}

#define local_irq_save(flags)									\
	do {														\
		BUILD_ERROR_ON(!TYPE_COMPATIBLE(flags, unsigned long));	\
		flags = arch_irq_save();								\
	} while (0)

static inline unsigned long ecall(
	unsigned long arg0, unsigned long arg1,
	unsigned long arg2, unsigned long arg3)
{
	unsigned long ret = 0;

	register long a0 asm ("a0") = arg0;
	register long a1 asm ("a1") = arg1;
	register long a2 asm ("a2") = arg2;
	register long a3 asm ("a3") = arg3;

	asm volatile("ecall" : "=r" (ret)
				: "r" (a0), "r" (a1), "r" (a2), "r" (a3)
				: "memory", "cc");

	return ret;
}
#endif
#endif
