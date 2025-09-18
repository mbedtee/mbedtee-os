// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2022 Xing Loong <xing.xl.loong@gmail.com>
 * RISCV D-Cache VA Range Operations
 */

#include <io.h>
#include <cpu.h>
#include <defs.h>
#include <cache.h>
#include <stdint.h>
#include <barrier.h>
#include <cacheops.h>

#define DCACHE_INV_RANGE			(1)
#define DCACHE_CLEAN_INV_RANGE		(2)

/*
 * Cache line size in bytes, read from DTS "cache-line-size" property.
 * Used by all vendor-specific and standard cache operations.
 */
unsigned long riscv_cacheline_size = 64;

/*
 * Andes CCTL VA-range cache operations.
 * Uses ucctlbeginaddr (0x80B) and ucctlcommand (0x80C) CSRs
 * which are accessible from S-mode when CCTL_SUEN is enabled.
 */
static void andes_cctl_va_range_ops(unsigned long start,
	unsigned long stop, int range_op)
{
	unsigned long va = 0;
	int cmd = 0;

	switch (range_op) {
	case DCACHE_CLEAN_INV_RANGE:
		cmd = CCTL_L1D_VA_WBINVAL;
		break;
	case DCACHE_INV_RANGE:
		cmd = CCTL_L1D_VA_INVAL;
		break;
	default:
		return;
	}

	start = rounddown(start, riscv_cacheline_size);
	stop = roundup(stop, riscv_cacheline_size);

	smp_wmb();
	for (va = start; va < stop; va = va + riscv_cacheline_size) {
		write_csr(UCCTLBEGINADDR, va);
		write_csr(UCCTLCOMMAND, cmd);
	}

	if (range_op == DCACHE_CLEAN_INV_RANGE) {
		ioread32((void *)start);
		ioread32((void *)(stop - riscv_cacheline_size));
	}

	smp_rmb();
	isb();
}

/*
 * T-Head xtheadcmo VA-range cache operations.
 * Uses th.dcache.civa/th.dcache.iva encoded as raw instructions
 * since the toolchain may not support xtheadcmo mnemonics.
 *
 * Encodings (R-type, opcode=0x0b, rs1=a0):
 *   th.dcache.civa a0: 0x0275000b  (Clean & Invalidate by VA)
 *   th.dcache.iva  a0: 0x0265000b  (Invalidate by VA)
 *   th.sync.s:         0x0190000b  (Synchronize)
 */
#define THEAD_DCACHE_CIVA	".long 0x0275000b\n"
#define THEAD_DCACHE_IVA	".long 0x0265000b\n"
#define THEAD_SYNC_S		".long 0x0190000b\n"

static void thead_cmo_va_range_ops(unsigned long start,
	unsigned long stop, int range_op)
{
	unsigned long va = 0;

	start = rounddown(start, riscv_cacheline_size);
	stop = roundup(stop, riscv_cacheline_size);

	smp_wmb();

	switch (range_op) {
	case DCACHE_CLEAN_INV_RANGE:
		for (va = start; va < stop; va = va + riscv_cacheline_size) {
			asm volatile("mv a0, %0\n"
				THEAD_DCACHE_CIVA
				: : "r" (va) : "a0", "memory");
		}

		ioread32((void *)start);
		ioread32((void *)(stop - riscv_cacheline_size));

		break;
	case DCACHE_INV_RANGE:
		for (va = start; va < stop; va = va + riscv_cacheline_size) {
			asm volatile("mv a0, %0\n"
				THEAD_DCACHE_IVA
				: : "r" (va) : "a0", "memory");
		}
		break;
	default:
		return;
	}

	asm volatile(THEAD_SYNC_S ::: "memory");

	smp_rmb();
	isb();
}

static void dcache_va_range_ops(unsigned long start,
	unsigned long stop, int range_op)
{
	unsigned long va = 0;
	unsigned long line_len = 0;

	if (andes_supported()) {
		andes_cctl_va_range_ops(start, stop, range_op);
		return;
	}

	if (thead_supported()) {
		thead_cmo_va_range_ops(start, stop, range_op);
		return;
	}

	if (!zicbom_supported())
		return;

	line_len = riscv_cacheline_size;

	/* align the start */
	start = rounddown(start, line_len);

	/* align the end */
	stop = roundup(stop, line_len);

	/*
	 * drain the write buffer
	 * make sure any earlier stores to be finished before
	 * the stores introduced by following cache operations
	 */
	smp_wmb();
	switch (range_op) {
	case DCACHE_CLEAN_INV_RANGE:
		for (va = start; va < stop; va = va + line_len) {
			/* Clean & Invalidate data cache by VA*/
			asm volatile(
				".option push\n"
				".option arch, +zicbom\n"
				"cbo.flush (%0)\n"
				".option pop" : : "r" (va));
		}

		/* patch for memory write-back latency in SOC */
		ioread32((void *)start);
		ioread32((void *)(stop - line_len));

		break;
	case DCACHE_INV_RANGE:
		for (va = start; va < stop; va = va + line_len) {
			/* Invalidate data cache by VA */
			asm volatile(
				".option push\n"
				".option arch, +zicbom\n"
				"cbo.inval (%0)\n"
				".option pop" : : "r" (va));
		}
		break;
	default:
		break;
	}

	/*
	 * make sure the above cache operations
	 * to be finished before any later loads
	 */
	smp_rmb();
	isb();
}

/*
 * flush the data cache
 */
void flush_cache(void *start, size_t size)
{
	if (size != 0)
		dcache_va_range_ops((unsigned long)start,
			(unsigned long)start + size, DCACHE_CLEAN_INV_RANGE);
}

/*
 * invalidate the data cache
 */
void invalidate_cache(void *start, size_t size)
{
	if (size != 0)
		dcache_va_range_ops((unsigned long)start,
			(unsigned long)start + size, DCACHE_INV_RANGE);
}
