// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * RISCV D-Cache VA Range Operations
 */

#include <io.h>
#include <cpu.h>
#include <defs.h>
#include <cache.h>
#include <stdint.h>
#include <barrier.h>

#define DCACHE_INV_RANGE			(1)
#define DCACHE_CLEAN_INV_RANGE		(2)

static void dcache_va_range_ops(unsigned long start,
	unsigned long stop, int range_op)
{
	unsigned long va = 0;
	unsigned long line_len = 0;

	/* check line_len  */
	line_len = 64;

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
			asm volatile("cbo.flush (%0)" : : "r" (va));
		}

		/* patch for memory write-back latency in SOC */
		ioread32((void *)start);
		ioread32((void *)(stop - line_len));
		/* patch for memory write-back latency in SOC */

		break;
	case DCACHE_INV_RANGE:
		for (va = start; va < stop; va = va + line_len) {
			/* Invalidate data cache by VA */
			asm volatile("cbo.inval (%0)" : : "r" (va));
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
	dcache_va_range_ops((unsigned long)start,
		(unsigned long)start + size, DCACHE_CLEAN_INV_RANGE);
}

/*
 * invalidate the data cache
 */
void invalidate_cache(void *start, size_t size)
{
	dcache_va_range_ops((unsigned long)start,
		(unsigned long)start + size, DCACHE_INV_RANGE);
}
