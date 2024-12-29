// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch64 D-Cache VA Range Operations
 */

#include <io.h>
#include <mmu.h>
#include <cpu.h>
#include <defs.h>
#include <cache.h>
#include <stdint.h>
#include <barrier.h>

#define DCACHE_INV_RANGE			(1)
#define DCACHE_CLEAN_INV_RANGE		(2)

static void dcache_va_range_ops(unsigned long start,
	unsigned long end, int ops)
{
	unsigned long line_len = 0, ctr = 0;
	unsigned long va = 0;

	/* Get log2(words of per cache line) */
	asm volatile(
		"mrs %0, ctr_el0\n"
		"ubfx %0, %0, #16, #4\n"
		: "=r" (ctr));

	/* log2(words of per line) to (bytes of linelen) */
	line_len = BYTES_PER_INT << ctr;

	/* align the start */
	start = rounddown(start, line_len);

	/* align the end */
	end = roundup(end, line_len);

	/*
	 * drain the write buffer
	 * make sure any earlier stores to be finished before
	 * the stores introduced by following cache operations
	 */
	smp_wmb();
	switch (ops) {
	case DCACHE_CLEAN_INV_RANGE:
		for (va = start; va < end; va = va + line_len) {
			/* DC CIVAC - Clean & Invalidate data cache by VA */
			asm volatile("dc civac, %0" : : "r" (va));
		}

		/* patch for memory write-back latency in SOC */
		ioread32((void *)start);
		ioread32((void *)(end - line_len));
		/* patch for memory write-back latency in SOC */

		break;
	case DCACHE_INV_RANGE:
		for (va = start; va < end; va = va + line_len) {
			/* DC IVAC - Invalidate data cache by VA */
			asm volatile("dc ivac, %0" : : "r" (va));
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
