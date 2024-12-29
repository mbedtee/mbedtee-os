// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * AArch32 D-Cache VA Range Operations
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
	unsigned long stop, int ops)
{
	unsigned long line_len = 0, ctr = 0;
	unsigned long mva = 0;

	/* Read Cache line size register */
	asm volatile (
		"mrc p15, 0, %0, c0, c0, 1\n"
		: "=r" (ctr));

	/* log2(words of per line) */
	ctr = (ctr >> 16) & 0xf;
	/* log2(words of per line) to (bytes of linelen) */
	line_len = BYTES_PER_INT << ctr;

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
	switch (ops) {
	case DCACHE_CLEAN_INV_RANGE:
		for (mva = start; mva < stop; mva = mva + line_len) {
			/* DCCIMVAC - Clean & Invalidate data cache by VA*/
			asm volatile ("mcr p15, 0, %0, c7, c14, 1" : : "r" (mva));
		}

		/* patch for memory write-back latency in SOC */
		ioread32((void *)start);
		ioread32((void *)(stop - line_len));
		/* patch for memory write-back latency in SOC */

		break;
	case DCACHE_INV_RANGE:
		for (mva = start; mva < stop; mva = mva + line_len) {
			/* DCIMVAC - Invalidate data cache by VA */
			asm volatile ("mcr p15, 0, %0, c7, c6, 1" : : "r" (mva));
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
