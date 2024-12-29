// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * MIPS32 D-Cache VA Range Operations
 */

#include <io.h>
#include <cpu.h>
#include <defs.h>
#include <cache.h>
#include <stdint.h>
#include <barrier.h>

#define DCACHE_INV_RANGE			(0x11)
#define DCACHE_CLEAN_INV_RANGE		(0x15)
#define DCACHE_SECONDARY_TAG		(0x3)

static void dcache_va_range_ops(unsigned long start,
	unsigned long stop, int range_op)
{
	unsigned long line_len = 0, config1 = 0;
	unsigned long va = 0, config2 = 0, l2 = 0;

	/* Read Cache line size reg */
	config1 = read_cp0_register_ex(C0_CONFIG, 1);
	/* config1 DL [12:10] */
	line_len = (config1 >> 10) & 7;
	/* 2 * (1 << DL) */
	line_len = 1 << (line_len + 1);

	/* check if there is L2 - for DCACHE_SECONDARY_TAG */
	config2 = read_cp0_register_ex(C0_CONFIG, 2);
	l2 = (config2 >> 4) & 0xF;

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
			/* Flush & Invalidate data cache by VA*/
			asm volatile ("cache %1, (%0)" :
				: "r" (va), "i" (DCACHE_CLEAN_INV_RANGE));
			if (l2) {
				asm volatile ("cache %1, (%0)" :
					: "r" (va),
					"i" (DCACHE_CLEAN_INV_RANGE | DCACHE_SECONDARY_TAG));
			}
		}

		/* patch for memory write-back latency in SOC */
		ioread32((void *)(start | KSEG1));
		ioread32((void *)((stop | KSEG1) - line_len));
		/* patch for memory write-back latency in SOC */

		break;
	case DCACHE_INV_RANGE:
		for (va = start; va < stop; va = va + line_len) {
			/* Invalidate data cache by VA */
			asm volatile ("cache %1, (%0)" :
				: "r" (va), "i" (DCACHE_INV_RANGE));
			if (l2) {
				asm volatile ("cache %1, (%0)" :
					: "r" (va),
					"i" (DCACHE_INV_RANGE | DCACHE_SECONDARY_TAG));
			}
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
