/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * IO read/write functions
 */

#ifndef _IO_H
#define _IO_H

#include <stdint.h>
#include <barrier.h>

static inline uint8_t ioread8(const __volatile void *addr)
{
	uint8_t v = 0;

	if (addr) {
		v = *(const __volatile uint8_t *)addr;
		smp_rmb();	/* later loads are ordered */
	}

	return v;
}

static inline uint16_t ioread16(const __volatile void *addr)
{
	uint16_t v = 0;

	if (addr) {
		v = *(const __volatile uint16_t *)addr;
		smp_rmb();	/* later loads are ordered */
	}

	return v;
}

static inline uint32_t ioread32(const __volatile void *addr)
{
	uint32_t v = 0;

	if (addr) {
		v = *(const __volatile uint32_t *)addr;
		smp_rmb();	/* later loads are ordered */
	}

	return v;
}

static inline unsigned long ioreadl(const __volatile void *addr)
{
	unsigned long v = 0;

	if (addr) {
		v = *(const __volatile unsigned long *)addr;
		smp_rmb();	/* later loads are ordered */
	}

	return v;
}

static inline uint64_t ioread64(const __volatile void *addr)
{
	uint64_t v = 0;

	if (addr) {
		v = *(const __volatile uint64_t *)addr;
		smp_rmb();	/* later loads are ordered */
	}

	return v;
}

static inline void iowrite8(uint8_t value, __volatile void *addr)
{
	if (addr) {
		smp_wmb();	/* earlier sotres are ordered */
		*(__volatile uint8_t *)addr = value;
	}
}

static inline void iowrite16(uint16_t value, __volatile void *addr)
{
	if (addr) {
		smp_wmb();	/* earlier sotres are ordered */
		*(__volatile uint16_t *)addr = value;
	}
}

static inline void iowrite32(uint32_t value, __volatile void *addr)
{
	if (addr) {
		smp_wmb();	/* earlier sotres are ordered */
		*(__volatile uint32_t *)addr = value;
	}
}

static inline void iowritel(unsigned long value, __volatile void *addr)
{
	if (addr) {
		smp_wmb();	/* earlier sotres are ordered */
		*(__volatile unsigned long *)addr = value;
	}
}

static inline void iowrite64(uint64_t value, __volatile void *addr)
{
	if (addr) {
		smp_wmb();	/* earlier sotres are ordered */
		*(__volatile uint64_t *)addr = value;
	}
}

#endif
