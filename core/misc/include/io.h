/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * IO read/write functions
 */

#ifndef _IO_H
#define _IO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <barrier.h>

static inline uint8_t ioread8(const volatile void *addr)
{
	uint8_t v = 0;

	if (addr) {
		v = *(const volatile uint8_t *)addr;
		rmb();	/* later loads are ordered */
	}

	return v;
}

static inline uint16_t ioread16(const volatile void *addr)
{
	uint16_t v = 0;

	if (addr) {
		v = *(const volatile uint16_t *)addr;
		rmb();	/* later loads are ordered */
	}

	return v;
}

static inline uint32_t ioread32(const volatile void *addr)
{
	uint32_t v = 0;

	if (addr) {
		v = *(const volatile uint32_t *)addr;
		rmb();	/* later loads are ordered */
	}

	return v;
}

static inline unsigned long ioreadl(const volatile void *addr)
{
	unsigned long v = 0;

	if (addr) {
		v = *(const volatile unsigned long *)addr;
		rmb();	/* later loads are ordered */
	}

	return v;
}

static inline uint64_t ioread64(const volatile void *addr)
{
	uint64_t v = 0;

	if (addr) {
		v = *(const volatile uint64_t *)addr;
		rmb();	/* later loads are ordered */
	}

	return v;
}

static inline void iowrite8(uint8_t value, volatile void *addr)
{
	if (addr) {
		wmb();	/* earlier stores are ordered */
		*(volatile uint8_t *)addr = value;
	}
}

static inline void iowrite16(uint16_t value, volatile void *addr)
{
	if (addr) {
		wmb();	/* earlier stores are ordered */
		*(volatile uint16_t *)addr = value;
	}
}

static inline void iowrite32(uint32_t value, volatile void *addr)
{
	if (addr) {
		wmb();	/* earlier stores are ordered */
		*(volatile uint32_t *)addr = value;
	}
}

static inline void iowritel(unsigned long value, volatile void *addr)
{
	if (addr) {
		wmb();	/* earlier stores are ordered */
		*(volatile unsigned long *)addr = value;
	}
}

static inline void iowrite64(uint64_t value, volatile void *addr)
{
	if (addr) {
		wmb();	/* earlier stores are ordered */
		*(volatile uint64_t *)addr = value;
	}
}

#ifdef __cplusplus
}
#endif
#endif
