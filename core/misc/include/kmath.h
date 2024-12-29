/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Integer log2/pow2
 */

#ifndef _KMATH_H
#define _KMATH_H

#include <cpu.h>
#include <math.h>

#define is_pow2(x) (!((x) & ((x) - 1)))

static inline unsigned long roundup2pow(unsigned long x)
{
	if (is_pow2(x))
		return x;

	return 1UL << (BITS_PER_LONG - __builtin_clzl(x - 1));
}

static inline unsigned long rounddown2pow(unsigned long x)
{
	if (is_pow2(x))
		return x;

	return 1UL << (BITS_PER_LONG - __builtin_clzl(x - 1) - 1);
}

static inline unsigned long log2of(unsigned long x)
{
	if (x == 0)
		return 0;

	return BITS_PER_LONG - __builtin_clzl(x) - 1;
}

static inline unsigned long long pow_of(
	unsigned long long x, int y)
{
	int i = 0;
	unsigned long long res = 1;

	for (i = 0; i < y; i++)
		res = res * x;

	return res;
}

#endif
