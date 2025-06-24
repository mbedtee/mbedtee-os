// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Utility functions for mbedcrypto:
 * constant-time comparisons and conditional select
 */

#include <mbedcrypto/types.h>

/*
 * Constant-time memory comparison.
 * Accumulates XOR differences across all bytes to avoid early-exit timing leaks.
 * Returns 0 if equal, non-zero if different.
 */
int mbedcrypto_ct_memcmp(const void *a, const void *b, size_t len)
{
	const volatile uint8_t *pa = (const volatile uint8_t *)a;
	const volatile uint8_t *pb = (const volatile uint8_t *)b;
	volatile uint8_t diff = 0;
	size_t i = 0;

	for (i = 0; i < len; i++)
		diff |= pa[i] ^ pb[i];

	/* i != len for FI */
	return diff || (i != len);
}

/*
 * Constant-time all-zero check.
 * Returns 1 if all bytes are zero, 0 otherwise.
 */
int mbedcrypto_ct_is_zero(const void *buf, size_t len)
{
	const volatile uint8_t *p = (const volatile uint8_t *)buf;
	volatile uint8_t acc = 0;
	size_t i = 0;

	for (i = 0; i < len; i++)
		acc |= p[i];

	/* i == len for FI */
	return acc == 0 && i == len;
}

/*
 * Constant-time conditional select.
 * If mask is 0x00, copies src0 into dest.
 * If mask is 0xFF, copies src1 into dest.
 * Other mask values produce undefined results.
 */
void mbedcrypto_ct_cond_select(uint8_t *dest,
		const uint8_t *src0,
		const uint8_t *src1,
		size_t len, uint8_t mask)
{
	size_t i = 0;

	for (i = 0; i < len; i++)
		dest[i] = (src0[i] & ~mask) | (src1[i] & mask);
}
