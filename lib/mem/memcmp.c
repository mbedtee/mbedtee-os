// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Memory comparison functions:
 * - memcmp: standard byte-by-byte comparison
 * - mbedtee_memcmp: constant-time comparison for security contexts
 */

#include <stddef.h>
#include <string.h>

#include <mbedtee_memcmp.h>

/*
 * Standard memory comparison.
 * Returns <0, 0, or >0 based on lexicographic byte ordering.
 */
__weak_symbol int memcmp(const void *s1, const void *s2, size_t n)
{
	const unsigned char *p1 = s1;
	const unsigned char *p2 = s2;
	const int llen = sizeof(long);
	const int lmask = sizeof(long) - 1;

	if (n >= (llen << 1) && !(((long)p1 ^ (long)p2) & lmask)) {
		while ((long)p1 & lmask) {
			if (*p1 != *p2)
				return *p1 - *p2;
			p1++;
			p2++;
			n--;
		}

		do {
			const unsigned long *w1 = (const unsigned long *)p1;
			const unsigned long *w2 = (const unsigned long *)p2;

			while (n >= llen && *w1 == *w2) {
				w1++;
				w2++;
				n -= llen;
			}

			p1 = (const unsigned char *)w1;
			p2 = (const unsigned char *)w2;
		} while (0);
	}

	while (n--) {
		if (*p1 != *p2)
			return *p1 - *p2;
		p1++;
		p2++;
	}

	return 0;
}

/*
 * Constant-time memory comparison.
 * Returns 0 if the two buffers are identical, non-zero otherwise.
 * Always traverses all bytes regardless of mismatches,
 * preventing timing side-channel attacks.
 */
__weak_symbol int mbedtee_memcmp(const void *a, const void *b, size_t len)
{
	const volatile unsigned char *pa = (const volatile unsigned char *)a;
	const volatile unsigned char *pb = (const volatile unsigned char *)b;
	volatile unsigned char diff = 0;
	size_t i;

	for (i = 0; i < len; i++)
		diff |= pa[i] ^ pb[i];

	return diff || (i != len);
}
