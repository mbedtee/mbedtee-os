// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * memcpy
 */

#include <cpu.h>
#include <string.h>
#include <stddef.h>

__weak_symbol void *memcpy(void *dst,
	const void *src, size_t n)
{
	unsigned long *d = dst;
	const unsigned long *s = src;
	const int llen = sizeof(long);
	const int lmask = sizeof(long) - 1;

	if ((n >= 16) && !((long)s & lmask) && !((long)d & lmask)) {
		while (n >= llen << 2) {
			*d++ = *s++;
			*d++ = *s++;
			*d++ = *s++;
			*d++ = *s++;
			n -= llen << 2;
		}

#if !defined(CONFIG_64BIT)
		while (n >= llen << 1) {
			*d++ = *s++;
			*d++ = *s++;
			n -= llen << 1;
		}
#else
		while (n >= llen) {
			*d++ = *s++;
			n -= llen;
		}
#endif
	}

	while (n--) {
		*(unsigned char *)d = *(unsigned char *)s;
		d = (void *)d + 1;
		s = (void *)s + 1;
	}

	return dst;
}
