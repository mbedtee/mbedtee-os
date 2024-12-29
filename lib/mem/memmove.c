// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * memmove
 */

#include <string.h>
#include <stddef.h>

__weak_symbol void *memmove(void *dst,
	const void *src, size_t n)
{
	unsigned char *d = dst;
	const unsigned char *s = src;

	if (d - s < n) {
		d += n;
		s += n;
		while (n--)
			*--d = *--s;
	} else  {
		memcpy(dst, src, n);
	}

	return dst;
}
