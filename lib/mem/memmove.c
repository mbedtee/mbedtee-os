// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
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
		const int llen = sizeof(long);
		const int lmask = sizeof(long) - 1;

		d += n;
		s += n;

		if (n >= (llen << 2) && !(((long)s ^ (long)d) & lmask)) {
			while ((long)d & lmask) {
				*--d = *--s;
				n--;
			}

			do {
				unsigned long *wd = (unsigned long *)d;
				const unsigned long *ws = (const unsigned long *)s;

				while (n >= llen << 2) {
					*--wd = *--ws;
					*--wd = *--ws;
					*--wd = *--ws;
					*--wd = *--ws;
					n -= llen << 2;
				}

				while (n >= llen) {
					*--wd = *--ws;
					n -= llen;
				}

				d = (unsigned char *)wd;
				s = (const unsigned char *)ws;
			} while (0);
		}

		while (n--)
			*--d = *--s;
	} else {
		memcpy(dst, src, n);
	}

	return dst;
}
