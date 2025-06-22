// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * memset
 */

#include <cpu.h>
#include <string.h>
#include <stddef.h>

__weak_symbol void *memset(void *dst, int c, size_t n)
{
	unsigned long val = c & 0xff;
	unsigned long *d = dst;
	const int llen = sizeof(long);
	const int lmask = sizeof(long) - 1;

	while ((long)d & lmask)	{
		if (n == 0)
			return dst;
		*(unsigned char *)d = c;
		d = (void *)d + 1;
		n--;
	}

	if (n >= 16) {
		val = val | val << 8;
		val = val | val << 16;
#if defined(CONFIG_64BIT)
		val = val | val << 32;
#endif
		while (n >= llen << 2) {
			*d++ = val;
			*d++ = val;
			*d++ = val;
			*d++ = val;
			n -= llen << 2;
		}

#if !defined(CONFIG_64BIT)
		while (n >= llen << 1) {
			*d++ = val;
			*d++ = val;
			n -= llen << 1;
		}
#else
		while (n >= llen) {
			*d++ = val;
			n -= llen;
		}
#endif
	}

	while (n--) {
		*(unsigned char *)d = c;
		d = (void *)d + 1;
	}

	return dst;
}
