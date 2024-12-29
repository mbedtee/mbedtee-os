/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Define the user<->kernel memory_copy functions
 */

#ifndef _UACCESS_H
#define _UACCESS_H

#include <mmu.h>
#include <page.h>
#include <string.h>
#include <thread.h>

#define user_addr(addr)  (((unsigned long)(addr)) < USER_VA_TOP)
#define address_ok(addr) ((addr) && user_addr(addr))

#define size_ok(addr, size) (((unsigned long)(addr)) <= \
		((unsigned long)(addr)) + (unsigned long)(size))

/*
 * shall within the pre-defined user range
 */
#define user_range_ok(addr, size) (address_ok(addr) && \
		 address_ok(addr + size) && size_ok(addr, size))

#define access_ok(addr, size) user_range_ok(addr, size)

static inline size_t copy_from_user(void *to,
	const void *from, size_t n)
{
	if (access_ok(from, n)) {
		memcpy(to, from, n);
		return 0;
	}

	return n;
}

static inline size_t copy_to_user(void *to,
	const void *from, size_t n)
{
	if (access_ok(to, n)) {
		memcpy(to, from, n);
		return 0;
	}

	return n;
}

#define put_user(v, ptr)				\
({										\
	int __perror = 0;					\
	__typeof__(*(ptr)) *__p = (ptr);	\
	if (access_ok(__p, sizeof(*__p)))	\
		*__p = v;						\
	else								\
		__perror = -EFAULT;				\
	__perror;							\
})

#define get_user(v, ptr)				\
({										\
	int __perror = 0;					\
	__typeof__(*(ptr)) *__p = (ptr);	\
	if (access_ok(__p, sizeof(*__p)))	\
		v = *__p;						\
	else								\
		__perror = -EFAULT;				\
	__perror;							\
})

/*
 * excluding the terminating null byte ('\0')
 */
static inline long strnlen_user(const char *src, long cnt)
{
	long pos = 0, n = 0;
	long unalign = 0, ops = 0;

	while (pos < cnt) {
		unalign = PAGE_SIZE - ((long)src & ~PAGE_MASK);
		if (access_ok(src, 1)) {
			ops = min(cnt - pos, unalign);
			n = strnlen(src, ops);
			pos += n;
			src += n;
			if (ops > n)
				break;
		} else {
			pos = -EFAULT;
			break;
		}
	}

	return pos;
}

/*
 * At most 'cnt' bytes of src are copied.
 *
 * Warning: If there is no null byte among the first n bytes
 * of src, the string placed in dest will not be null-terminated.
 *
 * Warning: If there is page fault among "src" ~ "src + n", -EFAULT
 * will be returned to caller.
 *
 * return n bytes copied, excluding the terminating ('\0')
 */
static inline long strncpy_from_user(char *dst,
	const char *src, long cnt)
{
	long unalign = 0, ops = 0, pos = 0;

	while (pos < cnt) {
		unalign = PAGE_SIZE - ((long)src & ~PAGE_MASK);
		if (access_ok(src, 1)) {
			ops = min(cnt - pos, unalign);

			do {
				*dst = *src++;
				if (*dst == 0)
					break;
				dst++;
				pos++;
			} while (--ops != 0);

			if (ops)
				break;
		} else {
			pos = -EFAULT;
			break;
		}
	}

	return pos;
}

#endif
