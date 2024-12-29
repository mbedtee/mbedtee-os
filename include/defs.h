/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Some useful MbedTEE definitions
 */

#ifndef _MBEDDEFS_H
#define _MBEDDEFS_H

#define likely(x)   __builtin_expect(!!(x), 1)

#define unlikely(x) __builtin_expect(!!(x), 0)

#define roundup(x, y)	({			\
	const __typeof__(x) __x = (x);	\
	const __typeof__(y) __y = (y);	\
	((__x + __y - 1) / __y) * __y;	})

#define rounddown(x, y)	({			\
	__typeof__(x) __x = (x);		\
	__typeof__(y) __y = (y);		\
	__x - (__x % __y);				})

#define min(x, y)	({				\
	__typeof__(x) __x = (x);		\
	__typeof__(y) __y = (y);		\
	(void) (&__x == &__y);			\
	__x < __y ? __x : __y;			})

#define max(x, y)	({				\
	__typeof__(x) __x = (x);		\
	__typeof__(y) __y = (y);		\
	(void) (&__x == &__y);			\
	__x < __y ? __y : __x;			})

#define BUILD_ERROR_ON(cond) ((void)sizeof(int[1 - 2 * !!(cond)]))

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

#define TYPE_COMPATIBLE(x, y) __builtin_types_compatible_p(typeof(x), typeof(y))

#define TYPE_COMPATIBLE_CHECK(p, t, m) \
	BUILD_ERROR_ON((!TYPE_COMPATIBLE(*(p), ((t *)0)->m)) && (!TYPE_COMPATIBLE(*(p), void)))

#define __CONFIG_BOOLEAN__1 ,
#define __GET_OPTION1(opt0, opt1, ...) opt1
#define __IS_ENABLED(opt) __GET_OPTION1(opt 1, 0)
#define _IS_ENABLED(val) __IS_ENABLED(__CONFIG_BOOLEAN__##val)
#define IS_ENABLED(CONFIG_x) _IS_ENABLED(CONFIG_x)

#define container_of(ptr, type, member)	({					\
	const typeof(((type *)0)->member) * __mptr = (ptr);		\
	(type *)((char *)__mptr - offsetof(type, member)); })

#define weak_alias(ori, aliasname) extern typeof(ori) aliasname __attribute__ ((weak, alias(#ori)))

#define strong_alias(ori, aliasname) extern typeof(aliasname) aliasname __attribute__ ((alias(#ori)))

#define bswap16(_x) ((unsigned short)(((_x) >> 8) | (((_x) << 8) & 0xff00)))
#define bswap32(_x) ((unsigned int)(((_x) >> 24) | (((_x) >> 8) & 0xff00) | \
	    (((_x) << 8) & 0xff0000) | (((_x) << 24) & 0xff000000)))

#define __nosprot __attribute__((constructor, optimize("-fno-stack-protector")))

#define __printf(fmt, args) __attribute__((format(printf, fmt, args)))

#ifndef __ASSEMBLY__

#include <stdint.h>

#define U(x)  (x##U)
#define UL(x) (x##UL)

static inline void *ERR_PTR(long err)
{
	return (void *)err;
}

static inline long PTR_ERR(void *ptr)
{
	return (long)ptr;
}

static inline long IS_ERR_PTR(void *ptr)
{
	unsigned long p = PTR_ERR(ptr);

	/*
	 * kernel always reject the pointer
	 * address which is less than 64KiB
	 */
	return (p <= (unsigned long)UINT16_MAX) ||
		(p >= (unsigned long)(-2000UL));
}

#else

#define U(x)   (x)
#define UL(x)  (x)

#endif

#define BIT(nr) (UL(1) << (nr))

#endif
