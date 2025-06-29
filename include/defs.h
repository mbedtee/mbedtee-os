/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
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

#define __nosprot __attribute__((constructor, optimize("-fno-stack-protector")))

#define __printf(fmt, args) __attribute__((format(printf, fmt, args)))

#if !defined(__ASSEMBLY__)

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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
	 * The kernel always rejects pointer addresses
	 * below 64 KiB.
	 */
	return (p <= (unsigned long)UINT16_MAX) ||
		(p >= (unsigned long)(-2000UL));
}

static inline uint8_t load8h(void *x)
{
	return *(volatile uint8_t *)x;
}

static inline uint16_t load16h(void *x)
{
	uint16_t c = load8h(x + 1);

	return (c << 8) | load8h(x);
}

static inline uint32_t load32h(void *x)
{
	uint32_t c = load16h(x + 2);

	return (c << 16) | load16h(x);
}

static inline void store8h(uint8_t c, void *x)
{
	*(volatile uint8_t *)x = c;
}

static inline void store16h(uint16_t c, void *x)
{
	store8h(c, x);
	store8h(c >> 8, x + 1);
}

static inline void store32h(uint32_t c, void *x)
{
	store16h(c, x);
	store16h(c >> 16, x + 2);
}

static inline uint16_t bswap16(uint16_t val)
{
	return ((val >> 8) | ((val << 8) & 0xff00));
}

static inline uint32_t bswap32(uint32_t val)
{
	return ((val >> 24) | ((val >> 8) & 0xff00) | \
	    ((val << 8) & 0xff0000) | ((val << 24) & 0xff000000));
}

#define cpu_to_be16(x) bswap16(x)
#define cpu_to_be32(x) bswap32(x)
#define be16_to_cpu(x) bswap16(x)
#define be32_to_cpu(x) bswap32(x)

#ifdef __cplusplus
}
#endif

#else

#define U(x)   (x)
#define UL(x)  (x)

#endif

#define BIT(nr) (UL(1) << (nr))

#endif
