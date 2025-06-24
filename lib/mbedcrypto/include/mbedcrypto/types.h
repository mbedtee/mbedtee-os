/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Common types and utility functions for mbedcrypto
 */

#ifndef _MBEDCRYPTO_TYPES_H
#define _MBEDCRYPTO_TYPES_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef MBEDCRYPTO_HOST_BUILD
#include <generated/autoconf.h>
#endif

/* RNG callback type: int f_rng(void *ctx, uint8_t *out, size_t len) */
typedef int (*mbedcrypto_rng_fn)(void *ctx, uint8_t *out, size_t len);

/*
 * Constant-time buffer comparison
 * Returns 0 if equal, non-zero otherwise
 */
int mbedcrypto_ct_memcmp(const void *a, const void *b, size_t len);

/*
 * Constant-time all-zero check
 * Returns 1 if all bytes are zero, 0 otherwise
 */
int mbedcrypto_ct_is_zero(const void *buf, size_t len);

/*
 * Constant-time conditional select: dest = (mask == 0) ? src0 : src1
 * mask must be 0 or all-ones
 */
void mbedcrypto_ct_cond_select(uint8_t *dest,
	const uint8_t *src0,
	const uint8_t *src1,
	size_t len, uint8_t mask);

/*
 * Endian helpers
 */
static inline uint32_t mbedcrypto_get_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) |
	       ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] <<  8) |
	       (p[3]);
}

static inline void mbedcrypto_put_be32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >>  8;
	p[3] = v;
}

static inline uint64_t mbedcrypto_get_be64(const uint8_t *p)
{
	return ((uint64_t)p[0] << 56) |
	       ((uint64_t)p[1] << 48) |
	       ((uint64_t)p[2] << 40) |
	       ((uint64_t)p[3] << 32) |
	       ((uint64_t)p[4] << 24) |
	       ((uint64_t)p[5] << 16) |
	       ((uint64_t)p[6] <<  8) |
	       (p[7]);
}

static inline void mbedcrypto_put_be64(uint8_t *p, uint64_t v)
{
	p[0] = v >> 56;
	p[1] = v >> 48;
	p[2] = v >> 40;
	p[3] = v >> 32;
	p[4] = v >> 24;
	p[5] = v >> 16;
	p[6] = v >>  8;
	p[7] = v;
}

static inline uint32_t mbedcrypto_get_le32(const uint8_t *p)
{
	return (p[0])       |
	       ((uint32_t)p[1] <<  8) |
	       ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static inline void mbedcrypto_put_le32(uint8_t *p, uint32_t v)
{
	p[0] = v;
	p[1] = v >>  8;
	p[2] = v >> 16;
	p[3] = v >> 24;
}

static inline uint64_t mbedcrypto_get_le64(const uint8_t *p)
{
	return (p[0])       |
	       ((uint64_t)p[1] <<  8) |
	       ((uint64_t)p[2] << 16) |
	       ((uint64_t)p[3] << 24) |
	       ((uint64_t)p[4] << 32) |
	       ((uint64_t)p[5] << 40) |
	       ((uint64_t)p[6] << 48) |
	       ((uint64_t)p[7] << 56);
}

static inline void mbedcrypto_put_le64(uint8_t *p, uint64_t v)
{
	p[0] = v;
	p[1] = v >>  8;
	p[2] = v >> 16;
	p[3] = v >> 24;
	p[4] = v >> 32;
	p[5] = v >> 40;
	p[6] = v >> 48;
	p[7] = v >> 56;
}

static inline uint32_t mbedcrypto_rotr32(uint32_t x, unsigned int n)
{
	return (x >> n) | (x << (32 - n));
}

static inline uint32_t mbedcrypto_rotl32(uint32_t x, unsigned int n)
{
	return (x << n) | (x >> (32 - n));
}

static inline uint64_t mbedcrypto_rotr64(uint64_t x, unsigned int n)
{
	return (x >> n) | (x << (64 - n));
}

/*
 * XOR n bytes: r = a ^ b
 * r, a, b may alias freely.
 */
static inline void mbedcrypto_xor(uint8_t *r,
	const uint8_t *a, const uint8_t *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		r[i] = a[i] ^ b[i];
}

#endif /* _MBEDCRYPTO_TYPES_H */
