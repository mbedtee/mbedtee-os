/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * SM3 cryptographic hash algorithm (GB/T 32905-2016)
 */

#ifndef _MBEDCRYPTO_SM3_H
#define _MBEDCRYPTO_SM3_H

#include <mbedcrypto/types.h>

#define MBEDCRYPTO_SM3_BLKSIZE   64
#define MBEDCRYPTO_SM3_HASHSIZE  32

#if defined(CONFIG_MBEDCRYPTO_SM3)

/*
 * SM3 context
 */
struct mbedcrypto_sm3_ctx {
	uint32_t h[8];         /* chained state */
	uint64_t count;        /* total bytes processed */
	uint8_t blk[MBEDCRYPTO_SM3_BLKSIZE]; /* partial block buffer */
};

/*
 * Initialize an SM3 context.
 * Returns 0 on success.
 */
int mbedcrypto_sm3_init(struct mbedcrypto_sm3_ctx *ctx);

/*
 * Feed data into the hash computation.
 */
int mbedcrypto_sm3_update(struct mbedcrypto_sm3_ctx *ctx,
		const uint8_t *data, size_t len);

/*
 * Finalize the hash and write the 32-byte digest output.
 */
int mbedcrypto_sm3_final(struct mbedcrypto_sm3_ctx *ctx, uint8_t *out);

/*
 * Clone a hash context (for intermediate state reuse).
 */
void mbedcrypto_sm3_clone(struct mbedcrypto_sm3_ctx *dst,
		const struct mbedcrypto_sm3_ctx *src);

/*
 * Release / zeroize the hash context.
 */
void mbedcrypto_sm3_cleanup(struct mbedcrypto_sm3_ctx *ctx);

/*
 * One-shot SM3 convenience function.
 */
int mbedcrypto_sm3_digest(const uint8_t *data, size_t len, uint8_t *out);

#else /* !CONFIG_MBEDCRYPTO_SM3 */

struct mbedcrypto_sm3_ctx { char _dummy; };

static inline int mbedcrypto_sm3_init(
		struct mbedcrypto_sm3_ctx *ctx)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm3_update(
		struct mbedcrypto_sm3_ctx *ctx,
		const uint8_t *data, size_t len)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm3_final(
		struct mbedcrypto_sm3_ctx *ctx, uint8_t *out)
{ return -ENOTSUP; }
static inline void mbedcrypto_sm3_clone(
		struct mbedcrypto_sm3_ctx *dst,
		const struct mbedcrypto_sm3_ctx *src) { }
static inline void mbedcrypto_sm3_cleanup(
		struct mbedcrypto_sm3_ctx *ctx) { }
static inline int mbedcrypto_sm3_digest(
		const uint8_t *data, size_t len, uint8_t *out)
{ return -ENOTSUP; }

#endif /* CONFIG_MBEDCRYPTO_SM3 */

#endif /* _MBEDCRYPTO_SM3_H */
