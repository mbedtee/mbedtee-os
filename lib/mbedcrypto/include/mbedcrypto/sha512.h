/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * SHA-512 and SHA-384 hash algorithm (FIPS 180-4)
 */

#ifndef _MBEDCRYPTO_SHA512_H
#define _MBEDCRYPTO_SHA512_H

#include <mbedcrypto/types.h>

#define MBEDCRYPTO_SHA512_BLKSIZE   128
#define MBEDCRYPTO_SHA512_HASHSIZE  64
#define MBEDCRYPTO_SHA384_HASHSIZE  48

/*
 * SHA-512/384 context
 */
struct mbedcrypto_sha512_ctx {
	uint64_t h[8];         /* chained state */
	uint64_t count[2];     /* total bytes processed (128-bit) */
	uint8_t blk[MBEDCRYPTO_SHA512_BLKSIZE]; /* partial block buffer */
	uint8_t is384;             /* non-zero for SHA-384 variant */
};

/*
 * Initialize a SHA-512 or SHA-384 context.
 * variant: 0 for SHA-512, non-zero for SHA-384.
 * Returns 0 on success.
 */
int mbedcrypto_sha512_init(struct mbedcrypto_sha512_ctx *ctx, int variant);

/*
 * Feed data into the hash computation.
 */
int mbedcrypto_sha512_update(struct mbedcrypto_sha512_ctx *ctx,
		const uint8_t *data, size_t len);

/*
 * Finalize the hash and write the digest output.
 * Output must be at least 64 bytes for SHA-512
 * or 48 bytes for SHA-384.
 */
int mbedcrypto_sha512_final(struct mbedcrypto_sha512_ctx *ctx, uint8_t *out);

/*
 * Clone a hash context (for intermediate state reuse).
 */
void mbedcrypto_sha512_clone(struct mbedcrypto_sha512_ctx *dst,
		const struct mbedcrypto_sha512_ctx *src);

/*
 * Release / zeroize the hash context.
 */
void mbedcrypto_sha512_cleanup(struct mbedcrypto_sha512_ctx *ctx);

/*
 * One-shot SHA-512 / SHA-384 convenience function.
 */
int mbedcrypto_sha512_digest(const uint8_t *data, size_t len,
		uint8_t *out, int variant);

#endif /* _MBEDCRYPTO_SHA512_H */
