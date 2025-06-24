/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * SHA-256 and SHA-224 hash algorithm (FIPS 180-4)
 */

#ifndef _MBEDCRYPTO_SHA256_H
#define _MBEDCRYPTO_SHA256_H

#include <mbedcrypto/types.h>

#define MBEDCRYPTO_SHA256_BLKSIZE   64
#define MBEDCRYPTO_SHA256_HASHSIZE  32
#define MBEDCRYPTO_SHA224_HASHSIZE  28

/*
 * SHA-256/224 context
 */
struct mbedcrypto_sha256_ctx {
	uint32_t h[8];         /* chained state */
	uint64_t count;        /* total bytes processed */
	uint8_t blk[MBEDCRYPTO_SHA256_BLKSIZE]; /* partial block buffer */
	uint8_t is224;             /* non-zero for SHA-224 variant */
};

/*
 * Initialize a SHA-256 or SHA-224 context.
 * variant: 0 for SHA-256, non-zero for SHA-224.
 * Returns 0 on success.
 */
int mbedcrypto_sha256_init(struct mbedcrypto_sha256_ctx *ctx, int variant);

/*
 * Feed data into the hash computation.
 */
int mbedcrypto_sha256_update(struct mbedcrypto_sha256_ctx *ctx,
		const uint8_t *data, size_t len);

/*
 * Finalize the hash and write the digest output.
 * Output must be at least 32 bytes for SHA-256
 * or 28 bytes for SHA-224.
 */
int mbedcrypto_sha256_final(struct mbedcrypto_sha256_ctx *ctx, uint8_t *out);

/*
 * Clone a hash context (for intermediate state reuse).
 */
void mbedcrypto_sha256_clone(struct mbedcrypto_sha256_ctx *dst,
		const struct mbedcrypto_sha256_ctx *src);

/*
 * Release / zeroize the hash context.
 */
void mbedcrypto_sha256_cleanup(struct mbedcrypto_sha256_ctx *ctx);

/*
 * One-shot SHA-256 / SHA-224 convenience function.
 */
int mbedcrypto_sha256_digest(const uint8_t *data, size_t len,
		uint8_t *out, int variant);

#endif /* _MBEDCRYPTO_SHA256_H */
