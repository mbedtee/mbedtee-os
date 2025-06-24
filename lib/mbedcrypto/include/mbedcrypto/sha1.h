/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * SHA-1 hash algorithm (FIPS 180-4)
 */

#ifndef _MBEDCRYPTO_SHA1_H
#define _MBEDCRYPTO_SHA1_H

#include <mbedcrypto/types.h>

#define MBEDCRYPTO_SHA1_BLKSIZE   64
#define MBEDCRYPTO_SHA1_HASHSIZE  20

/*
 * SHA-1 context
 */
struct mbedcrypto_sha1_ctx {
	uint32_t h[5];         /* chained state */
	uint64_t count;        /* total bytes processed */
	uint8_t blk[MBEDCRYPTO_SHA1_BLKSIZE]; /* partial block buffer */
};

/*
 * Initialize a SHA-1 context. Returns 0 on success.
 */
int mbedcrypto_sha1_init(struct mbedcrypto_sha1_ctx *ctx);

/*
 * Feed data into the hash computation.
 */
int mbedcrypto_sha1_update(struct mbedcrypto_sha1_ctx *ctx,
		const uint8_t *data, size_t len);

/*
 * Finalize the hash and write the 20-byte digest output.
 */
int mbedcrypto_sha1_final(struct mbedcrypto_sha1_ctx *ctx, uint8_t *out);

/*
 * Clone a hash context (for intermediate state reuse).
 */
void mbedcrypto_sha1_clone(struct mbedcrypto_sha1_ctx *dst,
		const struct mbedcrypto_sha1_ctx *src);

/*
 * Release / zeroize the hash context.
 */
void mbedcrypto_sha1_cleanup(struct mbedcrypto_sha1_ctx *ctx);

/*
 * One-shot SHA-1 convenience function.
 */
int mbedcrypto_sha1_digest(const uint8_t *data, size_t len, uint8_t *out);

#endif /* _MBEDCRYPTO_SHA1_H */
