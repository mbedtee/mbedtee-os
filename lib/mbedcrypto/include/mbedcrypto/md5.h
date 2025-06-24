/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * MD5 hash algorithm (RFC 1321)
 */

#ifndef _MBEDCRYPTO_MD5_H
#define _MBEDCRYPTO_MD5_H

#include <mbedcrypto/types.h>

#define MBEDCRYPTO_MD5_BLKSIZE   64
#define MBEDCRYPTO_MD5_HASHSIZE  16

/*
 * MD5 context
 */
struct mbedcrypto_md5_ctx {
	uint32_t h[4];         /* chained state */
	uint64_t count;        /* total bytes processed */
	uint8_t blk[MBEDCRYPTO_MD5_BLKSIZE]; /* partial block buffer */
};

/*
 * Initialize an MD5 context. Returns 0 on success.
 */
int mbedcrypto_md5_init(struct mbedcrypto_md5_ctx *ctx);

/*
 * Feed data into the hash computation.
 */
int mbedcrypto_md5_update(struct mbedcrypto_md5_ctx *ctx,
		const uint8_t *data, size_t len);

/*
 * Finalize the hash and write the 16-byte digest output.
 */
int mbedcrypto_md5_final(struct mbedcrypto_md5_ctx *ctx, uint8_t *out);

/*
 * Clone a hash context (for intermediate state reuse).
 */
void mbedcrypto_md5_clone(struct mbedcrypto_md5_ctx *dst,
		const struct mbedcrypto_md5_ctx *src);

/*
 * Release / zeroize the hash context.
 */
void mbedcrypto_md5_cleanup(struct mbedcrypto_md5_ctx *ctx);

/*
 * One-shot MD5 convenience function.
 */
int mbedcrypto_md5_digest(const uint8_t *data, size_t len, uint8_t *out);

#endif /* _MBEDCRYPTO_MD5_H */
