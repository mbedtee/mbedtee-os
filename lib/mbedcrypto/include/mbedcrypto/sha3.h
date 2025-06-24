/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * SHA-3 (Keccak) hash family (FIPS 202)
 *
 * SHA3-224, SHA3-256, SHA3-384, SHA3-512
 */

#ifndef _MBEDCRYPTO_SHA3_H
#define _MBEDCRYPTO_SHA3_H

#include <mbedcrypto/types.h>

/* SHA-3 variant identifiers */
#define MBEDCRYPTO_SHA3_224   0
#define MBEDCRYPTO_SHA3_256   1
#define MBEDCRYPTO_SHA3_384   2
#define MBEDCRYPTO_SHA3_512   3
#define MBEDCRYPTO_SHAKE256   4

#if defined(CONFIG_MBEDCRYPTO_SHA3)

struct mbedcrypto_sha3_ctx {
	uint64_t state[25]; /* 1600-bit Keccak state */
	uint8_t buf[200]; /* input buffer (rate bytes) */
	size_t bufsz; /* bytes buffered */
	size_t rate; /* rate in bytes (200 - 2*digest_len) */
	size_t olen; /* digest length in bytes (0 for SHAKE XOF) */
	uint8_t dsep; /* domain sep: 0x06=SHA-3, 0x1f=SHAKE */
};

/* Initialize a SHA-3 context for the given variant. */
void mbedcrypto_sha3_init(struct mbedcrypto_sha3_ctx *ctx);

/* Start a SHA-3 hash computation. */
int mbedcrypto_sha3_start(struct mbedcrypto_sha3_ctx *ctx, int type);

/* Feed input data. */
int mbedcrypto_sha3_update(struct mbedcrypto_sha3_ctx *ctx,
		const uint8_t *input, size_t ilen);

/* Produce the final digest. */
int mbedcrypto_sha3_final(struct mbedcrypto_sha3_ctx *ctx,
		uint8_t *output, size_t olen);

/* Clone a SHA-3 context. */
void mbedcrypto_sha3_clone(struct mbedcrypto_sha3_ctx *dst,
		const struct mbedcrypto_sha3_ctx *src);

/* Free / zeroize a SHA-3 context. */
void mbedcrypto_sha3_cleanup(struct mbedcrypto_sha3_ctx *ctx);

#else /* !CONFIG_MBEDCRYPTO_SHA3 */

struct mbedcrypto_sha3_ctx { char _dummy; };

static inline void mbedcrypto_sha3_init(
		struct mbedcrypto_sha3_ctx *ctx) { }
static inline int mbedcrypto_sha3_start(
		struct mbedcrypto_sha3_ctx *ctx, int type)
{ return -ENOTSUP; }
static inline int mbedcrypto_sha3_update(
		struct mbedcrypto_sha3_ctx *ctx,
		const uint8_t *input, size_t ilen)
{ return -ENOTSUP; }
static inline int mbedcrypto_sha3_final(
		struct mbedcrypto_sha3_ctx *ctx,
		uint8_t *output, size_t olen)
{ return -ENOTSUP; }
static inline void mbedcrypto_sha3_clone(
		struct mbedcrypto_sha3_ctx *dst,
		const struct mbedcrypto_sha3_ctx *src) { }
static inline void mbedcrypto_sha3_cleanup(
		struct mbedcrypto_sha3_ctx *ctx) { }

#endif /* CONFIG_MBEDCRYPTO_SHA3 */

#endif /* _MBEDCRYPTO_SHA3_H */
