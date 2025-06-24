/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * SM4 block cipher (GB/T 32907-2016)
 * Modes: ECB
 */

#ifndef _MBEDCRYPTO_SM4_H
#define _MBEDCRYPTO_SM4_H

#include <mbedcrypto/types.h>

#define MBEDCRYPTO_SM4_BLKSIZE  16
#define MBEDCRYPTO_SM4_KEYSIZE  16

#define MBEDCRYPTO_SM4_ENCRYPT  0
#define MBEDCRYPTO_SM4_DECRYPT  1

/*
 * SM4 context - stores 32 round keys.
 */
struct mbedcrypto_sm4_ctx {
	uint32_t rk[32];  /* round keys */
	int dir;           /* ENCRYPT or DECRYPT */
};

#if defined(CONFIG_MBEDCRYPTO_SM4)

/*
 * Set SM4 encryption or decryption key.
 * key: 16 bytes (128-bit key only).
 * dir: MBEDCRYPTO_SM4_ENCRYPT or MBEDCRYPTO_SM4_DECRYPT.
 */
int mbedcrypto_sm4_setkey(struct mbedcrypto_sm4_ctx *ctx,
		const uint8_t key[MBEDCRYPTO_SM4_KEYSIZE], int dir);

/*
 * SM4-ECB: encrypt or decrypt a single 16-byte block.
 */
int mbedcrypto_sm4_ecb_crypt(const struct mbedcrypto_sm4_ctx *ctx,
		const uint8_t in[MBEDCRYPTO_SM4_BLKSIZE],
		uint8_t out[MBEDCRYPTO_SM4_BLKSIZE]);

/*
 * Cleanup / zeroize an SM4 context.
 */
void mbedcrypto_sm4_cleanup(struct mbedcrypto_sm4_ctx *ctx);

#else /* !CONFIG_MBEDCRYPTO_SM4 */

static inline int mbedcrypto_sm4_setkey(struct mbedcrypto_sm4_ctx *ctx,
		const uint8_t key[MBEDCRYPTO_SM4_KEYSIZE], int dir)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm4_ecb_crypt(
		const struct mbedcrypto_sm4_ctx *ctx,
		const uint8_t in[MBEDCRYPTO_SM4_BLKSIZE],
		uint8_t out[MBEDCRYPTO_SM4_BLKSIZE])
{ return -ENOTSUP; }
static inline void mbedcrypto_sm4_cleanup(
		struct mbedcrypto_sm4_ctx *ctx) { }

#endif /* CONFIG_MBEDCRYPTO_SM4 */

#endif /* _MBEDCRYPTO_SM4_H */
