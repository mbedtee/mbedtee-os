/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * AES block cipher (FIPS 197)
 * Modes: ECB, XTS
 */

#ifndef _MBEDCRYPTO_AES_H
#define _MBEDCRYPTO_AES_H

#include <mbedcrypto/types.h>

#define MBEDCRYPTO_AES_BLKSIZE    16
#define MBEDCRYPTO_AES_MAX_ROUNDS 14
#define MBEDCRYPTO_AES_MAX_RK     (4 * (MBEDCRYPTO_AES_MAX_ROUNDS + 1))

#define MBEDCRYPTO_AES_ENCRYPT    0
#define MBEDCRYPTO_AES_DECRYPT    1

/*
 * AES context - stores expanded round keys.
 * The direction is fixed at key setup time.
 */
struct mbedcrypto_aes_ctx {
	uint32_t rk[MBEDCRYPTO_AES_MAX_RK]; /* round keys */
	uint8_t nr;                          /* number of rounds (10/12/14) */
	uint8_t dir;                         /* ENCRYPT or DECRYPT */
};

/*
 * AES-XTS context - two AES keys for XTS mode.
 * 'crypt' is the data encryption/decryption key,
 * 'tweak' is the tweak encryption key (always encrypt direction).
 */
struct mbedcrypto_aes_xts_ctx {
	struct mbedcrypto_aes_ctx crypt;
	struct mbedcrypto_aes_ctx tweak;
};

/*
 * Set AES encryption or decryption key.
 * keybits: 128, 192, or 256.
 * dir: MBEDCRYPTO_AES_ENCRYPT or MBEDCRYPTO_AES_DECRYPT.
 */
int mbedcrypto_aes_setkey(struct mbedcrypto_aes_ctx *ctx,
		const uint8_t *key, unsigned int keybits, int dir);

/*
 * AES-ECB: encrypt or decrypt a single 16-byte block.
 * Direction was determined by the preceding setkey call.
 */
int mbedcrypto_aes_ecb_crypt(const struct mbedcrypto_aes_ctx *ctx,
		const uint8_t in[MBEDCRYPTO_AES_BLKSIZE],
		uint8_t out[MBEDCRYPTO_AES_BLKSIZE]);

/*
 * Set AES-XTS key.
 * keybits: total bits for both keys (256 for AES-128-XTS, 512 for AES-256-XTS).
 * The first half is the data key, the second half is the tweak key.
 */
int mbedcrypto_aes_xts_setkey(struct mbedcrypto_aes_xts_ctx *ctx,
		const uint8_t *key, unsigned int keybits, int dir);

/*
 * AES-XTS core: encrypt or decrypt 'len' bytes (>= 16, <= 2^24).
 * The tweak IV is updated in-place for multi-call streaming.
 * *olen receives the number of bytes written to output.
 */
int mbedcrypto_aes_xts_crypt(struct mbedcrypto_aes_xts_ctx *ctx,
		uint8_t tweak[MBEDCRYPTO_AES_BLKSIZE],
		const uint8_t *input, size_t len,
		uint8_t *output, size_t *olen);

/*
 * Cleanup / zeroize an AES context.
 */
void mbedcrypto_aes_cleanup(struct mbedcrypto_aes_ctx *ctx);

/*
 * Cleanup / zeroize an AES-XTS context.
 */
void mbedcrypto_aes_xts_cleanup(struct mbedcrypto_aes_xts_ctx *ctx);

#endif /* _MBEDCRYPTO_AES_H */
