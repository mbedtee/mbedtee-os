/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * DES / Triple-DES block cipher (FIPS 46-3)
 * Modes: ECB
 *
 * Warning: DES/3DES are considered weak ciphers. This is kept only
 * for GP TEE Internal API compatibility.
 */

#ifndef _MBEDCRYPTO_DES_H
#define _MBEDCRYPTO_DES_H

#include <mbedcrypto/types.h>

#define MBEDCRYPTO_DES_BLKSIZE  8
#define MBEDCRYPTO_DES_KEYSIZE  8

#define MBEDCRYPTO_DES_ENCRYPT  0
#define MBEDCRYPTO_DES_DECRYPT  1

/*
 * Single-DES context - stores 32 sub-keys (16 rounds x 2).
 */
struct mbedcrypto_des_ctx {
	uint32_t sk[32];
	int dir;
};

/*
 * Triple-DES context - stores 96 sub-keys (3 x 16 rounds x 2).
 */
struct mbedcrypto_des3_ctx {
	uint32_t sk[96];
	int dir;
};

/*
 * Initialize a DES context.
 */
void mbedcrypto_des_init(struct mbedcrypto_des_ctx *ctx);

/*
 * Cleanup / zeroize a DES context.
 */
void mbedcrypto_des_cleanup(struct mbedcrypto_des_ctx *ctx);

/*
 * Set DES key for encryption or decryption.
 * dir: MBEDCRYPTO_DES_ENCRYPT or MBEDCRYPTO_DES_DECRYPT.
 */
int mbedcrypto_des_setkey(struct mbedcrypto_des_ctx *ctx,
		const uint8_t key[MBEDCRYPTO_DES_KEYSIZE], int dir);

/*
 * DES-ECB: encrypt or decrypt a single 8-byte block.
 */
int mbedcrypto_des_ecb_crypt(const struct mbedcrypto_des_ctx *ctx,
		const uint8_t in[MBEDCRYPTO_DES_BLKSIZE],
		uint8_t out[MBEDCRYPTO_DES_BLKSIZE]);

/*
 * Initialize a Triple-DES context.
 */
void mbedcrypto_des3_init(struct mbedcrypto_des3_ctx *ctx);

/*
 * Cleanup / zeroize a Triple-DES context.
 */
void mbedcrypto_des3_cleanup(struct mbedcrypto_des3_ctx *ctx);

/*
 * Set Triple-DES key for encryption or decryption.
 * key: 24 bytes (three 8-byte DES keys).
 * dir: MBEDCRYPTO_DES_ENCRYPT or MBEDCRYPTO_DES_DECRYPT.
 */
int mbedcrypto_des3_setkey(struct mbedcrypto_des3_ctx *ctx,
		const uint8_t key[MBEDCRYPTO_DES_KEYSIZE * 3], int dir);

/*
 * Triple-DES ECB: encrypt or decrypt a single 8-byte block.
 */
int mbedcrypto_des3_ecb_crypt(const struct mbedcrypto_des3_ctx *ctx,
		const uint8_t in[MBEDCRYPTO_DES_BLKSIZE],
		uint8_t out[MBEDCRYPTO_DES_BLKSIZE]);

#endif /* _MBEDCRYPTO_DES_H */
