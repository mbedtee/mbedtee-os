/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * AES-CMAC message authentication code (NIST SP 800-38B / RFC 4493)
 */

#ifndef _MBEDCRYPTO_CMAC_H
#define _MBEDCRYPTO_CMAC_H

#include <mbedcrypto/aes.h>

#define MBEDCRYPTO_CMAC_TAG_SIZE  16

/*
 * CMAC context - multi-part MAC computation.
 *
 * Usage flow:
 *   cmac_setkey() -> cmac_update() [0..n] -> cmac_finish()
 *   Optionally cmac_reset() to reuse the key for a new MAC.
 */
struct mbedcrypto_cmac_ctx {
	struct mbedcrypto_aes_ctx aes;         /* AES-ECB encrypt context */
	uint8_t k1[16];                        /* subkey K1 */
	uint8_t k2[16];                        /* subkey K2 */
	uint8_t state[16];                     /* CBC-MAC running state */
	uint8_t buf[16];                       /* partial block buffer */
	size_t buf_len;                        /* bytes buffered (0..16) */
};

/*
 * Set AES key for CMAC and derive sub-keys K1, K2.
 * keybits: 128, 192, or 256.
 */
int mbedcrypto_cmac_setkey(struct mbedcrypto_cmac_ctx *ctx,
		const uint8_t *key, unsigned int keybits);

/*
 * Reset MAC state for a new computation (keeps the same key).
 */
int mbedcrypto_cmac_reset(struct mbedcrypto_cmac_ctx *ctx);

/*
 * Feed data into the CMAC computation.
 * May be called multiple times with arbitrary chunk sizes.
 */
int mbedcrypto_cmac_update(struct mbedcrypto_cmac_ctx *ctx,
		const uint8_t *data, size_t len);

/*
 * Finalize and output the CMAC tag (16 bytes).
 * The context is NOT automatically reset; call cmac_reset()
 * to compute another MAC with the same key.
 */
int mbedcrypto_cmac_final(struct mbedcrypto_cmac_ctx *ctx,
		uint8_t mac[MBEDCRYPTO_CMAC_TAG_SIZE]);

/*
 * Cleanup / zeroize the CMAC context.
 */
void mbedcrypto_cmac_cleanup(struct mbedcrypto_cmac_ctx *ctx);

#endif /* _MBEDCRYPTO_CMAC_H */
