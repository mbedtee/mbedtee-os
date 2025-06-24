/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * AES-SIV (RFC 5297)
 *
 * Synthetic Initialization Vector - deterministic AEAD.
 * Nonce-misuse resistant authenticated encryption.
 */

#ifndef _MBEDCRYPTO_AES_SIV_H
#define _MBEDCRYPTO_AES_SIV_H

#include <mbedcrypto/types.h>

#define MBEDCRYPTO_AES_SIV_TAG_SIZE 16

struct mbedcrypto_aes_siv_ctx {
	uint8_t k1[32]; /* S2V (CMAC) key, max 256-bit */
	uint8_t k2[32]; /* CTR key, max 256-bit */
	size_t keylen; /* half-key length: 16/24/32 */
};

#if defined(CONFIG_MBEDCRYPTO_AES_SIV)

/* Initialize an AES-SIV context. */
void mbedcrypto_aes_siv_init(struct mbedcrypto_aes_siv_ctx *ctx);

/* Cleanup / zeroize an AES-SIV context. */
void mbedcrypto_aes_siv_cleanup(struct mbedcrypto_aes_siv_ctx *ctx);

/*
 * Set the AES-SIV key.
 * keylen must be 32, 48, or 64 bytes (256/384/512-bit combined key).
 * The first half is K1 (CMAC), the second half is K2 (CTR).
 */
int mbedcrypto_aes_siv_setkey(struct mbedcrypto_aes_siv_ctx *ctx,
		const uint8_t *key, size_t keylen);

/*
 * AES-SIV encrypt.
 * aad/aad_len:        additional authenticated data (can be NULL).
 * input/len:          plaintext.
 * output:             ciphertext (same length as input).
 * tag:                16-byte authentication tag (SIV).
 */
int mbedcrypto_aes_siv_encrypt(struct mbedcrypto_aes_siv_ctx *ctx,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output,
		uint8_t tag[MBEDCRYPTO_AES_SIV_TAG_SIZE]);

/*
 * AES-SIV decrypt and verify.
 * Returns 0 on success, -EBADMSG if tag verification fails.
 */
int mbedcrypto_aes_siv_decrypt(struct mbedcrypto_aes_siv_ctx *ctx,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output,
		const uint8_t tag[MBEDCRYPTO_AES_SIV_TAG_SIZE]);

#else /* !CONFIG_MBEDCRYPTO_AES_SIV */

static inline void mbedcrypto_aes_siv_init(
		struct mbedcrypto_aes_siv_ctx *ctx) { }

static inline void mbedcrypto_aes_siv_cleanup(
		struct mbedcrypto_aes_siv_ctx *ctx) { }

static inline int mbedcrypto_aes_siv_setkey(
		struct mbedcrypto_aes_siv_ctx *ctx,
		const uint8_t *key, size_t keylen)
{ return -ENOTSUP; }

static inline int mbedcrypto_aes_siv_encrypt(
		struct mbedcrypto_aes_siv_ctx *ctx,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output,
		uint8_t tag[MBEDCRYPTO_AES_SIV_TAG_SIZE])
{ return -ENOTSUP; }

static inline int mbedcrypto_aes_siv_decrypt(
		struct mbedcrypto_aes_siv_ctx *ctx,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output,
		const uint8_t tag[MBEDCRYPTO_AES_SIV_TAG_SIZE])
{ return -ENOTSUP; }

#endif /* CONFIG_MBEDCRYPTO_AES_SIV */

#endif /* _MBEDCRYPTO_AES_SIV_H */
