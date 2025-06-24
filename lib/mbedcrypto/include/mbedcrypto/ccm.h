/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * CCM authenticated encryption (NIST SP 800-38C / RFC 3610 / RFC 8998)
 * AES-CCM and SM4-CCM (guarded by CONFIG_MBEDCRYPTO_SM4)
 */

#ifndef _MBEDCRYPTO_CCM_H
#define _MBEDCRYPTO_CCM_H

#include <mbedcrypto/aes.h>

/* State values */
#define MBEDCRYPTO_CCM_STATE_INIT       0
#define MBEDCRYPTO_CCM_STATE_STARTED    1
#define MBEDCRYPTO_CCM_STATE_LENGTHS    2
#define MBEDCRYPTO_CCM_STATE_AAD        3
#define MBEDCRYPTO_CCM_STATE_PAYLOAD    4

/* Block cipher ECB function pointer for CCM */
typedef void (*ccm_ecb_fn)(const void *cipher,
		const uint8_t in[16], uint8_t out[16]);

/*
 * Common CCM base context shared by AES-CCM and SM4-CCM.
 * Holds the multi-part state and a function pointer for
 * the underlying block cipher ECB operation.
 *
 * Usage flow:
 *   ccm_setkey -> ccm_start -> ccm_set_len ->
 *   ccm_update_aad [0..n] -> ccm_update [0..n] -> ccm_final
 */
struct ccm_base {
	ccm_ecb_fn ecb;                    /* block cipher ECB encrypt */
	const void *cipher;                /* pointer to cipher context */
	uint8_t ctr[16];                   /* counter block (A_i) */
	uint8_t mac[16];                   /* CBC-MAC state (Y_i) */
	uint8_t buf[16];                   /* partial-block buffer */
	uint8_t keystream[16];             /* cached CTR keystream block */
	size_t buf_len;                    /* bytes in partial buffer */
	size_t aad_len;                    /* total AAD length */
	size_t aad_done;                   /* AAD bytes processed so far */
	size_t payload_len;                /* total payload length */
	size_t payload_done;               /* payload bytes processed so far */
	uint8_t tag_len;                   /* authentication tag length */
	uint8_t dir;                       /* ENCRYPT or DECRYPT */
	uint8_t q;                         /* length-field size (15 - nonce_len) */
	uint8_t state;                     /* internal state machine */
};

/*
 * AES-CCM context
 */
struct mbedcrypto_aes_ccm_ctx {
	struct mbedcrypto_aes_ctx aes;
	struct ccm_base base;
};

/*
 * Initialize AES-CCM context with AES key.
 * keybits: 128, 192, or 256.
 */
int mbedcrypto_aes_ccm_setkey(struct mbedcrypto_aes_ccm_ctx *ctx,
		const uint8_t *key, unsigned int keybits);

/*
 * Start an AES-CCM encryption or decryption operation.
 * dir: MBEDCRYPTO_AES_ENCRYPT or MBEDCRYPTO_AES_DECRYPT.
 * nonce: 7 to 13 bytes.
 */
int mbedcrypto_aes_ccm_start(struct mbedcrypto_aes_ccm_ctx *ctx, int dir,
		const uint8_t *nonce, size_t nonce_len);

/*
 * Set the expected lengths for AAD, payload & tag.
 * Must be called after starts(), before any data.
 * tag_len: 4, 6, 8, 10, 12, 14, or 16.
 */
int mbedcrypto_aes_ccm_set_len(struct mbedcrypto_aes_ccm_ctx *ctx,
		size_t aad_len, size_t payload_len, size_t tag_len);

/*
 * Feed additional authenticated data.
 * May be called multiple times. Total must equal aad_len.
 */
int mbedcrypto_aes_ccm_update_aad(struct mbedcrypto_aes_ccm_ctx *ctx,
		const uint8_t *aad, size_t len);

/*
 * Encrypt or decrypt payload data.
 * May be called multiple times. Total must equal payload_len.
 * *olen receives the number of bytes written to output.
 */
int mbedcrypto_aes_ccm_update(struct mbedcrypto_aes_ccm_ctx *ctx,
		const uint8_t *input, size_t len,
		uint8_t *output, size_t *olen);

/*
 * Finalize the AES-CCM operation: outputs the computed tag.
 * Always writes tag_len bytes into tag buffer.
 */
int mbedcrypto_aes_ccm_final(struct mbedcrypto_aes_ccm_ctx *ctx,
		uint8_t *tag, size_t tag_len);

/*
 * Cleanup / zeroize the AES-CCM context.
 */
void mbedcrypto_aes_ccm_cleanup(struct mbedcrypto_aes_ccm_ctx *ctx);

/*
 * One-shot AES-CCM authenticated encryption.
 * Writes ciphertext to output and tag to tag.
 */
int mbedcrypto_aes_ccm_encrypt(struct mbedcrypto_aes_ccm_ctx *ctx,
		const uint8_t *nonce, size_t nonce_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, uint8_t *tag, size_t tag_len);

/*
 * One-shot AES-CCM authenticated decryption.
 * Decrypts input to output, then verifies the tag.
 * Returns -EBADMSG on authentication failure (output is zeroed).
 */
int mbedcrypto_aes_ccm_decrypt(struct mbedcrypto_aes_ccm_ctx *ctx,
		const uint8_t *nonce, size_t nonce_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, const uint8_t *tag, size_t tag_len);

/* ================================================================== */
/*  SM4-CCM (RFC 8998) - guarded by CONFIG_MBEDCRYPTO_SM4             */
/* ================================================================== */

#include <mbedcrypto/sm4.h>

struct mbedcrypto_sm4_ccm_ctx {
	struct mbedcrypto_sm4_ctx sm4;
	struct ccm_base base;
};

#if defined(CONFIG_MBEDCRYPTO_SM4)

int mbedcrypto_sm4_ccm_setkey(struct mbedcrypto_sm4_ccm_ctx *ctx,
		const uint8_t *key, unsigned int keybits);

int mbedcrypto_sm4_ccm_start(struct mbedcrypto_sm4_ccm_ctx *ctx, int dir,
		const uint8_t *nonce, size_t nonce_len);

int mbedcrypto_sm4_ccm_set_len(struct mbedcrypto_sm4_ccm_ctx *ctx,
		size_t aad_len, size_t payload_len, size_t tag_len);

int mbedcrypto_sm4_ccm_update_aad(struct mbedcrypto_sm4_ccm_ctx *ctx,
		const uint8_t *aad, size_t len);

int mbedcrypto_sm4_ccm_update(struct mbedcrypto_sm4_ccm_ctx *ctx,
		const uint8_t *input, size_t len,
		uint8_t *output, size_t *olen);

int mbedcrypto_sm4_ccm_final(struct mbedcrypto_sm4_ccm_ctx *ctx,
		uint8_t *tag, size_t tag_len);

void mbedcrypto_sm4_ccm_cleanup(struct mbedcrypto_sm4_ccm_ctx *ctx);

int mbedcrypto_sm4_ccm_encrypt(struct mbedcrypto_sm4_ccm_ctx *ctx,
		const uint8_t *nonce, size_t nonce_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, uint8_t *tag, size_t tag_len);

int mbedcrypto_sm4_ccm_decrypt(struct mbedcrypto_sm4_ccm_ctx *ctx,
		const uint8_t *nonce, size_t nonce_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, const uint8_t *tag, size_t tag_len);

#else /* !CONFIG_MBEDCRYPTO_SM4 */

static inline int mbedcrypto_sm4_ccm_setkey(
		struct mbedcrypto_sm4_ccm_ctx *ctx,
		const uint8_t *key, unsigned int keybits)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm4_ccm_start(
		struct mbedcrypto_sm4_ccm_ctx *ctx, int dir,
		const uint8_t *nonce, size_t nonce_len)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm4_ccm_set_len(
		struct mbedcrypto_sm4_ccm_ctx *ctx,
		size_t aad_len, size_t payload_len, size_t tag_len)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm4_ccm_update_aad(
		struct mbedcrypto_sm4_ccm_ctx *ctx,
		const uint8_t *aad, size_t len)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm4_ccm_update(
		struct mbedcrypto_sm4_ccm_ctx *ctx,
		const uint8_t *input, size_t len,
		uint8_t *output, size_t *olen)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm4_ccm_final(
		struct mbedcrypto_sm4_ccm_ctx *ctx,
		uint8_t *tag, size_t tag_len)
{ return -ENOTSUP; }
static inline void mbedcrypto_sm4_ccm_cleanup(
		struct mbedcrypto_sm4_ccm_ctx *ctx) { }
static inline int mbedcrypto_sm4_ccm_encrypt(
		struct mbedcrypto_sm4_ccm_ctx *ctx,
		const uint8_t *nonce, size_t nonce_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, uint8_t *tag, size_t tag_len)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm4_ccm_decrypt(
		struct mbedcrypto_sm4_ccm_ctx *ctx,
		const uint8_t *nonce, size_t nonce_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, const uint8_t *tag, size_t tag_len)
{ return -ENOTSUP; }

#endif /* CONFIG_MBEDCRYPTO_SM4 */

#endif /* _MBEDCRYPTO_CCM_H */
