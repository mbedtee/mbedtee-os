/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * GCM authenticated encryption (NIST SP 800-38D, RFC 8998)
 * AES-GCM and SM4-GCM (guarded by CONFIG_MBEDCRYPTO_SM4)
 */

#ifndef _MBEDCRYPTO_GCM_H
#define _MBEDCRYPTO_GCM_H

#include <mbedcrypto/aes.h>

#define MBEDCRYPTO_GCM_TAG_MAXSIZE  16

/* State values */
#define MBEDCRYPTO_GCM_STATE_NONE      0
#define MBEDCRYPTO_GCM_STATE_STARTED   1
#define MBEDCRYPTO_GCM_STATE_AAD       2
#define MBEDCRYPTO_GCM_STATE_DATA      3

/* Block cipher ECB function pointer for GCM */
typedef void (*gcm_ecb_fn)(const void *cipher,
		const uint8_t in[16], uint8_t out[16]);

/*
 * Common GCM base context shared by AES-GCM and SM4-GCM.
 * Holds the GHASH table, multi-part state, and a function
 * pointer for the underlying block cipher ECB operation.
 */
struct gcm_base {
	gcm_ecb_fn ecb;                 /* block cipher ECB encrypt */
	const void *cipher;             /* pointer to cipher context */
	uint64_t hl[16];                /* precalculated Htable low */
	uint64_t hh[16];                /* precalculated Htable high */
	uint8_t j0[16];                 /* initial counter J0 */
	uint8_t ctr[16];                /* working counter */
	uint8_t ghash[16];              /* GHASH accumulator */
	uint8_t buf[16];                /* partial block buffer (AAD/data) */
	uint8_t ectr[16];               /* saved keystream for partial data */
	size_t buf_len;                 /* bytes in partial buffer */
	size_t aad_len;                 /* total AAD bytes processed */
	size_t payload_len;             /* total payload bytes processed */
	uint8_t dir;                    /* encrypt or decrypt direction */
	uint8_t state;                  /* internal state machine */
};

/*
 * AES-GCM context
 */
struct mbedcrypto_aes_gcm_ctx {
	struct mbedcrypto_aes_ctx aes;
	struct gcm_base base;
};

/*
 * Initialize AES-GCM context with AES key.
 * keybits: 128, 192, or 256.
 */
int mbedcrypto_aes_gcm_setkey(struct mbedcrypto_aes_gcm_ctx *ctx,
		const uint8_t *key, unsigned int keybits);

/*
 * AES-GCM authenticated encryption (one-shot).
 * iv/iv_len: initialization vector (typically 12 bytes).
 * aad/aad_len: additional authenticated data (may be NULL/0).
 * input/len: plaintext.
 * output: ciphertext (same length as input).
 * tag/tag_len: authentication tag output (1..16 bytes).
 */
int mbedcrypto_aes_gcm_encrypt(struct mbedcrypto_aes_gcm_ctx *ctx,
		const uint8_t *iv, size_t iv_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output,
		uint8_t *tag, size_t tag_len);

/*
 * AES-GCM authenticated decryption (one-shot).
 * Returns 0 on success, -EBADMSG if the tag does not verify.
 */
int mbedcrypto_aes_gcm_decrypt(struct mbedcrypto_aes_gcm_ctx *ctx,
		const uint8_t *iv, size_t iv_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output,
		const uint8_t *tag, size_t tag_len);

/* ------------------------------------------------------------------ */
/*  Multi-part AES-GCM API                                            */
/*                                                                    */
/*  Usage: setkey -> start -> update_aad [0..n] -> update [0..n] -> final */
/* ------------------------------------------------------------------ */

/*
 * Start an AES-GCM operation.
 * dir: MBEDCRYPTO_AES_ENCRYPT or MBEDCRYPTO_AES_DECRYPT.
 * iv/iv_len: initialization vector (typically 12 bytes).
 */
int mbedcrypto_aes_gcm_start(struct mbedcrypto_aes_gcm_ctx *ctx, int dir,
		const uint8_t *iv, size_t iv_len);

/*
 * Feed additional authenticated data (AAD).
 * May be called multiple times. Must be done before gcm_update().
 */
int mbedcrypto_aes_gcm_update_aad(struct mbedcrypto_aes_gcm_ctx *ctx,
		const uint8_t *aad, size_t len);

/*
 * Encrypt or decrypt payload data.
 * May be called multiple times.
 * *olen receives the number of bytes written to output.
 * Output length equals input length.
 */
int mbedcrypto_aes_gcm_update(struct mbedcrypto_aes_gcm_ctx *ctx,
		const uint8_t *input, size_t len,
		uint8_t *output, size_t *olen);

/*
 * Finalize. Writes the authentication tag.
 */
int mbedcrypto_aes_gcm_final(struct mbedcrypto_aes_gcm_ctx *ctx,
		uint8_t *tag, size_t tag_len);

/*
 * Cleanup / zeroize the AES-GCM context.
 */
void mbedcrypto_aes_gcm_cleanup(struct mbedcrypto_aes_gcm_ctx *ctx);

/* ================================================================== */
/*  SM4-GCM (RFC 8998) - guarded by CONFIG_MBEDCRYPTO_SM4             */
/* ================================================================== */

#include <mbedcrypto/sm4.h>

struct mbedcrypto_sm4_gcm_ctx {
	struct mbedcrypto_sm4_ctx sm4;
	struct gcm_base base;
};

#if defined(CONFIG_MBEDCRYPTO_SM4)

int mbedcrypto_sm4_gcm_setkey(struct mbedcrypto_sm4_gcm_ctx *ctx,
		const uint8_t *key, unsigned int keybits);

int mbedcrypto_sm4_gcm_encrypt(struct mbedcrypto_sm4_gcm_ctx *ctx,
		const uint8_t *iv, size_t iv_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output,
		uint8_t *tag, size_t tag_len);

int mbedcrypto_sm4_gcm_decrypt(struct mbedcrypto_sm4_gcm_ctx *ctx,
		const uint8_t *iv, size_t iv_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output,
		const uint8_t *tag, size_t tag_len);

int mbedcrypto_sm4_gcm_start(struct mbedcrypto_sm4_gcm_ctx *ctx, int dir,
		const uint8_t *iv, size_t iv_len);

int mbedcrypto_sm4_gcm_update_aad(struct mbedcrypto_sm4_gcm_ctx *ctx,
		const uint8_t *aad, size_t len);

int mbedcrypto_sm4_gcm_update(struct mbedcrypto_sm4_gcm_ctx *ctx,
		const uint8_t *input, size_t len,
		uint8_t *output, size_t *olen);

int mbedcrypto_sm4_gcm_final(struct mbedcrypto_sm4_gcm_ctx *ctx,
		uint8_t *tag, size_t tag_len);

void mbedcrypto_sm4_gcm_cleanup(struct mbedcrypto_sm4_gcm_ctx *ctx);

#else /* !CONFIG_MBEDCRYPTO_SM4 */

static inline int mbedcrypto_sm4_gcm_setkey(
		struct mbedcrypto_sm4_gcm_ctx *ctx,
		const uint8_t *key, unsigned int keybits)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm4_gcm_encrypt(
		struct mbedcrypto_sm4_gcm_ctx *ctx,
		const uint8_t *iv, size_t iv_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, uint8_t *tag, size_t tag_len)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm4_gcm_decrypt(
		struct mbedcrypto_sm4_gcm_ctx *ctx,
		const uint8_t *iv, size_t iv_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, const uint8_t *tag, size_t tag_len)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm4_gcm_start(
		struct mbedcrypto_sm4_gcm_ctx *ctx, int dir,
		const uint8_t *iv, size_t iv_len)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm4_gcm_update_aad(
		struct mbedcrypto_sm4_gcm_ctx *ctx,
		const uint8_t *aad, size_t len)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm4_gcm_update(
		struct mbedcrypto_sm4_gcm_ctx *ctx,
		const uint8_t *input, size_t len,
		uint8_t *output, size_t *olen)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm4_gcm_final(
		struct mbedcrypto_sm4_gcm_ctx *ctx,
		uint8_t *tag, size_t tag_len)
{ return -ENOTSUP; }
static inline void mbedcrypto_sm4_gcm_cleanup(
		struct mbedcrypto_sm4_gcm_ctx *ctx) { }

#endif /* CONFIG_MBEDCRYPTO_SM4 */

#endif /* _MBEDCRYPTO_GCM_H */
