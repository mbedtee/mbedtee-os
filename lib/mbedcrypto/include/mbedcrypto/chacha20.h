/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * ChaCha20-Poly1305 AEAD cipher (RFC 8439)
 */

#ifndef _MBEDCRYPTO_CHACHA20_H
#define _MBEDCRYPTO_CHACHA20_H

#include <mbedcrypto/types.h>

#define MBEDCRYPTO_CHACHA20_KEY_SIZE   32
#define MBEDCRYPTO_CHACHA20_NONCE_SIZE 12
#define MBEDCRYPTO_POLY1305_TAG_SIZE   16

/*
 * ChaCha20 stream cipher context.
 */
struct mbedcrypto_chacha20_ctx {
	uint32_t state[16]; /* internal state matrix */
	uint8_t keystream[64]; /* current keystream block */
	size_t off; /* offset into keystream */
};

/*
 * Poly1305 one-time authenticator context.
 */
struct mbedcrypto_poly1305_ctx {
	uint32_t r[5]; /* clamped key r */
	uint32_t s[4]; /* key s */
	uint32_t acc[5]; /* accumulator */
	uint8_t queue[16]; /* partial block buffer */
	size_t queue_len;
};

/*
 * ChaCha20-Poly1305 AEAD context.
 */
struct mbedcrypto_chachapoly_ctx {
	struct mbedcrypto_chacha20_ctx chacha;
	struct mbedcrypto_poly1305_ctx poly;
	size_t aad_len; /* accumulated AAD length */
	size_t ct_len; /* accumulated ciphertext length */
	int dir; /* 0 = encrypt, 1 = decrypt */
};

#if defined(CONFIG_MBEDCRYPTO_CHACHA20)

/* ChaCha20 stream cipher */
void mbedcrypto_chacha20_init(struct mbedcrypto_chacha20_ctx *ctx);
void mbedcrypto_chacha20_cleanup(struct mbedcrypto_chacha20_ctx *ctx);
int mbedcrypto_chacha20_setkey(struct mbedcrypto_chacha20_ctx *ctx,
		const uint8_t key[MBEDCRYPTO_CHACHA20_KEY_SIZE]);
int mbedcrypto_chacha20_set_nonce(struct mbedcrypto_chacha20_ctx *ctx,
	const uint8_t nonce[MBEDCRYPTO_CHACHA20_NONCE_SIZE], uint32_t counter);
int mbedcrypto_chacha20_update(struct mbedcrypto_chacha20_ctx *ctx,
		const uint8_t *input, size_t len, uint8_t *output);

/* Poly1305 MAC */
void mbedcrypto_poly1305_init(struct mbedcrypto_poly1305_ctx *ctx);
void mbedcrypto_poly1305_cleanup(struct mbedcrypto_poly1305_ctx *ctx);
int mbedcrypto_poly1305_setkey(struct mbedcrypto_poly1305_ctx *ctx,
		const uint8_t key[32]);
int mbedcrypto_poly1305_update(struct mbedcrypto_poly1305_ctx *ctx,
		const uint8_t *input, size_t len);
int mbedcrypto_poly1305_final(struct mbedcrypto_poly1305_ctx *ctx,
		uint8_t tag[MBEDCRYPTO_POLY1305_TAG_SIZE]);

/* ChaCha20-Poly1305 AEAD */
void mbedcrypto_chachapoly_init(struct mbedcrypto_chachapoly_ctx *ctx);
void mbedcrypto_chachapoly_cleanup(struct mbedcrypto_chachapoly_ctx *ctx);
int mbedcrypto_chachapoly_setkey(struct mbedcrypto_chachapoly_ctx *ctx,
		const uint8_t key[MBEDCRYPTO_CHACHA20_KEY_SIZE]);
int mbedcrypto_chachapoly_start(struct mbedcrypto_chachapoly_ctx *ctx,
	const uint8_t nonce[MBEDCRYPTO_CHACHA20_NONCE_SIZE], int dir);
int mbedcrypto_chachapoly_update_aad(struct mbedcrypto_chachapoly_ctx *ctx,
		const uint8_t *aad, size_t aad_len);
int mbedcrypto_chachapoly_update(struct mbedcrypto_chachapoly_ctx *ctx,
		const uint8_t *input, size_t len, uint8_t *output);
int mbedcrypto_chachapoly_final(struct mbedcrypto_chachapoly_ctx *ctx,
		uint8_t tag[MBEDCRYPTO_POLY1305_TAG_SIZE]);

#else /* !CONFIG_MBEDCRYPTO_CHACHA20 */

static inline void mbedcrypto_chacha20_init(
		struct mbedcrypto_chacha20_ctx *ctx) { }
static inline void mbedcrypto_chacha20_cleanup(
		struct mbedcrypto_chacha20_ctx *ctx) { }
static inline int mbedcrypto_chacha20_setkey(
		struct mbedcrypto_chacha20_ctx *ctx,
		const uint8_t key[MBEDCRYPTO_CHACHA20_KEY_SIZE])
{ return -ENOTSUP; }
static inline int mbedcrypto_chacha20_set_nonce(
		struct mbedcrypto_chacha20_ctx *ctx,
		const uint8_t nonce[MBEDCRYPTO_CHACHA20_NONCE_SIZE],
		uint32_t counter)
{ return -ENOTSUP; }
static inline int mbedcrypto_chacha20_update(
		struct mbedcrypto_chacha20_ctx *ctx,
		const uint8_t *input, size_t len, uint8_t *output)
{ return -ENOTSUP; }

static inline void mbedcrypto_poly1305_init(
		struct mbedcrypto_poly1305_ctx *ctx) { }
static inline void mbedcrypto_poly1305_cleanup(
		struct mbedcrypto_poly1305_ctx *ctx) { }
static inline int mbedcrypto_poly1305_setkey(
		struct mbedcrypto_poly1305_ctx *ctx,
		const uint8_t key[32])
{ return -ENOTSUP; }
static inline int mbedcrypto_poly1305_update(
		struct mbedcrypto_poly1305_ctx *ctx,
		const uint8_t *input, size_t len)
{ return -ENOTSUP; }
static inline int mbedcrypto_poly1305_final(
		struct mbedcrypto_poly1305_ctx *ctx,
		uint8_t tag[MBEDCRYPTO_POLY1305_TAG_SIZE])
{ return -ENOTSUP; }

static inline void mbedcrypto_chachapoly_init(
		struct mbedcrypto_chachapoly_ctx *ctx) { }
static inline void mbedcrypto_chachapoly_cleanup(
		struct mbedcrypto_chachapoly_ctx *ctx) { }
static inline int mbedcrypto_chachapoly_setkey(
		struct mbedcrypto_chachapoly_ctx *ctx,
		const uint8_t key[MBEDCRYPTO_CHACHA20_KEY_SIZE])
{ return -ENOTSUP; }
static inline int mbedcrypto_chachapoly_start(
		struct mbedcrypto_chachapoly_ctx *ctx,
		const uint8_t nonce[MBEDCRYPTO_CHACHA20_NONCE_SIZE],
		int dir)
{ return -ENOTSUP; }
static inline int mbedcrypto_chachapoly_update_aad(
		struct mbedcrypto_chachapoly_ctx *ctx,
		const uint8_t *aad, size_t aad_len)
{ return -ENOTSUP; }
static inline int mbedcrypto_chachapoly_update(
		struct mbedcrypto_chachapoly_ctx *ctx,
		const uint8_t *input, size_t len, uint8_t *output)
{ return -ENOTSUP; }
static inline int mbedcrypto_chachapoly_final(
		struct mbedcrypto_chachapoly_ctx *ctx,
		uint8_t tag[MBEDCRYPTO_POLY1305_TAG_SIZE])
{ return -ENOTSUP; }

#endif /* CONFIG_MBEDCRYPTO_CHACHA20 */

#endif /* _MBEDCRYPTO_CHACHA20_H */
