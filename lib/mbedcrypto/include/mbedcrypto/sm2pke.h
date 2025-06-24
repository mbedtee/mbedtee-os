/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * SM2 Public Key Encryption (GB/T 32918.4-2016)
 *
 * Encrypts arbitrary length data using the SM2 curve and SM3 hash.
 * Ciphertext format: C1 || C3 || C2
 *   C1 = 04 || x1 || y1  (uncompressed EC point, 65 bytes)
 *   C3 = SM3(x2 || M || y2)  (32 bytes)
 *   C2 = M XOR KDF(x2 || y2, klen)  (same length as M)
 */

#ifndef _MBEDCRYPTO_SM2PKE_H
#define _MBEDCRYPTO_SM2PKE_H

#include <mbedcrypto/ecp.h>
#include <mbedcrypto/sm3.h>

/*
 * SM2 PKE context - reuses SM2 curve + keypair.
 */
struct mbedcrypto_sm2pke_ctx {
	struct mbedcrypto_ecp_group grp;
	struct mbedcrypto_bignum d;         /* private scalar (decrypt) */
	struct mbedcrypto_ecp_point Q;      /* public point (encrypt) */
};

#if defined(CONFIG_MBEDCRYPTO_SM2)

void mbedcrypto_sm2pke_init(struct mbedcrypto_sm2pke_ctx *ctx);
void mbedcrypto_sm2pke_cleanup(struct mbedcrypto_sm2pke_ctx *ctx);

/*
 * Load the SM2 curve into the context.
 */
int mbedcrypto_sm2pke_load_group(struct mbedcrypto_sm2pke_ctx *ctx);

/*
 * SM2 encrypt.
 *
 * input/ilen: plaintext
 * output: buffer for ciphertext (at least ilen + 97 bytes)
 * olen: on success, actual ciphertext length
 * f_rng/p_rng: random number generator
 *
 * Returns 0 on success.
 */
int mbedcrypto_sm2pke_encrypt(struct mbedcrypto_sm2pke_ctx *ctx,
		const uint8_t *input, size_t ilen,
		uint8_t *output, size_t *olen,
		mbedcrypto_rng_fn f_rng, void *p_rng);

/*
 * SM2 decrypt.
 *
 * input/ilen: ciphertext (C1 || C3 || C2)
 * output: buffer for plaintext (at least ilen - 97 bytes)
 * olen: on success, actual plaintext length
 *
 * Returns 0 on success, -EBADMSG if verification fails.
 */
int mbedcrypto_sm2pke_decrypt(struct mbedcrypto_sm2pke_ctx *ctx,
		const uint8_t *input, size_t ilen,
		uint8_t *output, size_t *olen);

#else /* !CONFIG_MBEDCRYPTO_SM2 */

static inline void mbedcrypto_sm2pke_init(
		struct mbedcrypto_sm2pke_ctx *ctx) { }
static inline void mbedcrypto_sm2pke_cleanup(
		struct mbedcrypto_sm2pke_ctx *ctx) { }
static inline int mbedcrypto_sm2pke_load_group(
		struct mbedcrypto_sm2pke_ctx *ctx)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm2pke_encrypt(
		struct mbedcrypto_sm2pke_ctx *ctx,
		const uint8_t *input, size_t ilen,
		uint8_t *output, size_t *olen,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm2pke_decrypt(
		struct mbedcrypto_sm2pke_ctx *ctx,
		const uint8_t *input, size_t ilen,
		uint8_t *output, size_t *olen)
{ return -ENOTSUP; }

#endif /* CONFIG_MBEDCRYPTO_SM2 */

#endif /* _MBEDCRYPTO_SM2PKE_H */
