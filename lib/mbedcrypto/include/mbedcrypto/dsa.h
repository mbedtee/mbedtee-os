/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * DSA digital signatures (FIPS 186)
 */

#ifndef _MBEDCRYPTO_DSA_H
#define _MBEDCRYPTO_DSA_H

#include <mbedcrypto/bignum.h>

/*
 * Maximum raw signature size for a given Q bit length: r || s.
 */
#define MBEDCRYPTO_DSA_MAX_SIG_LEN(qbits) (2 * (((qbits) + 7) / 8))

struct mbedcrypto_dsa_ctx {
	struct mbedcrypto_bignum P;   /* prime modulus */
	struct mbedcrypto_bignum Q;   /* prime divisor (subgroup order) */
	struct mbedcrypto_bignum G;   /* generator */
	struct mbedcrypto_bignum Y;   /* public value:  Y = G^X mod P */
	struct mbedcrypto_bignum X;   /* private value */
};

void mbedcrypto_dsa_init(struct mbedcrypto_dsa_ctx *ctx);
void mbedcrypto_dsa_cleanup(struct mbedcrypto_dsa_ctx *ctx);

/* Validate public key: checks (P,Q) sizes, G range, Y range. */
int mbedcrypto_dsa_validate_pubkey(const struct mbedcrypto_dsa_ctx *ctx);

/* Validate private key: checks (P,Q) sizes, G range, X range. */
int mbedcrypto_dsa_validate_privkey(const struct mbedcrypto_dsa_ctx *ctx);

/*
 * Generate DSA domain parameters P, Q, G.
 * nbits: 512..1024 (multiple of 64), 2048, or 3072.
 */
int mbedcrypto_dsa_gen_params(struct mbedcrypto_dsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		unsigned int nbits);

/*
 * Generate key pair (X, Y) given existing domain parameters.
 */
int mbedcrypto_dsa_keygen(struct mbedcrypto_dsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng);

/*
 * Import raw key components (big-endian).
 * Any parameter may be NULL (skipped).
 */
int mbedcrypto_dsa_import_components(struct mbedcrypto_dsa_ctx *ctx,
		const uint8_t *P, size_t P_len,
		const uint8_t *Q, size_t Q_len,
		const uint8_t *G, size_t G_len,
		const uint8_t *Y, size_t Y_len,
		const uint8_t *X, size_t X_len);

/*
 * Export raw key components (big-endian).
 * Any parameter may be NULL (skipped).
 */
int mbedcrypto_dsa_export_components(const struct mbedcrypto_dsa_ctx *ctx,
		uint8_t *P, size_t P_len,
		uint8_t *Q, size_t Q_len,
		uint8_t *G, size_t G_len,
		uint8_t *Y, size_t Y_len,
		uint8_t *X, size_t X_len);

/*
 * Sign a message hash. Produces raw r (q_len bytes) || s (q_len bytes).
 * sig buffer should be at least MBEDCRYPTO_DSA_MAX_SIG_LEN(Q-bits) bytes.
 * *slen receives the actual signature length.
 */
int mbedcrypto_dsa_sign(struct mbedcrypto_dsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		unsigned int hashlen, const uint8_t *hash,
		uint8_t *sig, size_t *slen);

/*
 * Verify a raw DSA signature against a message hash.
 */
int mbedcrypto_dsa_verify(struct mbedcrypto_dsa_ctx *ctx,
		unsigned int hashlen, const uint8_t *hash,
		const uint8_t *sig, size_t slen);

/*
 * Maximum DER-encoded signature size for a given Q bit length.
 * SEQUENCE { INTEGER r, INTEGER s }
 */
#define MBEDCRYPTO_DSA_MAX_DER_SIG_LEN(qbits) \
	(3 + 2 * (3 + ((qbits) / 8 + 1)))

/*
 * Sign a message hash. Produces DER-encoded SEQUENCE{INTEGER r, INTEGER s}.
 * sig buffer should be at least MBEDCRYPTO_DSA_MAX_DER_SIG_LEN(Q-bits) bytes.
 */
int mbedcrypto_dsa_sign_der(struct mbedcrypto_dsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		unsigned int hashlen, const uint8_t *hash,
		uint8_t *sig, size_t sig_size, size_t *slen);

/*
 * Verify a DER-encoded DSA signature against a message hash.
 */
int mbedcrypto_dsa_verify_der(struct mbedcrypto_dsa_ctx *ctx,
		unsigned int hashlen, const uint8_t *hash,
		const uint8_t *sig, size_t slen);

#endif /* _MBEDCRYPTO_DSA_H */
