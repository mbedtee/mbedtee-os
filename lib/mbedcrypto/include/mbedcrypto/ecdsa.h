/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Elliptic Curve Digital Signature Algorithm (ECDSA)
 */

#ifndef _MBEDCRYPTO_ECDSA_H
#define _MBEDCRYPTO_ECDSA_H

#include <mbedcrypto/ecp.h>

/*
 * Maximum signature length in bytes (raw r || s).
 * Each component is (key_bits/8) bytes, zero-padded big-endian.
 */
#define MBEDCRYPTO_ECDSA_MAX_SIG_LEN(bits) (2 * (((bits) + 7) / 8))

/*
 * ECDSA context is an ECC keypair: group + private scalar d + public point Q.
 */
struct mbedcrypto_ecdsa_ctx {
	struct mbedcrypto_ecp_group grp;
	struct mbedcrypto_bignum d;
	struct mbedcrypto_ecp_point Q;
};

void mbedcrypto_ecdsa_init(struct mbedcrypto_ecdsa_ctx *ctx);
void mbedcrypto_ecdsa_cleanup(struct mbedcrypto_ecdsa_ctx *ctx);

/*
 * Sign: compute ECDSA (r,s) over digest, write raw signature.
 *
 * hash_id: hash algorithm used (for future deterministic ECDSA; currently unused).
 * digest/dlen: hash of the message.
 * sig/sig_size: output buffer and its capacity.
 * slen: on success, set to actual signature length.
 * f_rng/p_rng: random number generator for ephemeral key k.
 *
 * Returns 0 on success, negative errno on error.
 */
int mbedcrypto_ecdsa_sign(struct mbedcrypto_ecdsa_ctx *ctx,
		int hash_id,
		const uint8_t *digest, size_t dlen,
		uint8_t *sig, size_t sig_size, size_t *slen,
		mbedcrypto_rng_fn f_rng, void *p_rng);

/*
 * Verify: decode raw signature, verify ECDSA (r,s) against digest.
 *
 * digest/dlen: hash of the message.
 * sig/slen: raw signature (r || s).
 *
 * Returns 0 on valid signature, -EBADMSG on invalid.
 */
int mbedcrypto_ecdsa_verify(struct mbedcrypto_ecdsa_ctx *ctx,
		const uint8_t *digest, size_t dlen,
		const uint8_t *sig, size_t slen);

/*
 * Maximum DER-encoded ECDSA signature length.
 */
#define MBEDCRYPTO_ECDSA_MAX_DER_SIG_LEN(bits) \
	(3 + 2 * (3 + ((bits) / 8 + 1)))

/*
 * Sign: produce DER-encoded SEQUENCE { INTEGER r, INTEGER s }.
 */
int mbedcrypto_ecdsa_sign_der(struct mbedcrypto_ecdsa_ctx *ctx,
		int hash_id,
		const uint8_t *digest, size_t dlen,
		uint8_t *sig, size_t sig_size, size_t *slen,
		mbedcrypto_rng_fn f_rng, void *p_rng);

/*
 * Verify: decode DER-encoded signature, verify ECDSA (r,s).
 */
int mbedcrypto_ecdsa_verify_der(struct mbedcrypto_ecdsa_ctx *ctx,
		const uint8_t *digest, size_t dlen,
		const uint8_t *sig, size_t slen);

#endif /* _MBEDCRYPTO_ECDSA_H */
