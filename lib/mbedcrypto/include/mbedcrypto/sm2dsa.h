/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * SM2 Digital Signature Algorithm (GB/T 32918.2-2016)
 *
 * Uses SM3 hash and the SM2 recommended 256-bit curve.
 */

#ifndef _MBEDCRYPTO_SM2DSA_H
#define _MBEDCRYPTO_SM2DSA_H

#include <mbedcrypto/ecp.h>
#include <mbedcrypto/sm3.h>

/*
 * Maximum SM2 signature length (raw r || s, each 32 bytes).
 */
#define MBEDCRYPTO_SM2DSA_MAX_SIG_LEN  64

/*
 * SM2 DSA context.
 */
struct mbedcrypto_sm2dsa_ctx {
	struct mbedcrypto_ecp_group grp;
	struct mbedcrypto_bignum d;         /* private scalar */
	struct mbedcrypto_ecp_point Q;      /* public point */
};

#if defined(CONFIG_MBEDCRYPTO_SM2)

void mbedcrypto_sm2dsa_init(struct mbedcrypto_sm2dsa_ctx *ctx);
void mbedcrypto_sm2dsa_cleanup(struct mbedcrypto_sm2dsa_ctx *ctx);

/*
 * Load the SM2 curve into the context.
 * Must be called before sign/verify.
 */
int mbedcrypto_sm2dsa_load_group(struct mbedcrypto_sm2dsa_ctx *ctx);

/*
 * Compute the SM2 Z value:
 *   Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
 *
 * id/idlen: user identity (default: "1234567812345678", 16 bytes)
 * z: output, 32 bytes
 */
int mbedcrypto_sm2_compute_z(const struct mbedcrypto_sm2dsa_ctx *ctx,
		const uint8_t *id, size_t idlen, uint8_t z[32]);

/*
 * SM2 sign: compute signature over a message hash e.
 *
 * e: the SM3 digest of (Z || M), 32 bytes
 * sig/sig_size: output buffer for raw signature (r || s)
 * slen: on success, actual signature length
 * f_rng/p_rng: random number generator for ephemeral k
 */
int mbedcrypto_sm2dsa_sign(struct mbedcrypto_sm2dsa_ctx *ctx,
		const uint8_t *e, size_t elen,
		uint8_t *sig, size_t sig_size, size_t *slen,
		mbedcrypto_rng_fn f_rng, void *p_rng);

/*
 * SM2 verify: verify a raw signature against digest e.
 *
 * e: the SM3 digest of (Z || M), 32 bytes
 * sig/slen: raw signature (r || s)
 *
 * Returns 0 on valid signature, -EBADMSG on invalid.
 */
int mbedcrypto_sm2dsa_verify(struct mbedcrypto_sm2dsa_ctx *ctx,
		const uint8_t *e, size_t elen,
		const uint8_t *sig, size_t slen);

/*
 * Maximum DER-encoded SM2 signature length.
 */
#define MBEDCRYPTO_SM2DSA_MAX_DER_SIG_LEN  72

/*
 * SM2 sign: produce DER-encoded SEQUENCE { INTEGER r, INTEGER s }.
 */
int mbedcrypto_sm2dsa_sign_der(struct mbedcrypto_sm2dsa_ctx *ctx,
		const uint8_t *e, size_t elen,
		uint8_t *sig, size_t sig_size, size_t *slen,
		mbedcrypto_rng_fn f_rng, void *p_rng);

/*
 * SM2 verify: verify a DER-encoded signature against digest e.
 */
int mbedcrypto_sm2dsa_verify_der(struct mbedcrypto_sm2dsa_ctx *ctx,
		const uint8_t *e, size_t elen,
		const uint8_t *sig, size_t slen);

#else /* !CONFIG_MBEDCRYPTO_SM2 */

static inline void mbedcrypto_sm2dsa_init(
		struct mbedcrypto_sm2dsa_ctx *ctx) { }
static inline void mbedcrypto_sm2dsa_cleanup(
		struct mbedcrypto_sm2dsa_ctx *ctx) { }
static inline int mbedcrypto_sm2dsa_load_group(
		struct mbedcrypto_sm2dsa_ctx *ctx)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm2_compute_z(
		const struct mbedcrypto_sm2dsa_ctx *ctx,
		const uint8_t *id, size_t idlen, uint8_t z[32])
{ return -ENOTSUP; }
static inline int mbedcrypto_sm2dsa_sign(
		struct mbedcrypto_sm2dsa_ctx *ctx,
		const uint8_t *e, size_t elen,
		uint8_t *sig, size_t sig_size, size_t *slen,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm2dsa_verify(
		struct mbedcrypto_sm2dsa_ctx *ctx,
		const uint8_t *e, size_t elen,
		const uint8_t *sig, size_t slen)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm2dsa_sign_der(
		struct mbedcrypto_sm2dsa_ctx *ctx,
		const uint8_t *e, size_t elen,
		uint8_t *sig, size_t sig_size, size_t *slen,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{ return -ENOTSUP; }
static inline int mbedcrypto_sm2dsa_verify_der(
		struct mbedcrypto_sm2dsa_ctx *ctx,
		const uint8_t *e, size_t elen,
		const uint8_t *sig, size_t slen)
{ return -ENOTSUP; }

#endif /* CONFIG_MBEDCRYPTO_SM2 */

#endif /* _MBEDCRYPTO_SM2DSA_H */
