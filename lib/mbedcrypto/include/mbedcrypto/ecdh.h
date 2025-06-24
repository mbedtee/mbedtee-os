/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Elliptic Curve Diffie-Hellman (ECDH)
 */

#ifndef _MBEDCRYPTO_ECDH_H
#define _MBEDCRYPTO_ECDH_H

#include <mbedcrypto/ecp.h>

/*
 * ECDH context.
 *
 *  grp: curve group parameters
 *  d:   our private scalar
 *  Q:   our public point  (optional, not needed for calc_secret)
 *  Qp:  peer's public point
 */
struct mbedcrypto_ecdh_ctx {
	struct mbedcrypto_ecp_group grp;
	struct mbedcrypto_bignum d;
	struct mbedcrypto_ecp_point Q;
	struct mbedcrypto_ecp_point Qp;
};

void mbedcrypto_ecdh_init(struct mbedcrypto_ecdh_ctx *ctx);
void mbedcrypto_ecdh_cleanup(struct mbedcrypto_ecdh_ctx *ctx);

/*
 * Setup ECDH context: load curve, set our private key, set peer's public key.
 *
 * grp_id:   curve identifier (e.g., MBEDCRYPTO_ECP_DP_SECP256R1).
 * priv:     our private scalar.
 * peer_pub: peer's public point.
 *
 * Returns 0 on success, negative errno on error.
 */
int mbedcrypto_ecdh_setup(struct mbedcrypto_ecdh_ctx *ctx,
		int grp_id,
		const struct mbedcrypto_bignum *priv,
		const struct mbedcrypto_ecp_point *peer_pub);

/*
 * Compute the shared secret:  z = d * Qp.
 *
 * For short-Weierstrass curves the output is the X coordinate of the
 * resulting point, zero-padded to the field size.
 *
 * For Curve25519 the output is the X coordinate (u-coordinate).
 *
 * olen: set to the number of bytes written.
 * buf/blen: output buffer and its capacity.
 * f_rng/p_rng: optional RNG (unused, present for API compatibility).
 *
 * Returns 0 on success, negative errno on error.
 */
int mbedcrypto_ecdh_derive_shared(struct mbedcrypto_ecdh_ctx *ctx,
		size_t *olen, uint8_t *buf, size_t blen,
		mbedcrypto_rng_fn f_rng, void *p_rng);

#endif /* _MBEDCRYPTO_ECDH_H */
