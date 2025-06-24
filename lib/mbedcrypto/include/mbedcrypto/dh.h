/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Diffie-Hellman key exchange
 */

#ifndef _MBEDCRYPTO_DH_H
#define _MBEDCRYPTO_DH_H

#include <mbedcrypto/bignum.h>

struct mbedcrypto_dh_ctx {
	struct mbedcrypto_bignum P;   /* prime modulus */
	struct mbedcrypto_bignum G;   /* generator */
	struct mbedcrypto_bignum X;   /* our secret value */
	struct mbedcrypto_bignum GX;  /* our public value:   G^X mod P */
	struct mbedcrypto_bignum GY;  /* peer's public value: G^Y mod P */
	struct mbedcrypto_bignum RR;  /* cached R^2 mod P for Montgomery */
};

void mbedcrypto_dh_init(struct mbedcrypto_dh_ctx *ctx);
void mbedcrypto_dh_cleanup(struct mbedcrypto_dh_ctx *ctx);

/* Return |P| in bytes. */
size_t mbedcrypto_dh_len(const struct mbedcrypto_dh_ctx *ctx);

/*
 * Generate keypair (X, GX = G^X mod P).
 * x_size: desired byte-length for the private value X.
 * output / olen: receives the raw public value GX (big-endian,
 *                zero-padded to |P| bytes).
 */
int mbedcrypto_dh_gen_public(struct mbedcrypto_dh_ctx *ctx,
		int x_size, uint8_t *output, size_t olen,
		mbedcrypto_rng_fn f_rng, void *p_rng);

/*
 * Derive shared secret: output = GY^X mod P.
 * output_size: buffer capacity. *olen receives actual length.
 */
int mbedcrypto_dh_derive_shared(struct mbedcrypto_dh_ctx *ctx,
		uint8_t *output, size_t output_size, size_t *olen,
		mbedcrypto_rng_fn f_rng, void *p_rng);

#endif /* _MBEDCRYPTO_DH_H */
