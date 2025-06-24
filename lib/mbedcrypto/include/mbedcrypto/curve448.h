/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Ed448 / X448 (RFC 8032, RFC 7748)
 *
 * Ed448:  Edwards-curve Digital Signature Algorithm (Goldilocks)
 * X448:   Diffie-Hellman key exchange on Curve448
 */

#ifndef _MBEDCRYPTO_CURVE448_H
#define _MBEDCRYPTO_CURVE448_H

#include <mbedcrypto/types.h>

#define MBEDCRYPTO_X448_KEY_SIZE    56
#define MBEDCRYPTO_ED448_SIG_SIZE   114
#define MBEDCRYPTO_ED448_KEY_SIZE   57

#if defined(CONFIG_MBEDCRYPTO_CURVE448)

/*
 * X448 Diffie-Hellman.
 */

/* Compute a public key from a private key. */
int mbedcrypto_x448_calc_public(
		uint8_t pub[MBEDCRYPTO_X448_KEY_SIZE],
		const uint8_t priv[MBEDCRYPTO_X448_KEY_SIZE]);

/* Compute the shared secret: out = X448(our_priv, their_pub). */
int mbedcrypto_x448_calc_secret(
		uint8_t secret[MBEDCRYPTO_X448_KEY_SIZE],
		const uint8_t our_priv[MBEDCRYPTO_X448_KEY_SIZE],
		const uint8_t their_pub[MBEDCRYPTO_X448_KEY_SIZE]);

/* Generate an X448 keypair. */
int mbedcrypto_x448_gen_keypair(
		uint8_t pub[MBEDCRYPTO_X448_KEY_SIZE],
		uint8_t priv[MBEDCRYPTO_X448_KEY_SIZE],
		mbedcrypto_rng_fn f_rng, void *p_rng);

/*
 * Ed448 digital signatures.
 */

/* Generate an Ed448 keypair. */
int mbedcrypto_ed448_gen_keypair(
		uint8_t pub[MBEDCRYPTO_ED448_KEY_SIZE],
		uint8_t priv[2 * MBEDCRYPTO_ED448_KEY_SIZE],
		mbedcrypto_rng_fn f_rng, void *p_rng);

/* Sign a message with Ed448. */
int mbedcrypto_ed448_sign(
		uint8_t sig[MBEDCRYPTO_ED448_SIG_SIZE],
		const uint8_t *msg, size_t msg_len,
		const uint8_t priv[2 * MBEDCRYPTO_ED448_KEY_SIZE]);

/* Verify an Ed448 signature. */
int mbedcrypto_ed448_verify(
		const uint8_t sig[MBEDCRYPTO_ED448_SIG_SIZE],
		const uint8_t *msg, size_t msg_len,
		const uint8_t pub[MBEDCRYPTO_ED448_KEY_SIZE]);

#else /* !CONFIG_MBEDCRYPTO_CURVE448 */

static inline int mbedcrypto_x448_calc_public(
		uint8_t pub[MBEDCRYPTO_X448_KEY_SIZE],
		const uint8_t priv[MBEDCRYPTO_X448_KEY_SIZE])
{ return -ENOTSUP; }

static inline int mbedcrypto_x448_calc_secret(
		uint8_t secret[MBEDCRYPTO_X448_KEY_SIZE],
		const uint8_t our_priv[MBEDCRYPTO_X448_KEY_SIZE],
		const uint8_t their_pub[MBEDCRYPTO_X448_KEY_SIZE])
{ return -ENOTSUP; }

static inline int mbedcrypto_x448_gen_keypair(
		uint8_t pub[MBEDCRYPTO_X448_KEY_SIZE],
		uint8_t priv[MBEDCRYPTO_X448_KEY_SIZE],
		mbedcrypto_rng_fn f_rng, void *p_rng)
{ return -ENOTSUP; }

static inline int mbedcrypto_ed448_gen_keypair(
		uint8_t pub[MBEDCRYPTO_ED448_KEY_SIZE],
		uint8_t priv[2 * MBEDCRYPTO_ED448_KEY_SIZE],
		mbedcrypto_rng_fn f_rng, void *p_rng)
{ return -ENOTSUP; }

static inline int mbedcrypto_ed448_sign(
		uint8_t sig[MBEDCRYPTO_ED448_SIG_SIZE],
		const uint8_t *msg, size_t msg_len,
		const uint8_t priv[2 * MBEDCRYPTO_ED448_KEY_SIZE])
{ return -ENOTSUP; }

static inline int mbedcrypto_ed448_verify(
		const uint8_t sig[MBEDCRYPTO_ED448_SIG_SIZE],
		const uint8_t *msg, size_t msg_len,
		const uint8_t pub[MBEDCRYPTO_ED448_KEY_SIZE])
{ return -ENOTSUP; }

#endif /* CONFIG_MBEDCRYPTO_CURVE448 */

#endif /* _MBEDCRYPTO_CURVE448_H */
