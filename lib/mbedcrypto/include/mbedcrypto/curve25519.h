/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Ed25519 / X25519 (RFC 8032, RFC 7748)
 *
 * Ed25519: Edwards-curve Digital Signature Algorithm
 * X25519:  Diffie-Hellman key exchange on Curve25519
 */

#ifndef _MBEDCRYPTO_CURVE25519_H
#define _MBEDCRYPTO_CURVE25519_H

#include <mbedcrypto/types.h>

#define MBEDCRYPTO_X25519_KEY_SIZE   32
#define MBEDCRYPTO_ED25519_SIG_SIZE  64
#define MBEDCRYPTO_ED25519_KEY_SIZE  32

#if defined(CONFIG_MBEDCRYPTO_CURVE25519)

/*
 * X25519 Diffie-Hellman.
 */

/* Compute a public key from a private key. */
int mbedcrypto_x25519_calc_public(
		uint8_t pub[MBEDCRYPTO_X25519_KEY_SIZE],
		const uint8_t priv[MBEDCRYPTO_X25519_KEY_SIZE]);

/* Compute the shared secret: out = X25519(our_priv, their_pub). */
int mbedcrypto_x25519_calc_secret(
		uint8_t secret[MBEDCRYPTO_X25519_KEY_SIZE],
		const uint8_t our_priv[MBEDCRYPTO_X25519_KEY_SIZE],
		const uint8_t their_pub[MBEDCRYPTO_X25519_KEY_SIZE]);

/* Generate an X25519 keypair. */
int mbedcrypto_x25519_gen_keypair(
		uint8_t pub[MBEDCRYPTO_X25519_KEY_SIZE],
		uint8_t priv[MBEDCRYPTO_X25519_KEY_SIZE],
		mbedcrypto_rng_fn f_rng, void *p_rng);

/*
 * Ed25519 digital signatures.
 */

/* Generate an Ed25519 keypair (seed -> private, derive public). */
int mbedcrypto_ed25519_gen_keypair(
		uint8_t pub[MBEDCRYPTO_ED25519_KEY_SIZE],
		uint8_t priv[2 * MBEDCRYPTO_ED25519_KEY_SIZE],
		mbedcrypto_rng_fn f_rng, void *p_rng);

/* Sign a message with Ed25519. */
int mbedcrypto_ed25519_sign(
		uint8_t sig[MBEDCRYPTO_ED25519_SIG_SIZE],
		const uint8_t *msg, size_t msg_len,
		const uint8_t priv[2 * MBEDCRYPTO_ED25519_KEY_SIZE]);

/* Verify an Ed25519 signature. */
int mbedcrypto_ed25519_verify(
		const uint8_t sig[MBEDCRYPTO_ED25519_SIG_SIZE],
		const uint8_t *msg, size_t msg_len,
		const uint8_t pub[MBEDCRYPTO_ED25519_KEY_SIZE]);

#else /* !CONFIG_MBEDCRYPTO_CURVE25519 */

static inline int mbedcrypto_x25519_calc_public(
		uint8_t pub[MBEDCRYPTO_X25519_KEY_SIZE],
		const uint8_t priv[MBEDCRYPTO_X25519_KEY_SIZE])
{ return -ENOTSUP; }

static inline int mbedcrypto_x25519_calc_secret(
		uint8_t secret[MBEDCRYPTO_X25519_KEY_SIZE],
		const uint8_t our_priv[MBEDCRYPTO_X25519_KEY_SIZE],
		const uint8_t their_pub[MBEDCRYPTO_X25519_KEY_SIZE])
{ return -ENOTSUP; }

static inline int mbedcrypto_x25519_gen_keypair(
		uint8_t pub[MBEDCRYPTO_X25519_KEY_SIZE],
		uint8_t priv[MBEDCRYPTO_X25519_KEY_SIZE],
		mbedcrypto_rng_fn f_rng, void *p_rng)
{ return -ENOTSUP; }

static inline int mbedcrypto_ed25519_gen_keypair(
		uint8_t pub[MBEDCRYPTO_ED25519_KEY_SIZE],
		uint8_t priv[2 * MBEDCRYPTO_ED25519_KEY_SIZE],
		mbedcrypto_rng_fn f_rng, void *p_rng)
{ return -ENOTSUP; }

static inline int mbedcrypto_ed25519_sign(
		uint8_t sig[MBEDCRYPTO_ED25519_SIG_SIZE],
		const uint8_t *msg, size_t msg_len,
		const uint8_t priv[2 * MBEDCRYPTO_ED25519_KEY_SIZE])
{ return -ENOTSUP; }

static inline int mbedcrypto_ed25519_verify(
		const uint8_t sig[MBEDCRYPTO_ED25519_SIG_SIZE],
		const uint8_t *msg, size_t msg_len,
		const uint8_t pub[MBEDCRYPTO_ED25519_KEY_SIZE])
{ return -ENOTSUP; }

#endif /* CONFIG_MBEDCRYPTO_CURVE25519 */

#endif /* _MBEDCRYPTO_CURVE25519_H */
