/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * RSA public-key cryptography (PKCS#1 v1.5, OAEP, PSS)
 */

#ifndef _MBEDCRYPTO_RSA_H
#define _MBEDCRYPTO_RSA_H

#include <mbedcrypto/bignum.h>

/* Padding modes. */
#define MBEDCRYPTO_RSA_PKCS1_V15   0
#define MBEDCRYPTO_RSA_PKCS1_V21   1	/* OAEP / PSS */

/* Hash identifiers for OAEP / PSS. */
#define MBEDCRYPTO_RSA_HASH_NONE     0
#define MBEDCRYPTO_RSA_HASH_MD5      1
#define MBEDCRYPTO_RSA_HASH_SHA1     2
#define MBEDCRYPTO_RSA_HASH_SHA224   3
#define MBEDCRYPTO_RSA_HASH_SHA256   4
#define MBEDCRYPTO_RSA_HASH_SHA384   5
#define MBEDCRYPTO_RSA_HASH_SHA512   6

/*
 * RSA context.
 * All bignums are cleaned up by mbedcrypto_rsa_cleanup().
 */
struct mbedcrypto_rsa_ctx {
	uint8_t padding;             /* PKCS1_V15 or PKCS1_V21 */
	uint8_t hash_id;             /* hash for OAEP / PSS */
	uint8_t mgf_hash_id;        /* separate MGF1 hash (0 = same as hash_id) */

	struct mbedcrypto_bignum N;     /* modulus */
	struct mbedcrypto_bignum E;     /* public exponent */
	struct mbedcrypto_bignum D;     /* private exponent */
	struct mbedcrypto_bignum P;     /* 1st prime factor */
	struct mbedcrypto_bignum Q;     /* 2nd prime factor */
	struct mbedcrypto_bignum DP;    /* D mod (P - 1) */
	struct mbedcrypto_bignum DQ;    /* D mod (Q - 1) */
	struct mbedcrypto_bignum QP;    /* Q^(-1) mod P */

	/* Cached values for performance */
	struct mbedcrypto_bignum unblind;    /* cached unblinding value */
	struct mbedcrypto_bignum blind;    /* cached blinding value */
	struct mbedcrypto_bignum RR_P;  /* R^2 mod P for Montgomery */
	struct mbedcrypto_bignum RR_Q;  /* R^2 mod Q for Montgomery */
	struct mbedcrypto_bignum RR_N;  /* R^2 mod N for Montgomery */
};

void mbedcrypto_rsa_init(struct mbedcrypto_rsa_ctx *ctx);
void mbedcrypto_rsa_cleanup(struct mbedcrypto_rsa_ctx *ctx);

/* Configure padding mode and hash (for OAEP/PSS). */
void mbedcrypto_rsa_configure(struct mbedcrypto_rsa_ctx *ctx,
		int padding, int hash_id);

/* Return modulus length in bytes. */
size_t mbedcrypto_rsa_len(const struct mbedcrypto_rsa_ctx *ctx);

/*
 * Import raw key components (big-endian).
 * Any component may be NULL (skipped).
 */
int mbedcrypto_rsa_import_components(struct mbedcrypto_rsa_ctx *ctx,
		const uint8_t *N, size_t N_len,
		const uint8_t *P, size_t P_len,
		const uint8_t *Q, size_t Q_len,
		const uint8_t *D, size_t D_len,
		const uint8_t *E, size_t E_len);

/*
 * Complete the private key by computing DP, DQ, QP from D, P, Q.
 * Must be called after import if CRT parameters are not provided.
 */
int mbedcrypto_rsa_derive_crt(struct mbedcrypto_rsa_ctx *ctx);

/*
 * Generate an RSA keypair.
 * nbits: key size (1024, 2048, 3072, 4096).
 * exponent: public exponent (typically 65537).
 */
int mbedcrypto_rsa_keygen(struct mbedcrypto_rsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		unsigned int nbits, int exponent);

/* ------------------------------------------------------------------ */
/*  Raw RSA (textbook, no padding)                                     */
/* ------------------------------------------------------------------ */

/* Public-key operation: output = input^E mod N. */
int mbedcrypto_rsa_raw_public(struct mbedcrypto_rsa_ctx *ctx,
		const uint8_t *input, uint8_t *output);

/* Private-key operation (CRT): output = input^D mod N. */
int mbedcrypto_rsa_raw_private(struct mbedcrypto_rsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		const uint8_t *input, uint8_t *output);

/* ------------------------------------------------------------------ */
/*  PKCS#1 v1.5 / OAEP encryption                                     */
/* ------------------------------------------------------------------ */

int mbedcrypto_rsa_encrypt(struct mbedcrypto_rsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		size_t ilen, const uint8_t *input,
		uint8_t *output);

int mbedcrypto_rsa_decrypt(struct mbedcrypto_rsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		size_t *olen, const uint8_t *input,
		uint8_t *output, size_t output_max_len);

/* ------------------------------------------------------------------ */
/*  PKCS#1 v1.5 / PSS signature                                       */
/* ------------------------------------------------------------------ */

int mbedcrypto_rsa_sign(struct mbedcrypto_rsa_ctx *ctx,
		mbedcrypto_rng_fn f_rng, void *p_rng,
		int hash_id, size_t hashlen,
		const uint8_t *hash, uint8_t *sig);

int mbedcrypto_rsa_verify(struct mbedcrypto_rsa_ctx *ctx,
		int hash_id, size_t hashlen,
		const uint8_t *hash, const uint8_t *sig);

#endif /* _MBEDCRYPTO_RSA_H */
