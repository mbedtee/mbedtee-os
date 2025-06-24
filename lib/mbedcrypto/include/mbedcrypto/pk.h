/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Public key / private key DER decoding/importing
 *
 * Supports RSA, ECC, and DH key formats commonly used in
 * TEE authentication and crypto operations.
 */

#ifndef _MBEDCRYPTO_PK_H
#define _MBEDCRYPTO_PK_H

#include <mbedcrypto/rsa.h>
#include <mbedcrypto/ecp.h>
#include <mbedcrypto/dh.h>

/*
 * Decode/import an RSA public key from DER encoding.
 *
 * Accepts both SubjectPublicKeyInfo (SPKI) format and bare
 * PKCS#1 RSAPublicKey format.  On success, rsa->N and rsa->E
 * are populated.
 *
 * The caller must call mbedcrypto_rsa_init() before and
 * mbedcrypto_rsa_cleanup() after use.
 */
int mbedcrypto_pk_decode_rsa_pubkey_der(struct mbedcrypto_rsa_ctx *rsa,
		const uint8_t *buf, size_t buflen);

/*
 * Decode/import a PKCS#1 RSAPrivateKey from DER encoding.
 *
 * Populates all CRT fields: N, E, D, P, Q, DP, DQ, QP.
 *
 * The caller must call mbedcrypto_rsa_init() before and
 * mbedcrypto_rsa_cleanup() after use.
 */
int mbedcrypto_pk_decode_rsa_privkey_der(struct mbedcrypto_rsa_ctx *rsa,
		const uint8_t *buf, size_t buflen);

/*
 * Decode/import an EC public key from an uncompressed point (04 || X || Y).
 *
 * Loads the curve identified by grp_id into key->grp, then reads the
 * public point into key->Q.
 */
int mbedcrypto_pk_decode_ec_pubkey(struct mbedcrypto_ecp_keypair *key,
		int grp_id, const uint8_t *buf, size_t buflen);

/*
 * Decode/import an EC private key from a raw scalar.
 *
 * Loads the curve identified by grp_id into key->grp, then reads the
 * private scalar into key->d.  The public point key->Q is NOT computed;
 * use ecp_mul(grp, &Q, &d, &grp.G) if needed.
 */
int mbedcrypto_pk_decode_ec_privkey(struct mbedcrypto_ecp_keypair *key,
		int grp_id, const uint8_t *buf, size_t buflen);

/*
 * Decode/import DH parameters from DER (DHParameter ::= SEQUENCE { P, G }).
 *
 * Populates ctx->P and ctx->G.
 */
int mbedcrypto_pk_decode_dh_params_der(struct mbedcrypto_dh_ctx *ctx,
		const uint8_t *buf, size_t buflen);

/* ------------------------------------------------------------------ */
/* DER encoding functions                                             */
/* ------------------------------------------------------------------ */

/*
 * Encode RSA public key as PKCS#1 RSAPublicKey DER.
 * SEQUENCE { INTEGER N, INTEGER E }.
 * Returns total DER size (> 0) written to buf, or negative errno.
 */
int mbedcrypto_pk_encode_rsa_pubkey_der(struct mbedcrypto_rsa_ctx *rsa,
		uint8_t *buf, size_t buflen);

/*
 * Encode RSA private key as PKCS#1 RSAPrivateKey DER.
 * SEQUENCE { version(0), N, E, D, P, Q, DP, DQ, QP }.
 * Returns total DER size (> 0) written to buf, or negative errno.
 */
int mbedcrypto_pk_encode_rsa_privkey_der(struct mbedcrypto_rsa_ctx *rsa,
		uint8_t *buf, size_t buflen);

/*
 * Encode EC public key as SubjectPublicKeyInfo DER (RFC 5480).
 * SEQUENCE { AlgorithmIdentifier, BIT STRING (04 || X || Y) }.
 * Returns total DER size (> 0) written to buf, or negative errno.
 */
int mbedcrypto_pk_encode_ec_pubkey_der(struct mbedcrypto_ecp_keypair *key,
		uint8_t *buf, size_t buflen);

/*
 * Encode EC private key as SEC1 ECPrivateKey DER (RFC 5915).
 * SEQUENCE { version(1), OCTET STRING d, [0] curve OID }.
 * Returns total DER size (> 0) written to buf, or negative errno.
 */
int mbedcrypto_pk_encode_ec_privkey_der(struct mbedcrypto_ecp_keypair *key,
		uint8_t *buf, size_t buflen);

/*
 * Decode/import an EC public key from SubjectPublicKeyInfo DER (RFC 5480).
 * Curve is determined from the embedded OID; no grp_id parameter needed.
 */
int mbedcrypto_pk_decode_ec_pubkey_der(struct mbedcrypto_ecp_keypair *key,
		const uint8_t *buf, size_t buflen);

/*
 * Decode/import an EC private key from SEC1 ECPrivateKey DER (RFC 5915).
 * Curve is determined from the embedded OID; no grp_id parameter needed.
 */
int mbedcrypto_pk_decode_ec_privkey_der(struct mbedcrypto_ecp_keypair *key,
		const uint8_t *buf, size_t buflen);

/* ------------------------------------------------------------------ */
/* File-based key importing (DER files only)                          */
/* ------------------------------------------------------------------ */

/*
 * Read a DER file and import an RSA public key.
 * Accepts both SubjectPublicKeyInfo and bare PKCS#1 RSAPublicKey.
 */
int mbedcrypto_pk_decode_rsa_pubkey_file(struct mbedcrypto_rsa_ctx *rsa,
		const char *path);

/*
 * Read a DER file and import a PKCS#1 RSAPrivateKey.
 */
int mbedcrypto_pk_decode_rsa_privkey_file(struct mbedcrypto_rsa_ctx *rsa,
		const char *path);

/*
 * Read a DER file and import an EC public key (SubjectPublicKeyInfo DER).
 */
int mbedcrypto_pk_decode_ec_pubkey_file(struct mbedcrypto_ecp_keypair *key,
		const char *path);

/*
 * Read a DER file and import an EC private key (SEC1 ECPrivateKey DER).
 */
int mbedcrypto_pk_decode_ec_privkey_file(struct mbedcrypto_ecp_keypair *key,
		const char *path);

/*
 * Read a DER file and import DH parameters.
 */
int mbedcrypto_pk_decode_dh_params_file(struct mbedcrypto_dh_ctx *ctx,
		const char *path);

/* ------------------------------------------------------------------ */
/* File-based key writing                                             */
/* ------------------------------------------------------------------ */

/*
 * Encode and write RSA public key (PKCS#1 DER) to a file.
 */
int mbedcrypto_pk_encode_rsa_pubkey_file(struct mbedcrypto_rsa_ctx *rsa,
		const char *path);

/*
 * Encode and write RSA private key (PKCS#1 DER) to a file.
 */
int mbedcrypto_pk_encode_rsa_privkey_file(struct mbedcrypto_rsa_ctx *rsa,
		const char *path);

/*
 * Encode and write EC public key (SubjectPublicKeyInfo DER) to a file.
 */
int mbedcrypto_pk_encode_ec_pubkey_file(struct mbedcrypto_ecp_keypair *key,
		const char *path);

/*
 * Encode and write EC private key (SEC1 ECPrivateKey DER) to a file.
 */
int mbedcrypto_pk_encode_ec_privkey_file(struct mbedcrypto_ecp_keypair *key,
		const char *path);

#endif /* _MBEDCRYPTO_PK_H */
