/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * HKDF key derivation function (RFC 5869)
 * Supports multiple hash algorithms for the underlying PRF.
 */

#ifndef _MBEDCRYPTO_HKDF_H
#define _MBEDCRYPTO_HKDF_H

#include <mbedcrypto/sha256.h>

/*
 * HMAC-SHA256 context
 */
struct mbedcrypto_hmac_sha256_ctx {
	struct mbedcrypto_sha256_ctx inner;
	struct mbedcrypto_sha256_ctx outer;
};

/*
 * HMAC-SHA256 operations
 */
int mbedcrypto_hmac_sha256_init(struct mbedcrypto_hmac_sha256_ctx *ctx,
		const uint8_t *key, size_t key_len);
int mbedcrypto_hmac_sha256_update(struct mbedcrypto_hmac_sha256_ctx *ctx,
		const uint8_t *data, size_t len);
int mbedcrypto_hmac_sha256_final(struct mbedcrypto_hmac_sha256_ctx *ctx,
		uint8_t mac[MBEDCRYPTO_SHA256_HASHSIZE]);
void mbedcrypto_hmac_sha256_cleanup(struct mbedcrypto_hmac_sha256_ctx *ctx);

/*
 * One-shot HMAC-SHA256
 */
int mbedcrypto_hmac_sha256(const uint8_t *key, size_t key_len,
		const uint8_t *data, size_t data_len,
		uint8_t mac[MBEDCRYPTO_SHA256_HASHSIZE]);

/*
 * HKDF-Extract (RFC 5869 Section 2.2)
 * Outputs a 32-byte pseudorandom key (PRK).
 * salt may be NULL (uses all-zero salt of hash length).
 */
int mbedcrypto_hkdf_extract(const uint8_t *salt, size_t salt_len,
		const uint8_t *ikm, size_t ikm_len,
		uint8_t prk[MBEDCRYPTO_SHA256_HASHSIZE]);

/*
 * HKDF-Expand (RFC 5869 Section 2.3)
 * Outputs up to 255 * 32 bytes of key material.
 */
int mbedcrypto_hkdf_expand(const uint8_t prk[MBEDCRYPTO_SHA256_HASHSIZE],
		const uint8_t *info, size_t info_len,
		uint8_t *okm, size_t okm_len);

/*
 * HKDF full (Extract-then-Expand)
 */
int mbedcrypto_hkdf_derive(const uint8_t *salt, size_t salt_len,
		const uint8_t *ikm, size_t ikm_len,
		const uint8_t *info, size_t info_len,
		uint8_t *okm, size_t okm_len);

/*
 * Generic HKDF with selectable hash algorithm.
 * hash_id: one of MBEDCRYPTO_HASH_* constants.
 */
int mbedcrypto_hkdf_derive_hash(int hash_id,
		const uint8_t *salt, size_t salt_len,
		const uint8_t *ikm, size_t ikm_len,
		const uint8_t *info, size_t info_len,
		uint8_t *okm, size_t okm_len);

#endif /* _MBEDCRYPTO_HKDF_H */
