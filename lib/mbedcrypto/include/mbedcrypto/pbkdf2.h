/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * PBKDF2 key derivation (RFC 8018)
 */

#ifndef _MBEDCRYPTO_PBKDF2_H
#define _MBEDCRYPTO_PBKDF2_H

#include <mbedcrypto/types.h>

#if defined(CONFIG_MBEDCRYPTO_PBKDF2)

/*
 * PBKDF2-HMAC key derivation.
 *
 * hash_id: one of MBEDCRYPTO_HASH_* (from mbedcrypto.h).
 * password / plen: the input password.
 * salt / slen: the salt value.
 * iterations: iteration count (must be >= 1).
 * output / olen: receives the derived key material.
 *
 * Returns 0 on success, negative errno on failure.
 */
int mbedcrypto_pbkdf2_derive(int hash_id,
		const uint8_t *password, size_t plen,
		const uint8_t *salt, size_t slen,
		unsigned int iterations,
		uint8_t *output, size_t olen);

#else /* !CONFIG_MBEDCRYPTO_PBKDF2 */

static inline int mbedcrypto_pbkdf2_derive(int hash_id,
		const uint8_t *password, size_t plen,
		const uint8_t *salt, size_t slen,
		unsigned int iterations,
		uint8_t *output, size_t olen)
{
	return -ENOTSUP;
}

#endif /* CONFIG_MBEDCRYPTO_PBKDF2 */

#endif /* _MBEDCRYPTO_PBKDF2_H */
