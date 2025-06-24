// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * PBKDF2 key derivation (RFC 8018)
 *
 * PBKDF2-HMAC: Password-Based Key Derivation Function 2
 */

#include <string.h>

#include <mbedcrypto.h>

int mbedcrypto_pbkdf2_derive(int hash_id,
		const uint8_t *password, size_t plen,
		const uint8_t *salt, size_t slen,
		unsigned int iterations,
		uint8_t *output, size_t olen)
{
	size_t hlen = mbedcrypto_hash_size(hash_id);
	uint32_t block_num = 1;
	uint8_t u[64]; /* max hash output (SHA-512 = 64) */
	uint8_t t[64];
	uint8_t int_be[4];
	size_t copy_len = 0;
	unsigned int j = 0;
	size_t k = 0;
	int ret = 0;

	if (!password || !output)
		return -EINVAL;
	if (iterations == 0 || hlen == 0)
		return -EINVAL;
	if (olen == 0)
		return 0;

	/*
	 * For each block i = 1..ceil(olen/hlen):
	 *   U_1 = HMAC(password, salt || INT32_BE(i))
	 *   U_j = HMAC(password, U_{j-1})   for j = 2..iterations
	 *   T_i = U_1 ^ U_2 ^ ... ^ U_iterations
	 * DK = T_1 || T_2 || ... (truncated to olen)
	 */
	while (olen > 0) {
		struct mbedcrypto_hmac_ctx hctx;

		/* U_1 = HMAC(password, salt || INT32_BE(block_num)) */
		mbedcrypto_put_be32(int_be, block_num);

		ret = mbedcrypto_hmac_init(&hctx, hash_id, password, plen);
		if (ret != 0)
			goto cleanup;
		if (salt && slen)
			mbedcrypto_hmac_update(&hctx, salt, slen);
		mbedcrypto_hmac_update(&hctx, int_be, 4);
		mbedcrypto_hmac_final(&hctx, u);
		mbedcrypto_hmac_cleanup(&hctx);

		memcpy(t, u, hlen);

		/* U_2 .. U_iterations */
		for (j = 1; j < iterations; j++) {
			ret = mbedcrypto_hmac_init(&hctx, hash_id,
						   password, plen);
			if (ret != 0)
				goto cleanup;
			mbedcrypto_hmac_update(&hctx, u, hlen);
			mbedcrypto_hmac_final(&hctx, u);
			mbedcrypto_hmac_cleanup(&hctx);

			for (k = 0; k < hlen; k++)
				t[k] ^= u[k];
		}

		/* Copy T_i to output */
		copy_len = (olen < hlen) ? olen : hlen;
		memcpy(output, t, copy_len);
		output += copy_len;
		olen -= copy_len;
		block_num++;
	}

	ret = 0;

cleanup:
	memset(u, 0, sizeof(u));
	memset(t, 0, sizeof(t));
	return ret;
}
