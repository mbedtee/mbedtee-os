// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Diffie-Hellman key exchange
 *
 * Supports arbitrary-size safe primes.
 */

#include <string.h>

#include <mbedcrypto/dh.h>

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                         */
/* ------------------------------------------------------------------ */

void mbedcrypto_dh_init(struct mbedcrypto_dh_ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

void mbedcrypto_dh_cleanup(struct mbedcrypto_dh_ctx *ctx)
{
	if (!ctx)
		return;
	mbedcrypto_bn_cleanup(&ctx->RR);
	mbedcrypto_bn_cleanup(&ctx->GY);
	mbedcrypto_bn_cleanup(&ctx->GX);
	mbedcrypto_bn_cleanup(&ctx->X);
	mbedcrypto_bn_cleanup(&ctx->G);
	mbedcrypto_bn_cleanup(&ctx->P);
}

size_t mbedcrypto_dh_len(const struct mbedcrypto_dh_ctx *ctx)
{
	return mbedcrypto_bn_byte_count(&ctx->P);
}

/* ------------------------------------------------------------------ */
/*  Generate keypair                                                  */
/* ------------------------------------------------------------------ */

int mbedcrypto_dh_gen_public(struct mbedcrypto_dh_ctx *ctx,
		int x_size, uint8_t *output, size_t olen,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	int ret, count = 0;

	if (!ctx || !output || !f_rng)
		return -EINVAL;

	if (x_size < 1 || olen < mbedcrypto_bn_byte_count(&ctx->P))
		return -EINVAL;

	/*
	 * Generate random X in [2, P - 2].
	 * Retry on degenerate values.
	 */
	do {
		ret = mbedcrypto_bn_random(&ctx->X, x_size,
				f_rng, p_rng);
		if (ret != 0)
			return ret;

		if (count++ > 10)
			return -EAGAIN;
	} while (mbedcrypto_bn_cmp(&ctx->X, &ctx->P) >= 0 ||
		 mbedcrypto_bn_cmp_word(&ctx->X, 2) < 0);

	/* GX = G^X mod P */
	ret = mbedcrypto_bn_modpow(&ctx->GX, &ctx->G, &ctx->X,
			&ctx->P, &ctx->RR);
	if (ret != 0)
		return ret;

	/* Export GX to output (big-endian, zero-padded) */
	ret = mbedcrypto_bn_to_binary(&ctx->GX, output, olen);
	return ret;
}

/* ------------------------------------------------------------------ */
/*  Derive shared secret                                              */
/* ------------------------------------------------------------------ */

int mbedcrypto_dh_derive_shared(struct mbedcrypto_dh_ctx *ctx,
		uint8_t *output, size_t output_size, size_t *olen,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	int ret = 0;
	size_t p_len = 0;
	struct mbedcrypto_bignum K;

	if (!ctx || !output || !olen)
		return -EINVAL;

	p_len = mbedcrypto_bn_byte_count(&ctx->P);
	if (output_size < p_len)
		return -EINVAL;

	/* Basic validation: 2 <= GY <= P - 2 */
	{
		struct mbedcrypto_bignum pm2;

		mbedcrypto_bn_init(&pm2);
		ret = mbedcrypto_bn_add_word(&pm2, &ctx->P, -2);
		if (ret != 0 || mbedcrypto_bn_cmp_word(&ctx->GY, 2) < 0 ||
		    mbedcrypto_bn_cmp(&ctx->GY, &pm2) > 0) {
			mbedcrypto_bn_cleanup(&pm2);
			return -EINVAL;
		}
		mbedcrypto_bn_cleanup(&pm2);
	}

	mbedcrypto_bn_init(&K);

	/* K = GY^X mod P */
	ret = mbedcrypto_bn_modpow(&K, &ctx->GY, &ctx->X,
			&ctx->P, &ctx->RR);
	if (ret != 0)
		goto cleanup;

	*olen = p_len;
	ret = mbedcrypto_bn_to_binary(&K, output, p_len);

cleanup:
	mbedcrypto_bn_cleanup(&K);
	return ret;
}
