// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * SM2 Public Key Encryption (GB/T 32918.4-2016)
 */

#include <string.h>

#include <mbedcrypto/sm2pke.h>
#include <mbedcrypto/sm2kep.h>

/* ---------------------------------------------------------------- */
/*  Context lifecycle                                               */
/* ---------------------------------------------------------------- */

void mbedcrypto_sm2pke_init(struct mbedcrypto_sm2pke_ctx *ctx)
{
	mbedcrypto_ecp_group_init(&ctx->grp);
	mbedcrypto_bn_init(&ctx->d);
	mbedcrypto_ecp_point_init(&ctx->Q);
}

void mbedcrypto_sm2pke_cleanup(struct mbedcrypto_sm2pke_ctx *ctx)
{
	mbedcrypto_ecp_group_cleanup(&ctx->grp);
	mbedcrypto_bn_cleanup(&ctx->d);
	mbedcrypto_ecp_point_cleanup(&ctx->Q);
}

int mbedcrypto_sm2pke_load_group(struct mbedcrypto_sm2pke_ctx *ctx)
{
	return mbedcrypto_ecp_load_group(&ctx->grp, MBEDCRYPTO_ECP_DP_SM2);
}

/* ---------------------------------------------------------------- */
/*  SM2 Encrypt                                                     */
/* ---------------------------------------------------------------- */

/*
 * Output: C1 || C3 || C2
 *   C1 = 04 || x1 || y1  (65 bytes, uncompressed point k*G)
 *   C3 = SM3(x2 || M || y2)  (32 bytes)
 *   C2 = M ^ KDF(x2 || y2, mlen)  (mlen bytes)
 * Total: mlen + 97 bytes
 */
int mbedcrypto_sm2pke_encrypt(struct mbedcrypto_sm2pke_ctx *ctx,
		const uint8_t *input, size_t ilen,
		uint8_t *output, size_t *olen,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	struct mbedcrypto_bignum k;
	struct mbedcrypto_ecp_point C1, S;
	uint8_t x2[32], y2[32];
	uint8_t c3[32];
	struct mbedcrypto_sm3_ctx sm3;
	int ret = 0;
	size_t i = 0;

	mbedcrypto_bn_init(&k);
	mbedcrypto_ecp_point_init(&C1);
	mbedcrypto_ecp_point_init(&S);

retry:
	/* Step 1: random k in [1, n-1] */
	if ((ret = mbedcrypto_bn_random(&k, 32, f_rng, p_rng)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_mod(&k, &k, &ctx->grp.N)) != 0)
		goto cleanup;
	if (mbedcrypto_bn_cmp_word(&k, 0) == 0)
		goto retry;

	/* Step 2: C1 = k * G */
	if ((ret = mbedcrypto_ecp_scalar_mul(&ctx->grp, &C1, &k, &ctx->grp.G, f_rng, p_rng)) != 0)
		goto cleanup;

	/* Step 3: (x2, y2) = k * Q_B */
	if ((ret = mbedcrypto_ecp_scalar_mul(&ctx->grp, &S, &k, &ctx->Q, f_rng, p_rng)) != 0)
		goto cleanup;

	mbedcrypto_bn_to_binary(&S.X, x2, 32);
	mbedcrypto_bn_to_binary(&S.Y, y2, 32);

	/* Step 4: t = KDF(x2 || y2, klen) - write directly into output C2 area */
	{
		uint8_t z_input[64];

		memcpy(z_input, x2, 32);
		memcpy(z_input + 32, y2, 32);
		memset(output + 97, 0, ilen);
		if ((ret = mbedcrypto_sm2_kdf(z_input, 64, output + 97, ilen)) != 0)
			goto cleanup;
	}

	/* If t is all zeros, try again with a new k */
	if (ilen > 0 && mbedcrypto_ct_is_zero(output + 97, ilen))
		goto retry;

	/* Step 5: C2 = M ^ t */
	for (i = 0; i < ilen; i++)
		output[97 + i] ^= input[i];

	/* Step 6: C3 = SM3(x2 || M || y2) */
	if ((ret = mbedcrypto_sm3_init(&sm3)) != 0)
		goto cleanup;
	mbedcrypto_sm3_update(&sm3, x2, 32);
	mbedcrypto_sm3_update(&sm3, input, ilen);
	mbedcrypto_sm3_update(&sm3, y2, 32);
	if ((ret = mbedcrypto_sm3_final(&sm3, c3)) != 0)
		goto cleanup;

	/* Output: C1 || C3 || C2 */
	/* C1: 04 || x1 || y1 */
	output[0] = 0x04;
	mbedcrypto_bn_to_binary(&C1.X, output + 1, 32);
	mbedcrypto_bn_to_binary(&C1.Y, output + 33, 32);

	/* C3: 32-byte hash */
	memcpy(output + 65, c3, 32);

	/* C2 already in output + 97 */

	*olen = 97 + ilen;
	ret = 0;

cleanup:
	mbedcrypto_bn_cleanup(&k);
	mbedcrypto_ecp_point_cleanup(&C1);
	mbedcrypto_ecp_point_cleanup(&S);
	memset(x2, 0, sizeof(x2));
	memset(y2, 0, sizeof(y2));
	return ret;
}

/* ---------------------------------------------------------------- */
/*  SM2 Decrypt                                                     */
/* ---------------------------------------------------------------- */

/*
 * Input: C1 || C3 || C2
 *   C1 = 04 || x1 || y1  (65 bytes)
 *   C3 = 32 bytes
 *   C2 = ciphertext (ilen - 97 bytes)
 */
int mbedcrypto_sm2pke_decrypt(struct mbedcrypto_sm2pke_ctx *ctx,
		const uint8_t *input, size_t ilen,
		uint8_t *output, size_t *olen)
{
	struct mbedcrypto_ecp_point C1, S;
	uint8_t x2[32], y2[32];
	uint8_t c3_check[32];
	struct mbedcrypto_sm3_ctx sm3;
	size_t mlen = 0;
	int ret = 0;
	size_t i = 0;

	if (ilen < 97 || input[0] != 0x04)
		return -EINVAL;

	mlen = ilen - 97;

	mbedcrypto_ecp_point_init(&C1);
	mbedcrypto_ecp_point_init(&S);

	/* Parse C1 */
	if ((ret = mbedcrypto_bn_from_binary(&C1.X, input + 1, 32)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_from_binary(&C1.Y, input + 33, 32)) != 0)
		goto cleanup;
	if ((ret = mbedcrypto_bn_set_word(&C1.Z, 1)) != 0)
		goto cleanup;

	/* Verify C1 is on the curve */
	if ((ret = mbedcrypto_ecp_validate_point(&ctx->grp, &C1)) != 0)
		goto cleanup;

	/* (x2, y2) = d * C1 */
	if ((ret = mbedcrypto_ecp_scalar_mul(&ctx->grp, &S, &ctx->d, &C1, NULL, NULL)) != 0)
		goto cleanup;

	mbedcrypto_bn_to_binary(&S.X, x2, 32);
	mbedcrypto_bn_to_binary(&S.Y, y2, 32);

	/* t = KDF(x2 || y2, mlen) - write directly into output */
	{
		uint8_t z_input[64];

		memcpy(z_input, x2, 32);
		memcpy(z_input + 32, y2, 32);
		memset(output, 0, mlen);
		if ((ret = mbedcrypto_sm2_kdf(z_input, 64, output, mlen)) != 0)
			goto cleanup;
	}

	if (mlen > 0 && mbedcrypto_ct_is_zero(output, mlen)) {
		ret = -EBADMSG;
		goto cleanup;
	}

	/* M = C2 ^ t */
	for (i = 0; i < mlen; i++)
		output[i] ^= input[97 + i];

	/* Verify: u = SM3(x2 || M || y2), check u == C3 */
	if ((ret = mbedcrypto_sm3_init(&sm3)) != 0)
		goto cleanup;
	mbedcrypto_sm3_update(&sm3, x2, 32);
	mbedcrypto_sm3_update(&sm3, output, mlen);
	mbedcrypto_sm3_update(&sm3, y2, 32);
	if ((ret = mbedcrypto_sm3_final(&sm3, c3_check)) != 0)
		goto cleanup;

	if (mbedcrypto_ct_memcmp(c3_check, input + 65, 32) != 0) {
		memset(output, 0, mlen);
		ret = -EBADMSG;
		goto cleanup;
	}

	*olen = mlen;
	ret = 0;

cleanup:
	mbedcrypto_ecp_point_cleanup(&C1);
	mbedcrypto_ecp_point_cleanup(&S);
	memset(x2, 0, sizeof(x2));
	memset(y2, 0, sizeof(y2));
	return ret;
}
