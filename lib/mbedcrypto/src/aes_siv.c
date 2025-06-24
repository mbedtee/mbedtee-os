// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * AES-SIV (RFC 5297)
 *
 * Synthetic Initialization Vector - deterministic AEAD.
 * Uses AES-CMAC for S2V and AES-CTR for encryption.
 */

#include <string.h>
#include <errno.h>

#include <mbedcrypto/aes_siv.h>
#include <mbedcrypto/aes.h>
#include <mbedcrypto/cmac.h>

/* Double a 16-byte value in GF(2^128) with Rb = 0x87 */
static void siv_dbl(uint8_t d[16], const uint8_t s[16])
{
	int carry = s[0] >> 7;
	int i = 0;

	for (i = 0; i < 15; i++)
		d[i] = (s[i] << 1) | (s[i + 1] >> 7);
	d[15] = (s[15] << 1) ^ (carry ? 0x87 : 0x00);
}

/*
 * S2V: compute the synthetic IV using AES-CMAC.
 *
 * RFC 5297 Section 2.4:
 *   D = CMAC(K, <zero>)
 *   for each S_i in AD components:
 *     D = dbl(D) XOR CMAC(K, S_i)
 *   if len(Sn) >= 128:
 *     T = Sn XOR_end D
 *   else:
 *     T = dbl(D) XOR pad(Sn)
 *   V = CMAC(K, T)
 */
static int siv_s2v(const uint8_t *key, size_t keylen,
		   const uint8_t *aad, size_t aad_len,
		   const uint8_t *ptext, size_t ptext_len,
		   uint8_t v[16])
{
	struct mbedcrypto_cmac_ctx cmac, cmac_init;
	uint8_t d[16], t[16];
	uint8_t zero[16] = {0};
	int ret = 0;

	/* Set up CMAC key once - reuse via memcpy for each operation */
	ret = mbedcrypto_cmac_setkey(&cmac_init, key,
			keylen * 8);
	if (ret != 0)
		return ret;

	/* D = CMAC(K, <zero>) */
	memcpy(&cmac, &cmac_init, sizeof(cmac));
	mbedcrypto_cmac_update(&cmac, zero, 16);
	mbedcrypto_cmac_final(&cmac, d);

	/* D = dbl(D) XOR CMAC(K, AAD) - if AAD is provided */
	if (aad && aad_len > 0) {
		uint8_t tmp[16];

		siv_dbl(tmp, d);
		memcpy(d, tmp, 16);

		memcpy(&cmac, &cmac_init, sizeof(cmac));
		mbedcrypto_cmac_update(&cmac, aad, aad_len);
		mbedcrypto_cmac_final(&cmac, tmp);

		mbedcrypto_xor(d, d, tmp, 16);
	}

	/* Final: T depends on plaintext length */
	if (ptext_len >= 16) {
		/*
		 * T = ptext with last 16 bytes XORed with D
		 * Then V = CMAC(K, T)
		 */
		memcpy(&cmac, &cmac_init, sizeof(cmac));

		if (ptext_len > 16)
			mbedcrypto_cmac_update(&cmac, ptext, ptext_len - 16);

		memcpy(t, ptext + ptext_len - 16, 16);
		mbedcrypto_xor(t, t, d, 16);
		mbedcrypto_cmac_update(&cmac, t, 16);
		mbedcrypto_cmac_final(&cmac, v);
	} else {
		/* T = dbl(D) XOR pad(Sn) */
		siv_dbl(t, d);

		if (ptext && ptext_len > 0)
			mbedcrypto_xor(t, t, ptext, ptext_len);
		t[ptext_len] ^= 0x80; /* padding bit */

		memcpy(&cmac, &cmac_init, sizeof(cmac));
		mbedcrypto_cmac_update(&cmac, t, 16);
		mbedcrypto_cmac_final(&cmac, v);
	}

	mbedcrypto_cmac_cleanup(&cmac_init);
	return 0;
}

/*
 * AES-CTR encrypt/decrypt using SIV as nonce.
 * Per RFC 5297, bits 31 and 63 of the IV are cleared.
 */
static int siv_ctr(const uint8_t *key, size_t keylen,
		   const uint8_t iv[16],
		   const uint8_t *input, size_t len,
		   uint8_t *output)
{
	struct mbedcrypto_aes_ctx aes;
	uint8_t ctr[16], ks[16];
	int ret = 0, i = 0;

	ret = mbedcrypto_aes_setkey(&aes, key,
			keylen * 8, 0);
	if (ret != 0)
		return ret;

	/* Build initial counter: clear bits 31 and 63 */
	memcpy(ctr, iv, 16);
	ctr[8] &= 0x7f;
	ctr[12] &= 0x7f;

	/* Process full 16-byte blocks */
	while (len >= 16) {
		mbedcrypto_aes_ecb_crypt(&aes, ctr, ks);
		for (i = 15; i >= 0; i--)
			if (++ctr[i] != 0)
				break;
		mbedcrypto_xor(output, input, ks, 16);
		output += 16;
		input += 16;
		len -= 16;
	}

	/* Handle trailing partial block */
	if (len > 0) {
		mbedcrypto_aes_ecb_crypt(&aes, ctr, ks);
		mbedcrypto_xor(output, input, ks, len);
	}

	mbedcrypto_aes_cleanup(&aes);
	return 0;
}

void mbedcrypto_aes_siv_init(struct mbedcrypto_aes_siv_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

void mbedcrypto_aes_siv_cleanup(struct mbedcrypto_aes_siv_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

int mbedcrypto_aes_siv_setkey(struct mbedcrypto_aes_siv_ctx *ctx,
		const uint8_t *key, size_t keylen)
{
	if (!ctx || !key)
		return -EINVAL;

	/* Combined key must be 32, 48, or 64 bytes */
	if (keylen != 32 && keylen != 48 && keylen != 64)
		return -EINVAL;

	ctx->keylen = keylen / 2;
	memcpy(ctx->k1, key, ctx->keylen);
	memcpy(ctx->k2, key + ctx->keylen, ctx->keylen);

	return 0;
}

int mbedcrypto_aes_siv_encrypt(struct mbedcrypto_aes_siv_ctx *ctx,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output,
		uint8_t tag[MBEDCRYPTO_AES_SIV_TAG_SIZE])
{
	int ret = 0;

	if (!ctx || !tag)
		return -EINVAL;

	/* V = S2V(K1, AAD, plaintext) */
	ret = siv_s2v(ctx->k1, ctx->keylen, aad, aad_len, input, len, tag);
	if (ret != 0)
		return ret;

	/* ciphertext = AES-CTR(K2, V, plaintext) */
	if (len > 0) {
		if (!input || !output)
			return -EINVAL;
		ret = siv_ctr(ctx->k2, ctx->keylen, tag, input, len, output);
	}

	return ret;
}

int mbedcrypto_aes_siv_decrypt(struct mbedcrypto_aes_siv_ctx *ctx,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output,
		const uint8_t tag[MBEDCRYPTO_AES_SIV_TAG_SIZE])
{
	uint8_t v[16];
	int ret = 0;

	if (!ctx || !tag)
		return -EINVAL;

	/* plaintext = AES-CTR(K2, tag, ciphertext) */
	if (len > 0) {
		if (!input || !output)
			return -EINVAL;
		ret = siv_ctr(ctx->k2, ctx->keylen, tag, input, len, output);
		if (ret != 0)
			return ret;
	}

	/* V = S2V(K1, AAD, plaintext) */
	ret = siv_s2v(ctx->k1, ctx->keylen, aad, aad_len,
		      len > 0 ? output : NULL, len, v);
	if (ret != 0)
		return ret;

	/* Verify V == tag (constant-time) */
	if (mbedcrypto_ct_memcmp(v, tag, 16) != 0) {
		/* Authentication failed: zeroize output */
		if (len > 0)
			memset(output, 0, len);
		return -EBADMSG;
	}

	return 0;
}
