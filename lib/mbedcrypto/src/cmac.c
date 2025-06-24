// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * AES-CMAC message authentication code (NIST SP 800-38B / RFC 4493)
 *
 * CMAC provides message authentication using AES as the underlying
 * block cipher, with sub-key derivation per NIST SP 800-38B.
 */

#include <string.h>

#include <mbedcrypto/cmac.h>

/* Rb constant for GF(2^128): x^128 + x^7 + x^2 + x + 1 */
#define CMAC_RB  0x87

/*
 * Left-shift a 16-byte block by one bit in GF(2^128).
 * If the MSB was 1, XOR with Rb.
 */
static void cmac_shift_left(uint8_t out[16], const uint8_t in[16])
{
	uint8_t carry = 0;
	int i = 0;

	for (i = 15; i >= 0; i--) {
		uint8_t next_carry = in[i] >> 7;

		out[i] = (in[i] << 1) | carry;
		carry = next_carry;
	}

	/* If MSB of input was 1, XOR with Rb */
	if (in[0] & 0x80)
		out[15] ^= CMAC_RB;
}

int mbedcrypto_cmac_setkey(struct mbedcrypto_cmac_ctx *ctx,
		const uint8_t *key, unsigned int keybits)
{
	uint8_t L[16] = {0};
	int ret = 0;

	if (!ctx || !key)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));

	/* CMAC uses AES in encrypt direction only */
	ret = mbedcrypto_aes_setkey(&ctx->aes, key, keybits,
			MBEDCRYPTO_AES_ENCRYPT);
	if (ret != 0)
		return ret;

	/*
	 * Derive sub-keys per NIST SP 800-38B Section 6.1:
	 *   L = AES(0^128)
	 *   K1 = L << 1 (in GF(2^128))
	 *   K2 = K1 << 1 (in GF(2^128))
	 */
	mbedcrypto_aes_ecb_crypt(&ctx->aes, L, L);

	cmac_shift_left(ctx->k1, L);
	cmac_shift_left(ctx->k2, ctx->k1);

	memset(L, 0, sizeof(L));

	return 0;
}

int mbedcrypto_cmac_reset(struct mbedcrypto_cmac_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	memset(ctx->state, 0, 16);
	memset(ctx->buf, 0, 16);
	ctx->buf_len = 0;

	return 0;
}

int mbedcrypto_cmac_update(struct mbedcrypto_cmac_ctx *ctx,
		const uint8_t *data, size_t len)
{
	size_t use = 0;

	if (!ctx)
		return -EINVAL;

	if (len == 0)
		return 0;

	/*
	 * Buffering strategy: always keep at least 1 byte buffered so
	 * that finish() knows whether the final block is complete.
	 *
	 * - If buf already has data and adding len would exceed 16 bytes,
	 *   process the full buffer block first.
	 * - Then process as many complete 16-byte blocks as possible,
	 *   but always keep the last block buffered.
	 */

	/* Fill the buffer if it has a partial block */
	if (ctx->buf_len > 0) {
		use = 16 - ctx->buf_len;
		if (use > len)
			use = len;

		memcpy(ctx->buf + ctx->buf_len, data, use);
		ctx->buf_len += use;
		data += use;
		len -= use;

		/*
		 * Buffer is full and there is more data coming,
		 * so this is not the last block -- process it
		 */
		if (ctx->buf_len == 16 && len > 0) {
			mbedcrypto_xor(ctx->state, ctx->state, ctx->buf, 16);
			mbedcrypto_aes_ecb_crypt(&ctx->aes, ctx->state,
					ctx->state);
			ctx->buf_len = 0;
		}
	}

	/* Process complete blocks, keeping the last one buffered */
	while (len > 16) {
		mbedcrypto_xor(ctx->state, ctx->state, data, 16);
		mbedcrypto_aes_ecb_crypt(&ctx->aes, ctx->state, ctx->state);
		data += 16;
		len -= 16;
	}

	/* Buffer the remaining bytes (1..16, or 0 if nothing left) */
	if (len > 0) {
		memcpy(ctx->buf + ctx->buf_len, data, len);
		ctx->buf_len += len;
	}

	return 0;
}

int mbedcrypto_cmac_final(struct mbedcrypto_cmac_ctx *ctx,
		uint8_t mac[MBEDCRYPTO_CMAC_TAG_SIZE])
{
	if (!ctx || !mac)
		return -EINVAL;

	if (ctx->buf_len == 16) {
		/*
		 * Last block is complete: XOR with K1.
		 */
		mbedcrypto_xor(ctx->buf, ctx->buf, ctx->k1, 16);
	} else {
		/*
		 * Last block is incomplete (or empty message):
		 * Pad with 10*0, XOR with K2.
		 */
		ctx->buf[ctx->buf_len] = 0x80;
		if (ctx->buf_len + 1 < 16)
			memset(ctx->buf + ctx->buf_len + 1, 0,
					16 - ctx->buf_len - 1);
		mbedcrypto_xor(ctx->buf, ctx->buf, ctx->k2, 16);
	}

	mbedcrypto_xor(ctx->state, ctx->state, ctx->buf, 16);
	mbedcrypto_aes_ecb_crypt(&ctx->aes, ctx->state, mac);

	return 0;
}

void mbedcrypto_cmac_cleanup(struct mbedcrypto_cmac_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}
