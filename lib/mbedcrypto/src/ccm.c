// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * CCM authenticated encryption (NIST SP 800-38C / RFC 3610 / RFC 8998)
 *
 * Counter with CBC-MAC: provides both confidentiality and
 * authentication using a single block cipher key.
 *
 * Unified core used by both AES-CCM and SM4-CCM. Only the block
 * cipher ECB call differs, supplied via function pointer in ccm_base.
 */

#include <string.h>

#include <mbedcrypto/ccm.h>

/* ================================================================== */
/*  Shared CCM helpers                                                */
/* ================================================================== */

/*
 * Increment the counter portion of the A_i block.
 * The counter occupies the last 'q' bytes as a big-endian integer.
 */
static void ccm_increment_ctr(uint8_t ctr[16], int q)
{
	int i = 0;

	for (i = 15; i > 15 - q; i--) {
		if (++ctr[i] != 0)
			break;
	}
}

/*
 * CBC-MAC one 16-byte block: mac = E_K(mac XOR buf).
 */
static void ccm_mac_block(struct ccm_base *c)
{
	mbedcrypto_xor(c->mac, c->mac, c->buf, 16);
	c->ecb(c->cipher, c->mac, c->mac);
}

/* ================================================================== */
/*  Unified CCM core (operates on struct ccm_base)                    */
/* ================================================================== */

static int ccm_start(struct ccm_base *c, int dir,
		const uint8_t *nonce, size_t nonce_len)
{
	if (!nonce)
		return -EINVAL;

	/* Nonce length must be 7..13 (q = 15 - nonce_len = 2..8) */
	if (nonce_len < 7 || nonce_len > 13)
		return -EINVAL;

	c->dir = dir;
	c->q = 15 - nonce_len;

	/*
	 * Format the counter block A_0:
	 *   flags = (q - 1)
	 *   A_0 = flags | nonce | 0^q
	 */
	memset(c->ctr, 0, 16);
	c->ctr[0] = c->q - 1;
	memcpy(c->ctr + 1, nonce, nonce_len);

	memset(c->mac, 0, 16);
	c->buf_len = 0;
	c->aad_done = 0;
	c->payload_done = 0;
	c->state = MBEDCRYPTO_CCM_STATE_STARTED;

	return 0;
}

static int ccm_set_len(struct ccm_base *c,
		size_t aad_len, size_t payload_len, size_t tag_len)
{
	uint8_t b0[16];
	uint8_t flags = 0;

	if (c->state != MBEDCRYPTO_CCM_STATE_STARTED)
		return -EINVAL;

	/* tag_len must be even, 4..16 (or 0 for no authentication) */
	if (tag_len != 0 && (tag_len < 4 || tag_len > 16 || (tag_len & 1)))
		return -EINVAL;

	c->tag_len = tag_len;
	c->aad_len = aad_len;
	c->payload_len = payload_len;

	/*
	 * Format B_0 block:
	 *   flags = 64 * (aad_len > 0) + 8 * ((tag_len - 2) / 2) + (q - 1)
	 *   B_0 = flags | nonce | payload_len (q bytes, big-endian)
	 */
	flags = c->q - 1;
	if (aad_len > 0)
		flags |= 0x40;
	if (tag_len > 0)
		flags |= ((tag_len - 2) / 2) << 3;

	memset(b0, 0, 16);
	b0[0] = flags;
	/* Copy nonce from the counter block (bytes 1..nonce_len) */
	memcpy(b0 + 1, c->ctr + 1, 15 - c->q);

	/* Encode payload length in last q bytes, big-endian */
	{
		size_t plen = payload_len;
		int i = 0;

		for (i = 15; i > 15 - c->q; i--) {
			b0[i] = plen & 0xFF;
			plen >>= 8;
		}
	}

	/* CBC-MAC the B_0 block: Y_0 = E_K(B_0) */
	memcpy(c->buf, b0, 16);
	/* mac is still zero, so E_K(0 XOR B_0) = E_K(B_0) */
	ccm_mac_block(c);

	/*
	 * If there is AAD, prepend the AAD length encoding.
	 * For aad_len < 0xFF00 (65280): 2-byte big-endian.
	 * For aad_len >= 0xFF00: 0xFF 0xFE + 4-byte big-endian.
	 */
	c->buf_len = 0;
	if (aad_len > 0) {
		if (aad_len < 0xFF00) {
			c->buf[0] = aad_len >> 8;
			c->buf[1] = aad_len;
			c->buf_len = 2;
		} else {
			c->buf[0] = 0xFF;
			c->buf[1] = 0xFE;
			c->buf[2] = aad_len >> 24;
			c->buf[3] = aad_len >> 16;
			c->buf[4] = aad_len >> 8;
			c->buf[5] = aad_len;
			c->buf_len = 6;
		}
		c->state = MBEDCRYPTO_CCM_STATE_LENGTHS;
	} else
		c->state = MBEDCRYPTO_CCM_STATE_PAYLOAD;

	return 0;
}

static int ccm_update_aad(struct ccm_base *c,
		const uint8_t *aad, size_t len)
{
	size_t use = 0;

	if (c->state == MBEDCRYPTO_CCM_STATE_LENGTHS)
		c->state = MBEDCRYPTO_CCM_STATE_AAD;

	if (c->state != MBEDCRYPTO_CCM_STATE_AAD)
		return -EINVAL;

	if (c->aad_done + len > c->aad_len)
		return -EINVAL;

	c->aad_done += len;

	/* Feed AAD bytes into the CBC-MAC buffer */
	while (len > 0) {
		use = 16 - c->buf_len;
		if (use > len)
			use = len;

		memcpy(c->buf + c->buf_len, aad, use);
		c->buf_len += use;
		aad += use;
		len -= use;

		if (c->buf_len == 16) {
			ccm_mac_block(c);
			c->buf_len = 0;
		}
	}

	/* When all AAD is fed, pad & MAC the final partial block */
	if (c->aad_done == c->aad_len) {
		if (c->buf_len > 0) {
			memset(c->buf + c->buf_len, 0, 16 - c->buf_len);
			ccm_mac_block(c);
			c->buf_len = 0;
		}
		c->state = MBEDCRYPTO_CCM_STATE_PAYLOAD;
	}

	return 0;
}

static int ccm_update(struct ccm_base *c,
		const uint8_t *input, size_t len,
		uint8_t *output, size_t *olen)
{
	size_t done = 0;
	size_t use = 0;

	if (!output || !olen)
		return -EINVAL;

	/* Finish any pending AAD (auto-pad) */
	if (c->state == MBEDCRYPTO_CCM_STATE_AAD ||
	    c->state == MBEDCRYPTO_CCM_STATE_LENGTHS) {
		if (c->aad_done < c->aad_len)
			return -EINVAL;
		if (c->buf_len > 0) {
			memset(c->buf + c->buf_len, 0, 16 - c->buf_len);
			ccm_mac_block(c);
		}
		c->buf_len = 0;
		c->state = MBEDCRYPTO_CCM_STATE_PAYLOAD;
	}

	if (c->state != MBEDCRYPTO_CCM_STATE_PAYLOAD)
		return -EINVAL;

	if (c->payload_done + len > c->payload_len)
		return -EINVAL;

	/*
	 * CCM payload processing:
	 *   Encrypt: CBC-MAC the plaintext, then CTR-encrypt it.
	 *   Decrypt: CTR-decrypt to get plaintext, then CBC-MAC plaintext.
	 *
	 * We buffer partial blocks in c->buf (plaintext for MAC).
	 * Each new 16-byte block increments the counter to generate keystream.
	 */
	while (len > 0) {
		/* Generate keystream for new block (skip if resuming partial) */
		if (c->buf_len == 0) {
			ccm_increment_ctr(c->ctr, c->q);
			c->ecb(c->cipher, c->ctr, c->keystream);
		}

		/* Determine how many bytes to process in this block */
		use = 16 - c->buf_len;
		if (use > len)
			use = len;

		/* Process 'use' bytes: CTR + CBC-MAC */
		if (c->dir == MBEDCRYPTO_AES_ENCRYPT) {
			memcpy(c->buf + c->buf_len, input + done, use);
			mbedcrypto_xor(output + done, input + done,
					c->keystream + c->buf_len, use);
		} else {
			mbedcrypto_xor(output + done, input + done,
					c->keystream + c->buf_len, use);
			memcpy(c->buf + c->buf_len, output + done, use);
		}

		c->buf_len += use;
		done += use;
		len -= use;
		c->payload_done += use;

		/* Full block ready for CBC-MAC */
		if (c->buf_len == 16) {
			ccm_mac_block(c);
			c->buf_len = 0;
		}
	}

	*olen = done;

	return 0;
}

static int ccm_final(struct ccm_base *c,
		uint8_t *tag, size_t tag_len)
{
	int i = 0;
	uint8_t s0[16];

	if (!tag)
		return -EINVAL;

	if (tag_len > c->tag_len)
		tag_len = c->tag_len;

	/* Pad & MAC any remaining partial payload block */
	if (c->buf_len > 0) {
		memset(c->buf + c->buf_len, 0, 16 - c->buf_len);
		ccm_mac_block(c);
	}

	/*
	 * Encrypt the tag with counter A_0.
	 * A_0 has the counter portion set to zero.
	 */
	for (i = 15; i > 15 - c->q; i--)
		c->ctr[i] = 0;

	c->ecb(c->cipher, c->ctr, s0);

	/* T = first tag_len bytes of (CBC-MAC result XOR S_0) */
	mbedcrypto_xor(c->mac, c->mac, s0, 16);

	memcpy(tag, c->mac, tag_len);

	memset(s0, 0, sizeof(s0));
	return 0;
}

/*
 * One-shot CCM processing (internal helper).
 */
static int ccm_oneshot(struct ccm_base *c, int dir,
		const uint8_t *nonce, size_t nonce_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, uint8_t *tag, size_t tag_len)
{
	size_t olen = 0;
	int ret = 0;

	ret = ccm_start(c, dir, nonce, nonce_len);
	if (ret != 0)
		return ret;

	ret = ccm_set_len(c, aad_len, len, tag_len);
	if (ret != 0)
		return ret;

	if (aad_len > 0) {
		ret = ccm_update_aad(c, aad, aad_len);
		if (ret != 0)
			return ret;
	}

	if (len > 0) {
		ret = ccm_update(c, input, len, output, &olen);
		if (ret != 0)
			return ret;
	}

	return ccm_final(c, tag, tag_len);
}

static int ccm_encrypt(struct ccm_base *c,
		const uint8_t *nonce, size_t nonce_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, uint8_t *tag, size_t tag_len)
{
	if (!tag)
		return -EINVAL;

	return ccm_oneshot(c, MBEDCRYPTO_AES_ENCRYPT,
		nonce, nonce_len, aad, aad_len,
		input, len, output, tag, tag_len);
}

static int ccm_decrypt(struct ccm_base *c,
		const uint8_t *nonce, size_t nonce_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, const uint8_t *tag, size_t tag_len)
{
	uint8_t expected[16];
	int ret = 0;

	if (!tag || tag_len > 16)
		return -EINVAL;

	ret = ccm_oneshot(c, MBEDCRYPTO_AES_DECRYPT,
		nonce, nonce_len, aad, aad_len,
		input, len, output, expected, tag_len);
	if (ret != 0) {
		memset(output, 0, len);
		return ret;
	}

	/* Constant-time tag comparison */
	if (mbedcrypto_ct_memcmp(expected, tag, tag_len) != 0) {
		memset(output, 0, len);
		memset(expected, 0, sizeof(expected));
		return -EBADMSG;
	}

	memset(expected, 0, sizeof(expected));
	return 0;
}

/* ================================================================== */
/*  AES-CCM public API (thin wrappers around ccm core)                */
/* ================================================================== */

static void aes_ecb_wrap(const void *cipher, const uint8_t in[16],
		uint8_t out[16])
{
	mbedcrypto_aes_ecb_crypt(cipher, in, out);
}

int mbedcrypto_aes_ccm_setkey(struct mbedcrypto_aes_ccm_ctx *ctx,
		const uint8_t *key, unsigned int keybits)
{
	if (!ctx || !key)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));

	ctx->base.ecb = aes_ecb_wrap;
	ctx->base.cipher = &ctx->aes;

	/* CCM always uses AES in encrypt direction for both CTR and CBC-MAC */
	return mbedcrypto_aes_setkey(&ctx->aes, key, keybits,
			MBEDCRYPTO_AES_ENCRYPT);
}

int mbedcrypto_aes_ccm_start(struct mbedcrypto_aes_ccm_ctx *ctx, int dir,
		const uint8_t *nonce, size_t nonce_len)
{
	if (!ctx)
		return -EINVAL;

	return ccm_start(&ctx->base, dir, nonce, nonce_len);
}

int mbedcrypto_aes_ccm_set_len(struct mbedcrypto_aes_ccm_ctx *ctx,
		size_t aad_len, size_t payload_len, size_t tag_len)
{
	if (!ctx)
		return -EINVAL;

	return ccm_set_len(&ctx->base, aad_len, payload_len, tag_len);
}

int mbedcrypto_aes_ccm_update_aad(struct mbedcrypto_aes_ccm_ctx *ctx,
		const uint8_t *aad, size_t len)
{
	if (!ctx)
		return -EINVAL;

	return ccm_update_aad(&ctx->base, aad, len);
}

int mbedcrypto_aes_ccm_update(struct mbedcrypto_aes_ccm_ctx *ctx,
		const uint8_t *input, size_t len,
		uint8_t *output, size_t *olen)
{
	if (!ctx)
		return -EINVAL;

	return ccm_update(&ctx->base, input, len, output, olen);
}

int mbedcrypto_aes_ccm_final(struct mbedcrypto_aes_ccm_ctx *ctx,
		uint8_t *tag, size_t tag_len)
{
	if (!ctx)
		return -EINVAL;

	return ccm_final(&ctx->base, tag, tag_len);
}

int mbedcrypto_aes_ccm_encrypt(struct mbedcrypto_aes_ccm_ctx *ctx,
		const uint8_t *nonce, size_t nonce_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, uint8_t *tag, size_t tag_len)
{
	if (!ctx)
		return -EINVAL;

	return ccm_encrypt(&ctx->base, nonce, nonce_len, aad, aad_len,
		input, len, output, tag, tag_len);
}

int mbedcrypto_aes_ccm_decrypt(struct mbedcrypto_aes_ccm_ctx *ctx,
		const uint8_t *nonce, size_t nonce_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, const uint8_t *tag, size_t tag_len)
{
	if (!ctx)
		return -EINVAL;

	return ccm_decrypt(&ctx->base, nonce, nonce_len, aad, aad_len,
		input, len, output, tag, tag_len);
}

void mbedcrypto_aes_ccm_cleanup(struct mbedcrypto_aes_ccm_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

/* ================================================================== */
/*  SM4-CCM public API (thin wrappers around ccm core)                */
/* ================================================================== */

#if defined(CONFIG_MBEDCRYPTO_SM4)

static void sm4_ecb_wrap(const void *cipher, const uint8_t in[16],
		uint8_t out[16])
{
	mbedcrypto_sm4_ecb_crypt(cipher, in, out);
}

int mbedcrypto_sm4_ccm_setkey(struct mbedcrypto_sm4_ccm_ctx *ctx,
		const uint8_t *key, unsigned int keybits)
{
	if (!ctx || !key)
		return -EINVAL;
	if (keybits != 128)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));

	ctx->base.ecb = sm4_ecb_wrap;
	ctx->base.cipher = &ctx->sm4;

	return mbedcrypto_sm4_setkey(&ctx->sm4, key,
			MBEDCRYPTO_SM4_ENCRYPT);
}

int mbedcrypto_sm4_ccm_start(struct mbedcrypto_sm4_ccm_ctx *ctx, int dir,
		const uint8_t *nonce, size_t nonce_len)
{
	if (!ctx)
		return -EINVAL;

	return ccm_start(&ctx->base, dir, nonce, nonce_len);
}

int mbedcrypto_sm4_ccm_set_len(struct mbedcrypto_sm4_ccm_ctx *ctx,
		size_t aad_len, size_t payload_len, size_t tag_len)
{
	if (!ctx)
		return -EINVAL;

	return ccm_set_len(&ctx->base, aad_len, payload_len, tag_len);
}

int mbedcrypto_sm4_ccm_update_aad(struct mbedcrypto_sm4_ccm_ctx *ctx,
		const uint8_t *aad, size_t len)
{
	if (!ctx)
		return -EINVAL;

	return ccm_update_aad(&ctx->base, aad, len);
}

int mbedcrypto_sm4_ccm_update(struct mbedcrypto_sm4_ccm_ctx *ctx,
		const uint8_t *input, size_t len,
		uint8_t *output, size_t *olen)
{
	if (!ctx)
		return -EINVAL;

	return ccm_update(&ctx->base, input, len, output, olen);
}

int mbedcrypto_sm4_ccm_final(struct mbedcrypto_sm4_ccm_ctx *ctx,
		uint8_t *tag, size_t tag_len)
{
	if (!ctx)
		return -EINVAL;

	return ccm_final(&ctx->base, tag, tag_len);
}

int mbedcrypto_sm4_ccm_encrypt(struct mbedcrypto_sm4_ccm_ctx *ctx,
		const uint8_t *nonce, size_t nonce_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, uint8_t *tag, size_t tag_len)
{
	if (!ctx)
		return -EINVAL;

	return ccm_encrypt(&ctx->base, nonce, nonce_len, aad, aad_len,
		input, len, output, tag, tag_len);
}

int mbedcrypto_sm4_ccm_decrypt(struct mbedcrypto_sm4_ccm_ctx *ctx,
		const uint8_t *nonce, size_t nonce_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, const uint8_t *tag, size_t tag_len)
{
	if (!ctx)
		return -EINVAL;

	return ccm_decrypt(&ctx->base, nonce, nonce_len, aad, aad_len,
		input, len, output, tag, tag_len);
}

void mbedcrypto_sm4_ccm_cleanup(struct mbedcrypto_sm4_ccm_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

#endif /* CONFIG_MBEDCRYPTO_SM4 */
