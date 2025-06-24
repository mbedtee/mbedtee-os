// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * GCM authenticated encryption (NIST SP 800-38D, RFC 8998)
 *
 * Shared GHASH (4-bit table-driven GF(2^128)) and unified core
 * used by both AES-GCM and SM4-GCM. Only the block cipher
 * ECB call differs, supplied via function pointer in gcm_base.
 */

#include <string.h>

#include <mbedcrypto/gcm.h>

/* ================================================================== */
/*  Shared GHASH helpers                                              */
/* ================================================================== */

/*
 * Precompute the GHASH multiplication table for subkey H.
 * Uses 4-bit table-driven method for GF(2^128) multiplication.
 *
 * Table entry i represents i*H stored as two 64-bit halves.
 * Index bits correspond to coefficients of x^3, x^2, x^1, x^0
 * relative to the current nibble position, so index 8 holds H
 * itself (x^0 coefficient).
 */
static void gcm_gen_table(uint64_t hl[16], uint64_t hh[16],
		const uint8_t h[16])
{
	uint64_t hi = 0, lo = 0;
	int i = 0;

	hi = mbedcrypto_get_be64(h);
	lo = mbedcrypto_get_be64(h + 8);

	hl[0] = 0;
	hh[0] = 0;

	/* Entry 8 = H */
	hh[8] = hi;
	hl[8] = lo;

	/*
	 * Entries 4, 2, 1: successive right-shifts of H in GF(2^128).
	 * Right-shift = multiply by x, with reduction by the GCM
	 * polynomial x^128 + x^7 + x^2 + x + 1 when the LSB is set.
	 */
	for (i = 4; i >= 1; i >>= 1) {
		uint64_t phi = hh[i << 1];
		uint64_t plo = hl[i << 1];
		uint64_t r = (plo & 1) ? UINT64_C(0xe100000000000000) : 0;

		hl[i] = (phi << 63) | (plo >> 1);
		hh[i] = (phi >> 1) ^ r;
	}

	/* Remaining entries: XOR combinations of {1, 2, 4, 8} */
	for (i = 3; i < 16; i++) {
		int j = i & (-i); /* lowest set bit */

		hh[i] = hh[i ^ j] ^ hh[j];
		hl[i] = hl[i ^ j] ^ hl[j];
	}
}

/*
 * GF(2^128) reduction table for 4-bit nibbles.
 *
 * When the 128-bit accumulator is right-shifted by 4 during Shoup's
 * method, the 4 bits that fall off must be folded back via the GCM
 * irreducible polynomial x^128 + x^7 + x^2 + x + 1.
 *
 * Entry i is the pre-shifted reduction value for nibble i, sitting
 * in bits 48..63 of a 64-bit word. This eliminates the runtime shift
 * that would be needed with a 16-bit table.
 */
static const uint64_t gf128_reduce[16] = {
	UINT64_C(0x0000000000000000), UINT64_C(0x1c20000000000000),
	UINT64_C(0x3840000000000000), UINT64_C(0x2460000000000000),
	UINT64_C(0x7080000000000000), UINT64_C(0x6ca0000000000000),
	UINT64_C(0x48c0000000000000), UINT64_C(0x54e0000000000000),
	UINT64_C(0xe100000000000000), UINT64_C(0xfd20000000000000),
	UINT64_C(0xd940000000000000), UINT64_C(0xc560000000000000),
	UINT64_C(0x9180000000000000), UINT64_C(0x8da0000000000000),
	UINT64_C(0xa9c0000000000000), UINT64_C(0xb5e0000000000000),
};

/*
 * GHASH multiply: x = x * H using 4-bit table-driven method.
 *
 * Processes all 32 nibbles of the 128-bit input in a unified loop,
 * from the LSB nibble of byte 15 up to the MSB nibble of byte 0.
 * Each step right-shifts the accumulator by 4, applies polynomial
 * reduction via the precomputed table, and XORs in the table entry.
 */
static void gcm_mult(const uint64_t hl[16], const uint64_t hh[16],
		uint8_t x[16])
{
	uint64_t rh = 0, rl = 0;
	int k = 0;

	/* First nibble: initialize accumulator without shift/reduce */
	rh = hh[x[15] & 0x0f];
	rl = hl[x[15] & 0x0f];

	/* Remaining 31 nibbles: shift, reduce, XOR */
	for (k = 1; k < 32; k++) {
		unsigned int nib = (k & 1)
			? (x[15 - (k >> 1)] >> 4)
			: (x[15 - (k >> 1)] & 0x0f);

		uint64_t rv = gf128_reduce[rl & 0x0f];

		rl = (rh << 60) | (rl >> 4);
		rh = (rh >> 4) ^ rv;
		rh ^= hh[nib];
		rl ^= hl[nib];
	}

	mbedcrypto_put_be64(x, rh);
	mbedcrypto_put_be64(x + 8, rl);
}

/*
 * Increment the 32-bit counter portion of a 16-byte block.
 */
static inline void gcm_incr(uint8_t ctr[16])
{
	uint32_t val = mbedcrypto_get_be32(ctr + 12);

	mbedcrypto_put_be32(ctr + 12, val + 1);
}

/*
 * Compute J0 from IV using GHASH.
 */
static void gcm_compute_j0(uint64_t hl[16], uint64_t hh[16],
		uint8_t j0[16], uint8_t ctr[16],
		const uint8_t *iv, size_t iv_len)
{
	uint8_t work[16];

	memset(j0, 0, 16);

	if (iv_len == 12) {
		memcpy(j0, iv, 12);
		j0[12] = 0; j0[13] = 0;
		j0[14] = 0; j0[15] = 1;
	} else {
		size_t orig = iv_len;

		while (iv_len >= 16) {
			mbedcrypto_xor(j0, j0, iv, 16);
			gcm_mult(hl, hh, j0);
			iv += 16;
			iv_len -= 16;
		}
		if (iv_len > 0) {
			memset(work, 0, 16);
			memcpy(work, iv, iv_len);
			mbedcrypto_xor(j0, j0, work, 16);
			gcm_mult(hl, hh, j0);
		}
		memset(work, 0, 16);
		mbedcrypto_put_be64(work + 8, (uint64_t)orig * 8);
		mbedcrypto_xor(j0, j0, work, 16);
		gcm_mult(hl, hh, j0);
	}

	memcpy(ctr, j0, 16);
}

/* ================================================================== */
/*  Unified GCM core (operates on struct gcm_base)                    */
/* ================================================================== */

static void aes_ecb_wrap(const void *cipher, const uint8_t in[16],
		uint8_t out[16])
{
	mbedcrypto_aes_ecb_crypt(cipher, in, out);
}

static int gcm_setkey(struct gcm_base *g)
{
	uint8_t h[16] = {0};

	/* Generate H = E_K(0^128) */
	g->ecb(g->cipher, h, h);

	/* Precompute GHASH table */
	gcm_gen_table(g->hl, g->hh, h);

	memset(h, 0, sizeof(h));
	return 0;
}

static int gcm_start(struct gcm_base *g, int dir,
		const uint8_t *iv, size_t iv_len)
{
	if (!iv || iv_len == 0)
		return -EINVAL;

	g->dir = dir;
	g->aad_len = 0;
	g->payload_len = 0;
	g->buf_len = 0;
	memset(g->ghash, 0, 16);

	gcm_compute_j0(g->hl, g->hh, g->j0, g->ctr, iv, iv_len);

	g->state = MBEDCRYPTO_GCM_STATE_STARTED;
	return 0;
}

static int gcm_update_aad(struct gcm_base *g,
		const uint8_t *aad, size_t len)
{
	if (g->state != MBEDCRYPTO_GCM_STATE_STARTED &&
	    g->state != MBEDCRYPTO_GCM_STATE_AAD)
		return -EINVAL;
	if (len == 0)
		return 0;
	if (!aad)
		return -EINVAL;

	g->state = MBEDCRYPTO_GCM_STATE_AAD;
	g->aad_len += len;

	/* If we have buffered partial AAD, fill it first */
	if (g->buf_len > 0) {
		size_t fill = 16 - g->buf_len;

		if (len < fill) {
			memcpy(g->buf + g->buf_len, aad, len);
			g->buf_len += len;
			return 0;
		}
		memcpy(g->buf + g->buf_len, aad, fill);
		mbedcrypto_xor(g->ghash, g->ghash, g->buf, 16);
		gcm_mult(g->hl, g->hh, g->ghash);
		aad += fill;
		len -= fill;
		g->buf_len = 0;
	}

	/* Process full blocks */
	while (len >= 16) {
		mbedcrypto_xor(g->ghash, g->ghash, aad, 16);
		gcm_mult(g->hl, g->hh, g->ghash);
		aad += 16;
		len -= 16;
	}

	/* Buffer remaining */
	if (len > 0) {
		memcpy(g->buf, aad, len);
		g->buf_len = len;
	}

	return 0;
}

static int gcm_update(struct gcm_base *g,
		const uint8_t *input, size_t len,
		uint8_t *output, size_t *olen)
{
	uint8_t work[16];

	if (g->state != MBEDCRYPTO_GCM_STATE_STARTED &&
	    g->state != MBEDCRYPTO_GCM_STATE_AAD &&
	    g->state != MBEDCRYPTO_GCM_STATE_DATA)
		return -EINVAL;

	/* Transitioning from AAD to DATA: flush partial AAD */
	if (g->state != MBEDCRYPTO_GCM_STATE_DATA) {
		if (g->buf_len > 0) {
			memset(work, 0, 16);
			memcpy(work, g->buf, g->buf_len);
			mbedcrypto_xor(g->ghash, g->ghash, work, 16);
			gcm_mult(g->hl, g->hh, g->ghash);
			g->buf_len = 0;
		}
		g->state = MBEDCRYPTO_GCM_STATE_DATA;
	}

	if (olen)
		*olen = len;
	if (len == 0)
		return 0;
	if (!input || !output)
		return -EINVAL;

	g->payload_len += len;

	/*
	 * Streaming GCM with partial-block buffering.
	 *
	 * CTR keystream is generated per 16-byte counter block. Data is
	 * encrypted/decrypted immediately (output = input XOR keystream).
	 * Ciphertext is accumulated into g->buf for GHASH; a GHASH
	 * multiply is performed for each completed 16-byte block.
	 * Any remaining partial block stays in g->buf until the next
	 * update() call fills it, or finish() flushes it (zero-padded).
	 *
	 * The saved keystream (g->ectr) avoids recomputing the block
	 * cipher when a partial block spans multiple update() calls.
	 */

	/* Fill partial block from previous call */
	if (g->buf_len > 0 && len > 0) {
		size_t use = 16 - g->buf_len;

		if (use > len)
			use = len;
		if (g->dir == MBEDCRYPTO_AES_ENCRYPT) {
			mbedcrypto_xor(output, input, g->ectr + g->buf_len, use);
			memcpy(g->buf + g->buf_len, output, use);
		} else {
			memcpy(g->buf + g->buf_len, input, use);
			mbedcrypto_xor(output, input, g->ectr + g->buf_len, use);
		}
		g->buf_len += use;
		input += use;
		output += use;
		len -= use;

		if (g->buf_len == 16) {
			mbedcrypto_xor(g->ghash, g->ghash, g->buf, 16);
			gcm_mult(g->hl, g->hh, g->ghash);
			g->buf_len = 0;
		}
	}

	/* Process complete 16-byte blocks */
	while (len >= 16) {
		uint8_t eblk[16];

		gcm_incr(g->ctr);
		g->ecb(g->cipher, g->ctr, eblk);

		if (g->dir == MBEDCRYPTO_AES_DECRYPT) {
			mbedcrypto_xor(g->ghash, g->ghash, input, 16);
			gcm_mult(g->hl, g->hh, g->ghash);
		}

		mbedcrypto_xor(output, input, eblk, 16);

		if (g->dir == MBEDCRYPTO_AES_ENCRYPT) {
			mbedcrypto_xor(g->ghash, g->ghash, output, 16);
			gcm_mult(g->hl, g->hh, g->ghash);
		}

		input  += 16;
		output += 16;
		len    -= 16;
	}

	/* Buffer remaining partial block */
	if (len > 0) {
		gcm_incr(g->ctr);
		g->ecb(g->cipher, g->ctr, g->ectr);

		if (g->dir == MBEDCRYPTO_AES_ENCRYPT) {
			mbedcrypto_xor(output, input, g->ectr, len);
			memcpy(g->buf, output, len);
		} else {
			memcpy(g->buf, input, len);
			mbedcrypto_xor(output, input, g->ectr, len);
		}
		g->buf_len = len;
	}

	return 0;
}

static int gcm_final(struct gcm_base *g,
		uint8_t *tag, size_t tag_len)
{
	uint8_t work[16], eblk[16];

	if (!tag)
		return -EINVAL;
	if (tag_len < 1 || tag_len > MBEDCRYPTO_GCM_TAG_MAXSIZE)
		return -EINVAL;
	if (g->state == MBEDCRYPTO_GCM_STATE_NONE)
		return -EINVAL;

	/* Flush partial AAD if update() was never called */
	if (g->state == MBEDCRYPTO_GCM_STATE_AAD ||
	    g->state == MBEDCRYPTO_GCM_STATE_STARTED) {
		if (g->buf_len > 0) {
			memset(work, 0, 16);
			memcpy(work, g->buf, g->buf_len);
			mbedcrypto_xor(g->ghash, g->ghash, work, 16);
			gcm_mult(g->hl, g->hh, g->ghash);
			g->buf_len = 0;
		}
	}

	/* Flush partial data block (ciphertext buffered for GHASH) */
	if (g->state == MBEDCRYPTO_GCM_STATE_DATA && g->buf_len > 0) {
		memset(work, 0, 16);
		memcpy(work, g->buf, g->buf_len);
		mbedcrypto_xor(g->ghash, g->ghash, work, 16);
		gcm_mult(g->hl, g->hh, g->ghash);
		g->buf_len = 0;
	}

	/* Final GHASH block: [len(A)]64 || [len(C)]64 in bits */
	memset(work, 0, 16);
	mbedcrypto_put_be64(work, (uint64_t)g->aad_len * 8);
	mbedcrypto_put_be64(work + 8, (uint64_t)g->payload_len * 8);
	mbedcrypto_xor(g->ghash, g->ghash, work, 16);
	gcm_mult(g->hl, g->hh, g->ghash);

	/* Tag = GCTR(J0, GHASH) */
	g->ecb(g->cipher, g->j0, eblk);
	mbedcrypto_xor(tag, g->ghash, eblk, tag_len);

	g->state = MBEDCRYPTO_GCM_STATE_NONE;
	return 0;
}

/*
 * One-shot GCM processing: delegates to the multi-part core.
 */
static int gcm_process(struct gcm_base *g, int dir,
		const uint8_t *iv, size_t iv_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, uint8_t *tag, size_t tag_len)
{
	size_t olen = 0;
	int ret = 0;

	ret = gcm_start(g, dir, iv, iv_len);
	if (ret != 0)
		return ret;

	ret = gcm_update_aad(g, aad, aad_len);
	if (ret != 0)
		return ret;

	ret = gcm_update(g, input, len, output, &olen);
	if (ret != 0)
		return ret;

	return gcm_final(g, tag, tag_len);
}

static int gcm_encrypt(struct gcm_base *g,
		const uint8_t *iv, size_t iv_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, uint8_t *tag, size_t tag_len)
{
	if (!tag)
		return -EINVAL;
	if (!iv && iv_len != 0)
		return -EINVAL;

	return gcm_process(g, MBEDCRYPTO_AES_ENCRYPT,
		iv, iv_len, aad, aad_len,
		input, len, output, tag, tag_len);
}

static int gcm_decrypt(struct gcm_base *g,
		const uint8_t *iv, size_t iv_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output, const uint8_t *tag, size_t tag_len)
{
	uint8_t computed_tag[MBEDCRYPTO_GCM_TAG_MAXSIZE];
	int ret = 0;

	if (!tag)
		return -EINVAL;
	if (!iv && iv_len != 0)
		return -EINVAL;

	ret = gcm_process(g, MBEDCRYPTO_AES_DECRYPT,
		iv, iv_len, aad, aad_len,
		input, len, output, computed_tag, tag_len);
	if (ret != 0)
		return ret;

	/* Constant-time tag comparison */
	if (mbedcrypto_ct_memcmp(computed_tag, tag, tag_len) != 0) {
		memset(output, 0, len);
		memset(computed_tag, 0, sizeof(computed_tag));
		return -EBADMSG;
	}

	memset(computed_tag, 0, sizeof(computed_tag));
	return 0;
}

/* ================================================================== */
/*  AES-GCM public API (thin wrappers around gcm core)                */
/* ================================================================== */

int mbedcrypto_aes_gcm_setkey(struct mbedcrypto_aes_gcm_ctx *ctx,
		const uint8_t *key, unsigned int keybits)
{
	int ret = 0;

	if (!ctx || !key)
		return -EINVAL;
	if (keybits != 128 && keybits != 192 && keybits != 256)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));

	ret = mbedcrypto_aes_setkey(&ctx->aes, key, keybits,
			MBEDCRYPTO_AES_ENCRYPT);
	if (ret != 0)
		return ret;

	ctx->base.ecb = aes_ecb_wrap;
	ctx->base.cipher = &ctx->aes;

	return gcm_setkey(&ctx->base);
}

int mbedcrypto_aes_gcm_start(struct mbedcrypto_aes_gcm_ctx *ctx, int dir,
		const uint8_t *iv, size_t iv_len)
{
	if (!ctx)
		return -EINVAL;

	return gcm_start(&ctx->base, dir, iv, iv_len);
}

int mbedcrypto_aes_gcm_update_aad(struct mbedcrypto_aes_gcm_ctx *ctx,
		const uint8_t *aad, size_t len)
{
	if (!ctx)
		return -EINVAL;

	return gcm_update_aad(&ctx->base, aad, len);
}

int mbedcrypto_aes_gcm_update(struct mbedcrypto_aes_gcm_ctx *ctx,
		const uint8_t *input, size_t len,
		uint8_t *output, size_t *olen)
{
	if (!ctx)
		return -EINVAL;

	return gcm_update(&ctx->base, input, len, output, olen);
}

int mbedcrypto_aes_gcm_final(struct mbedcrypto_aes_gcm_ctx *ctx,
		uint8_t *tag, size_t tag_len)
{
	if (!ctx)
		return -EINVAL;

	return gcm_final(&ctx->base, tag, tag_len);
}

int mbedcrypto_aes_gcm_encrypt(struct mbedcrypto_aes_gcm_ctx *ctx,
		const uint8_t *iv, size_t iv_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output,
		uint8_t *tag, size_t tag_len)
{
	if (!ctx)
		return -EINVAL;

	return gcm_encrypt(&ctx->base, iv, iv_len, aad, aad_len,
		input, len, output, tag, tag_len);
}

int mbedcrypto_aes_gcm_decrypt(struct mbedcrypto_aes_gcm_ctx *ctx,
		const uint8_t *iv, size_t iv_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output,
		const uint8_t *tag, size_t tag_len)
{
	if (!ctx)
		return -EINVAL;

	return gcm_decrypt(&ctx->base, iv, iv_len, aad, aad_len,
		input, len, output, tag, tag_len);
}

void mbedcrypto_aes_gcm_cleanup(struct mbedcrypto_aes_gcm_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

/* ================================================================== */
/*  SM4-GCM public API (thin wrappers around gcm core)                */
/* ================================================================== */

#if defined(CONFIG_MBEDCRYPTO_SM4)

static void sm4_ecb_wrap(const void *cipher, const uint8_t in[16],
		uint8_t out[16])
{
	mbedcrypto_sm4_ecb_crypt(cipher, in, out);
}

int mbedcrypto_sm4_gcm_setkey(struct mbedcrypto_sm4_gcm_ctx *ctx,
		const uint8_t *key, unsigned int keybits)
{
	int ret = 0;

	if (!ctx || !key)
		return -EINVAL;
	if (keybits != 128)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));

	ret = mbedcrypto_sm4_setkey(&ctx->sm4, key,
			MBEDCRYPTO_SM4_ENCRYPT);
	if (ret != 0)
		return ret;

	ctx->base.ecb = sm4_ecb_wrap;
	ctx->base.cipher = &ctx->sm4;

	return gcm_setkey(&ctx->base);
}

int mbedcrypto_sm4_gcm_start(struct mbedcrypto_sm4_gcm_ctx *ctx, int dir,
		const uint8_t *iv, size_t iv_len)
{
	if (!ctx)
		return -EINVAL;

	return gcm_start(&ctx->base, dir, iv, iv_len);
}

int mbedcrypto_sm4_gcm_update_aad(struct mbedcrypto_sm4_gcm_ctx *ctx,
		const uint8_t *aad, size_t len)
{
	if (!ctx)
		return -EINVAL;

	return gcm_update_aad(&ctx->base, aad, len);
}

int mbedcrypto_sm4_gcm_update(struct mbedcrypto_sm4_gcm_ctx *ctx,
		const uint8_t *input, size_t len,
		uint8_t *output, size_t *olen)
{
	if (!ctx)
		return -EINVAL;

	return gcm_update(&ctx->base, input, len, output, olen);
}

int mbedcrypto_sm4_gcm_final(struct mbedcrypto_sm4_gcm_ctx *ctx,
		uint8_t *tag, size_t tag_len)
{
	if (!ctx)
		return -EINVAL;

	return gcm_final(&ctx->base, tag, tag_len);
}

int mbedcrypto_sm4_gcm_encrypt(struct mbedcrypto_sm4_gcm_ctx *ctx,
		const uint8_t *iv, size_t iv_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output,
		uint8_t *tag, size_t tag_len)
{
	if (!ctx)
		return -EINVAL;

	return gcm_encrypt(&ctx->base, iv, iv_len, aad, aad_len,
		input, len, output, tag, tag_len);
}

int mbedcrypto_sm4_gcm_decrypt(struct mbedcrypto_sm4_gcm_ctx *ctx,
		const uint8_t *iv, size_t iv_len,
		const uint8_t *aad, size_t aad_len,
		const uint8_t *input, size_t len,
		uint8_t *output,
		const uint8_t *tag, size_t tag_len)
{
	if (!ctx)
		return -EINVAL;

	return gcm_decrypt(&ctx->base, iv, iv_len, aad, aad_len,
		input, len, output, tag, tag_len);
}

void mbedcrypto_sm4_gcm_cleanup(struct mbedcrypto_sm4_gcm_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

#endif /* CONFIG_MBEDCRYPTO_SM4 */
