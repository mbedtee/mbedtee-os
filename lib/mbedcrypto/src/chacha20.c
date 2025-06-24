// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * ChaCha20-Poly1305 AEAD cipher (RFC 8439)
 *
 * ChaCha20 stream cipher, Poly1305 one-time authenticator,
 * and the combined AEAD construction.
 */

#include <string.h>
#include <errno.h>

#include <mbedcrypto/chacha20.h>
#include <mbedcrypto/types.h>

/* ---------------------------------------------------------------- */
/* ChaCha20 stream cipher                                           */
/* ---------------------------------------------------------------- */

/* Quarter round on four 32-bit words */
#define QR(a, b, c, d)                        \
	do {                                      \
		(a) += (b); (d) ^= (a); (d) = ROTL32((d), 16); \
		(c) += (d); (b) ^= (c); (b) = ROTL32((b), 12); \
		(a) += (b); (d) ^= (a); (d) = ROTL32((d),  8); \
		(c) += (d); (b) ^= (c); (b) = ROTL32((b),  7); \
	} while (0)

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/*
 * Generate one 64-byte keystream block from the state.
 * The counter in state[12] is incremented after generation.
 */
static void chacha20_block(struct mbedcrypto_chacha20_ctx *ctx)
{
	uint32_t x[16];
	int i = 0;

	memcpy(x, ctx->state, sizeof(x));

	/* 20 rounds (10 column rounds + 10 diagonal rounds) */
	for (i = 0; i < 10; i++) {
		/* Column rounds */
		QR(x[0], x[4], x[ 8], x[12]);
		QR(x[1], x[5], x[ 9], x[13]);
		QR(x[2], x[6], x[10], x[14]);
		QR(x[3], x[7], x[11], x[15]);
		/* Diagonal rounds */
		QR(x[0], x[5], x[10], x[15]);
		QR(x[1], x[6], x[11], x[12]);
		QR(x[2], x[7], x[ 8], x[13]);
		QR(x[3], x[4], x[ 9], x[14]);
	}

	/* Add original state to working state */
	for (i = 0; i < 16; i++)
		x[i] += ctx->state[i];

	/* Serialize to little-endian keystream */
	for (i = 0; i < 16; i++)
		mbedcrypto_put_le32(ctx->keystream + 4 * i, x[i]);

	/* Increment block counter */
	ctx->state[12]++;
}

void mbedcrypto_chacha20_init(struct mbedcrypto_chacha20_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

void mbedcrypto_chacha20_cleanup(struct mbedcrypto_chacha20_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

int mbedcrypto_chacha20_setkey(struct mbedcrypto_chacha20_ctx *ctx,
		const uint8_t key[MBEDCRYPTO_CHACHA20_KEY_SIZE])
{
	if (!ctx || !key)
		return -EINVAL;

	/* "expand 32-byte k" constants */
	ctx->state[0] = 0x61707865;
	ctx->state[1] = 0x3320646e;
	ctx->state[2] = 0x79622d32;
	ctx->state[3] = 0x6b206574;

	/* Key words (little-endian) */
	ctx->state[4]  = mbedcrypto_get_le32(key);
	ctx->state[5]  = mbedcrypto_get_le32(key + 4);
	ctx->state[6]  = mbedcrypto_get_le32(key + 8);
	ctx->state[7]  = mbedcrypto_get_le32(key + 12);
	ctx->state[8]  = mbedcrypto_get_le32(key + 16);
	ctx->state[9]  = mbedcrypto_get_le32(key + 20);
	ctx->state[10] = mbedcrypto_get_le32(key + 24);
	ctx->state[11] = mbedcrypto_get_le32(key + 28);

	return 0;
}

int mbedcrypto_chacha20_set_nonce(struct mbedcrypto_chacha20_ctx *ctx,
		const uint8_t nonce[MBEDCRYPTO_CHACHA20_NONCE_SIZE],
		uint32_t counter)
{
	if (!ctx || !nonce)
		return -EINVAL;

	ctx->state[12] = counter;
	ctx->state[13] = mbedcrypto_get_le32(nonce);
	ctx->state[14] = mbedcrypto_get_le32(nonce + 4);
	ctx->state[15] = mbedcrypto_get_le32(nonce + 8);

	ctx->off = 0;
	return 0;
}

/*
 * Generate one 64-byte keystream block and XOR it directly with input.
 * Avoids the separate serialize + byte-by-byte XOR path for full blocks.
 */
static void chacha20_block_xor(struct mbedcrypto_chacha20_ctx *ctx,
		const uint8_t *input, uint8_t *output)
{
	uint32_t x[16];
	int i = 0;

	memcpy(x, ctx->state, sizeof(x));

	for (i = 0; i < 10; i++) {
		QR(x[0], x[4], x[ 8], x[12]);
		QR(x[1], x[5], x[ 9], x[13]);
		QR(x[2], x[6], x[10], x[14]);
		QR(x[3], x[7], x[11], x[15]);
		QR(x[0], x[5], x[10], x[15]);
		QR(x[1], x[6], x[11], x[12]);
		QR(x[2], x[7], x[ 8], x[13]);
		QR(x[3], x[4], x[ 9], x[14]);
	}

	for (i = 0; i < 16; i++)
		mbedcrypto_put_le32(output + 4 * i,
			(x[i] + ctx->state[i]) ^ mbedcrypto_get_le32(input + 4 * i));

	ctx->state[12]++;
}

int mbedcrypto_chacha20_update(struct mbedcrypto_chacha20_ctx *ctx,
		const uint8_t *input, size_t len, uint8_t *output)
{
	if (!ctx)
		return -EINVAL;
	if (len == 0)
		return 0;
	if (!input || !output)
		return -EINVAL;

	/* Drain leftover keystream bytes */
	while (ctx->off > 0 && ctx->off < 64 && len > 0) {
		*output++ = *input++ ^ ctx->keystream[ctx->off++];
		len--;
	}

	/* Fast path: process full 64-byte blocks with word-sized XOR */
	while (len >= 64) {
		chacha20_block_xor(ctx, input, output);
		input += 64;
		output += 64;
		len -= 64;
	}

	/* Handle trailing partial block */
	if (len > 0) {
		chacha20_block(ctx);
		ctx->off = 0;
		while (len > 0) {
			*output++ = *input++ ^ ctx->keystream[ctx->off++];
			len--;
		}
	}

	return 0;
}

/* ---------------------------------------------------------------- */
/* Poly1305 MAC                                                     */
/* ---------------------------------------------------------------- */

/*
 * Poly1305 uses 130-bit arithmetic modulo p = 2^130 - 5.
 * We represent the accumulator and r as five 26-bit digits
 * for 32-bit-friendly computation.
 */

void mbedcrypto_poly1305_init(struct mbedcrypto_poly1305_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

void mbedcrypto_poly1305_cleanup(struct mbedcrypto_poly1305_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

int mbedcrypto_poly1305_setkey(struct mbedcrypto_poly1305_ctx *ctx,
		const uint8_t key[32])
{
	uint32_t t0 = 0, t1 = 0, t2 = 0, t3 = 0;

	if (!ctx || !key)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));

	/* Clamp r: clear bits as required by spec */
	t0 = mbedcrypto_get_le32(key);
	t1 = mbedcrypto_get_le32(key + 4);
	t2 = mbedcrypto_get_le32(key + 8);
	t3 = mbedcrypto_get_le32(key + 12);

	ctx->r[0] = t0 & 0x03ffffff;
	ctx->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x03ffff03;
	ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x03ffc0ff;
	ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x03f03fff;
	ctx->r[4] = (t3 >> 8) & 0x000fffff;

	/* s = key[16..31] */
	ctx->s[0] = mbedcrypto_get_le32(key + 16);
	ctx->s[1] = mbedcrypto_get_le32(key + 20);
	ctx->s[2] = mbedcrypto_get_le32(key + 24);
	ctx->s[3] = mbedcrypto_get_le32(key + 28);

	return 0;
}

/* Process one 16-byte block */
static void poly1305_block(struct mbedcrypto_poly1305_ctx *ctx,
		const uint8_t *block, uint32_t hibit)
{
	uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2];
	uint32_t r3 = ctx->r[3], r4 = ctx->r[4];
	uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
	uint32_t h0 = ctx->acc[0], h1 = ctx->acc[1], h2 = ctx->acc[2];
	uint32_t h3 = ctx->acc[3], h4 = ctx->acc[4];
	uint32_t t0 = 0, t1 = 0, t2 = 0, t3 = 0;
	uint64_t d0 = 0, d1 = 0, d2 = 0, d3 = 0, d4 = 0;
	uint32_t c = 0;

	/* h += msg */
	t0 = mbedcrypto_get_le32(block);
	t1 = mbedcrypto_get_le32(block + 4);
	t2 = mbedcrypto_get_le32(block + 8);
	t3 = mbedcrypto_get_le32(block + 12);

	h0 += t0 & 0x03ffffff;
	h1 += ((t0 >> 26) | (t1 << 6)) & 0x03ffffff;
	h2 += ((t1 >> 20) | (t2 << 12)) & 0x03ffffff;
	h3 += ((t2 >> 14) | (t3 << 18)) & 0x03ffffff;
	h4 += (t3 >> 8) | hibit;

	/* h *= r (mod 2^130 - 5) */
	d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 +
	     (uint64_t)h2 * s3 + (uint64_t)h3 * s2 +
	     (uint64_t)h4 * s1;
	d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 +
	     (uint64_t)h2 * s4 + (uint64_t)h3 * s3 +
	     (uint64_t)h4 * s2;
	d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 +
	     (uint64_t)h2 * r0 + (uint64_t)h3 * s4 +
	     (uint64_t)h4 * s3;
	d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 +
	     (uint64_t)h2 * r1 + (uint64_t)h3 * r0 +
	     (uint64_t)h4 * s4;
	d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 +
	     (uint64_t)h2 * r2 + (uint64_t)h3 * r1 +
	     (uint64_t)h4 * r0;

	/* Partial reduction mod 2^130 - 5 */
	c = d0 >> 26; h0 = d0 & 0x03ffffff; d1 += c;
	c = d1 >> 26; h1 = d1 & 0x03ffffff; d2 += c;
	c = d2 >> 26; h2 = d2 & 0x03ffffff; d3 += c;
	c = d3 >> 26; h3 = d3 & 0x03ffffff; d4 += c;
	c = d4 >> 26; h4 = d4 & 0x03ffffff;
	h0 += c * 5;
	c = h0 >> 26; h0 &= 0x03ffffff; h1 += c;

	ctx->acc[0] = h0; ctx->acc[1] = h1; ctx->acc[2] = h2;
	ctx->acc[3] = h3; ctx->acc[4] = h4;
}

int mbedcrypto_poly1305_update(struct mbedcrypto_poly1305_ctx *ctx,
		const uint8_t *input, size_t len)
{
	size_t fill = 0;

	if (!ctx)
		return -EINVAL;
	if (len == 0)
		return 0;
	if (!input)
		return -EINVAL;

	/* Fill partial block buffer */
	if (ctx->queue_len > 0) {
		fill = 16 - ctx->queue_len;
		if (len < fill) {
			memcpy(ctx->queue + ctx->queue_len, input, len);
			ctx->queue_len += len;
			return 0;
		}
		memcpy(ctx->queue + ctx->queue_len, input, fill);
		poly1305_block(ctx, ctx->queue, 1 << 24);
		input += fill;
		len -= fill;
		ctx->queue_len = 0;
	}

	/* Process full 16-byte blocks */
	while (len >= 16) {
		poly1305_block(ctx, input, 1 << 24);
		input += 16;
		len -= 16;
	}

	/* Buffer remaining partial block */
	if (len > 0) {
		memcpy(ctx->queue, input, len);
		ctx->queue_len = len;
	}

	return 0;
}

int mbedcrypto_poly1305_final(struct mbedcrypto_poly1305_ctx *ctx,
		uint8_t tag[MBEDCRYPTO_POLY1305_TAG_SIZE])
{
	uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
	uint32_t g0 = 0, g1 = 0, g2 = 0, g3 = 0, g4 = 0;
	uint32_t mask = 0;
	uint64_t f = 0;
	uint8_t block[16];

	if (!ctx || !tag)
		return -EINVAL;

	/* Process remaining partial block */
	if (ctx->queue_len > 0) {
		memset(block, 0, sizeof(block));
		memcpy(block, ctx->queue, ctx->queue_len);
		block[ctx->queue_len] = 1; /* padding bit */
		poly1305_block(ctx, block, 0); /* no high bit for final block */
	}

	h0 = ctx->acc[0]; h1 = ctx->acc[1]; h2 = ctx->acc[2];
	h3 = ctx->acc[3]; h4 = ctx->acc[4];

	/* Full carry */
	h1 += h0 >> 26; h0 &= 0x03ffffff;
	h2 += h1 >> 26; h1 &= 0x03ffffff;
	h3 += h2 >> 26; h2 &= 0x03ffffff;
	h4 += h3 >> 26; h3 &= 0x03ffffff;
	h0 += (h4 >> 26) * 5; h4 &= 0x03ffffff;
	h1 += h0 >> 26; h0 &= 0x03ffffff;

	/* Compute h + (-p) = h - (2^130 - 5) */
	g0 = h0 + 5;
	g1 = h1 + (g0 >> 26); g0 &= 0x03ffffff;
	g2 = h2 + (g1 >> 26); g1 &= 0x03ffffff;
	g3 = h3 + (g2 >> 26); g2 &= 0x03ffffff;
	g4 = h4 + (g3 >> 26) - (1 << 26); g3 &= 0x03ffffff;

	/* Select h or g based on whether g < 2^130 */
	mask = (g4 >> 31) - 1; /* 0 if g4 bit 31 is 1, 0xffffffff otherwise */
	g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
	mask = ~mask;
	h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2; h3 = (h3 & mask) | g3;
	h4 = (h4 & mask) | g4;

	/* Pack h into 128 bits and add s */
	f = (uint64_t)(h0 | (h1 << 26)) + ctx->s[0];
	mbedcrypto_put_le32(tag, f);
	f = (uint64_t)((h1 >> 6) | (h2 << 20)) + ctx->s[1] + (f >> 32);
	mbedcrypto_put_le32(tag + 4, f);
	f = (uint64_t)((h2 >> 12) | (h3 << 14)) + ctx->s[2] + (f >> 32);
	mbedcrypto_put_le32(tag + 8, f);
	f = (uint64_t)((h3 >> 18) | (h4 << 8)) + ctx->s[3] + (f >> 32);
	mbedcrypto_put_le32(tag + 12, f);

	return 0;
}

/* ---------------------------------------------------------------- */
/* ChaCha20-Poly1305 AEAD                                            */
/* ---------------------------------------------------------------- */

void mbedcrypto_chachapoly_init(struct mbedcrypto_chachapoly_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

void mbedcrypto_chachapoly_cleanup(struct mbedcrypto_chachapoly_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

int mbedcrypto_chachapoly_setkey(struct mbedcrypto_chachapoly_ctx *ctx,
		const uint8_t key[MBEDCRYPTO_CHACHA20_KEY_SIZE])
{
	if (!ctx || !key)
		return -EINVAL;

	ctx->aad_len = 0;
	ctx->ct_len = 0;

	return mbedcrypto_chacha20_setkey(&ctx->chacha, key);
}

int mbedcrypto_chachapoly_start(struct mbedcrypto_chachapoly_ctx *ctx,
		const uint8_t nonce[MBEDCRYPTO_CHACHA20_NONCE_SIZE],
		int dir)
{
	uint8_t poly_key[64] = {0};
	int ret = 0;

	if (!ctx || !nonce)
		return -EINVAL;

	ctx->dir = dir;
	ctx->aad_len = 0;
	ctx->ct_len = 0;

	/* Generate Poly1305 key: encrypt 64 zero bytes with counter=0 */
	ret = mbedcrypto_chacha20_set_nonce(&ctx->chacha, nonce, 0);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_chacha20_update(&ctx->chacha,
			poly_key, sizeof(poly_key), poly_key);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_poly1305_setkey(&ctx->poly, poly_key);
	memset(poly_key, 0, sizeof(poly_key));
	if (ret != 0)
		return ret;

	/* Set counter to 1 for message encryption */
	ret = mbedcrypto_chacha20_set_nonce(&ctx->chacha, nonce, 1);

	return ret;
}

int mbedcrypto_chachapoly_update_aad(
		struct mbedcrypto_chachapoly_ctx *ctx,
		const uint8_t *aad, size_t aad_len)
{
	if (!ctx)
		return -EINVAL;
	if (aad_len == 0)
		return 0;
	if (!aad)
		return -EINVAL;

	ctx->aad_len += aad_len;
	return mbedcrypto_poly1305_update(&ctx->poly, aad, aad_len);
}

/* Pad Poly1305 state to a 16-byte boundary */
static void chachapoly_pad(struct mbedcrypto_poly1305_ctx *poly,
		size_t len)
{
	uint8_t zero[16] = {0};
	size_t pad = (16 - (len & 0xf)) & 0xf;

	if (pad > 0)
		mbedcrypto_poly1305_update(poly, zero, pad);
}

int mbedcrypto_chachapoly_update(struct mbedcrypto_chachapoly_ctx *ctx,
		const uint8_t *input, size_t len, uint8_t *output)
{
	int ret = 0;

	if (!ctx)
		return -EINVAL;
	if (len == 0)
		return 0;
	if (!input || !output)
		return -EINVAL;

	/* On first data, pad the AAD */
	if (ctx->ct_len == 0)
		chachapoly_pad(&ctx->poly, ctx->aad_len);

	if (ctx->dir == 0) {
		/* Encrypt then MAC */
		ret = mbedcrypto_chacha20_update(&ctx->chacha,
				input, len, output);
		if (ret != 0)
			return ret;
		mbedcrypto_poly1305_update(&ctx->poly, output, len);
	} else {
		/* MAC then decrypt */
		mbedcrypto_poly1305_update(&ctx->poly, input, len);
		ret = mbedcrypto_chacha20_update(&ctx->chacha,
				input, len, output);
		if (ret != 0)
			return ret;
	}

	ctx->ct_len += len;
	return 0;
}

int mbedcrypto_chachapoly_final(struct mbedcrypto_chachapoly_ctx *ctx,
		uint8_t tag[MBEDCRYPTO_POLY1305_TAG_SIZE])
{
	uint8_t len_block[16];

	if (!ctx || !tag)
		return -EINVAL;

	/* Pad the ciphertext */
	chachapoly_pad(&ctx->poly, ctx->ct_len);

	/* Write lengths (little-endian 64-bit) */
	mbedcrypto_put_le64(len_block, ctx->aad_len);
	mbedcrypto_put_le64(len_block + 8, ctx->ct_len);
	mbedcrypto_poly1305_update(&ctx->poly, len_block, 16);

	return mbedcrypto_poly1305_final(&ctx->poly, tag);
}
