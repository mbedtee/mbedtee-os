// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * SM3 cryptographic hash implementation (GB/T 32905-2016)
 */

#include <string.h>

#include <mbedcrypto/sm3.h>

/* SM3 round constants */
#define SM3_T0  0x79cc4519u
#define SM3_T1  0x7a879d8au

/* Circular left-rotate for uint32_t */
#define ROTL(x, n)  (((x) << (n)) | ((x) >> (32 - (n))))

/* Boolean functions */
#define FF0(x, y, z)  ((x) ^ (y) ^ (z))
#define FF1(x, y, z)  (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z)  ((x) ^ (y) ^ (z))
#define GG1(x, y, z)  (((x) & (y)) | (~(x) & (z)))

/* Permutation functions */
#define P0(x)  ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x)  ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))

/*
 * Pre-computed round constants: sm3_t[i] = ROTL(T_j, i & 31)
 * where T_j = SM3_T0 for rounds 0-15, SM3_T1 for rounds 16-63.
 */
static const uint32_t sm3_t[64] = {
	SM3_T0,          ROTL(SM3_T0,  1), ROTL(SM3_T0,  2), ROTL(SM3_T0,  3),
	ROTL(SM3_T0,  4), ROTL(SM3_T0,  5), ROTL(SM3_T0,  6), ROTL(SM3_T0,  7),
	ROTL(SM3_T0,  8), ROTL(SM3_T0,  9), ROTL(SM3_T0, 10), ROTL(SM3_T0, 11),
	ROTL(SM3_T0, 12), ROTL(SM3_T0, 13), ROTL(SM3_T0, 14), ROTL(SM3_T0, 15),
	ROTL(SM3_T1, 16), ROTL(SM3_T1, 17), ROTL(SM3_T1, 18), ROTL(SM3_T1, 19),
	ROTL(SM3_T1, 20), ROTL(SM3_T1, 21), ROTL(SM3_T1, 22), ROTL(SM3_T1, 23),
	ROTL(SM3_T1, 24), ROTL(SM3_T1, 25), ROTL(SM3_T1, 26), ROTL(SM3_T1, 27),
	ROTL(SM3_T1, 28), ROTL(SM3_T1, 29), ROTL(SM3_T1, 30), ROTL(SM3_T1, 31),
	SM3_T1,          ROTL(SM3_T1,  1), ROTL(SM3_T1,  2), ROTL(SM3_T1,  3),
	ROTL(SM3_T1,  4), ROTL(SM3_T1,  5), ROTL(SM3_T1,  6), ROTL(SM3_T1,  7),
	ROTL(SM3_T1,  8), ROTL(SM3_T1,  9), ROTL(SM3_T1, 10), ROTL(SM3_T1, 11),
	ROTL(SM3_T1, 12), ROTL(SM3_T1, 13), ROTL(SM3_T1, 14), ROTL(SM3_T1, 15),
	ROTL(SM3_T1, 16), ROTL(SM3_T1, 17), ROTL(SM3_T1, 18), ROTL(SM3_T1, 19),
	ROTL(SM3_T1, 20), ROTL(SM3_T1, 21), ROTL(SM3_T1, 22), ROTL(SM3_T1, 23),
	ROTL(SM3_T1, 24), ROTL(SM3_T1, 25), ROTL(SM3_T1, 26), ROTL(SM3_T1, 27),
	ROTL(SM3_T1, 28), ROTL(SM3_T1, 29), ROTL(SM3_T1, 30), ROTL(SM3_T1, 31),
};

/*
 * Process one 64-byte block through the SM3 compression function.
 *
 * Uses a full w[68] expansion array with direct indexing instead of
 * a 20-word circular buffer, avoiding expensive modulo-20 operations
 * that generate multiply-shift-subtract sequences on ARM32.
 */
static void sm3_compress(uint32_t h[8], const uint8_t block[64])
{
	uint32_t w[68];
	uint32_t a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, hh = 0;
	uint32_t a12 = 0, ss1 = 0, ss2 = 0, tt1 = 0, tt2 = 0;
	int i = 0;

	/* Load 16 message words (big-endian) */
	for (i = 0; i < 16; i++)
		w[i] = mbedcrypto_get_be32(block + 4 * i);

	/* Message expansion: w[16..67] */
	for (i = 16; i < 68; i++)
		w[i] = P1(w[i - 16] ^ w[i - 9] ^ ROTL(w[i - 3], 15)) ^
			ROTL(w[i - 13], 7) ^ w[i - 6];

	/* Working variables */
	a = h[0]; b = h[1]; c = h[2]; d = h[3];
	e = h[4]; f = h[5]; g = h[6]; hh = h[7];

	/* Rounds 0-15: FF0/GG0 */
	for (i = 0; i < 16; i++) {
		a12 = ROTL(a, 12);
		ss1 = ROTL(a12 + e + sm3_t[i], 7);
		ss2 = ss1 ^ a12;
		tt1 = FF0(a, b, c) + d + ss2 + (w[i] ^ w[i + 4]);
		tt2 = GG0(e, f, g) + hh + ss1 + w[i];
		d = c;
		c = ROTL(b, 9);
		b = a;
		a = tt1;
		hh = g;
		g = ROTL(f, 19);
		f = e;
		e = P0(tt2);
	}

	/* Rounds 16-63: FF1/GG1 */
	for (; i < 64; i++) {
		a12 = ROTL(a, 12);
		ss1 = ROTL(a12 + e + sm3_t[i], 7);
		ss2 = ss1 ^ a12;
		tt1 = FF1(a, b, c) + d + ss2 + (w[i] ^ w[i + 4]);
		tt2 = GG1(e, f, g) + hh + ss1 + w[i];
		d = c;
		c = ROTL(b, 9);
		b = a;
		a = tt1;
		hh = g;
		g = ROTL(f, 19);
		f = e;
		e = P0(tt2);
	}

	/* Accumulate */
	h[0] ^= a; h[1] ^= b; h[2] ^= c; h[3] ^= d;
	h[4] ^= e; h[5] ^= f; h[6] ^= g; h[7] ^= hh;
}

int mbedcrypto_sm3_init(struct mbedcrypto_sm3_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));

	/* SM3 initial hash values (GB/T 32905-2016 Section 4.1) */
	ctx->h[0] = 0x7380166f;
	ctx->h[1] = 0x4914b2b9;
	ctx->h[2] = 0x172442d7;
	ctx->h[3] = 0xda8a0600;
	ctx->h[4] = 0xa96f30bc;
	ctx->h[5] = 0x163138aa;
	ctx->h[6] = 0xe38dee4d;
	ctx->h[7] = 0xb0fb0e4e;

	return 0;
}

int mbedcrypto_sm3_update(struct mbedcrypto_sm3_ctx *ctx,
		const uint8_t *data, size_t len)
{
	size_t buffered = 0, space = 0;

	if (!ctx)
		return -EINVAL;
	if (len == 0)
		return 0;
	if (!data)
		return -EINVAL;

	buffered = ctx->count & 0x3f;
	ctx->count += len;

	/* Fill up partial block first */
	if (buffered > 0) {
		space = MBEDCRYPTO_SM3_BLKSIZE - buffered;
		if (len < space) {
			memcpy(ctx->blk + buffered, data, len);
			return 0;
		}
		memcpy(ctx->blk + buffered, data, space);
		sm3_compress(ctx->h, ctx->blk);
		data += space;
		len -= space;
	}

	/* Process full blocks */
	while (len >= MBEDCRYPTO_SM3_BLKSIZE) {
		sm3_compress(ctx->h, data);
		data += MBEDCRYPTO_SM3_BLKSIZE;
		len -= MBEDCRYPTO_SM3_BLKSIZE;
	}

	/* Store leftover */
	if (len > 0)
		memcpy(ctx->blk, data, len);

	return 0;
}

int mbedcrypto_sm3_final(struct mbedcrypto_sm3_ctx *ctx, uint8_t *out)
{
	size_t buffered = 0;
	uint64_t bits = 0;
	int i = 0;

	if (!ctx || !out)
		return -EINVAL;

	buffered = ctx->count & 0x3f;
	bits = ctx->count << 3;

	/* Padding: append 1 bit, then zeros, then 64-bit big-endian bit count */
	ctx->blk[buffered++] = 0x80;

	if (buffered > 56) {
		/* Not enough room for the length in this block */
		memset(ctx->blk + buffered, 0, MBEDCRYPTO_SM3_BLKSIZE - buffered);
		sm3_compress(ctx->h, ctx->blk);
		buffered = 0;
	}

	memset(ctx->blk + buffered, 0, 56 - buffered);
	mbedcrypto_put_be64(ctx->blk + 56, bits);
	sm3_compress(ctx->h, ctx->blk);

	/* Write the digest */
	for (i = 0; i < 8; i++)
		mbedcrypto_put_be32(out + 4 * i, ctx->h[i]);

	memset(ctx, 0, sizeof(*ctx));
	return 0;
}

void mbedcrypto_sm3_clone(struct mbedcrypto_sm3_ctx *dst,
		const struct mbedcrypto_sm3_ctx *src)
{
	if (dst && src)
		memcpy(dst, src, sizeof(*dst));
}

void mbedcrypto_sm3_cleanup(struct mbedcrypto_sm3_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

int mbedcrypto_sm3_digest(const uint8_t *data, size_t len, uint8_t *out)
{
	struct mbedcrypto_sm3_ctx ctx;
	int ret = 0;

	ret = mbedcrypto_sm3_init(&ctx);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_sm3_update(&ctx, data, len);
	if (ret != 0)
		goto done;

	ret = mbedcrypto_sm3_final(&ctx, out);

done:
	memset(&ctx, 0, sizeof(ctx));
	return ret;
}
