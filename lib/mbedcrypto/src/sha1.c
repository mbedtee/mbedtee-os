// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * SHA-1 implementation (FIPS 180-4)
 *
 * WARNING: SHA-1 is cryptographically broken.
 * Provided only for legacy compatibility.
 */

#include <string.h>

#include <mbedcrypto/sha1.h>

/* SHA-1 round constants */
#define K0  0x5a827999
#define K1  0x6ed9eba1
#define K2  0x8f1bbcdc
#define K3  0xca62c1d6

/* Boolean functions (optimized: fewer operations than textbook) */
#define CH(x, y, z)  ((z) ^ ((x) & ((y) ^ (z))))
#define PAR(x, y, z) ((x) ^ (y) ^ (z))
#define MAJ(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))

/* Message schedule: expand and fetch w[t] using a circular buffer */
#define WW(t)    w[(t) & 0x0f]
#define SCHED(t) (WW(t) = mbedcrypto_rotl32(                           \
		WW(t) ^ WW((t) - 3) ^ WW((t) - 8) ^ WW((t) - 14), 1))

/*
 * Process one 64-byte block through the SHA-1 compression function.
 *
 * Loop-based round processing with a 16-word circular message schedule.
 * Balances code size and performance for this legacy algorithm.
 */
static void sha1_compress(uint32_t h[5], const uint8_t block[64])
{
	uint32_t w[16];
	uint32_t a = 0, b = 0, c = 0, d = 0, e = 0, tmp = 0;
	int i = 0;

	for (i = 0; i < 16; i++)
		w[i] = mbedcrypto_get_be32(block + 4 * i);

	a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];

	/* Rounds  0-15: Ch, pre-loaded message words */
	for (i = 0; i < 16; i++) {
		tmp = mbedcrypto_rotl32(a, 5) + CH(b, c, d) + e + K0 + WW(i);
		e = d; d = c; c = mbedcrypto_rotl32(b, 30); b = a; a = tmp;
	}
	/* Rounds 16-19: Ch, schedule expansion */
	for (; i < 20; i++) {
		tmp = mbedcrypto_rotl32(a, 5) + CH(b, c, d) + e + K0 + SCHED(i);
		e = d; d = c; c = mbedcrypto_rotl32(b, 30); b = a; a = tmp;
	}
	/* Rounds 20-39: Parity */
	for (; i < 40; i++) {
		tmp = mbedcrypto_rotl32(a, 5) + PAR(b, c, d) + e + K1 + SCHED(i);
		e = d; d = c; c = mbedcrypto_rotl32(b, 30); b = a; a = tmp;
	}
	/* Rounds 40-59: Majority */
	for (; i < 60; i++) {
		tmp = mbedcrypto_rotl32(a, 5) + MAJ(b, c, d) + e + K2 + SCHED(i);
		e = d; d = c; c = mbedcrypto_rotl32(b, 30); b = a; a = tmp;
	}
	/* Rounds 60-79: Parity */
	for (; i < 80; i++) {
		tmp = mbedcrypto_rotl32(a, 5) + PAR(b, c, d) + e + K3 + SCHED(i);
		e = d; d = c; c = mbedcrypto_rotl32(b, 30); b = a; a = tmp;
	}

	h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

int mbedcrypto_sha1_init(struct mbedcrypto_sha1_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));

	/* SHA-1 initial hash values (FIPS 180-4 Section 5.3.1) */
	ctx->h[0] = 0x67452301;
	ctx->h[1] = 0xefcdab89;
	ctx->h[2] = 0x98badcfe;
	ctx->h[3] = 0x10325476;
	ctx->h[4] = 0xc3d2e1f0;

	return 0;
}

int mbedcrypto_sha1_update(struct mbedcrypto_sha1_ctx *ctx,
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

	if (buffered > 0) {
		space = MBEDCRYPTO_SHA1_BLKSIZE - buffered;
		if (len < space) {
			memcpy(ctx->blk + buffered, data, len);
			return 0;
		}
		memcpy(ctx->blk + buffered, data, space);
		sha1_compress(ctx->h, ctx->blk);
		data += space;
		len -= space;
	}

	while (len >= MBEDCRYPTO_SHA1_BLKSIZE) {
		sha1_compress(ctx->h, data);
		data += MBEDCRYPTO_SHA1_BLKSIZE;
		len -= MBEDCRYPTO_SHA1_BLKSIZE;
	}

	if (len > 0)
		memcpy(ctx->blk, data, len);

	return 0;
}

int mbedcrypto_sha1_final(struct mbedcrypto_sha1_ctx *ctx, uint8_t *out)
{
	size_t buffered = 0;
	uint64_t bits = 0;
	int i = 0;

	if (!ctx || !out)
		return -EINVAL;

	buffered = ctx->count & 0x3f;
	bits = ctx->count << 3;

	ctx->blk[buffered++] = 0x80;

	if (buffered > 56) {
		memset(ctx->blk + buffered, 0, MBEDCRYPTO_SHA1_BLKSIZE - buffered);
		sha1_compress(ctx->h, ctx->blk);
		buffered = 0;
	}

	memset(ctx->blk + buffered, 0, 56 - buffered);
	mbedcrypto_put_be64(ctx->blk + 56, bits);
	sha1_compress(ctx->h, ctx->blk);

	for (i = 0; i < 5; i++)
		mbedcrypto_put_be32(out + 4 * i, ctx->h[i]);

	memset(ctx, 0, sizeof(*ctx));
	return 0;
}

void mbedcrypto_sha1_clone(struct mbedcrypto_sha1_ctx *dst,
		const struct mbedcrypto_sha1_ctx *src)
{
	if (dst && src)
		memcpy(dst, src, sizeof(*dst));
}

void mbedcrypto_sha1_cleanup(struct mbedcrypto_sha1_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

int mbedcrypto_sha1_digest(const uint8_t *data, size_t len, uint8_t *out)
{
	struct mbedcrypto_sha1_ctx ctx;
	int ret = 0;

	ret = mbedcrypto_sha1_init(&ctx);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_sha1_update(&ctx, data, len);
	if (ret != 0)
		goto done;

	ret = mbedcrypto_sha1_final(&ctx, out);

done:
	memset(&ctx, 0, sizeof(ctx));
	return ret;
}
