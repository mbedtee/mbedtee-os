// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * SHA-256 and SHA-224 implementation (FIPS 180-4)
 */

#include <string.h>

#include <mbedcrypto/sha256.h>

/*
 * SHA-256 round constants (first 32 bits of the fractional
 * parts of the cube roots of the first 64 primes 2..311)
 */
static const uint32_t rc[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/* SHA-256 logical functions (FIPS 180-4 Section 4.1.2) */
#define CH(x, y, z)    (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z)   (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)       (mbedcrypto_rotr32(x, 2) ^ mbedcrypto_rotr32(x, 13) ^ mbedcrypto_rotr32(x, 22))
#define BSIG1(x)       (mbedcrypto_rotr32(x, 6) ^ mbedcrypto_rotr32(x, 11) ^ mbedcrypto_rotr32(x, 25))
#define SSIG0(x)       (mbedcrypto_rotr32(x, 7) ^ mbedcrypto_rotr32(x, 18) ^ ((x) >> 3))
#define SSIG1(x)       (mbedcrypto_rotr32(x, 17) ^ mbedcrypto_rotr32(x, 19) ^ ((x) >> 10))

/* Message schedule: circular buffer with on-the-fly expansion */
#define WW(t)      w[(t) & 0x0f]
#define SCHED(t)   (WW(t) = SSIG1(WW((t) - 2)) + WW((t) - 7) + \
                    SSIG0(WW((t) - 15)) + WW((t) - 16))

/*
 * Process one 64-byte block through the SHA-256 compression function.
 *
 * Uses a 16-word circular message schedule (64 bytes) instead of
 * the full 64-word expansion (256 bytes), saving 192 bytes of stack.
 */
static void sha256_compress(uint32_t h[8], const uint8_t block[64])
{
	uint32_t w[16];
	uint32_t a = 0, b = 0, c = 0, d = 0, e = 0, f = 0, g = 0, hh = 0;
	uint32_t t1 = 0, t2 = 0;
	int i = 0;

	for (i = 0; i < 16; i++)
		w[i] = mbedcrypto_get_be32(block + 4 * i);

	/* Working variables */
	a = h[0]; b = h[1]; c = h[2]; d = h[3];
	e = h[4]; f = h[5]; g = h[6]; hh = h[7];

	/* Rounds 0-15: use pre-loaded message words */
	for (i = 0; i < 16; i++) {
		t1 = hh + BSIG1(e) + CH(e, f, g) + rc[i] + WW(i);
		t2 = BSIG0(a) + MAJ(a, b, c);
		hh = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	/* Rounds 16-63: expand on-the-fly */
	for (; i < 64; i++) {
		t1 = hh + BSIG1(e) + CH(e, f, g) + rc[i] + SCHED(i);
		t2 = BSIG0(a) + MAJ(a, b, c);
		hh = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	/* Accumulate */
	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

int mbedcrypto_sha256_init(struct mbedcrypto_sha256_ctx *ctx, int variant)
{
	if (!ctx)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->is224 = variant;

	if (variant) {
		/* SHA-224 initial hash values (FIPS 180-4 Section 5.3.2) */
		ctx->h[0] = 0xc1059ed8;
		ctx->h[1] = 0x367cd507;
		ctx->h[2] = 0x3070dd17;
		ctx->h[3] = 0xf70e5939;
		ctx->h[4] = 0xffc00b31;
		ctx->h[5] = 0x68581511;
		ctx->h[6] = 0x64f98fa7;
		ctx->h[7] = 0xbefa4fa4;
	} else {
		/* SHA-256 initial hash values (FIPS 180-4 Section 5.3.3) */
		ctx->h[0] = 0x6a09e667;
		ctx->h[1] = 0xbb67ae85;
		ctx->h[2] = 0x3c6ef372;
		ctx->h[3] = 0xa54ff53a;
		ctx->h[4] = 0x510e527f;
		ctx->h[5] = 0x9b05688c;
		ctx->h[6] = 0x1f83d9ab;
		ctx->h[7] = 0x5be0cd19;
	}

	return 0;
}

int mbedcrypto_sha256_update(struct mbedcrypto_sha256_ctx *ctx,
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
		space = MBEDCRYPTO_SHA256_BLKSIZE - buffered;
		if (len < space) {
			memcpy(ctx->blk + buffered, data, len);
			return 0;
		}
		memcpy(ctx->blk + buffered, data, space);
		sha256_compress(ctx->h, ctx->blk);
		data += space;
		len -= space;
	}

	/* Process full blocks */
	while (len >= MBEDCRYPTO_SHA256_BLKSIZE) {
		sha256_compress(ctx->h, data);
		data += MBEDCRYPTO_SHA256_BLKSIZE;
		len -= MBEDCRYPTO_SHA256_BLKSIZE;
	}

	/* Store leftover */
	if (len > 0)
		memcpy(ctx->blk, data, len);

	return 0;
}

int mbedcrypto_sha256_final(struct mbedcrypto_sha256_ctx *ctx, uint8_t *out)
{
	size_t buffered = 0;
	uint64_t bits = 0;
	int i = 0, hashwords = 0;

	if (!ctx || !out)
		return -EINVAL;

	buffered = ctx->count & 0x3f;
	bits = ctx->count << 3;

	/* Padding: append 1 bit, then zeros, then 64-bit big-endian bit count */
	ctx->blk[buffered++] = 0x80;

	if (buffered > 56) {
		/* Not enough room for the length in this block */
		memset(ctx->blk + buffered, 0, MBEDCRYPTO_SHA256_BLKSIZE - buffered);
		sha256_compress(ctx->h, ctx->blk);
		buffered = 0;
	}

	memset(ctx->blk + buffered, 0, 56 - buffered);
	mbedcrypto_put_be64(ctx->blk + 56, bits);
	sha256_compress(ctx->h, ctx->blk);

	/* Write the digest */
	hashwords = ctx->is224 ? 7 : 8;
	for (i = 0; i < hashwords; i++)
		mbedcrypto_put_be32(out + 4 * i, ctx->h[i]);

	memset(ctx, 0, sizeof(*ctx));
	return 0;
}

void mbedcrypto_sha256_clone(struct mbedcrypto_sha256_ctx *dst,
		const struct mbedcrypto_sha256_ctx *src)
{
	if (dst && src)
		memcpy(dst, src, sizeof(*dst));
}

void mbedcrypto_sha256_cleanup(struct mbedcrypto_sha256_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

int mbedcrypto_sha256_digest(const uint8_t *data, size_t len,
		uint8_t *out, int variant)
{
	struct mbedcrypto_sha256_ctx ctx;
	int ret = 0;

	ret = mbedcrypto_sha256_init(&ctx, variant);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_sha256_update(&ctx, data, len);
	if (ret != 0)
		goto done;

	ret = mbedcrypto_sha256_final(&ctx, out);

done:
	memset(&ctx, 0, sizeof(ctx));
	return ret;
}
