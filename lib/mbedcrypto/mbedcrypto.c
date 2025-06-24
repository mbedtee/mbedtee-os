/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Unified mbedcrypto wrapper layer
 *
 * Hash dispatch, HMAC, symmetric cipher, and cipher-based MAC.
 */

#include <string.h>

#include <mbedcrypto.h>

/* ---------------------------------------------------------------- */
/* Hash dispatch                                                    */
/* ---------------------------------------------------------------- */

size_t mbedcrypto_hash_size(int algo)
{
	switch (algo) {
	case MBEDCRYPTO_HASH_NONE:   return 0;
	case MBEDCRYPTO_HASH_MD5:    return 16;
	case MBEDCRYPTO_HASH_SHA1:   return 20;
	case MBEDCRYPTO_HASH_SHA224: return 28;
	case MBEDCRYPTO_HASH_SHA256: return 32;
	case MBEDCRYPTO_HASH_SHA384: return 48;
	case MBEDCRYPTO_HASH_SHA512: return 64;
	case MBEDCRYPTO_HASH_SM3:    return 32;
	case MBEDCRYPTO_HASH_SHA3_224: return 28;
	case MBEDCRYPTO_HASH_SHA3_256: return 32;
	case MBEDCRYPTO_HASH_SHA3_384: return 48;
	case MBEDCRYPTO_HASH_SHA3_512: return 64;
	default: return 0;
	}
}

size_t mbedcrypto_hash_blksize(int algo)
{
	switch (algo) {
	case MBEDCRYPTO_HASH_MD5:    return 64;
	case MBEDCRYPTO_HASH_SHA1:   return 64;
	case MBEDCRYPTO_HASH_SHA224: return 64;
	case MBEDCRYPTO_HASH_SHA256: return 64;
	case MBEDCRYPTO_HASH_SHA384: return 128;
	case MBEDCRYPTO_HASH_SHA512: return 128;
	case MBEDCRYPTO_HASH_SM3:    return 64;
	case MBEDCRYPTO_HASH_SHA3_224: return 144;
	case MBEDCRYPTO_HASH_SHA3_256: return 136;
	case MBEDCRYPTO_HASH_SHA3_384: return 104;
	case MBEDCRYPTO_HASH_SHA3_512: return 72;
	default: return 0;
	}
}

int mbedcrypto_hash_init(struct mbedcrypto_hash_ctx *ctx, int algo)
{
	ctx->algo = algo;
	switch (algo) {
	case MBEDCRYPTO_HASH_MD5:    return mbedcrypto_md5_init(&ctx->md5);
	case MBEDCRYPTO_HASH_SHA1:   return mbedcrypto_sha1_init(&ctx->sha1);
	case MBEDCRYPTO_HASH_SHA224: return mbedcrypto_sha256_init(&ctx->sha256, 1);
	case MBEDCRYPTO_HASH_SHA256: return mbedcrypto_sha256_init(&ctx->sha256, 0);
	case MBEDCRYPTO_HASH_SHA384: return mbedcrypto_sha512_init(&ctx->sha512, 1);
	case MBEDCRYPTO_HASH_SHA512: return mbedcrypto_sha512_init(&ctx->sha512, 0);
	case MBEDCRYPTO_HASH_SM3:    return mbedcrypto_sm3_init(&ctx->sm3);
	case MBEDCRYPTO_HASH_SHA3_224:
		mbedcrypto_sha3_init(&ctx->sha3);
		return mbedcrypto_sha3_start(&ctx->sha3, MBEDCRYPTO_SHA3_224);
	case MBEDCRYPTO_HASH_SHA3_256:
		mbedcrypto_sha3_init(&ctx->sha3);
		return mbedcrypto_sha3_start(&ctx->sha3, MBEDCRYPTO_SHA3_256);
	case MBEDCRYPTO_HASH_SHA3_384:
		mbedcrypto_sha3_init(&ctx->sha3);
		return mbedcrypto_sha3_start(&ctx->sha3, MBEDCRYPTO_SHA3_384);
	case MBEDCRYPTO_HASH_SHA3_512:
		mbedcrypto_sha3_init(&ctx->sha3);
		return mbedcrypto_sha3_start(&ctx->sha3, MBEDCRYPTO_SHA3_512);
	default: return -EINVAL;
	}
}

int mbedcrypto_hash_update(struct mbedcrypto_hash_ctx *ctx,
		const uint8_t *data, size_t len)
{
	switch (ctx->algo) {
	case MBEDCRYPTO_HASH_MD5:
		return mbedcrypto_md5_update(&ctx->md5, data, len);
	case MBEDCRYPTO_HASH_SHA1:
		return mbedcrypto_sha1_update(&ctx->sha1, data, len);
	case MBEDCRYPTO_HASH_SHA224:
	case MBEDCRYPTO_HASH_SHA256:
		return mbedcrypto_sha256_update(&ctx->sha256, data, len);
	case MBEDCRYPTO_HASH_SHA384:
	case MBEDCRYPTO_HASH_SHA512:
		return mbedcrypto_sha512_update(&ctx->sha512, data, len);
	case MBEDCRYPTO_HASH_SM3:
		return mbedcrypto_sm3_update(&ctx->sm3, data, len);
	case MBEDCRYPTO_HASH_SHA3_224:
	case MBEDCRYPTO_HASH_SHA3_256:
	case MBEDCRYPTO_HASH_SHA3_384:
	case MBEDCRYPTO_HASH_SHA3_512:
		return mbedcrypto_sha3_update(&ctx->sha3, data, len);
	default: return -EINVAL;
	}
}

int mbedcrypto_hash_final(struct mbedcrypto_hash_ctx *ctx, uint8_t *out)
{
	switch (ctx->algo) {
	case MBEDCRYPTO_HASH_MD5:    return mbedcrypto_md5_final(&ctx->md5, out);
	case MBEDCRYPTO_HASH_SHA1:   return mbedcrypto_sha1_final(&ctx->sha1, out);
	case MBEDCRYPTO_HASH_SHA224:
	case MBEDCRYPTO_HASH_SHA256: return mbedcrypto_sha256_final(&ctx->sha256, out);
	case MBEDCRYPTO_HASH_SHA384:
	case MBEDCRYPTO_HASH_SHA512: return mbedcrypto_sha512_final(&ctx->sha512, out);
	case MBEDCRYPTO_HASH_SM3:    return mbedcrypto_sm3_final(&ctx->sm3, out);
	case MBEDCRYPTO_HASH_SHA3_224:
	case MBEDCRYPTO_HASH_SHA3_256:
	case MBEDCRYPTO_HASH_SHA3_384:
	case MBEDCRYPTO_HASH_SHA3_512:
		return mbedcrypto_sha3_final(&ctx->sha3, out,
				mbedcrypto_hash_size(ctx->algo));
	default: return -EINVAL;
	}
}

void mbedcrypto_hash_clone(struct mbedcrypto_hash_ctx *dst,
		const struct mbedcrypto_hash_ctx *src)
{
	dst->algo = src->algo;
	switch (src->algo) {
	case MBEDCRYPTO_HASH_MD5:
		mbedcrypto_md5_clone(&dst->md5, &src->md5); break;
	case MBEDCRYPTO_HASH_SHA1:
		mbedcrypto_sha1_clone(&dst->sha1, &src->sha1); break;
	case MBEDCRYPTO_HASH_SHA224:
	case MBEDCRYPTO_HASH_SHA256:
		mbedcrypto_sha256_clone(&dst->sha256, &src->sha256); break;
	case MBEDCRYPTO_HASH_SHA384:
	case MBEDCRYPTO_HASH_SHA512:
		mbedcrypto_sha512_clone(&dst->sha512, &src->sha512); break;
	case MBEDCRYPTO_HASH_SM3:
		mbedcrypto_sm3_clone(&dst->sm3, &src->sm3); break;
	case MBEDCRYPTO_HASH_SHA3_224:
	case MBEDCRYPTO_HASH_SHA3_256:
	case MBEDCRYPTO_HASH_SHA3_384:
	case MBEDCRYPTO_HASH_SHA3_512:
		mbedcrypto_sha3_clone(&dst->sha3, &src->sha3); break;
	default: break;
	}
}

void mbedcrypto_hash_cleanup(struct mbedcrypto_hash_ctx *ctx)
{
	switch (ctx->algo) {
	case MBEDCRYPTO_HASH_MD5:    mbedcrypto_md5_cleanup(&ctx->md5); break;
	case MBEDCRYPTO_HASH_SHA1:   mbedcrypto_sha1_cleanup(&ctx->sha1); break;
	case MBEDCRYPTO_HASH_SHA224:
	case MBEDCRYPTO_HASH_SHA256: mbedcrypto_sha256_cleanup(&ctx->sha256); break;
	case MBEDCRYPTO_HASH_SHA384:
	case MBEDCRYPTO_HASH_SHA512: mbedcrypto_sha512_cleanup(&ctx->sha512); break;
	case MBEDCRYPTO_HASH_SM3:    mbedcrypto_sm3_cleanup(&ctx->sm3); break;
	case MBEDCRYPTO_HASH_SHA3_224:
	case MBEDCRYPTO_HASH_SHA3_256:
	case MBEDCRYPTO_HASH_SHA3_384:
	case MBEDCRYPTO_HASH_SHA3_512:
		mbedcrypto_sha3_cleanup(&ctx->sha3); break;
	default: break;
	}
}

/* ---------------------------------------------------------------- */
/* HMAC                                                             */
/* ---------------------------------------------------------------- */

int mbedcrypto_hmac_init(struct mbedcrypto_hmac_ctx *ctx,
		int algo, const uint8_t *key, size_t keylen)
{
	size_t blk = mbedcrypto_hash_blksize(algo);
	uint8_t kbuf[144]; /* max block size (SHA3-224 rate = 144) */
	struct mbedcrypto_hash_ctx opad_ctx;
	size_t i = 0;
	int ret = 0;

	memset(ctx, 0, sizeof(*ctx));
	ctx->algo = algo;

	/* If key > block size, hash it */
	if (keylen > blk) {
		struct mbedcrypto_hash_ctx kh;

		if ((ret = mbedcrypto_hash_init(&kh, algo)) != 0)
			goto out;
		mbedcrypto_hash_update(&kh, key, keylen);
		mbedcrypto_hash_final(&kh, kbuf);
		mbedcrypto_hash_cleanup(&kh);
		keylen = mbedcrypto_hash_size(algo);
	} else
		memcpy(kbuf, key, keylen);

	/* Pad to block size */
	if (keylen < blk)
		memset(kbuf + keylen, 0, blk - keylen);

	/* Inner hash: H(K ^ ipad || ...) */
	if ((ret = mbedcrypto_hash_init(&ctx->inner, algo)) != 0)
		goto out;

	for (i = 0; i < blk; i++)
		kbuf[i] ^= 0x36;
	mbedcrypto_hash_update(&ctx->inner, kbuf, blk);

	/* Prepare outer hash state: H(K ^ opad || ...) */
	for (i = 0; i < blk; i++)
		kbuf[i] ^= 0x36 ^ 0x5c;

	if ((ret = mbedcrypto_hash_init(&opad_ctx, algo)) != 0)
		goto out_inner;
	mbedcrypto_hash_update(&opad_ctx, kbuf, blk);

	/* Save outer state for final */
	memcpy(ctx->opad_state, &opad_ctx, sizeof(opad_ctx));

	memset(kbuf, 0, sizeof(kbuf));
	return 0;

out_inner:
	mbedcrypto_hash_cleanup(&ctx->inner);
out:
	memset(kbuf, 0, sizeof(kbuf));
	return ret;
}

int mbedcrypto_hmac_update(struct mbedcrypto_hmac_ctx *ctx,
		const uint8_t *data, size_t len)
{
	return mbedcrypto_hash_update(&ctx->inner, data, len);
}

int mbedcrypto_hmac_final(struct mbedcrypto_hmac_ctx *ctx, uint8_t *mac)
{
	uint8_t inner_hash[64]; /* max hash size */
	size_t hlen = mbedcrypto_hash_size(ctx->algo);
	struct mbedcrypto_hash_ctx outer;
	int ret = 0;

	if ((ret = mbedcrypto_hash_final(&ctx->inner, inner_hash)) != 0)
		return ret;

	/* Clone the saved outer state */
	memcpy(&outer, ctx->opad_state, sizeof(outer));

	/* outer = H(K ^ opad || inner_hash) */
	mbedcrypto_hash_update(&outer, inner_hash, hlen);
	ret = mbedcrypto_hash_final(&outer, mac);

	memset(inner_hash, 0, sizeof(inner_hash));
	mbedcrypto_hash_cleanup(&outer);
	return ret;
}

void mbedcrypto_hmac_cleanup(struct mbedcrypto_hmac_ctx *ctx)
{
	mbedcrypto_hash_cleanup(&ctx->inner);
	memset(ctx, 0, sizeof(*ctx));
}

/* ---------------------------------------------------------------- */
/* Cipher helpers                                                   */
/* ---------------------------------------------------------------- */

static inline int is_ecb(int type)
{
	return type == MBEDCRYPTO_CIPHER_AES_ECB ||
	       type == MBEDCRYPTO_CIPHER_DES_ECB ||
	       type == MBEDCRYPTO_CIPHER_DES3_ECB ||
	       type == MBEDCRYPTO_CIPHER_SM4_ECB ||
	       type == MBEDCRYPTO_CIPHER_SM4_ECB_PKCS5;
}

static inline int is_cbc(int type)
{
	return type == MBEDCRYPTO_CIPHER_AES_CBC ||
	       type == MBEDCRYPTO_CIPHER_DES_CBC ||
	       type == MBEDCRYPTO_CIPHER_DES3_CBC ||
	       type == MBEDCRYPTO_CIPHER_SM4_CBC ||
	       type == MBEDCRYPTO_CIPHER_AES_CBC_PKCS5 ||
	       type == MBEDCRYPTO_CIPHER_DES_CBC_PKCS5 ||
	       type == MBEDCRYPTO_CIPHER_DES3_CBC_PKCS5 ||
	       type == MBEDCRYPTO_CIPHER_SM4_CBC_PKCS5;
}

static inline int is_pkcs5(int type)
{
	return type == MBEDCRYPTO_CIPHER_AES_CBC_PKCS5 ||
	       type == MBEDCRYPTO_CIPHER_DES_CBC_PKCS5 ||
	       type == MBEDCRYPTO_CIPHER_DES3_CBC_PKCS5 ||
	       type == MBEDCRYPTO_CIPHER_SM4_CBC_PKCS5 ||
	       type == MBEDCRYPTO_CIPHER_SM4_ECB_PKCS5;
}

static inline int is_ctr(int type)
{
	return type == MBEDCRYPTO_CIPHER_AES_CTR ||
	       type == MBEDCRYPTO_CIPHER_SM4_CTR;
}

static inline int is_cts(int type)
{
	return type == MBEDCRYPTO_CIPHER_AES_CTS ||
	       type == MBEDCRYPTO_CIPHER_DES3_CTS ||
	       type == MBEDCRYPTO_CIPHER_SM4_CTS;
}

/* ---------------------------------------------------------------- */
/* Cipher API                                                       */
/* ---------------------------------------------------------------- */

int mbedcrypto_cipher_init(struct mbedcrypto_cipher_ctx *ctx,
		int type, const uint8_t *key,
		unsigned int keybits, int dir)
{
	int ret = 0;

	if (!ctx || !key)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->type = type;
	ctx->dir = dir;

	switch (type) {
	case MBEDCRYPTO_CIPHER_AES_ECB:
	case MBEDCRYPTO_CIPHER_AES_CBC:
	case MBEDCRYPTO_CIPHER_AES_CTS:
	case MBEDCRYPTO_CIPHER_AES_CBC_PKCS5:
		ctx->blksize = 16;
		ret = mbedcrypto_aes_setkey(&ctx->aes, key, keybits, dir);
		break;

	case MBEDCRYPTO_CIPHER_AES_CTR:
		ctx->blksize = 16;
		ret = mbedcrypto_aes_setkey(&ctx->aes, key, keybits,
					    MBEDCRYPTO_AES_ENCRYPT);
		break;

	case MBEDCRYPTO_CIPHER_AES_XTS:
		ctx->blksize = 16;
		ret = mbedcrypto_aes_xts_setkey(&ctx->xts, key, keybits, dir);
		break;

	case MBEDCRYPTO_CIPHER_DES_ECB:
	case MBEDCRYPTO_CIPHER_DES_CBC:
	case MBEDCRYPTO_CIPHER_DES_CBC_PKCS5:
		ctx->blksize = 8;
		mbedcrypto_des_init(&ctx->des);
		ret = mbedcrypto_des_setkey(&ctx->des, key, dir);
		break;

	case MBEDCRYPTO_CIPHER_DES3_ECB:
	case MBEDCRYPTO_CIPHER_DES3_CBC:
	case MBEDCRYPTO_CIPHER_DES3_CTS:
	case MBEDCRYPTO_CIPHER_DES3_CBC_PKCS5:
		ctx->blksize = 8;
		mbedcrypto_des3_init(&ctx->des3);
		ret = mbedcrypto_des3_setkey(&ctx->des3, key, dir);
		break;

	case MBEDCRYPTO_CIPHER_SM4_ECB:
	case MBEDCRYPTO_CIPHER_SM4_CBC:
	case MBEDCRYPTO_CIPHER_SM4_CTS:
	case MBEDCRYPTO_CIPHER_SM4_ECB_PKCS5:
	case MBEDCRYPTO_CIPHER_SM4_CBC_PKCS5:
		ctx->blksize = 16;
		ret = mbedcrypto_sm4_setkey(&ctx->sm4, key, dir);
		break;

	case MBEDCRYPTO_CIPHER_SM4_CTR:
		ctx->blksize = 16;
		ret = mbedcrypto_sm4_setkey(&ctx->sm4, key,
					    MBEDCRYPTO_SM4_ENCRYPT);
		break;

	case MBEDCRYPTO_CIPHER_CHACHA20:
		ctx->blksize = 1; /* stream cipher, no block alignment */
		mbedcrypto_chacha20_init(&ctx->chacha20);
		ret = mbedcrypto_chacha20_setkey(&ctx->chacha20, key);
		break;

	default:
		return -EINVAL;
	}

	return ret;
}

int mbedcrypto_cipher_set_iv(struct mbedcrypto_cipher_ctx *ctx,
		const uint8_t *iv, size_t iv_len)
{
	if (!ctx)
		return -EINVAL;

	/* ECB modes don't use IV */
	if (is_ecb(ctx->type))
		return 0;

	/* ChaCha20: 12-byte nonce, counter starts at 1 (RFC 8439) */
	if (ctx->type == MBEDCRYPTO_CIPHER_CHACHA20) {
		if (!iv || iv_len != MBEDCRYPTO_CHACHA20_NONCE_SIZE)
			return -EINVAL;
		return mbedcrypto_chacha20_set_nonce(&ctx->chacha20, iv, 1);
	}

	if (!iv || iv_len != ctx->blksize)
		return -EINVAL;

	memcpy(ctx->iv, iv, iv_len);
	ctx->ctr_off = 0;
	memset(ctx->keystream, 0, 16);

	/* XTS: encrypt the data unit index with the tweak key */
	if (ctx->type == MBEDCRYPTO_CIPHER_AES_XTS)
		mbedcrypto_aes_ecb_crypt(&ctx->xts.tweak, iv, ctx->iv);

	return 0;
}

void mbedcrypto_cipher_reset(struct mbedcrypto_cipher_ctx *ctx)
{
	if (!ctx)
		return;

	ctx->ctr_off = 0;
	ctx->partial_len = 0;
	memset(ctx->keystream, 0, 16);
}

/*
 * Encrypt/decrypt a single block using the raw algorithm.
 * Internal: always called with valid ctx/in/out, cannot fail.
 */
static void cipher_crypt_block(struct mbedcrypto_cipher_ctx *ctx,
		const uint8_t *in, uint8_t *out)
{
	switch (ctx->type) {
	case MBEDCRYPTO_CIPHER_AES_ECB:
	case MBEDCRYPTO_CIPHER_AES_CBC:
	case MBEDCRYPTO_CIPHER_AES_CTR:
	case MBEDCRYPTO_CIPHER_AES_CTS:
	case MBEDCRYPTO_CIPHER_AES_CBC_PKCS5:
		mbedcrypto_aes_ecb_crypt(&ctx->aes, in, out);
		break;

	case MBEDCRYPTO_CIPHER_DES_ECB:
	case MBEDCRYPTO_CIPHER_DES_CBC:
	case MBEDCRYPTO_CIPHER_DES_CBC_PKCS5:
		mbedcrypto_des_ecb_crypt(&ctx->des, in, out);
		break;

	case MBEDCRYPTO_CIPHER_DES3_ECB:
	case MBEDCRYPTO_CIPHER_DES3_CBC:
	case MBEDCRYPTO_CIPHER_DES3_CTS:
	case MBEDCRYPTO_CIPHER_DES3_CBC_PKCS5:
		mbedcrypto_des3_ecb_crypt(&ctx->des3, in, out);
		break;

	case MBEDCRYPTO_CIPHER_SM4_ECB:
	case MBEDCRYPTO_CIPHER_SM4_CBC:
	case MBEDCRYPTO_CIPHER_SM4_CTR:
	case MBEDCRYPTO_CIPHER_SM4_CTS:
	case MBEDCRYPTO_CIPHER_SM4_ECB_PKCS5:
	case MBEDCRYPTO_CIPHER_SM4_CBC_PKCS5:
		mbedcrypto_sm4_ecb_crypt(&ctx->sm4, in, out);
		break;

	default:
		break;
	}
}

/*
 * Generic CBC encrypt/decrypt for full blocks.
 * Safe for in-place operation (input == output).
 * Internal: always called with valid data, cannot fail.
 */
static void cipher_cbc_crypt(struct mbedcrypto_cipher_ctx *ctx,
		const uint8_t *in, size_t len, uint8_t *out)
{
	size_t bs = ctx->blksize;

	if (ctx->dir == MBEDCRYPTO_ENCRYPT) {
		while (len >= bs) {
			mbedcrypto_xor(out, in, ctx->iv, bs);
			cipher_crypt_block(ctx, out, out);
			memcpy(ctx->iv, out, bs);
			in += bs; out += bs; len -= bs;
		}
	} else {
		uint8_t temp[16];

		while (len >= bs) {
			memcpy(temp, in, bs);
			cipher_crypt_block(ctx, in, out);
			mbedcrypto_xor(out, out, ctx->iv, bs);
			memcpy(ctx->iv, temp, bs);
			in += bs; out += bs; len -= bs;
		}
	}
}

/*
 * Generic CTR encrypt/decrypt (block-level, stateful).
 * Internal: always called with valid data, cannot fail.
 */
static void cipher_ctr_crypt(struct mbedcrypto_cipher_ctx *ctx,
		const uint8_t *in, size_t len, uint8_t *out)
{
	size_t n = ctx->ctr_off;
	size_t bs = ctx->blksize;
	int i = 0;

	/* Consume leftover keystream from prior call */
	while (n != 0 && len > 0) {
		*out++ = *in++ ^ ctx->keystream[n];
		if (++n == bs)
			n = 0;
		len--;
	}

	/* Process full blocks */
	while (len >= bs) {
		cipher_crypt_block(ctx, ctx->iv, ctx->keystream);
		for (i = bs - 1; i >= 0; i--)
			if (++ctx->iv[i] != 0)
				break;
		mbedcrypto_xor(out, in, ctx->keystream, bs);
		in += bs;
		out += bs;
		len -= bs;
	}

	/* Handle trailing partial block */
	if (len > 0) {
		cipher_crypt_block(ctx, ctx->iv, ctx->keystream);
		for (i = bs - 1; i >= 0; i--)
			if (++ctx->iv[i] != 0)
				break;
		n = 0;
		while (len > 0) {
			*out++ = *in++ ^ ctx->keystream[n++];
			len--;
		}
	}

	ctx->ctr_off = n;
}

/*
 * Generic CTS (CBC-CS3) encrypt/decrypt.
 *
 * is_final == 0: standard CBC, len must be block-aligned.
 * is_final != 0: ciphertext stealing, len must be > blksize.
 */
static int cipher_cts_crypt(struct mbedcrypto_cipher_ctx *ctx,
		const uint8_t *in, size_t len,
		uint8_t *out, size_t *olen, int is_final)
{
	size_t bs = ctx->blksize;
	uint8_t temp[16], cx[16], ccx[16];

	if (!is_final) {
		if (len % bs != 0)
			return -EINVAL;

		*olen = len;
		cipher_cbc_crypt(ctx, in, len, out);
		return 0;
	}

	/* Final call with ciphertext stealing */
	if (len <= bs)
		return -EINVAL;

	*olen = len;

	/* Process full blocks except last two via CBC */
	if (len > 2 * bs) {
		size_t pre = ((len - bs - 1) / bs) * bs;

		cipher_cbc_crypt(ctx, in, pre, out);
		in += pre; out += pre; len -= pre;
	}

	if (ctx->dir == MBEDCRYPTO_DECRYPT) {
		/* Decrypt C(n-1) -> C'(x) */
		cipher_crypt_block(ctx, in, ccx);
		len -= bs;
		in += bs;

		/* Reconstruct C(x): residue from C(n) + tail from C'(x) */
		memcpy(cx, in, len);
		memcpy(cx + len, ccx + len, bs - len);

		/* Decrypt C(x), XOR with IV -> P(n-1) */
		cipher_crypt_block(ctx, cx, temp);
		mbedcrypto_xor(out, temp, ctx->iv, bs);
		out += bs;

		/* XOR C'(x) with C(x) -> residue P(n) */
		mbedcrypto_xor(out, ccx, cx, len);
	} else {
		/* C(x) = ENCRYPT(IV XOR P(n-1)) */
		mbedcrypto_xor(cx, in, ctx->iv, bs);
		cipher_crypt_block(ctx, cx, cx);

		/* Build P'(n): residue of P(n) + zero-pad */
		memset(temp, 0, sizeof(temp));
		memcpy(temp, in + bs, len - bs);

		/* C(y) = ENCRYPT(P'(n) XOR C(x)) */
		mbedcrypto_xor(ccx, temp, cx, bs);
		cipher_crypt_block(ctx, ccx, ccx);

		/* Output: C(n-1)=C(y), C(n)=C(x)[1..residue] */
		memcpy(out, ccx, bs);
		memcpy(out + bs, cx, len - bs);
	}

	return 0;
}

/*
 * ECB with partial-block buffering (all block ciphers).
 * Accepts arbitrary-length input; buffers a partial tail block
 * and processes it on the next call.
 */
static int cipher_ecb_buffered(struct mbedcrypto_cipher_ctx *ctx,
		const uint8_t *in, size_t ilen,
		uint8_t *out, size_t *olen)
{
	size_t bs = ctx->blksize;
	size_t done = 0;

	/* Fill partial block from previous call */
	if (ctx->partial_len > 0) {
		size_t need = bs - ctx->partial_len;

		if (ilen < need) {
			memcpy(ctx->partial_blk + ctx->partial_len, in, ilen);
			ctx->partial_len += ilen;
			if (olen)
				*olen = 0;
			return 0;
		}

		memcpy(ctx->partial_blk + ctx->partial_len, in, need);
		cipher_crypt_block(ctx, ctx->partial_blk, out);

		ctx->partial_len = 0;
		in += need; ilen -= need;
		out += bs; done += bs;
	}

	/* Process full blocks */
	while (ilen >= bs) {
		cipher_crypt_block(ctx, in, out);
		in += bs; out += bs; ilen -= bs; done += bs;
	}

	/* Buffer remaining partial block */
	if (ilen > 0) {
		memcpy(ctx->partial_blk, in, ilen);
		ctx->partial_len = ilen;
	}

	if (olen)
		*olen = done;
	return 0;
}

/*
 * CBC with partial-block buffering (all block ciphers).
 * Accepts arbitrary-length input; buffers a partial tail block
 * and delegates complete block chains to cipher_cbc_crypt().
 */
static int cipher_cbc_buffered(struct mbedcrypto_cipher_ctx *ctx,
		const uint8_t *in, size_t ilen,
		uint8_t *out, size_t *olen)
{
	size_t bs = ctx->blksize;
	size_t done = 0;
	size_t full = 0;

	/* Fill partial block from previous call */
	if (ctx->partial_len > 0) {
		size_t need = bs - ctx->partial_len;

		if (ilen < need) {
			memcpy(ctx->partial_blk + ctx->partial_len, in, ilen);
			ctx->partial_len += ilen;
			if (olen)
				*olen = 0;
			return 0;
		}

		memcpy(ctx->partial_blk + ctx->partial_len, in, need);
		cipher_cbc_crypt(ctx, ctx->partial_blk, bs, out);

		ctx->partial_len = 0;
		in += need; ilen -= need;
		out += bs; done += bs;
	}

	/* Process full blocks via generic CBC */
	full = ilen & ~(bs - 1);
	if (full > 0) {
		cipher_cbc_crypt(ctx, in, full, out);
		in += full; ilen -= full;
		out += full; done += full;
	}

	/* Buffer remaining partial block */
	if (ilen > 0) {
		memcpy(ctx->partial_blk, in, ilen);
		ctx->partial_len = ilen;
	}

	if (olen)
		*olen = done;
	return 0;
}

/*
 * CTS buffered update: output CBC blocks while always holding back
 * at least two full blocks in partial_blk[] for cipher_final to
 * apply ciphertext stealing (CBC-CS3).
 *
 * When is_final is set, the remaining partial buffer is flushed
 * through cipher_cts_crypt with ciphertext stealing unconditionally.
 */
static int cipher_cts_buffered(struct mbedcrypto_cipher_ctx *ctx,
		const uint8_t *in, size_t ilen,
		uint8_t *out, size_t *olen, int is_final)
{
	size_t bs = ctx->blksize;
	size_t done = 0;
	size_t total = ctx->partial_len + ilen;
	size_t nout = 0;

	/*
	 * Output blocks via plain CBC, keeping at least 2 full blocks
	 * buffered for final CTS processing (CBC-CS3 requires ciphertext
	 * stealing even when block-aligned).
	 *
	 * nout: round down to block boundary, ensuring remaining <= 2*bs.
	 */
	nout = (total > 2 * bs) ?
			((total - bs - 1) / bs) * bs : 0;

	if (nout > 0 && ctx->partial_len > 0 &&
	    out >= in && out < in + ilen) {
		/*
		 * In-place overlap: draining partial blocks to out would
		 * overwrite input that Part 3 still needs.  Drain to a
		 * stack buffer, save remaining input before Part 3 can
		 * overwrite it, then assemble the final output.
		 */
		uint8_t drain[32];
		size_t dlen = 0;

		/* Part 1: drain full blocks from partial */
		while (nout > 0 && ctx->partial_len >= bs) {
			cipher_cbc_crypt(ctx, ctx->partial_blk, bs,
					 drain + dlen);
			ctx->partial_len -= bs;
			if (ctx->partial_len > 0)
				memmove(ctx->partial_blk,
					ctx->partial_blk + bs,
					ctx->partial_len);
			dlen += bs;
			nout -= bs;
		}

		/* Part 2: complete partial block from input */
		if (nout > 0 && ctx->partial_len > 0) {
			size_t need = bs - ctx->partial_len;

			memcpy(ctx->partial_blk + ctx->partial_len, in, need);
			cipher_cbc_crypt(ctx, ctx->partial_blk, bs,
					 drain + dlen);
			in += need; ilen -= need;
			dlen += bs;
			nout -= bs;
			ctx->partial_len = 0;
		}

		/* Buffer remaining input before it gets overwritten */
		if (ilen > nout) {
			size_t rem = ilen - nout;

			memcpy(ctx->partial_blk + ctx->partial_len,
			       in + nout, rem);
			ctx->partial_len += rem;
		}

		/*
		 * Part 3: process remaining blocks from input in-place
		 * (gap = 0), then shift right to make room for drain.
		 *
		 * We cannot write to out + dlen directly because the
		 * gap (dlen) causes output to overrun input after
		 * dlen/blksize blocks, corrupting subsequent reads.
		 */
		if (nout > 0) {
			cipher_cbc_crypt(ctx, in, nout, (uint8_t *)in);
			memmove(out + dlen, in, nout);
		}

		/* Insert drain at beginning of output */
		memcpy(out, drain, dlen);
		done = dlen + nout;
		out += done;
	} else {
		/* Normal (non-overlapping) path */

		/* Part 1: drain buffered data */
		while (nout > 0 && ctx->partial_len >= bs) {
			cipher_cbc_crypt(ctx, ctx->partial_blk, bs, out);
			ctx->partial_len -= bs;
			if (ctx->partial_len > 0)
				memmove(ctx->partial_blk,
					ctx->partial_blk + bs,
					ctx->partial_len);
			out += bs; done += bs; nout -= bs;
		}

		/* Part 2: complete partial buffer from input */
		if (nout > 0 && ctx->partial_len > 0) {
			size_t need = bs - ctx->partial_len;

			memcpy(ctx->partial_blk + ctx->partial_len, in, need);
			cipher_cbc_crypt(ctx, ctx->partial_blk, bs, out);
			in += need; ilen -= need;
			out += bs; done += bs; nout -= bs;
			ctx->partial_len = 0;
		}

		/* Part 3: output remaining blocks */
		if (nout > 0) {
			cipher_cbc_crypt(ctx, in, nout, out);
			in += nout; ilen -= nout;
			out += nout; done += nout;
		}

		/* Buffer remaining input */
		if (ilen > 0) {
			memcpy(ctx->partial_blk + ctx->partial_len, in, ilen);
			ctx->partial_len += ilen;
		}
	}

	/* Finalize: apply CTS (CBC-CS3) to the last 2 blocks */
	if (is_final && ctx->partial_len > 0) {
		size_t flen = 0;
		int ret = 0;

		if ((ret = cipher_cts_crypt(ctx, ctx->partial_blk,
				ctx->partial_len, out, &flen, 1)) != 0)
			return ret;
		done += flen;
		ctx->partial_len = 0;
	}

	if (olen)
		*olen = done;
	return 0;
}

/*
 * XTS buffered update: output full blocks while always holding back
 * at least one full block in partial_blk[] for final CTS handling.
 *
 * When is_final is set, the remaining partial buffer is flushed
 * through mbedcrypto_aes_xts_crypt (which handles CTS internally).
 */
static int cipher_xts_buffered(struct mbedcrypto_cipher_ctx *ctx,
		const uint8_t *in, size_t ilen,
		uint8_t *out, size_t *olen, int is_final)
{
	size_t bs = ctx->blksize;
	size_t done = 0;
	size_t total = 0, nout_blks = 0, nout_bytes = 0, from_buf = 0;
	int ret = 0;

	total = ctx->partial_len + ilen;

	/* How many full blocks can we output, keeping >= 1 block buffered */
	nout_blks = (total / bs > 0) ? (total / bs - 1) : 0;
	nout_bytes = nout_blks * bs;

	if (nout_blks == 0) {
		if (ilen > 0)
			memcpy(ctx->partial_blk + ctx->partial_len, in, ilen);
		ctx->partial_len = total;
		goto flush;
	}

	if (nout_blks > 0 && ctx->partial_len > 0 &&
	    out >= in && out < in + ilen) {
		/*
		 * In-place overlap: drain partial to stack buffer,
		 * save remaining input before Part 3, then assemble.
		 */
		uint8_t drain[32];
		size_t dlen = 0;

		/* Part 1: drain full blocks from partial */
		if (ctx->partial_len >= bs) {
			from_buf = ctx->partial_len & ~(bs - 1);
			if (from_buf > nout_bytes)
				from_buf = nout_bytes;

			ret = mbedcrypto_aes_xts_crypt(&ctx->xts, ctx->iv,
					ctx->partial_blk, from_buf,
					drain, &from_buf);
			if (ret != 0)
				return ret;
			dlen = from_buf;
			nout_bytes -= from_buf;

			ctx->partial_len -= from_buf;
			if (ctx->partial_len > 0)
				memmove(ctx->partial_blk,
					ctx->partial_blk + from_buf,
					ctx->partial_len);
		}

		/* Part 2: complete partial block from input */
		if (ctx->partial_len > 0 && nout_bytes > 0) {
			size_t need = bs - ctx->partial_len;
			size_t flen = bs;

			memcpy(ctx->partial_blk + ctx->partial_len, in, need);
			in += need;
			ilen -= need;

			ret = mbedcrypto_aes_xts_crypt(&ctx->xts, ctx->iv,
					ctx->partial_blk, bs,
					drain + dlen, &flen);
			if (ret != 0)
				return ret;
			dlen += flen;
			nout_bytes -= flen;
			ctx->partial_len = 0;
		}

		/* Buffer remaining input before it gets overwritten */
		if (ilen > nout_bytes) {
			size_t rem = ilen - nout_bytes;

			memcpy(ctx->partial_blk + ctx->partial_len,
			       in + nout_bytes, rem);
			ctx->partial_len += rem;
		}

		/*
		 * Part 3: process remaining blocks from input in-place,
		 * then shift right to make room for drain.
		 */
		if (nout_bytes > 0) {
			size_t flen = nout_bytes;

			ret = mbedcrypto_aes_xts_crypt(&ctx->xts, ctx->iv,
					in, nout_bytes,
					(uint8_t *)in, &flen);
			if (ret != 0)
				return ret;
			memmove(out + dlen, in, nout_bytes);
		}

		/* Insert drain at beginning of output */
		memcpy(out, drain, dlen);
		done = dlen + nout_bytes;
		out += done;
	} else {
		/* Normal (non-overlapping) path */

		/* Part 1: output full blocks from buffered data */
		if (ctx->partial_len >= bs) {
			from_buf = ctx->partial_len & ~(bs - 1);
			if (from_buf > nout_bytes)
				from_buf = nout_bytes;

			ret = mbedcrypto_aes_xts_crypt(&ctx->xts, ctx->iv,
					ctx->partial_blk, from_buf,
					out, &from_buf);
			if (ret != 0)
				return ret;
			out += from_buf;
			done += from_buf;
			nout_bytes -= from_buf;

			ctx->partial_len -= from_buf;
			if (ctx->partial_len > 0)
				memmove(ctx->partial_blk,
					ctx->partial_blk + from_buf,
					ctx->partial_len);
		}

		/* Part 2: complete partial buffered block from input */
		if (ctx->partial_len > 0 && nout_bytes > 0) {
			size_t need = bs - ctx->partial_len;
			size_t flen = bs;

			memcpy(ctx->partial_blk + ctx->partial_len, in, need);
			in += need;
			ilen -= need;

			ret = mbedcrypto_aes_xts_crypt(&ctx->xts, ctx->iv,
					ctx->partial_blk, bs,
					out, &flen);
			if (ret != 0)
				return ret;
			out += flen;
			done += flen;
			nout_bytes -= flen;
			ctx->partial_len = 0;
		}

		/* Part 3: output remaining blocks from input */
		if (nout_bytes > 0) {
			size_t flen = nout_bytes;

			ret = mbedcrypto_aes_xts_crypt(&ctx->xts, ctx->iv,
					in, nout_bytes, out, &flen);
			if (ret != 0)
				return ret;
			out += flen;
			in += flen;
			ilen -= flen;
			done += flen;
		}

		/* Buffer remaining input */
		if (ilen > 0) {
			memcpy(ctx->partial_blk + ctx->partial_len, in, ilen);
			ctx->partial_len += ilen;
		}
	}

flush:
	if (is_final && ctx->partial_len > 0) {
		size_t flen = ctx->partial_len;

		ret = mbedcrypto_aes_xts_crypt(&ctx->xts, ctx->iv,
				ctx->partial_blk, ctx->partial_len,
				out, &flen);
		if (ret != 0)
			return ret;
		done += flen;
		ctx->partial_len = 0;
	}

	if (olen)
		*olen = done;
	return 0;
}

static int cipher_chacha20_update(struct mbedcrypto_cipher_ctx *ctx,
		const uint8_t *in, size_t ilen,
		uint8_t *out, size_t *olen)
{
	int ret = mbedcrypto_chacha20_update(&ctx->chacha20, in, ilen, out);
	if (olen)
		*olen = ilen;
	return ret;
}

static int cipher_pkcs5_final(struct mbedcrypto_cipher_ctx *ctx,
		uint8_t *out, size_t ulen, size_t *olen)
{
	size_t bs = ctx->blksize, i = 0;

	if (ctx->dir == MBEDCRYPTO_ENCRYPT) {
		/* Add PKCS7 padding and encrypt the final block */
		uint8_t pad = bs - ctx->partial_len;
		size_t flen = 0;
		int ret = 0;

		memset(ctx->partial_blk + ctx->partial_len, pad, pad);
		ctx->partial_len = bs;

		if (is_ecb(ctx->type))
			ret = cipher_ecb_buffered(ctx, NULL, 0,
					out + ulen, &flen);
		else
			ret = cipher_cbc_buffered(ctx, NULL, 0,
					out + ulen, &flen);
		if (ret != 0)
			return ret;
		ulen += flen;
	} else {
		/*
		 * Decrypt: partial_len must be 0 (last block already
		 * processed). The last decrypted block is in
		 * out[ulen-bs..ulen-1]. Validate and strip padding.
		 */
		uint8_t pad = 0;
		uint8_t diff = 0;

		if (ctx->partial_len > 0 || ulen < bs)
			return -EINVAL;

		pad = out[ulen - 1];
		if (pad == 0 || pad > bs)
			return -EINVAL;
		/* Constant-time padding validation */
		for (i = 0; i < pad; i++)
			diff |= out[ulen - 1 - i] ^ pad;
		if (diff != 0 || i != pad)
			return -EINVAL;
		ulen -= pad;
	}
	if (olen)
		*olen = ulen;
	return 0;
}

int mbedcrypto_cipher_update(struct mbedcrypto_cipher_ctx *ctx,
		const uint8_t *in, size_t ilen,
		uint8_t *out, size_t *olen)
{
	if (!ctx)
		return -EINVAL;

	if (is_ecb(ctx->type))
		return cipher_ecb_buffered(ctx, in, ilen, out, olen);

	if (is_cbc(ctx->type))
		return cipher_cbc_buffered(ctx, in, ilen, out, olen);

	if (is_ctr(ctx->type)) {
		cipher_ctr_crypt(ctx, in, ilen, out);
		if (olen)
			*olen = ilen;
		return 0;
	}

	if (is_cts(ctx->type))
		return cipher_cts_buffered(ctx, in, ilen, out, olen, 0);

	if (ctx->type == MBEDCRYPTO_CIPHER_AES_XTS)
		return cipher_xts_buffered(ctx, in, ilen, out, olen, 0);

	if (ctx->type == MBEDCRYPTO_CIPHER_CHACHA20)
		return cipher_chacha20_update(ctx, in, ilen, out, olen);

	return -EINVAL;
}

int mbedcrypto_cipher_final(struct mbedcrypto_cipher_ctx *ctx,
		const uint8_t *in, size_t ilen,
		uint8_t *out, size_t *olen)
{
	size_t ulen = 0;
	int ret = 0;

	if (!ctx)
		return -EINVAL;

	/* CTS/XTS: buffered function handles input and finalization */
	if (is_cts(ctx->type))
		return cipher_cts_buffered(ctx, in, ilen, out, olen, 1);

	if (ctx->type == MBEDCRYPTO_CIPHER_AES_XTS)
		return cipher_xts_buffered(ctx, in, ilen, out, olen, 1);

	/* Other modes: process remaining input via update */
	if (in && ilen > 0) {
		ret = mbedcrypto_cipher_update(ctx, in, ilen, out, &ulen);
		if (ret != 0)
			return ret;
	}

	/* PKCS7 padding for PKCS5 cipher types */
	if (is_pkcs5(ctx->type))
		return cipher_pkcs5_final(ctx, out, ulen, olen);

	/* no leftover allowed in final stage */
	if (ctx->partial_len > 0)
		return -EINVAL;

	if (olen)
		*olen = ulen;
	return 0;
}

void mbedcrypto_cipher_cleanup(struct mbedcrypto_cipher_ctx *ctx)
{
	if (!ctx)
		return;

	switch (ctx->type) {
	case MBEDCRYPTO_CIPHER_AES_ECB:
	case MBEDCRYPTO_CIPHER_AES_CBC:
	case MBEDCRYPTO_CIPHER_AES_CTR:
	case MBEDCRYPTO_CIPHER_AES_CTS:
	case MBEDCRYPTO_CIPHER_AES_CBC_PKCS5:
		mbedcrypto_aes_cleanup(&ctx->aes);
		break;
	case MBEDCRYPTO_CIPHER_AES_XTS:
		mbedcrypto_aes_xts_cleanup(&ctx->xts);
		break;
	case MBEDCRYPTO_CIPHER_DES_ECB:
	case MBEDCRYPTO_CIPHER_DES_CBC:
	case MBEDCRYPTO_CIPHER_DES_CBC_PKCS5:
		mbedcrypto_des_cleanup(&ctx->des);
		break;
	case MBEDCRYPTO_CIPHER_DES3_ECB:
	case MBEDCRYPTO_CIPHER_DES3_CBC:
	case MBEDCRYPTO_CIPHER_DES3_CTS:
	case MBEDCRYPTO_CIPHER_DES3_CBC_PKCS5:
		mbedcrypto_des3_cleanup(&ctx->des3);
		break;
	case MBEDCRYPTO_CIPHER_SM4_ECB:
	case MBEDCRYPTO_CIPHER_SM4_CBC:
	case MBEDCRYPTO_CIPHER_SM4_CTR:
	case MBEDCRYPTO_CIPHER_SM4_CTS:
	case MBEDCRYPTO_CIPHER_SM4_ECB_PKCS5:
	case MBEDCRYPTO_CIPHER_SM4_CBC_PKCS5:
		mbedcrypto_sm4_cleanup(&ctx->sm4);
		break;
	case MBEDCRYPTO_CIPHER_CHACHA20:
		mbedcrypto_chacha20_cleanup(&ctx->chacha20);
		break;
	default:
		break;
	}

	memset(ctx, 0, sizeof(*ctx));
}

/* ---------------------------------------------------------------- */
/* Cipher-based MAC API                                             */
/* ---------------------------------------------------------------- */

int mbedcrypto_mac_init(struct mbedcrypto_mac_ctx *ctx,
		int type, const uint8_t *key, unsigned int keybits)
{
	int ret = 0;

	if (!ctx || !key)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	ctx->type = type;

	switch (type) {
	case MBEDCRYPTO_CMAC_AES:
		ctx->blksize = 16;
		ctx->nopad = 1;
		ret = mbedcrypto_cmac_setkey(&ctx->cmac, key, keybits);
		break;

	case MBEDCRYPTO_CMAC_AES_CBC_NOPAD:
	case MBEDCRYPTO_CMAC_AES_CBC_PKCS5:
	case MBEDCRYPTO_CMAC_DES_CBC_NOPAD:
	case MBEDCRYPTO_CMAC_DES_CBC_PKCS5:
	case MBEDCRYPTO_CMAC_DES3_CBC_NOPAD:
	case MBEDCRYPTO_CMAC_DES3_CBC_PKCS5: {
		int cipher_type = 0;
		uint8_t zero_iv[16] = {0};

		if (type == MBEDCRYPTO_CMAC_AES_CBC_NOPAD ||
		    type == MBEDCRYPTO_CMAC_AES_CBC_PKCS5) {
			ctx->blksize = 16;
			cipher_type = MBEDCRYPTO_CIPHER_AES_CBC;
		} else if (type == MBEDCRYPTO_CMAC_DES_CBC_NOPAD ||
			   type == MBEDCRYPTO_CMAC_DES_CBC_PKCS5) {
			ctx->blksize = 8;
			cipher_type = MBEDCRYPTO_CIPHER_DES_CBC;
		} else {
			ctx->blksize = 8;
			cipher_type = MBEDCRYPTO_CIPHER_DES3_CBC;
		}

		ctx->nopad = (type == MBEDCRYPTO_CMAC_AES_CBC_NOPAD ||
			      type == MBEDCRYPTO_CMAC_DES_CBC_NOPAD ||
			      type == MBEDCRYPTO_CMAC_DES3_CBC_NOPAD);

		ret = mbedcrypto_cipher_init(&ctx->cipher, cipher_type,
				key, keybits, MBEDCRYPTO_ENCRYPT);
		if (ret == 0)
			mbedcrypto_cipher_set_iv(&ctx->cipher,
					zero_iv, ctx->blksize);
		break;
	}

	default:
		return -EINVAL;
	}

	return ret;
}

int mbedcrypto_mac_reset(struct mbedcrypto_mac_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	if (ctx->type == MBEDCRYPTO_CMAC_AES)
		return mbedcrypto_cmac_reset(&ctx->cmac);

	/* CBC-MAC: reset IV to zero and clear buffers */
	memset(ctx->cipher.iv, 0, sizeof(ctx->cipher.iv));
	mbedcrypto_cipher_reset(&ctx->cipher);
	return 0;
}

int mbedcrypto_mac_update(struct mbedcrypto_mac_ctx *ctx,
		const uint8_t *data, size_t len)
{
	if (!ctx)
		return -EINVAL;

	if (ctx->type == MBEDCRYPTO_CMAC_AES)
		return mbedcrypto_cmac_update(&ctx->cmac, data, len);

	/* CBC-MAC: encrypt through the cipher, discard output */
	{
		uint8_t dst[16]; /* single block, output is discarded */
		size_t off = 0, olen = 0, ilen;
		int ret = 0;

		while (len > 0) {
			ilen = len < sizeof(dst) ? len : sizeof(dst);
			ret = mbedcrypto_cipher_update(&ctx->cipher,
					data + off, ilen, dst, &olen);
			if (ret != 0)
				return ret;
			len -= ilen;
			off += ilen;
		}
	}
	return 0;
}

int mbedcrypto_mac_final(struct mbedcrypto_mac_ctx *ctx,
		uint8_t *mac, size_t *maclen)
{
	int ret = 0;

	if (!ctx || !mac || !maclen)
		return -EINVAL;

	if (ctx->type == MBEDCRYPTO_CMAC_AES) {
		if (*maclen < 16) {
			*maclen = 16;
			return -ERANGE;
		}
		ret = mbedcrypto_cmac_final(&ctx->cmac, mac);
		if (ret == 0)
			*maclen = 16;
		return ret;
	}

	/* CBC-MAC final */
	{
		size_t bs = ctx->blksize;

		if (*maclen < bs) {
			*maclen = bs;
			return -ERANGE;
		}

		if (!ctx->nopad) {
			/* PKCS5 padding */
			uint8_t pad_buf[16];
			size_t remain = ctx->cipher.partial_len;
			uint8_t padval = bs - remain;
			size_t olen = 0;

			memset(pad_buf, padval, bs);
			if (remain > 0)
				memcpy(pad_buf, ctx->cipher.partial_blk, remain);
			ctx->cipher.partial_len = 0;

			ret = mbedcrypto_cipher_update(&ctx->cipher,
					pad_buf, bs, mac, &olen);
			if (ret != 0)
				return ret;
			*maclen = bs;
		} else {
			/* NOPAD: return the last CBC IV (last cipher block) */
			memcpy(mac, ctx->cipher.iv, bs);
			*maclen = bs;
		}
	}
	return 0;
}

void mbedcrypto_mac_cleanup(struct mbedcrypto_mac_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->type == MBEDCRYPTO_CMAC_AES)
		mbedcrypto_cmac_cleanup(&ctx->cmac);
	else
		mbedcrypto_cipher_cleanup(&ctx->cipher);

	memset(ctx, 0, sizeof(*ctx));
}

/* ---------------------------------------------------------------- */
/* AEAD (Authenticated Encryption with Associated Data)             */
/* ---------------------------------------------------------------- */

int mbedcrypto_aead_setkey(struct mbedcrypto_aead_ctx *ctx,
		int algo, const uint8_t *key, unsigned int keybits)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->algo = algo;

	switch (algo) {
	case MBEDCRYPTO_AEAD_AES_GCM:
		return mbedcrypto_aes_gcm_setkey(&ctx->aes_gcm, key, keybits);
	case MBEDCRYPTO_AEAD_AES_CCM:
		return mbedcrypto_aes_ccm_setkey(&ctx->aes_ccm, key, keybits);
	case MBEDCRYPTO_AEAD_SM4_GCM:
		return mbedcrypto_sm4_gcm_setkey(&ctx->sm4_gcm, key, keybits);
	case MBEDCRYPTO_AEAD_SM4_CCM:
		return mbedcrypto_sm4_ccm_setkey(&ctx->sm4_ccm, key, keybits);
	case MBEDCRYPTO_AEAD_CHACHA20_POLY1305:
		if (keybits != 256)
			return -EINVAL;
		mbedcrypto_chachapoly_init(&ctx->chachapoly);
		return mbedcrypto_chachapoly_setkey(&ctx->chachapoly, key);
	default:
		return -EINVAL;
	}
}

int mbedcrypto_aead_start(struct mbedcrypto_aead_ctx *ctx, int dir,
		const uint8_t *iv, size_t iv_len,
		size_t tag_len, size_t aad_len, size_t payload_len)
{
	int r = 0;

	switch (ctx->algo) {
	case MBEDCRYPTO_AEAD_AES_GCM:
		return mbedcrypto_aes_gcm_start(&ctx->aes_gcm, dir, iv, iv_len);
	case MBEDCRYPTO_AEAD_AES_CCM:
		r = mbedcrypto_aes_ccm_start(&ctx->aes_ccm, dir, iv, iv_len);
		if (r != 0)
			return r;
		return mbedcrypto_aes_ccm_set_len(&ctx->aes_ccm,
				aad_len, payload_len, tag_len);
	case MBEDCRYPTO_AEAD_SM4_GCM:
		return mbedcrypto_sm4_gcm_start(&ctx->sm4_gcm, dir, iv, iv_len);
	case MBEDCRYPTO_AEAD_SM4_CCM:
		r = mbedcrypto_sm4_ccm_start(&ctx->sm4_ccm, dir, iv, iv_len);
		if (r != 0)
			return r;
		return mbedcrypto_sm4_ccm_set_len(&ctx->sm4_ccm,
				aad_len, payload_len, tag_len);
	case MBEDCRYPTO_AEAD_CHACHA20_POLY1305:
		return mbedcrypto_chachapoly_start(&ctx->chachapoly, iv, dir);
	default:
		return -EINVAL;
	}
}

int mbedcrypto_aead_update_aad(struct mbedcrypto_aead_ctx *ctx,
		const uint8_t *aad, size_t len)
{
	switch (ctx->algo) {
	case MBEDCRYPTO_AEAD_AES_GCM:
		return mbedcrypto_aes_gcm_update_aad(&ctx->aes_gcm, aad, len);
	case MBEDCRYPTO_AEAD_AES_CCM:
		return mbedcrypto_aes_ccm_update_aad(&ctx->aes_ccm, aad, len);
	case MBEDCRYPTO_AEAD_SM4_GCM:
		return mbedcrypto_sm4_gcm_update_aad(&ctx->sm4_gcm, aad, len);
	case MBEDCRYPTO_AEAD_SM4_CCM:
		return mbedcrypto_sm4_ccm_update_aad(&ctx->sm4_ccm, aad, len);
	case MBEDCRYPTO_AEAD_CHACHA20_POLY1305:
		return mbedcrypto_chachapoly_update_aad(&ctx->chachapoly,
				aad, len);
	default:
		return -EINVAL;
	}
}

int mbedcrypto_aead_update(struct mbedcrypto_aead_ctx *ctx,
		const uint8_t *input, size_t len,
		uint8_t *output, size_t *olen)
{
	switch (ctx->algo) {
	case MBEDCRYPTO_AEAD_AES_GCM:
		return mbedcrypto_aes_gcm_update(&ctx->aes_gcm,
				input, len, output, olen);
	case MBEDCRYPTO_AEAD_AES_CCM:
		return mbedcrypto_aes_ccm_update(&ctx->aes_ccm,
				input, len, output, olen);
	case MBEDCRYPTO_AEAD_SM4_GCM:
		return mbedcrypto_sm4_gcm_update(&ctx->sm4_gcm,
				input, len, output, olen);
	case MBEDCRYPTO_AEAD_SM4_CCM:
		return mbedcrypto_sm4_ccm_update(&ctx->sm4_ccm,
				input, len, output, olen);
	case MBEDCRYPTO_AEAD_CHACHA20_POLY1305: {
		int r = mbedcrypto_chachapoly_update(&ctx->chachapoly,
				input, len, output);
		if (r == 0)
			*olen = len;
		return r;
	}
	default:
		return -EINVAL;
	}
}

int mbedcrypto_aead_final(struct mbedcrypto_aead_ctx *ctx,
		uint8_t *tag, size_t tag_len)
{
	switch (ctx->algo) {
	case MBEDCRYPTO_AEAD_AES_GCM:
		return mbedcrypto_aes_gcm_final(&ctx->aes_gcm, tag, tag_len);
	case MBEDCRYPTO_AEAD_AES_CCM:
		return mbedcrypto_aes_ccm_final(&ctx->aes_ccm, tag, tag_len);
	case MBEDCRYPTO_AEAD_SM4_GCM:
		return mbedcrypto_sm4_gcm_final(&ctx->sm4_gcm, tag, tag_len);
	case MBEDCRYPTO_AEAD_SM4_CCM:
		return mbedcrypto_sm4_ccm_final(&ctx->sm4_ccm, tag, tag_len);
	case MBEDCRYPTO_AEAD_CHACHA20_POLY1305:
		return mbedcrypto_chachapoly_final(&ctx->chachapoly, tag);
	default:
		return -EINVAL;
	}
}

void mbedcrypto_aead_cleanup(struct mbedcrypto_aead_ctx *ctx)
{
	if (!ctx)
		return;

	switch (ctx->algo) {
	case MBEDCRYPTO_AEAD_AES_GCM:
		mbedcrypto_aes_gcm_cleanup(&ctx->aes_gcm);
		break;
	case MBEDCRYPTO_AEAD_AES_CCM:
		mbedcrypto_aes_ccm_cleanup(&ctx->aes_ccm);
		break;
	case MBEDCRYPTO_AEAD_SM4_GCM:
		mbedcrypto_sm4_gcm_cleanup(&ctx->sm4_gcm);
		break;
	case MBEDCRYPTO_AEAD_SM4_CCM:
		mbedcrypto_sm4_ccm_cleanup(&ctx->sm4_ccm);
		break;
	case MBEDCRYPTO_AEAD_CHACHA20_POLY1305:
		mbedcrypto_chachapoly_cleanup(&ctx->chachapoly);
		break;
	}
	memset(ctx, 0, sizeof(*ctx));
}
