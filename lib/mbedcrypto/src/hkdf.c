// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * HMAC-SHA256 and HKDF key derivation (RFC 5869)
 * Generic multi-hash HKDF support.
 */

#include <string.h>

#include <mbedcrypto/hkdf.h>

/* Maximum hash output size (SHA-512 = 64) */
#define HKDF_MAX_HASHSIZE   64

/* ---------------------------------------------------------------- */
/* HMAC-SHA256 (RFC 2104)                                           */
/* ---------------------------------------------------------------- */

int mbedcrypto_hmac_sha256_init(struct mbedcrypto_hmac_sha256_ctx *ctx,
		const uint8_t *key, size_t key_len)
{
	uint8_t kpad[MBEDCRYPTO_SHA256_BLKSIZE] = {0};
	uint8_t khash[MBEDCRYPTO_SHA256_HASHSIZE];
	int i = 0, ret = 0;

	if (!ctx || !key)
		return -EINVAL;

	/* Keys longer than block size are first hashed */
	if (key_len > MBEDCRYPTO_SHA256_BLKSIZE) {
		ret = mbedcrypto_sha256_digest(key, key_len, khash, 0);
		if (ret != 0)
			return ret;
		memcpy(kpad, khash, MBEDCRYPTO_SHA256_HASHSIZE);
		memset(khash, 0, sizeof(khash));
	} else
		memcpy(kpad, key, key_len);

	/* Inner hash: SHA-256(K ^ ipad || ...) */
	ret = mbedcrypto_sha256_init(&ctx->inner, 0);
	if (ret != 0)
		goto out;

	for (i = 0; i < MBEDCRYPTO_SHA256_BLKSIZE; i++)
		kpad[i] ^= 0x36;

	ret = mbedcrypto_sha256_update(&ctx->inner, kpad, sizeof(kpad));
	if (ret != 0)
		goto out;

	/* Restore key then apply opad */
	for (i = 0; i < MBEDCRYPTO_SHA256_BLKSIZE; i++)
		kpad[i] ^= 0x36 ^ 0x5c;

	/* Outer hash: SHA-256(K ^ opad || ...) */
	ret = mbedcrypto_sha256_init(&ctx->outer, 0);
	if (ret != 0)
		goto out;

	ret = mbedcrypto_sha256_update(&ctx->outer, kpad, sizeof(kpad));

out:
	memset(kpad, 0, sizeof(kpad));
	return ret;
}

int mbedcrypto_hmac_sha256_update(struct mbedcrypto_hmac_sha256_ctx *ctx,
		const uint8_t *data, size_t len)
{
	if (!ctx)
		return -EINVAL;

	return mbedcrypto_sha256_update(&ctx->inner, data, len);
}

int mbedcrypto_hmac_sha256_final(struct mbedcrypto_hmac_sha256_ctx *ctx,
		uint8_t mac[MBEDCRYPTO_SHA256_HASHSIZE])
{
	uint8_t inner_hash[MBEDCRYPTO_SHA256_HASHSIZE];
	int ret = 0;

	if (!ctx || !mac)
		return -EINVAL;

	/* Finalize inner hash */
	ret = mbedcrypto_sha256_final(&ctx->inner, inner_hash);
	if (ret != 0)
		goto out;

	/* Feed inner hash into outer context */
	ret = mbedcrypto_sha256_update(&ctx->outer, inner_hash,
			MBEDCRYPTO_SHA256_HASHSIZE);
	if (ret != 0)
		goto out;

	/* Finalize outer hash = HMAC result */
	ret = mbedcrypto_sha256_final(&ctx->outer, mac);

out:
	memset(inner_hash, 0, sizeof(inner_hash));
	return ret;
}

void mbedcrypto_hmac_sha256_cleanup(struct mbedcrypto_hmac_sha256_ctx *ctx)
{
	if (ctx)
		memset(ctx, 0, sizeof(*ctx));
}

int mbedcrypto_hmac_sha256(const uint8_t *key, size_t key_len,
		const uint8_t *data, size_t data_len,
		uint8_t mac[MBEDCRYPTO_SHA256_HASHSIZE])
{
	struct mbedcrypto_hmac_sha256_ctx ctx;
	int ret = 0;

	ret = mbedcrypto_hmac_sha256_init(&ctx, key, key_len);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_hmac_sha256_update(&ctx, data, data_len);
	if (ret != 0)
		goto done;

	ret = mbedcrypto_hmac_sha256_final(&ctx, mac);

done:
	mbedcrypto_hmac_sha256_cleanup(&ctx);
	return ret;
}

/* ---------------------------------------------------------------- */
/* HKDF (RFC 5869) using HMAC-SHA256                                */
/* ---------------------------------------------------------------- */

int mbedcrypto_hkdf_extract(const uint8_t *salt, size_t salt_len,
		const uint8_t *ikm, size_t ikm_len,
		uint8_t prk[MBEDCRYPTO_SHA256_HASHSIZE])
{
	uint8_t default_salt[MBEDCRYPTO_SHA256_HASHSIZE];

	if (!ikm || !prk)
		return -EINVAL;

	/* If no salt, use a string of HashLen zeroes (RFC 5869 Section 2.2) */
	if (!salt || salt_len == 0) {
		memset(default_salt, 0, sizeof(default_salt));
		salt = default_salt;
		salt_len = MBEDCRYPTO_SHA256_HASHSIZE;
	}

	return mbedcrypto_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

int mbedcrypto_hkdf_expand(const uint8_t prk[MBEDCRYPTO_SHA256_HASHSIZE],
		const uint8_t *info, size_t info_len,
		uint8_t *okm, size_t okm_len)
{
	struct mbedcrypto_hmac_sha256_ctx ctx;
	uint8_t t[MBEDCRYPTO_SHA256_HASHSIZE];
	uint8_t counter = 0;
	size_t n = 0, done = 0, copy_len = 0;
	int ret = 0;

	if (!prk || !okm)
		return -EINVAL;

	/* Max output: 255 * HashLen */
	n = (okm_len + MBEDCRYPTO_SHA256_HASHSIZE - 1) /
		MBEDCRYPTO_SHA256_HASHSIZE;
	if (n > 255)
		return -EINVAL;

	done = 0;

	for (counter = 1; done < okm_len; counter++) {
		ret = mbedcrypto_hmac_sha256_init(&ctx, prk,
				MBEDCRYPTO_SHA256_HASHSIZE);
		if (ret != 0)
			goto out;

		/* T(i) = HMAC-Hash(PRK, T(i-1) | info | i) */
		if (counter > 1) {
			ret = mbedcrypto_hmac_sha256_update(&ctx, t,
					MBEDCRYPTO_SHA256_HASHSIZE);
			if (ret != 0)
				goto out;
		}

		if (info && info_len > 0) {
			ret = mbedcrypto_hmac_sha256_update(&ctx,
					info, info_len);
			if (ret != 0)
				goto out;
		}

		ret = mbedcrypto_hmac_sha256_update(&ctx, &counter, 1);
		if (ret != 0)
			goto out;

		ret = mbedcrypto_hmac_sha256_final(&ctx, t);
		if (ret != 0)
			goto out;

		copy_len = okm_len - done;
		if (copy_len > MBEDCRYPTO_SHA256_HASHSIZE)
			copy_len = MBEDCRYPTO_SHA256_HASHSIZE;

		memcpy(okm + done, t, copy_len);
		done += copy_len;
	}

	ret = 0;

out:
	mbedcrypto_hmac_sha256_cleanup(&ctx);
	memset(t, 0, sizeof(t));
	return ret;
}

int mbedcrypto_hkdf_derive(const uint8_t *salt, size_t salt_len,
		const uint8_t *ikm, size_t ikm_len,
		const uint8_t *info, size_t info_len,
		uint8_t *okm, size_t okm_len)
{
	uint8_t prk[MBEDCRYPTO_SHA256_HASHSIZE];
	int ret = 0;

	ret = mbedcrypto_hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_hkdf_expand(prk, info, info_len, okm, okm_len);

	memset(prk, 0, sizeof(prk));
	return ret;
}

#ifndef __KERNEL__
#include <mbedcrypto.h>

/* ---------------------------------------------------------------- */
/* Generic HKDF with selectable hash algorithm                      */
/* Uses the unified mbedcrypto_hmac_* and mbedcrypto_hash_size APIs */
/* ---------------------------------------------------------------- */

/*
 * Generic HKDF-Extract (RFC 5869 Section 2.2)
 */
static int hkdf_extract_hash(int hash_id,
		const uint8_t *salt, size_t salt_len,
		const uint8_t *ikm, size_t ikm_len,
		uint8_t *prk)
{
	uint8_t default_salt[HKDF_MAX_HASHSIZE];
	struct mbedcrypto_hmac_ctx ctx;
	size_t hlen = mbedcrypto_hash_size(hash_id);
	int ret = 0;

	if (!ikm || !prk || hlen == 0)
		return -EINVAL;

	/* If no salt, use a string of HashLen zeroes */
	if (!salt || salt_len == 0) {
		memset(default_salt, 0, hlen);
		salt = default_salt;
		salt_len = hlen;
	}

	ret = mbedcrypto_hmac_init(&ctx, hash_id, salt, salt_len);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_hmac_update(&ctx, ikm, ikm_len);
	if (ret != 0)
		goto out;

	ret = mbedcrypto_hmac_final(&ctx, prk);

out:
	mbedcrypto_hmac_cleanup(&ctx);
	return ret;
}

/*
 * Generic HKDF-Expand (RFC 5869 Section 2.3)
 */
static int hkdf_expand_hash(int hash_id, const uint8_t *prk,
		const uint8_t *info, size_t info_len,
		uint8_t *okm, size_t okm_len)
{
	struct mbedcrypto_hmac_ctx ctx;
	uint8_t t[HKDF_MAX_HASHSIZE];
	size_t hlen = mbedcrypto_hash_size(hash_id);
	uint8_t counter = 0;
	size_t n = 0, done = 0, copy_len = 0;
	int ret = 0;

	if (!prk || !okm || hlen == 0)
		return -EINVAL;

	/* Max output: 255 * HashLen */
	n = (okm_len + hlen - 1) / hlen;
	if (n > 255)
		return -EINVAL;

	done = 0;

	for (counter = 1; done < okm_len; counter++) {
		ret = mbedcrypto_hmac_init(&ctx, hash_id, prk, hlen);
		if (ret != 0)
			goto out;

		/* T(i) = HMAC-Hash(PRK, T(i-1) | info | i) */
		if (counter > 1) {
			ret = mbedcrypto_hmac_update(&ctx, t, hlen);
			if (ret != 0)
				goto out;
		}

		if (info && info_len > 0) {
			ret = mbedcrypto_hmac_update(&ctx, info, info_len);
			if (ret != 0)
				goto out;
		}

		ret = mbedcrypto_hmac_update(&ctx, &counter, 1);
		if (ret != 0)
			goto out;

		ret = mbedcrypto_hmac_final(&ctx, t);
		if (ret != 0)
			goto out;

		copy_len = okm_len - done;
		if (copy_len > hlen)
			copy_len = hlen;

		memcpy(okm + done, t, copy_len);
		done += copy_len;
	}

	ret = 0;

out:
	mbedcrypto_hmac_cleanup(&ctx);
	memset(t, 0, sizeof(t));
	return ret;
}

int mbedcrypto_hkdf_derive_hash(int hash_id,
		const uint8_t *salt, size_t salt_len,
		const uint8_t *ikm, size_t ikm_len,
		const uint8_t *info, size_t info_len,
		uint8_t *okm, size_t okm_len)
{
	uint8_t prk[HKDF_MAX_HASHSIZE];
	size_t hlen = mbedcrypto_hash_size(hash_id);
	int ret = 0;

	if (hlen == 0)
		return -EINVAL;

	ret = hkdf_extract_hash(hash_id, salt, salt_len,
				ikm, ikm_len, prk);
	if (ret != 0)
		return ret;

	ret = hkdf_expand_hash(hash_id, prk, info, info_len,
			       okm, okm_len);

	memset(prk, 0, hlen);
	return ret;
}
#endif /* !__KERNEL__ */
