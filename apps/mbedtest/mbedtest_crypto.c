/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 *
 * Comprehensive mbedcrypto test suite
 *
 * Covers every public API with golden vectors (NIST/RFC/GB/T),
 * roundtrip tests, edge cases, streaming, different key/data sizes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <utrace.h>
#include <mbedcrypto.h>

#include "mbedtest.h"
#include "mbedtest_internal.h"

/* ----- Hex conversion helpers (used only by crypto tests) ------------ */
static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int hex2bin(const char *hex, uint8_t *bin, size_t bin_len)
{
	size_t i = 0;
	int hi, lo;

	for (i = 0; i < bin_len; i++) {
		hi = hexval(hex[2 * i]);
		lo = hexval(hex[2 * i + 1]);
		if (hi < 0 || lo < 0)
			return -1;
		bin[i] = (hi << 4) | lo;
	}
	return 0;
}

static int hexcmp(const uint8_t *bin, const char *hex, size_t len)
{
	uint8_t expected[256];

	if (len > sizeof(expected))
		return -1;
	hex2bin(hex, expected, len);
	return memcmp(bin, expected, len);
}

/* Fixed-data RNG for deterministic keygen tests */
static int fixed_rng(void *ctx, uint8_t *out, size_t len)
{
	memcpy(out, ctx, len);
	return 0;
}

/*
 * Multi-update cipher helper: feed data in chunks of `step` bytes,
 * then call final(NULL, 0). step=0: one-shot via final(in, ilen).
 */
static int cipher_multi(int type, const uint8_t *key, int keybits, int dir,
	const uint8_t *iv, int ivlen, const uint8_t *in, size_t ilen,
	uint8_t *out, size_t *out_len, size_t step)
{
	struct mbedcrypto_cipher_ctx ctx;
	size_t olen, total = 0;
	int ret = 0;
	size_t off = 0;

	mbedcrypto_cipher_init(&ctx, type, key, keybits, dir);
	mbedcrypto_cipher_set_iv(&ctx, iv, ivlen);
	if (step == 0) {
		ret = mbedcrypto_cipher_final(&ctx, in, ilen, out, &olen);
		total = olen;
	} else {
		for (off = 0; off < ilen && ret == 0; off += step) {
			size_t chunk = (off + step <= ilen) ? step : (ilen - off);
			ret = mbedcrypto_cipher_update(&ctx, in + off, chunk,
					out + total, &olen);
			total += olen;
		}
		if (ret == 0) {
			ret = mbedcrypto_cipher_final(&ctx, NULL, 0,
					out + total, &olen);
			total += olen;
		}
	}
	mbedcrypto_cipher_cleanup(&ctx);
	*out_len = total;
	return ret;
}

/*
 * Split cipher helper: update(in, split) + final(in+split, ilen-split).
 */
static int cipher_split(int type, const uint8_t *key, int keybits, int dir,
	const uint8_t *iv, int ivlen, const uint8_t *in, size_t ilen,
	uint8_t *out, size_t *out_len, size_t split)
{
	struct mbedcrypto_cipher_ctx ctx;
	size_t olen, total = 0;
	int ret = 0;

	mbedcrypto_cipher_init(&ctx, type, key, keybits, dir);
	mbedcrypto_cipher_set_iv(&ctx, iv, ivlen);
	ret = mbedcrypto_cipher_update(&ctx, in, split, out, &olen);
	total = olen;
	if (ret == 0) {
		ret = mbedcrypto_cipher_final(&ctx, in + split, ilen - split,
				out + total, &olen);
		total += olen;
	}
	mbedcrypto_cipher_cleanup(&ctx);
	*out_len = total;
	return ret;
}

static void test_md5(void)
{
	TEST_START("MD5");
	struct mbedcrypto_md5_ctx ctx, ctx2;
	uint8_t out[16];
	uint8_t buf[1000];
	int ret = 0;

	/* RFC 1321: MD5("") = d41d8cd98f00b204e9800998ecf8427e */
	ret = mbedcrypto_md5_init(&ctx);
	CHECK(ret == 0, ret);
	ret = mbedcrypto_md5_update(&ctx, (const uint8_t *)"", 0);
	CHECK(ret == 0, ret);
	ret = mbedcrypto_md5_final(&ctx, out);
	CHECK(ret == 0, ret);
	CHECK(hexcmp(out, "d41d8cd98f00b204e9800998ecf8427e", 16) == 0, EBADMSG);
	mbedcrypto_md5_cleanup(&ctx);

	/* MD5("abc") = 900150983cd24fb0d6963f7d28e17f72 */
	ret = mbedcrypto_md5_init(&ctx);
	mbedcrypto_md5_update(&ctx, (const uint8_t *)"abc", 3);
	mbedcrypto_md5_final(&ctx, out);
	CHECK(hexcmp(out, "900150983cd24fb0d6963f7d28e17f72", 16) == 0, EBADMSG);
	mbedcrypto_md5_cleanup(&ctx);

	/* One-shot API: MD5("abc") */
	ret = mbedcrypto_md5_digest((const uint8_t *)"abc", 3, out);
	CHECK(ret == 0, ret);
	CHECK(hexcmp(out, "900150983cd24fb0d6963f7d28e17f72", 16) == 0, EBADMSG);

	/* Streaming: MD5("a" + "bc") should equal MD5("abc") */
	mbedcrypto_md5_init(&ctx);
	mbedcrypto_md5_update(&ctx, (const uint8_t *)"a", 1);
	mbedcrypto_md5_update(&ctx, (const uint8_t *)"bc", 2);
	mbedcrypto_md5_final(&ctx, out);
	CHECK(hexcmp(out, "900150983cd24fb0d6963f7d28e17f72", 16) == 0, EBADMSG);
	mbedcrypto_md5_cleanup(&ctx);

	/* Clone test */
	mbedcrypto_md5_init(&ctx);
	mbedcrypto_md5_update(&ctx, (const uint8_t *)"ab", 2);
	mbedcrypto_md5_clone(&ctx2, &ctx);
	mbedcrypto_md5_update(&ctx2, (const uint8_t *)"c", 1);
	mbedcrypto_md5_final(&ctx2, out);
	CHECK(hexcmp(out, "900150983cd24fb0d6963f7d28e17f72", 16) == 0, EBADMSG);
	mbedcrypto_md5_cleanup(&ctx);
	mbedcrypto_md5_cleanup(&ctx2);

	/* Long message: 1000 bytes of 'a' */
	memset(buf, 'a', 1000);
	mbedcrypto_md5_digest(buf, 1000, out);
	/* Reference: MD5("a"*1000) = cabe45dcc9ae5b66ba86600cca6b8ba8 */
	CHECK(hexcmp(out, "cabe45dcc9ae5b66ba86600cca6b8ba8", 16) == 0, EBADMSG);

	/* Byte-by-byte streaming of "abc" */
	mbedcrypto_md5_init(&ctx);
	mbedcrypto_md5_update(&ctx, (const uint8_t *)"a", 1);
	mbedcrypto_md5_update(&ctx, (const uint8_t *)"b", 1);
	mbedcrypto_md5_update(&ctx, (const uint8_t *)"c", 1);
	mbedcrypto_md5_final(&ctx, out);
	CHECK(hexcmp(out, "900150983cd24fb0d6963f7d28e17f72", 16) == 0, EBADMSG);
	mbedcrypto_md5_cleanup(&ctx);

out:
	TEST_END();
}

static void test_sha1(void)
{
	TEST_START("SHA-1");
	struct mbedcrypto_sha1_ctx ctx, ctx2;
	uint8_t out[20];

	/* FIPS 180-4: SHA1("abc") */
	mbedcrypto_sha1_init(&ctx);
	mbedcrypto_sha1_update(&ctx, (const uint8_t *)"abc", 3);
	mbedcrypto_sha1_final(&ctx, out);
	CHECK(hexcmp(out, "a9993e364706816aba3e25717850c26c9cd0d89d", 20) == 0, EBADMSG);
	mbedcrypto_sha1_cleanup(&ctx);

	/* Empty string */
	mbedcrypto_sha1_init(&ctx);
	mbedcrypto_sha1_update(&ctx, (const uint8_t *)"", 0);
	mbedcrypto_sha1_final(&ctx, out);
	CHECK(hexcmp(out, "da39a3ee5e6b4b0d3255bfef95601890afd80709", 20) == 0, EBADMSG);
	mbedcrypto_sha1_cleanup(&ctx);

	/* One-shot */
	mbedcrypto_sha1_digest((const uint8_t *)"abc", 3, out);
	CHECK(hexcmp(out, "a9993e364706816aba3e25717850c26c9cd0d89d", 20) == 0, EBADMSG);

	/* Streaming: "a" + "bc" */
	mbedcrypto_sha1_init(&ctx);
	mbedcrypto_sha1_update(&ctx, (const uint8_t *)"a", 1);
	mbedcrypto_sha1_update(&ctx, (const uint8_t *)"bc", 2);
	mbedcrypto_sha1_final(&ctx, out);
	CHECK(hexcmp(out, "a9993e364706816aba3e25717850c26c9cd0d89d", 20) == 0, EBADMSG);
	mbedcrypto_sha1_cleanup(&ctx);

	/* Clone */
	mbedcrypto_sha1_init(&ctx);
	mbedcrypto_sha1_update(&ctx, (const uint8_t *)"ab", 2);
	mbedcrypto_sha1_clone(&ctx2, &ctx);
	mbedcrypto_sha1_update(&ctx2, (const uint8_t *)"c", 1);
	mbedcrypto_sha1_final(&ctx2, out);
	CHECK(hexcmp(out, "a9993e364706816aba3e25717850c26c9cd0d89d", 20) == 0, EBADMSG);
	mbedcrypto_sha1_cleanup(&ctx);
	mbedcrypto_sha1_cleanup(&ctx2);

out:
	TEST_END();
}

static void test_sha256(void)
{
	TEST_START("SHA-224/256");
	struct mbedcrypto_sha256_ctx ctx, ctx2;
	uint8_t out[32];
	uint8_t block64[64], block65[65], ref[32];

	/* SHA-256("abc") - FIPS 180-4 */
	mbedcrypto_sha256_init(&ctx, 0); /* 0 = SHA-256 */
	mbedcrypto_sha256_update(&ctx, (const uint8_t *)"abc", 3);
	mbedcrypto_sha256_final(&ctx, out);
	CHECK(hexcmp(out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32) == 0, EBADMSG);
	mbedcrypto_sha256_cleanup(&ctx);

	/* SHA-256("") */
	mbedcrypto_sha256_init(&ctx, 0);
	mbedcrypto_sha256_update(&ctx, (const uint8_t *)"", 0);
	mbedcrypto_sha256_final(&ctx, out);
	CHECK(hexcmp(out, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 32) == 0, EBADMSG);
	mbedcrypto_sha256_cleanup(&ctx);

	/* SHA-224("abc") - FIPS 180-4 */
	mbedcrypto_sha256_init(&ctx, 1); /* 1 = SHA-224 */
	mbedcrypto_sha256_update(&ctx, (const uint8_t *)"abc", 3);
	mbedcrypto_sha256_final(&ctx, out);
	CHECK(hexcmp(out, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", 28) == 0, EBADMSG);
	mbedcrypto_sha256_cleanup(&ctx);

	/* One-shot SHA-256 */
	mbedcrypto_sha256_digest((const uint8_t *)"abc", 3, out, 0);
	CHECK(hexcmp(out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32) == 0, EBADMSG);

	/* One-shot SHA-224 */
	mbedcrypto_sha256_digest((const uint8_t *)"abc", 3, out, 1);
	CHECK(hexcmp(out, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", 28) == 0, EBADMSG);

	/* Streaming multi-update */
	mbedcrypto_sha256_init(&ctx, 0);
	mbedcrypto_sha256_update(&ctx, (const uint8_t *)"a", 1);
	mbedcrypto_sha256_update(&ctx, (const uint8_t *)"b", 1);
	mbedcrypto_sha256_update(&ctx, (const uint8_t *)"c", 1);
	mbedcrypto_sha256_final(&ctx, out);
	CHECK(hexcmp(out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32) == 0, EBADMSG);
	mbedcrypto_sha256_cleanup(&ctx);

	/* Clone test */
	mbedcrypto_sha256_init(&ctx, 0);
	mbedcrypto_sha256_update(&ctx, (const uint8_t *)"ab", 2);
	mbedcrypto_sha256_clone(&ctx2, &ctx);
	mbedcrypto_sha256_update(&ctx2, (const uint8_t *)"c", 1);
	mbedcrypto_sha256_final(&ctx2, out);
	CHECK(hexcmp(out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32) == 0, EBADMSG);
	mbedcrypto_sha256_cleanup(&ctx);
	mbedcrypto_sha256_cleanup(&ctx2);

	/* Cross-block boundary: 64 bytes (exactly one block) */
	memset(block64, 'a', 64);
	mbedcrypto_sha256_digest(block64, 64, out, 0);
	CHECK(hexcmp(out, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb", 32) == 0, EBADMSG);

	/* 65 bytes (one block + 1) - compare one-shot vs streaming */
	memset(block65, 'a', 65);
	mbedcrypto_sha256_digest(block65, 65, out, 0);
	mbedcrypto_sha256_init(&ctx, 0);
	mbedcrypto_sha256_update(&ctx, block65, 65);
	mbedcrypto_sha256_final(&ctx, ref);
	mbedcrypto_sha256_cleanup(&ctx);
	CHECK(memcmp(out, ref, 32) == 0, EBADMSG);

out:
	TEST_END();
}

static void test_sha512(void)
{
	TEST_START("SHA-384/512");
	struct mbedcrypto_sha512_ctx ctx, ctx2;
	uint8_t out[64];

	/* SHA-512("abc") */
	mbedcrypto_sha512_init(&ctx, 0); /* 0 = SHA-512 */
	mbedcrypto_sha512_update(&ctx, (const uint8_t *)"abc", 3);
	mbedcrypto_sha512_final(&ctx, out);
	CHECK(hexcmp(out, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
		"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", 64) == 0, EBADMSG);
	mbedcrypto_sha512_cleanup(&ctx);

	/* SHA-384("abc") */
	mbedcrypto_sha512_init(&ctx, 1); /* 1 = SHA-384 */
	mbedcrypto_sha512_update(&ctx, (const uint8_t *)"abc", 3);
	mbedcrypto_sha512_final(&ctx, out);
	CHECK(hexcmp(out, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
		"8086072ba1e7cc2358baeca134c825a7", 48) == 0, EBADMSG);
	mbedcrypto_sha512_cleanup(&ctx);

	/* SHA-512("") */
	mbedcrypto_sha512_init(&ctx, 0);
	mbedcrypto_sha512_update(&ctx, (const uint8_t *)"", 0);
	mbedcrypto_sha512_final(&ctx, out);
	CHECK(hexcmp(out, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
		"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", 64) == 0, EBADMSG);
	mbedcrypto_sha512_cleanup(&ctx);

	/* One-shot */
	mbedcrypto_sha512_digest((const uint8_t *)"abc", 3, out, 0);
	CHECK(hexcmp(out, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
		"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", 64) == 0, EBADMSG);

	/* Clone */
	mbedcrypto_sha512_init(&ctx, 0);
	mbedcrypto_sha512_update(&ctx, (const uint8_t *)"ab", 2);
	mbedcrypto_sha512_clone(&ctx2, &ctx);
	mbedcrypto_sha512_update(&ctx2, (const uint8_t *)"c", 1);
	mbedcrypto_sha512_final(&ctx2, out);
	CHECK(hexcmp(out, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
		"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", 64) == 0, EBADMSG);
	mbedcrypto_sha512_cleanup(&ctx);
	mbedcrypto_sha512_cleanup(&ctx2);

out:
	TEST_END();
}

static void test_sm3(void)
{
	TEST_START("SM3");
	struct mbedcrypto_sm3_ctx ctx, ctx2;
	uint8_t out[32];
	uint8_t rep[64];
	int i = 0;

	/* GB/T 32905-2016 Example 1: SM3("abc") */
	mbedcrypto_sm3_init(&ctx);
	mbedcrypto_sm3_update(&ctx, (const uint8_t *)"abc", 3);
	mbedcrypto_sm3_final(&ctx, out);
	CHECK(hexcmp(out, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", 32) == 0, EBADMSG);
	mbedcrypto_sm3_cleanup(&ctx);

	/* SM3("") */
	mbedcrypto_sm3_init(&ctx);
	mbedcrypto_sm3_update(&ctx, (const uint8_t *)"", 0);
	mbedcrypto_sm3_final(&ctx, out);
	CHECK(hexcmp(out, "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", 32) == 0, EBADMSG);
	mbedcrypto_sm3_cleanup(&ctx);

	/* One-shot */
	mbedcrypto_sm3_digest((const uint8_t *)"abc", 3, out);
	CHECK(hexcmp(out, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", 32) == 0, EBADMSG);

	/* Streaming */
	mbedcrypto_sm3_init(&ctx);
	mbedcrypto_sm3_update(&ctx, (const uint8_t *)"a", 1);
	mbedcrypto_sm3_update(&ctx, (const uint8_t *)"bc", 2);
	mbedcrypto_sm3_final(&ctx, out);
	CHECK(hexcmp(out, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", 32) == 0, EBADMSG);
	mbedcrypto_sm3_cleanup(&ctx);

	/* Clone */
	mbedcrypto_sm3_init(&ctx);
	mbedcrypto_sm3_update(&ctx, (const uint8_t *)"ab", 2);
	mbedcrypto_sm3_clone(&ctx2, &ctx);
	mbedcrypto_sm3_update(&ctx2, (const uint8_t *)"c", 1);
	mbedcrypto_sm3_final(&ctx2, out);
	CHECK(hexcmp(out, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", 32) == 0, EBADMSG);
	mbedcrypto_sm3_cleanup(&ctx);
	mbedcrypto_sm3_cleanup(&ctx2);

	/* GB/T 32905-2016 Example 2: SM3("abcd" * 16) */
	for (i = 0; i < 16; i++)
		memcpy(rep + 4*i, "abcd", 4);
	mbedcrypto_sm3_digest(rep, 64, out);
	CHECK(hexcmp(out, "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732", 32) == 0, EBADMSG);

out:
	TEST_END();
}

static void test_sha3(void)
{
	TEST_START("SHA-3");
	struct mbedcrypto_sha3_ctx ctx, ctx2;
	uint8_t out[64];
	int i = 0;

	/* SHA3-256("") - NIST */
	mbedcrypto_sha3_init(&ctx);
	mbedcrypto_sha3_start(&ctx, MBEDCRYPTO_SHA3_256);
	mbedcrypto_sha3_update(&ctx, (const uint8_t *)"", 0);
	mbedcrypto_sha3_final(&ctx, out, 32);
	CHECK(hexcmp(out, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", 32) == 0, EBADMSG);
	mbedcrypto_sha3_cleanup(&ctx);

	/* SHA3-256("abc") */
	mbedcrypto_sha3_init(&ctx);
	mbedcrypto_sha3_start(&ctx, MBEDCRYPTO_SHA3_256);
	mbedcrypto_sha3_update(&ctx, (const uint8_t *)"abc", 3);
	mbedcrypto_sha3_final(&ctx, out, 32);
	CHECK(hexcmp(out, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", 32) == 0, EBADMSG);
	mbedcrypto_sha3_cleanup(&ctx);

	/* SHA3-224("abc") */
	mbedcrypto_sha3_init(&ctx);
	mbedcrypto_sha3_start(&ctx, MBEDCRYPTO_SHA3_224);
	mbedcrypto_sha3_update(&ctx, (const uint8_t *)"abc", 3);
	mbedcrypto_sha3_final(&ctx, out, 28);
	CHECK(hexcmp(out, "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf", 28) == 0, EBADMSG);
	mbedcrypto_sha3_cleanup(&ctx);

	/* SHA3-384("abc") */
	mbedcrypto_sha3_init(&ctx);
	mbedcrypto_sha3_start(&ctx, MBEDCRYPTO_SHA3_384);
	mbedcrypto_sha3_update(&ctx, (const uint8_t *)"abc", 3);
	mbedcrypto_sha3_final(&ctx, out, 48);
	CHECK(hexcmp(out, "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
		"98d88cea927ac7f539f1edf228376d25", 48) == 0, EBADMSG);
	mbedcrypto_sha3_cleanup(&ctx);

	/* SHA3-512("abc") */
	mbedcrypto_sha3_init(&ctx);
	mbedcrypto_sha3_start(&ctx, MBEDCRYPTO_SHA3_512);
	mbedcrypto_sha3_update(&ctx, (const uint8_t *)"abc", 3);
	mbedcrypto_sha3_final(&ctx, out, 64);
	CHECK(hexcmp(out, "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
		"10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0", 64) == 0, EBADMSG);
	mbedcrypto_sha3_cleanup(&ctx);

	/* Streaming SHA3-256: "a" + "bc" */
	mbedcrypto_sha3_init(&ctx);
	mbedcrypto_sha3_start(&ctx, MBEDCRYPTO_SHA3_256);
	mbedcrypto_sha3_update(&ctx, (const uint8_t *)"a", 1);
	mbedcrypto_sha3_update(&ctx, (const uint8_t *)"bc", 2);
	mbedcrypto_sha3_final(&ctx, out, 32);
	CHECK(hexcmp(out, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", 32) == 0, EBADMSG);
	mbedcrypto_sha3_cleanup(&ctx);

	/* Clone test */
	mbedcrypto_sha3_init(&ctx);
	mbedcrypto_sha3_start(&ctx, MBEDCRYPTO_SHA3_256);
	mbedcrypto_sha3_update(&ctx, (const uint8_t *)"ab", 2);
	mbedcrypto_sha3_clone(&ctx2, &ctx);
	mbedcrypto_sha3_update(&ctx2, (const uint8_t *)"c", 1);
	mbedcrypto_sha3_final(&ctx2, out, 32);
	CHECK(hexcmp(out, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", 32) == 0, EBADMSG);
	mbedcrypto_sha3_cleanup(&ctx);
	mbedcrypto_sha3_cleanup(&ctx2);

	/* SHAKE256("abc", output=32 bytes) */
	mbedcrypto_sha3_init(&ctx);
	mbedcrypto_sha3_start(&ctx, MBEDCRYPTO_SHAKE256);
	mbedcrypto_sha3_update(&ctx, (const uint8_t *)"abc", 3);
	mbedcrypto_sha3_final(&ctx, out, 32);
	CHECK(hexcmp(out, "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739", 32) == 0, EBADMSG);
	mbedcrypto_sha3_cleanup(&ctx);

	/* SHAKE256 with 64-byte output */
	mbedcrypto_sha3_init(&ctx);
	mbedcrypto_sha3_start(&ctx, MBEDCRYPTO_SHAKE256);
	mbedcrypto_sha3_update(&ctx, (const uint8_t *)"abc", 3);
	mbedcrypto_sha3_final(&ctx, out, 64);
	CHECK(hexcmp(out, "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
		"d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4", 64) == 0, EBADMSG);
	mbedcrypto_sha3_cleanup(&ctx);

	/* --- Extended coverage (merged from test_sha3_ext) --- */
	{
		/* SHA3-256 clone test */
		struct mbedcrypto_sha3_ctx ctx, clone;
		uint8_t hash1[32], hash2[32];

		mbedcrypto_sha3_init(&ctx);
		mbedcrypto_sha3_start(&ctx, MBEDCRYPTO_SHA3_256);
		mbedcrypto_sha3_update(&ctx, (const uint8_t *)"hello ", 6);

		/* Clone after partial data */
		mbedcrypto_sha3_clone(&clone, &ctx);

		/* Finish original with "world" */
		mbedcrypto_sha3_update(&ctx, (const uint8_t *)"world", 5);
		mbedcrypto_sha3_final(&ctx, hash1, 32);

		/* Finish clone with "world" - should produce same hash */
		mbedcrypto_sha3_update(&clone, (const uint8_t *)"world", 5);
		mbedcrypto_sha3_final(&clone, hash2, 32);

		CHECK(memcmp(hash1, hash2, 32) == 0, EBADMSG);

		/* Clone divergence: finish clone with different data */
		mbedcrypto_sha3_init(&ctx);
		mbedcrypto_sha3_start(&ctx, MBEDCRYPTO_SHA3_256);
		mbedcrypto_sha3_update(&ctx, (const uint8_t *)"prefix", 6);
		mbedcrypto_sha3_clone(&clone, &ctx);

		mbedcrypto_sha3_update(&ctx, (const uint8_t *)"A", 1);
		mbedcrypto_sha3_final(&ctx, hash1, 32);

		mbedcrypto_sha3_update(&clone, (const uint8_t *)"B", 1);
		mbedcrypto_sha3_final(&clone, hash2, 32);

		CHECK(memcmp(hash1, hash2, 32) != 0, EBADMSG);

		mbedcrypto_sha3_cleanup(&ctx);
		mbedcrypto_sha3_cleanup(&clone);

		/* SHA3-512 basic test with longer message */
		{
			struct mbedcrypto_sha3_ctx sctx;
			uint8_t hash[64];
			uint8_t buf[100];
			uint8_t hash_again[64];

			mbedcrypto_sha3_init(&sctx);
			mbedcrypto_sha3_start(&sctx, MBEDCRYPTO_SHA3_512);
			/* Feed 1000 bytes */
			for (i = 0; i < 100; i++)
				buf[i] = i;
			for (i = 0; i < 10; i++)
				mbedcrypto_sha3_update(&sctx, buf, 100);
			mbedcrypto_sha3_final(&sctx, hash, 64);

			/* Verify consistency: do it again */
			mbedcrypto_sha3_init(&sctx);
			mbedcrypto_sha3_start(&sctx, MBEDCRYPTO_SHA3_512);
			for (i = 0; i < 10; i++)
				mbedcrypto_sha3_update(&sctx, buf, 100);
			mbedcrypto_sha3_final(&sctx, hash_again, 64);
			CHECK(memcmp(hash, hash_again, 64) == 0, EBADMSG);
			mbedcrypto_sha3_cleanup(&sctx);
		}
	}

out:
	TEST_END();
}

static void test_hash_dispatch(void)
{
	TEST_START("hash_dispatch");
	struct mbedcrypto_hash_ctx hctx, hctx2;
	uint8_t out[64];
	size_t i = 0;
	int ret = 0;

	/* Test all hash algorithms through the dispatch layer */
	struct {
		int algo;
		const char *name;
		const char *input;
		size_t ilen;
		size_t hlen;
		const char *expected;
	} tests[] = {
		{ MBEDCRYPTO_HASH_MD5, "MD5", "abc", 3, 16,
		  "900150983cd24fb0d6963f7d28e17f72" },
		{ MBEDCRYPTO_HASH_SHA1, "SHA1", "abc", 3, 20,
		  "a9993e364706816aba3e25717850c26c9cd0d89d" },
		{ MBEDCRYPTO_HASH_SHA224, "SHA224", "abc", 3, 28,
		  "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
		{ MBEDCRYPTO_HASH_SHA256, "SHA256", "abc", 3, 32,
		  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
		{ MBEDCRYPTO_HASH_SHA384, "SHA384", "abc", 3, 48,
		  "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
		  "8086072ba1e7cc2358baeca134c825a7" },
		{ MBEDCRYPTO_HASH_SHA512, "SHA512", "abc", 3, 64,
		  "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
		  "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
		{ MBEDCRYPTO_HASH_SM3, "SM3", "abc", 3, 32,
		  "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0" },
		{ MBEDCRYPTO_HASH_SHA3_256, "SHA3-256", "abc", 3, 32,
		  "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532" },
		{ MBEDCRYPTO_HASH_SHA3_224, "SHA3-224", "abc", 3, 28,
		  "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf" },
		{ MBEDCRYPTO_HASH_SHA3_384, "SHA3-384", "abc", 3, 48,
		  "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
		  "98d88cea927ac7f539f1edf228376d25" },
		{ MBEDCRYPTO_HASH_SHA3_512, "SHA3-512", "abc", 3, 64,
		  "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
		  "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0" },
	};

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		ret = mbedcrypto_hash_init(&hctx, tests[i].algo);
		CHECK(ret == 0, ret);
		mbedcrypto_hash_update(&hctx, (const uint8_t *)tests[i].input, tests[i].ilen);
		mbedcrypto_hash_final(&hctx, out);
		CHECK(hexcmp(out, tests[i].expected, tests[i].hlen) == 0, EBADMSG);
		mbedcrypto_hash_cleanup(&hctx);
	}

	/* Test hash_size and hash_blksize */
	CHECK(mbedcrypto_hash_size(MBEDCRYPTO_HASH_MD5) == 16, EBADMSG);
	CHECK(mbedcrypto_hash_size(MBEDCRYPTO_HASH_SHA1) == 20, EBADMSG);
	CHECK(mbedcrypto_hash_size(MBEDCRYPTO_HASH_SHA256) == 32, EBADMSG);
	CHECK(mbedcrypto_hash_size(MBEDCRYPTO_HASH_SHA384) == 48, EBADMSG);
	CHECK(mbedcrypto_hash_size(MBEDCRYPTO_HASH_SHA512) == 64, EBADMSG);
	CHECK(mbedcrypto_hash_blksize(MBEDCRYPTO_HASH_MD5) == 64, EBADMSG);
	CHECK(mbedcrypto_hash_blksize(MBEDCRYPTO_HASH_SHA256) == 64, EBADMSG);
	CHECK(mbedcrypto_hash_blksize(MBEDCRYPTO_HASH_SHA512) == 128, EBADMSG);

	/* Hash dispatch clone test */
	mbedcrypto_hash_init(&hctx, MBEDCRYPTO_HASH_SHA256);
	mbedcrypto_hash_update(&hctx, (const uint8_t *)"ab", 2);
	mbedcrypto_hash_clone(&hctx2, &hctx);
	mbedcrypto_hash_update(&hctx2, (const uint8_t *)"c", 1);
	mbedcrypto_hash_final(&hctx2, out);
	CHECK(hexcmp(out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32) == 0, EBADMSG);
	mbedcrypto_hash_cleanup(&hctx);
	mbedcrypto_hash_cleanup(&hctx2);

out:
	TEST_END();
}

struct hmac_dispatch_vec {
	int algo;
	const char *name;
	const char *expected;
	size_t mac_len;
};

static int hmac_dispatch_check(const struct hmac_dispatch_vec *vec,
			       const uint8_t *key, size_t key_len,
			       const uint8_t *msg, size_t msg_len)
{
	struct mbedcrypto_hmac_ctx hmctx;
	uint8_t mac[64];
	int ret = 0;

	ret = mbedcrypto_hmac_init(&hmctx, vec->algo, key, key_len);
	if (ret != 0)
		return ret;

	mbedcrypto_hmac_update(&hmctx, msg, msg_len);
	mbedcrypto_hmac_final(&hmctx, mac);
	ret = hexcmp(mac, vec->expected, vec->mac_len);
	mbedcrypto_hmac_cleanup(&hmctx);

	return ret == 0 ? 0 : EBADMSG;
}

static void test_hmac(void)
{
	struct mbedcrypto_hmac_ctx hmctx;
	uint8_t mac[64];
	uint8_t longkey[128];
	int ret = 0;
	int i = 0;
	size_t t = 0;
	const uint8_t *jefe = (const uint8_t *)"Jefe";
	const uint8_t *rfc_msg = (const uint8_t *)"what do ya want for nothing?";
	static const struct hmac_dispatch_vec dispatch[] = {
		{ MBEDCRYPTO_HASH_SHA256, "HMAC-SHA256",
		  "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		  32 },
		{ MBEDCRYPTO_HASH_SHA1, "HMAC-SHA1",
		  "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", 20 },
		{ MBEDCRYPTO_HASH_MD5, "HMAC-MD5",
		  "750c783e6ab0b503eaa86e310a5db738", 16 },
		{ MBEDCRYPTO_HASH_SHA512, "HMAC-SHA512",
		  "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
		  "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
		  64 },
		{ MBEDCRYPTO_HASH_SHA384, "HMAC-SHA384",
		  "af45d2e376484031617f78d2b58a6b1b"
		  "9c7ef464f5a01b47e42ec3736322445"
		  "e8e2240ca5e69e2c78b3239ecfab21649", 48 },
		{ MBEDCRYPTO_HASH_SHA224, "HMAC-SHA224",
		  "a30e01098bc6dbbf45690f3a7e9e6d0f"
		  "8bbea2a39e6148008fd05e44", 28 },
	};

	TEST_START("HMAC");

	/* RFC 4231 Test Case 2: HMAC-SHA-256 */
	{
		const uint8_t *key = (const uint8_t *)"Jefe";
		const uint8_t *data = (const uint8_t *)"what do ya want for nothing?";
		struct mbedcrypto_hmac_sha256_ctx hctx;
		mbedcrypto_hmac_sha256_init(&hctx, key, 4);
		mbedcrypto_hmac_sha256_update(&hctx, data, 28);
		mbedcrypto_hmac_sha256_final(&hctx, mac);
		CHECK(hexcmp(mac, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
			32) == 0, EBADMSG);
		mbedcrypto_hmac_sha256_cleanup(&hctx);
	}

	/* HMAC-SHA256 one-shot */
	mbedcrypto_hmac_sha256(jefe, 4, rfc_msg, 28, mac);
	CHECK(hexcmp(mac, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		32) == 0, EBADMSG);

	/* HMAC dispatch - test with different hash algorithms */
	for (t = 0; t < sizeof(dispatch) / sizeof(dispatch[0]); t++) {
		ret = hmac_dispatch_check(&dispatch[t], jefe, 4, rfc_msg, 28);
		CHECK(ret == 0, ret, "%s", dispatch[t].name);
	}

	/* HMAC streaming: multi-update */
	mbedcrypto_hmac_init(&hmctx, MBEDCRYPTO_HASH_SHA256,
		(const uint8_t *)"Jefe", 4);
	mbedcrypto_hmac_update(&hmctx, (const uint8_t *)"what do ya ", 11);
	mbedcrypto_hmac_update(&hmctx, (const uint8_t *)"want for ", 9);
	mbedcrypto_hmac_update(&hmctx, (const uint8_t *)"nothing?", 8);
	mbedcrypto_hmac_final(&hmctx, mac);
	CHECK(hexcmp(mac, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", 32) == 0, EBADMSG);
	mbedcrypto_hmac_cleanup(&hmctx);

	/* HMAC with long key (> block size, triggers hashing of key) */
	memset(longkey, 0xaa, sizeof(longkey));
	mbedcrypto_hmac_init(&hmctx, MBEDCRYPTO_HASH_SHA256, longkey, 128);
	mbedcrypto_hmac_update(&hmctx, (const uint8_t *)"test", 4);
	mbedcrypto_hmac_final(&hmctx, mac);
	CHECK(hexcmp(mac, "66c75f6edb2aab63e08988a71eaa10785fc5e65ca07b401c5e6da1ad3cfa23c1", 32) == 0, EBADMSG);
	mbedcrypto_hmac_cleanup(&hmctx);

	/* --- Extended coverage (merged from test_hmac_ext) --- */
	{
		static const struct hmac_dispatch_vec kat[] = {
			{ MBEDCRYPTO_HASH_SM3, "HMAC-SM3",
			  "887bb464fd12653b7b8e90e4f176a698"
			  "a956de41fe469dbf77e34b76e655b8b2", 32 },
#ifdef CONFIG_MBEDCRYPTO_SHA3
			{ MBEDCRYPTO_HASH_SHA3_256, "HMAC-SHA3-256",
			  "e1756cb870fb8d8af532578a193d524d"
			  "f70f453369eb86e6317d052fd0b06e34", 32 },
			{ MBEDCRYPTO_HASH_SHA3_224, "HMAC-SHA3-224",
			  "97ff19666b53d55fd0a38e0bc311361e"
			  "f3106b9c4ea2d00541b8d614", 28 },
			{ MBEDCRYPTO_HASH_SHA3_384, "HMAC-SHA3-384",
			  "f7e6b51395ea4986c82b6259206efb03"
			  "df32c4268448f7de5c01a56da63c5518"
			  "d62ea6e5ac0487b2f554357ba2b659bf", 48 },
			{ MBEDCRYPTO_HASH_SHA3_512, "HMAC-SHA3-512",
			  "614163e9f435345e5aef54864d7b180e"
			  "0de71f36d072f2872d6603bea7fa3ed1"
			  "93be30e7a7a1fd2e7a5a475e9050e618"
			  "d951a06a90d408f859b5e4500ef057fb", 64 },
#endif
		};
		uint8_t hkey[32], hmsg[96];

		for (i = 0; i < 32; i++)
			hkey[i] = i;
		hex2bin("000102030405060708090a0b0c0d0e0f"
			"0a0b0c0d0e0f00010203040506070809"
			"0f0e0d0c0b0a09080706050403020100"
			"000102030405060708090a0b0c0d0e0f"
			"0a0b0c0d0e0f00010203040506070809"
			"0f0e0d0c0b0a09080706050403020100", hmsg, 96);

		for (t = 0; t < sizeof(kat) / sizeof(kat[0]); t++) {
			ret = mbedcrypto_hmac_init(&hmctx, kat[t].algo, hkey, 32);
			CHECK(ret == 0, ret, "%s init", kat[t].name);
			mbedcrypto_hmac_update(&hmctx, hmsg, 96);
			mbedcrypto_hmac_final(&hmctx, mac);
			CHECK(hexcmp(mac, kat[t].expected, kat[t].mac_len) == 0,
				EBADMSG, "%s", kat[t].name);
			mbedcrypto_hmac_cleanup(&hmctx);
		}

		/* HMAC with empty message */
		ret = mbedcrypto_hmac_init(&hmctx, MBEDCRYPTO_HASH_SHA256,
			(const uint8_t *)"key", 3);
		CHECK(ret == 0, ret);
		mbedcrypto_hmac_final(&hmctx, mac);
		mbedcrypto_hmac_cleanup(&hmctx);

		/* HMAC with empty key */
		ret = mbedcrypto_hmac_init(&hmctx, MBEDCRYPTO_HASH_SHA256,
			(const uint8_t *)"", 0);
		CHECK(ret == 0, ret);
		mbedcrypto_hmac_update(&hmctx, (const uint8_t *)"test", 4);
		mbedcrypto_hmac_final(&hmctx, mac);
		mbedcrypto_hmac_cleanup(&hmctx);
	}

out:
	TEST_END();
}

static void test_aes_ecb(void)
{
	TEST_START("AES-ECB");
	struct mbedcrypto_aes_ctx ctx;
	uint8_t out[16], dec[16];
	uint8_t key128[16], pt[16], ct128[16];
	uint8_t key192[24], ct192[16];
	uint8_t key256[32], ct256[16];
	uint8_t buf[16];
	int ret = 0;

	/* NIST FIPS 197 - AES-128 */
	hex2bin("2b7e151628aed2a6abf7158809cf4f3c", key128, 16);
	hex2bin("6bc1bee22e409f96e93d7e117393172a", pt, 16);
	hex2bin("3ad77bb40d7a3660a89ecaf32466ef97", ct128, 16);

	mbedcrypto_aes_setkey(&ctx, key128, 128, MBEDCRYPTO_AES_ENCRYPT);
	mbedcrypto_aes_ecb_crypt(&ctx, pt, out);
	CHECK(memcmp(out, ct128, 16) == 0, EBADMSG);
	mbedcrypto_aes_cleanup(&ctx);

	mbedcrypto_aes_setkey(&ctx, key128, 128, MBEDCRYPTO_AES_DECRYPT);
	mbedcrypto_aes_ecb_crypt(&ctx, ct128, dec);
	CHECK(memcmp(dec, pt, 16) == 0, EBADMSG);
	mbedcrypto_aes_cleanup(&ctx);

	/* AES-192 - NIST */
	hex2bin("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", key192, 24);
	hex2bin("bd334f1d6e45f25ff712a214571fa5cc", ct192, 16);

	mbedcrypto_aes_setkey(&ctx, key192, 192, MBEDCRYPTO_AES_ENCRYPT);
	mbedcrypto_aes_ecb_crypt(&ctx, pt, out);
	CHECK(memcmp(out, ct192, 16) == 0, EBADMSG);
	mbedcrypto_aes_cleanup(&ctx);

	mbedcrypto_aes_setkey(&ctx, key192, 192, MBEDCRYPTO_AES_DECRYPT);
	mbedcrypto_aes_ecb_crypt(&ctx, ct192, dec);
	CHECK(memcmp(dec, pt, 16) == 0, EBADMSG);
	mbedcrypto_aes_cleanup(&ctx);

	/* AES-256 - NIST */
	hex2bin("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key256, 32);
	hex2bin("f3eed1bdb5d2a03c064b5a7e3db181f8", ct256, 16);

	mbedcrypto_aes_setkey(&ctx, key256, 256, MBEDCRYPTO_AES_ENCRYPT);
	mbedcrypto_aes_ecb_crypt(&ctx, pt, out);
	CHECK(memcmp(out, ct256, 16) == 0, EBADMSG);
	mbedcrypto_aes_cleanup(&ctx);

	mbedcrypto_aes_setkey(&ctx, key256, 256, MBEDCRYPTO_AES_DECRYPT);
	mbedcrypto_aes_ecb_crypt(&ctx, ct256, dec);
	CHECK(memcmp(dec, pt, 16) == 0, EBADMSG);
	mbedcrypto_aes_cleanup(&ctx);

	/* In-place encrypt/decrypt */
	memcpy(buf, pt, 16);
	mbedcrypto_aes_setkey(&ctx, key128, 128, MBEDCRYPTO_AES_ENCRYPT);
	mbedcrypto_aes_ecb_crypt(&ctx, buf, buf); /* in-place */
	CHECK(memcmp(buf, ct128, 16) == 0, EBADMSG);
	mbedcrypto_aes_cleanup(&ctx);

	mbedcrypto_aes_setkey(&ctx, key128, 128, MBEDCRYPTO_AES_DECRYPT);
	mbedcrypto_aes_ecb_crypt(&ctx, buf, buf); /* in-place */
	CHECK(memcmp(buf, pt, 16) == 0, EBADMSG);
	mbedcrypto_aes_cleanup(&ctx);

	/* Invalid key length should fail */
	ret = mbedcrypto_aes_setkey(&ctx, key128, 64, MBEDCRYPTO_AES_ENCRYPT);
	CHECK(ret != 0, EBADMSG);

out:
	TEST_END();
}

static void test_aes_cbc(void)
{
	TEST_START("AES-CBC");
	struct mbedcrypto_cipher_ctx cctx;
	uint8_t key128[16], iv_save[16];
	uint8_t pt[64], ct[64], out[64], dec[64];
	uint8_t key192[24];
	uint8_t buf[64];
	size_t olen, total = 0, flen = 0;
	int ret = 0;
	int i = 0;

	/* NIST SP 800-38A F.2.1 AES-128 CBC encrypt */

	hex2bin("2b7e151628aed2a6abf7158809cf4f3c", key128, 16);
	hex2bin("000102030405060708090a0b0c0d0e0f", iv_save, 16);
	hex2bin("6bc1bee22e409f96e93d7e117393172a"
		"ae2d8a571e03ac9c9eb76fac45af8e51"
		"30c81c46a35ce411e5fbc1191a0a52ef"
		"f69f2445df4f9b17ad2b417be66c3710", pt, 64);
	hex2bin("7649abac8119b246cee98e9b12e9197d"
		"5086cb9b507219ee95db113a917678b2"
		"73bed6b8e3c1743b7116e69e22229516"
		"3ff1caa1681fac09120eca307586e1a7", ct, 64);

	/* Encrypt 4 blocks (one-shot via cipher_final) */
	mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CBC, key128, 128, 0);
	mbedcrypto_cipher_set_iv(&cctx, iv_save, 16);
	ret = mbedcrypto_cipher_final(&cctx, pt, 64, out, &olen);
	CHECK(ret == 0 && olen == 64, EBADMSG);
	CHECK(memcmp(out, ct, 64) == 0, EBADMSG);
	mbedcrypto_cipher_cleanup(&cctx);

	/* Decrypt 4 blocks */
	mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CBC, key128, 128, 1);
	mbedcrypto_cipher_set_iv(&cctx, iv_save, 16);
	ret = mbedcrypto_cipher_final(&cctx, ct, 64, dec, &olen);
	CHECK(ret == 0 && olen == 64 && memcmp(dec, pt, 64) == 0, EBADMSG);
	mbedcrypto_cipher_cleanup(&cctx);

	/* 1-block CBC */
	mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CBC, key128, 128, 0);
	mbedcrypto_cipher_set_iv(&cctx, iv_save, 16);
	ret = mbedcrypto_cipher_final(&cctx, pt, 16, out, &olen);
	CHECK(ret == 0 && olen == 16 && memcmp(out, ct, 16) == 0, EBADMSG);
	mbedcrypto_cipher_cleanup(&cctx);

	/* In-place encrypt */
	memcpy(buf, pt, 64);
	mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CBC, key128, 128, 0);
	mbedcrypto_cipher_set_iv(&cctx, iv_save, 16);
	ret = mbedcrypto_cipher_final(&cctx, buf, 64, buf, &olen);
	CHECK(ret == 0 && olen == 64 && memcmp(buf, ct, 64) == 0, EBADMSG);
	mbedcrypto_cipher_cleanup(&cctx);

	/* In-place decrypt */
	memcpy(buf, ct, 64);
	mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CBC, key128, 128, 1);
	mbedcrypto_cipher_set_iv(&cctx, iv_save, 16);
	ret = mbedcrypto_cipher_final(&cctx, buf, 64, buf, &olen);
	CHECK(ret == 0 && olen == 64 && memcmp(buf, pt, 64) == 0, EBADMSG);
	mbedcrypto_cipher_cleanup(&cctx);

	/* Multi-update: 16 bytes at a time */
	mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CBC, key128, 128, 0);
	mbedcrypto_cipher_set_iv(&cctx, iv_save, 16);
	total = 0;
	for (i = 0; i < 4; i++) {
		size_t ulen;
		mbedcrypto_cipher_update(&cctx, pt + i * 16, 16, out + total, &ulen);
		total += ulen;
	}
	mbedcrypto_cipher_final(&cctx, NULL, 0, out + total, &flen);
	total += flen;
	CHECK(total == 64 && memcmp(out, ct, 64) == 0, EBADMSG);
	mbedcrypto_cipher_cleanup(&cctx);

	/* NIST SP 800-38A F.2.3 AES-192 CBC KAT */
	hex2bin("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", key192, 24);
	{
		uint8_t ct192[64], iv192[16], enc192[64], dec192[64];
		hex2bin("000102030405060708090a0b0c0d0e0f", iv192, 16);
		hex2bin("4f021db243bc633d7178183a9fa071e8"
			"b4d9ada9ad7dedf4e5e738763f69145a"
			"571b242012fb7ae07fa9baac3df102e0"
			"08b0e27988598881d920a9e64f5615cd", ct192, 64);

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CBC, key192, 192, 0);
		mbedcrypto_cipher_set_iv(&cctx, iv192, 16);
		mbedcrypto_cipher_final(&cctx, pt, 64, enc192, &olen);
		CHECK(olen == 64 && memcmp(enc192, ct192, 64) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CBC, key192, 192, 1);
		mbedcrypto_cipher_set_iv(&cctx, iv192, 16);
		mbedcrypto_cipher_final(&cctx, ct192, 64, dec192, &olen);
		CHECK(olen == 64 && memcmp(dec192, pt, 64) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);
	}

	/* NIST SP 800-38A F.2.5 AES-256 CBC KAT */
	uint8_t key256[32];
	hex2bin("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key256, 32);
	{
		uint8_t ct256[64], iv256[16], enc256[64], dec256[64];
		hex2bin("000102030405060708090a0b0c0d0e0f", iv256, 16);
		hex2bin("f58c4c04d6e5f1ba779eabfb5f7bfbd6"
			"9cfc4e967edb808d679f777bc6702c7d"
			"39f23369a9d9bacfa530e26304231461"
			"b2eb05e2c39be9fcda6c19078c6a9d1b", ct256, 64);

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CBC, key256, 256, 0);
		mbedcrypto_cipher_set_iv(&cctx, iv256, 16);
		mbedcrypto_cipher_final(&cctx, pt, 64, enc256, &olen);
		CHECK(olen == 64 && memcmp(enc256, ct256, 64) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CBC, key256, 256, 1);
		mbedcrypto_cipher_set_iv(&cctx, iv256, 16);
		mbedcrypto_cipher_final(&cctx, ct256, 64, dec256, &olen);
		CHECK(olen == 64 && memcmp(dec256, pt, 64) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);
	}

out:
	TEST_END();
}

static void test_aes_ctr(void)
{
	TEST_START("AES-CTR");
	struct mbedcrypto_cipher_ctx cctx;
	int ret = 0;

	/* NIST SP 800-38A F.5.1 AES-128 CTR */
	uint8_t key128[16], nonce_save[16];
	uint8_t pt[64], ct[64], out[64], dec[64];
	size_t olen;
	int i = 0, si = 0;

	hex2bin("2b7e151628aed2a6abf7158809cf4f3c", key128, 16);
	hex2bin("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", nonce_save, 16);
	hex2bin("6bc1bee22e409f96e93d7e117393172a"
		"ae2d8a571e03ac9c9eb76fac45af8e51"
		"30c81c46a35ce411e5fbc1191a0a52ef"
		"f69f2445df4f9b17ad2b417be66c3710", pt, 64);
	hex2bin("874d6191b620e3261bef6864990db6ce"
		"9806f66b7970fdff8617187bb9fffdff"
		"5ae4df3edbd5d35e5b4f09020db03eab"
		"1e031dda2fbe03d1792170a0f3009cee", ct, 64);

	/* Encrypt all 64 bytes at once */
	mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTR, key128, 128, 0);
	mbedcrypto_cipher_set_iv(&cctx, nonce_save, 16);
	ret = mbedcrypto_cipher_final(&cctx, pt, 64, out, &olen);
	CHECK(ret == 0 && olen == 64 && memcmp(out, ct, 64) == 0, EBADMSG);
	mbedcrypto_cipher_cleanup(&cctx);

	/* Decrypt (CTR is symmetric) */
	mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTR, key128, 128, 0);
	mbedcrypto_cipher_set_iv(&cctx, nonce_save, 16);
	ret = mbedcrypto_cipher_final(&cctx, ct, 64, dec, &olen);
	CHECK(ret == 0 && olen == 64 && memcmp(dec, pt, 64) == 0, EBADMSG);
	mbedcrypto_cipher_cleanup(&cctx);

	/* Streaming: encrypt 1 byte at a time via multi-update */
	mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTR, key128, 128, 0);
	mbedcrypto_cipher_set_iv(&cctx, nonce_save, 16);
	for (i = 0; i < 64; i++) {
		size_t ulen;
		mbedcrypto_cipher_update(&cctx, pt + i, 1, out + i, &ulen);
	}
	size_t flen;
	mbedcrypto_cipher_final(&cctx, NULL, 0, NULL, &flen);
	CHECK(memcmp(out, ct, 64) == 0, EBADMSG);
	mbedcrypto_cipher_cleanup(&cctx);

	/* Unaligned sizes: roundtrip for representative sizes */
	int ctr_lens[] = {1, 15, 16, 17, 64};
	for (si = 0; si < 5; si++) {
		int sz = ctr_lens[si];
		uint8_t enc[64], dec2[64];
		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTR, key128, 128, 0);
		mbedcrypto_cipher_set_iv(&cctx, nonce_save, 16);
		mbedcrypto_cipher_final(&cctx, pt, sz, enc, &olen);
		mbedcrypto_cipher_cleanup(&cctx);

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTR, key128, 128, 0);
		mbedcrypto_cipher_set_iv(&cctx, nonce_save, 16);
		mbedcrypto_cipher_final(&cctx, enc, sz, dec2, &olen);
		CHECK(memcmp(dec2, pt, sz) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);
	}

	/* In-place CTR encrypt + decrypt */
	uint8_t buf[64];
	memcpy(buf, pt, 64);
	mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTR, key128, 128, 0);
	mbedcrypto_cipher_set_iv(&cctx, nonce_save, 16);
	mbedcrypto_cipher_final(&cctx, buf, 64, buf, &olen);
	CHECK(memcmp(buf, ct, 64) == 0, EBADMSG);
	mbedcrypto_cipher_cleanup(&cctx);

	mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTR, key128, 128, 0);
	mbedcrypto_cipher_set_iv(&cctx, nonce_save, 16);
	mbedcrypto_cipher_final(&cctx, buf, 64, buf, &olen);
	CHECK(memcmp(buf, pt, 64) == 0, EBADMSG);
	mbedcrypto_cipher_cleanup(&cctx);

	/* NIST SP 800-38A F.5.3 AES-192 CTR KAT */
	uint8_t key192[24];
	hex2bin("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", key192, 24);
	{
		uint8_t ct192[64], enc192[64], dec192[64];
		hex2bin("1abc932417521ca24f2b0459fe7e6e0b"
			"090339ec0aa6faefd5ccc2c6f4ce8e94"
			"1e36b26bd1ebc670d1bd1d665620abf7"
			"4f78a7f6d29809585a97daec58c6b050", ct192, 64);

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTR, key192, 192, 0);
		mbedcrypto_cipher_set_iv(&cctx, nonce_save, 16);
		mbedcrypto_cipher_final(&cctx, pt, 64, enc192, &olen);
		CHECK(olen == 64 && memcmp(enc192, ct192, 64) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTR, key192, 192, 0);
		mbedcrypto_cipher_set_iv(&cctx, nonce_save, 16);
		mbedcrypto_cipher_final(&cctx, ct192, 64, dec192, &olen);
		CHECK(olen == 64 && memcmp(dec192, pt, 64) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);
	}

	/* NIST SP 800-38A F.5.5 AES-256 CTR KAT */
	uint8_t key256[32];
	hex2bin("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key256, 32);
	{
		uint8_t ct256[64], enc256[64], dec256[64];
		hex2bin("601ec313775789a5b7a7f504bbf3d228"
			"f443e3ca4d62b59aca84e990cacaf5c5"
			"2b0930daa23de94ce87017ba2d84988d"
			"dfc9c58db67aada613c2dd08457941a6", ct256, 64);

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTR, key256, 256, 0);
		mbedcrypto_cipher_set_iv(&cctx, nonce_save, 16);
		mbedcrypto_cipher_final(&cctx, pt, 64, enc256, &olen);
		CHECK(olen == 64 && memcmp(enc256, ct256, 64) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTR, key256, 256, 0);
		mbedcrypto_cipher_set_iv(&cctx, nonce_save, 16);
		mbedcrypto_cipher_final(&cctx, ct256, 64, dec256, &olen);
		CHECK(olen == 64 && memcmp(dec256, pt, 64) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);
	}

out:
	TEST_END();
}

static void test_aes_cts(void)
{
	TEST_START("AES-CTS");
	struct mbedcrypto_cipher_ctx cctx;

	uint8_t key128[16], key192[24], key256[32];
	size_t bi = 0, cs = 0, ds = 0, fi = 0, i = 0, k = 0, off = 0, t = 0;
	hex2bin("2b7e151628aed2a6abf7158809cf4f3c", key128, 16);
	hex2bin("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", key192, 24);
	hex2bin("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key256, 32);

	/*
	 * CBC-CS3 reference vectors for AES-128.
	 * Derived from OpenSSL aes-128-cbc-cts (CS1 default) by swapping
	 * the last two ciphertext chunks to CS3 order.
	 * Key=2b7e151628aed2a6abf7158809cf4f3c, IV=0, PT=00 01 02 ... (len-1).
	 */
	static const struct { int len; const char *ct; } ref128[] = {
		{17, "d64f87afe27f42c6d5dfd6d6b1847e6450"},
		{20, "5e0505c938958a64620b0ce8a9a6f9a750fe67cc"},
		{31, "09112944295a353f0cf6e09bc06c9eb750fe67cc996d32b6da0937e99bafec"},
		{32, "359e6e3515b4f10112306f7aef739f4550fe67cc996d32b6da0937e99bafec60"},
		{33, "50fe67cc996d32b6da0937e99bafec6016b0e3d6c4ebe5ebf3680d928fbb8a2b35"},
		{48, "50fe67cc996d32b6da0937e99bafec60e9c278b0a8218eb950313481264fb986359e6e3515b4f10112306f7aef739f45"},
		{63, "50fe67cc996d32b6da0937e99bafec60359e6e3515b4f10112306f7aef739f45aa842ad239cb98190a0570c220acd96de9c278b0a8218eb950313481264fb9"},
		{64, "50fe67cc996d32b6da0937e99bafec60359e6e3515b4f10112306f7aef739f45ad1f720ba5095c31bf5cd8df1e3e7176e9c278b0a8218eb950313481264fb986"},
	};

	/* 1. AES-128 reference vector verification */
	for (t = 0; t < sizeof(ref128)/sizeof(ref128[0]); t++) {
		size_t len = ref128[t].len;
		uint8_t pt[64], ct[64], dec[64], iv[16];
		memset(iv, 0, sizeof(iv));
		size_t olen;

		for (i = 0; i < len; i++)
			pt[i] = i;

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTS, key128, 128, 0);
		mbedcrypto_cipher_set_iv(&cctx, iv, 16);
		int ret = mbedcrypto_cipher_final(&cctx, pt, len, ct, &olen);
		CHECK(ret == 0 && olen == len && hexcmp(ct, ref128[t].ct, len) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);

		memset(iv, 0, 16);
		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTS, key128, 128, 1);
		mbedcrypto_cipher_set_iv(&cctx, iv, 16);
		ret = mbedcrypto_cipher_final(&cctx, ct, len, dec, &olen);
		CHECK(ret == 0 && olen == len && memcmp(dec, pt, len) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);
	}

	/* 2. All key sizes roundtrip tested via sections 5-7 (inplace/multi-update) */
	struct { uint8_t *key; int keybits; const char *label; } keys[] = {
		{ key128, 128, "aes128" },
		{ key192, 192, "aes192" },
		{ key256, 256, "aes256" },
	};

	/* 3. Multi-update patterns: byte-by-byte and 13-byte chunks */
	{
		size_t test_lens[] = { 17, 33, 64 };
		for (t = 0; t < 3; t++) {
			size_t len = test_lens[t];
			/* find matching ref128 entry */
			int ri = -1;
			size_t r = 0;

			for (r = 0; r < sizeof(ref128)/sizeof(ref128[0]); r++) {
				if (ref128[r].len == len) {
					ri = r;
					break;
				}
			}
			if (ri < 0)
				continue;
			uint8_t pt[64], ct_ref[64], ct[64], dec[64], iv[16];
			memset(iv, 0, sizeof(iv));
			size_t olen, total;
			int ret = 0;

			for (i = 0; i < len; i++)
				pt[i] = i;
			hex2bin(ref128[ri].ct, ct_ref, len);

			/* Pattern A: byte-by-byte update + final(0) - encrypt */
			mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTS, key128, 128, 0);
			mbedcrypto_cipher_set_iv(&cctx, iv, 16);
			total = 0; ret = 0;
			for (i = 0; i < len && ret == 0; i++) {
				ret = mbedcrypto_cipher_update(&cctx, pt + i, 1, ct + total, &olen);
				total += olen;
			}
			if (ret == 0)
				ret = mbedcrypto_cipher_final(&cctx, NULL, 0, ct + total, &olen);
			total += olen;
			CHECK(ret == 0 && total == len && memcmp(ct, ct_ref, len) == 0, EBADMSG);
			mbedcrypto_cipher_cleanup(&cctx);

			/* Pattern A: byte-by-byte decrypt */
			memset(iv, 0, 16);
			mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTS, key128, 128, 1);
			mbedcrypto_cipher_set_iv(&cctx, iv, 16);
			total = 0; ret = 0;
			for (i = 0; i < len && ret == 0; i++) {
				ret = mbedcrypto_cipher_update(&cctx, ct_ref + i, 1, dec + total, &olen);
				total += olen;
			}
			if (ret == 0)
				ret = mbedcrypto_cipher_final(&cctx, NULL, 0, dec + total, &olen);
			total += olen;
			CHECK(ret == 0 && total == len && memcmp(dec, pt, len) == 0, EBADMSG);
			mbedcrypto_cipher_cleanup(&cctx);

			/* Pattern B: 13-byte chunks - encrypt */
			memset(iv, 0, 16);
			mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTS, key128, 128, 0);
			mbedcrypto_cipher_set_iv(&cctx, iv, 16);
			total = 0; ret = 0;
			for (off = 0; off < len && ret == 0; off += 13) {
				size_t chunk = (off + 13 <= len) ? 13 : (len - off);
				ret = mbedcrypto_cipher_update(&cctx, pt + off, chunk,
						ct + total, &olen);
				total += olen;
			}
			if (ret == 0)
				ret = mbedcrypto_cipher_final(&cctx, NULL, 0,
					ct + total, &olen);
			total += olen;
			CHECK(ret == 0 && total == len && memcmp(ct, ct_ref, len) == 0, EBADMSG);
			mbedcrypto_cipher_cleanup(&cctx);
		}
	}

	/* 4. Non-zero IV roundtrip */
	{
		uint8_t pt[48], ct[48], dec[48];
		uint8_t iv_val[16];
		size_t olen;

		hex2bin("deadbeefcafebabe0011223344556677", iv_val, 16);
		for (i = 0; i < 48; i++)
			pt[i] = i ^ 0xa5;

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTS, key256, 256, 0);
		mbedcrypto_cipher_set_iv(&cctx, iv_val, 16);
		mbedcrypto_cipher_final(&cctx, pt, 48, ct, &olen);
		mbedcrypto_cipher_cleanup(&cctx);

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTS, key256, 256, 1);
		mbedcrypto_cipher_set_iv(&cctx, iv_val, 16);
		mbedcrypto_cipher_final(&cctx, ct, 48, dec, &olen);
		CHECK(memcmp(dec, pt, 48) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);
	}

	/* 5. In-place encrypt/decrypt roundtrip */
	for (k = 0; k < sizeof(keys)/sizeof(keys[0]); k++) {
		size_t inplace_lens[] = { 17, 48, 64 };
		for (t = 0; t < sizeof(inplace_lens)/sizeof(inplace_lens[0]); t++) {
			size_t len = inplace_lens[t];
			uint8_t buf[64], pt_save[64], iv[16];
			memset(iv, 0, sizeof(iv));
			size_t olen;

			for (i = 0; i < len; i++)
				buf[i] = pt_save[i] = i + 0x10;

			mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTS,
					keys[k].key, keys[k].keybits, 0);
			mbedcrypto_cipher_set_iv(&cctx, iv, 16);
			mbedcrypto_cipher_final(&cctx, buf, len, buf, &olen);
			mbedcrypto_cipher_cleanup(&cctx);

			memset(iv, 0, 16);
			mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CTS,
					keys[k].key, keys[k].keybits, 1);
			mbedcrypto_cipher_set_iv(&cctx, iv, 16);
			mbedcrypto_cipher_final(&cctx, buf, len, buf, &olen);
			CHECK(memcmp(buf, pt_save, len) == 0, EBADMSG);
			mbedcrypto_cipher_cleanup(&cctx);
		}
	}

	/* 6. Large-data multi-call in-place roundtrip */
	{
		/*
		 * This test exercises the in-place overlap fix in
		 * cipher_cts_buffered: partial blocks from a prior
		 * update must not corrupt subsequent input.
		 */
		static uint8_t bigbuf[16384];
		static uint8_t pt_ref[16384];
		static uint8_t ct_ref[16384];
		size_t data_sizes[] = { 1024, 16384 };
		size_t chunk_sizes[] = { 17, 1024 };
		uint8_t iv[16];
		size_t olen;

		memset(iv, 0, sizeof(iv));
		for (ds = 0; ds < sizeof(data_sizes)/sizeof(data_sizes[0]); ds++) {
			size_t dlen = data_sizes[ds];

			/* Generate deterministic plaintext */
			for (i = 0; i < dlen; i++)
				pt_ref[i] = i * 37 + 17;

			/* Reference: one-shot encrypt */
			memcpy(bigbuf, pt_ref, dlen);
			memset(iv, 0, 16);
			cipher_multi(MBEDCRYPTO_CIPHER_AES_CTS, key256, 256, 0,
				iv, 16, bigbuf, dlen, ct_ref, &olen, 0);

			for (cs = 0; cs < sizeof(chunk_sizes)/sizeof(chunk_sizes[0]); cs++) {
				size_t chunk = chunk_sizes[cs];
				if (chunk > dlen)
					continue;

				/* Multi-call in-place encrypt */
				memcpy(bigbuf, pt_ref, dlen);
				memset(iv, 0, 16);
				CHECK(cipher_multi(MBEDCRYPTO_CIPHER_AES_CTS,
					key256, 256, 0, iv, 16,
					bigbuf, dlen, bigbuf, &olen, chunk) == 0
					&& olen == dlen
					&& memcmp(bigbuf, ct_ref, dlen) == 0, EBADMSG);

				/* Multi-call in-place decrypt */
				memcpy(bigbuf, ct_ref, dlen);
				memset(iv, 0, 16);
				CHECK(cipher_multi(MBEDCRYPTO_CIPHER_AES_CTS,
					key256, 256, 1, iv, 16,
					bigbuf, dlen, bigbuf, &olen, chunk) == 0
					&& olen == dlen
					&& memcmp(bigbuf, pt_ref, dlen) == 0, EBADMSG);
			}
		}
	}

	/*
	 * Test: auth_ta fixed-buffer inplace pattern.
	 *
	 * auth_ta reads chunks into a fixed buffer, calls CipherUpdate
	 * with the SAME buffer for both input and output (in == out),
	 * then reads the NEXT chunk into the SAME buffer. This means
	 * each call has in == out == buf with partial_len > 0 from the
	 * previous call, triggering the in-place overlap path.
	 *
	 * cipher_multi doesn't catch this because it advances both
	 * the input pointer (in + off) and output pointer (out + total)
	 * independently, so the output ends up BEHIND input and the
	 * overlap condition is never true.
	 */
	{
		static uint8_t pt_ref[32768];
		static uint8_t ct_buf[32768];
		static uint8_t dc_buf[32768];
		static uint8_t fbuf[8192 + 32]; /* +32 for CTS partial flush */
		uint8_t iv[16];
		size_t file_sizes[] = {8193, 32768};
		size_t buf_sizes[] = {4096};

		for (fi = 0;
		     fi < sizeof(file_sizes)/sizeof(file_sizes[0]); fi++) {
			size_t fsize = file_sizes[fi];

			for (i = 0; i < fsize; i++)
				pt_ref[i] = i * 137 + 42;

		  for (bi = 0;
		       bi < sizeof(buf_sizes)/sizeof(buf_sizes[0]); bi++) {
			size_t bsz = buf_sizes[bi];
			struct mbedcrypto_cipher_ctx ectx, dctx;
			size_t pos, opos, rd, olen;

			/* Encrypt: fixed-buffer inplace */
			memset(iv, 0, 16);
			mbedcrypto_cipher_init(&ectx,
				MBEDCRYPTO_CIPHER_AES_CTS,
				key128, 128, 0);
			mbedcrypto_cipher_set_iv(&ectx, iv, 16);
			pos = 0; opos = 0;
			while (pos < fsize) {
				rd = (fsize - pos < bsz) ?
					(fsize - pos) : bsz;
				memcpy(fbuf, pt_ref + pos, rd);
				pos += rd;
				if (pos < fsize)
					mbedcrypto_cipher_update(&ectx,
						fbuf, rd, fbuf, &olen);
				else
					mbedcrypto_cipher_final(&ectx,
						fbuf, rd, fbuf, &olen);
				memcpy(ct_buf + opos, fbuf, olen);
				opos += olen;
			}
			mbedcrypto_cipher_cleanup(&ectx);
			CHECK(opos == fsize, EBADMSG);

			/* Decrypt: fixed-buffer inplace */
			memset(iv, 0, 16);
			mbedcrypto_cipher_init(&dctx,
				MBEDCRYPTO_CIPHER_AES_CTS,
				key128, 128, 1);
			mbedcrypto_cipher_set_iv(&dctx, iv, 16);
			pos = 0; opos = 0;
			while (pos < fsize) {
				rd = (fsize - pos < bsz) ?
					(fsize - pos) : bsz;
				memcpy(fbuf, ct_buf + pos, rd);
				pos += rd;
				if (pos < fsize)
					mbedcrypto_cipher_update(&dctx,
						fbuf, rd, fbuf, &olen);
				else
					mbedcrypto_cipher_final(&dctx,
						fbuf, rd, fbuf, &olen);
				memcpy(dc_buf + opos, fbuf, olen);
				opos += olen;
			}
			mbedcrypto_cipher_cleanup(&dctx);
			CHECK(opos == fsize, EBADMSG);
			CHECK(memcmp(dc_buf, pt_ref, fsize) == 0, EBADMSG);
		  }
		}
	}

out:
	TEST_END();
}

static void test_aes_xts(void)
{
	TEST_START("AES-XTS");
	struct mbedcrypto_aes_xts_ctx xctx;

	/* IEEE 1619 XTS-AES-128 test vector */
	uint8_t key[32]; /* XTS uses double-size key */
	size_t cs = 0, ds = 0, i = 0, t = 0;
	hex2bin("0000000000000000000000000000000000000000000000000000000000000000", key, 32);
	uint8_t tweak[16];
	hex2bin("00000000000000000000000000000000", tweak, 16);
	uint8_t pt[32], ct_exp[32];
	hex2bin("0000000000000000000000000000000000000000000000000000000000000000", pt, 32);
	hex2bin("917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e", ct_exp, 32);

	uint8_t ct_buf[32], dec_buf[32], tweak_save[16];
	size_t olen;

	/*
	 * Raw XTS API expects the tweak to be PRE-ENCRYPTED.
	 * The dispatch layer does this in cipher_set_iv:
	 *   aes_ecb_crypt(&ctx->xts.tweak, iv, ctx->iv)
	 * For the raw API we must do it ourselves.
	 */
	memcpy(tweak_save, tweak, 16);
	mbedcrypto_aes_xts_setkey(&xctx, key, 256, MBEDCRYPTO_AES_ENCRYPT);
	/* Pre-encrypt the tweak */
	uint8_t enc_tweak[16];
	mbedcrypto_aes_ecb_crypt(&xctx.tweak, tweak, enc_tweak);
	mbedcrypto_aes_xts_crypt(&xctx, enc_tweak, pt, 32, ct_buf, &olen);
	CHECK(memcmp(ct_buf, ct_exp, 32) == 0, EBADMSG);
	mbedcrypto_aes_xts_cleanup(&xctx);

	memcpy(tweak, tweak_save, 16);
	mbedcrypto_aes_xts_setkey(&xctx, key, 256, MBEDCRYPTO_AES_DECRYPT);
	mbedcrypto_aes_ecb_crypt(&xctx.tweak, tweak, enc_tweak);
	mbedcrypto_aes_xts_crypt(&xctx, enc_tweak, ct_buf, 32, dec_buf, &olen);
	CHECK(memcmp(dec_buf, pt, 32) == 0, EBADMSG);
	mbedcrypto_aes_xts_cleanup(&xctx);

	/* XTS-AES-256 roundtrip with various lengths */
	uint8_t key512[64]; /* 256*2 bits */
	test_rng(NULL, key512, 64);
	size_t xts_lens[] = { 16, 17, 32, 64 };
	for (t = 0; t < sizeof(xts_lens)/sizeof(xts_lens[0]); t++) {
		size_t len = xts_lens[t];
		uint8_t ptx[64], ctx_buf[64], decx[64], tw[16];
		size_t ol;
		for (i = 0; i < len; i++)
			ptx[i] = i * 3 + t;
		memset(tw, 0, 16); tw[0] = t;

		uint8_t tw_save[16], etw[16];
		memcpy(tw_save, tw, 16);
		mbedcrypto_aes_xts_setkey(&xctx, key512, 512, MBEDCRYPTO_AES_ENCRYPT);
		mbedcrypto_aes_ecb_crypt(&xctx.tweak, tw, etw);
		mbedcrypto_aes_xts_crypt(&xctx, etw, ptx, len, ctx_buf, &ol);
		mbedcrypto_aes_xts_cleanup(&xctx);

		memcpy(tw, tw_save, 16);
		mbedcrypto_aes_xts_setkey(&xctx, key512, 512, MBEDCRYPTO_AES_DECRYPT);
		mbedcrypto_aes_ecb_crypt(&xctx.tweak, tw, etw);
		mbedcrypto_aes_xts_crypt(&xctx, etw, ctx_buf, len, decx, &ol);
		CHECK(memcmp(decx, ptx, len) == 0, EBADMSG);
		mbedcrypto_aes_xts_cleanup(&xctx);
	}

	/* XTS via dispatch layer: multi-update + in-place */
	{
		uint8_t xkey[32];
		test_rng(NULL, xkey, 32);
		uint8_t twk[16] = {0x01};
		size_t xts_dlens[] = { 16, 17, 32, 64 };
		size_t ol;

		for (t = 0; t < sizeof(xts_dlens)/sizeof(xts_dlens[0]); t++) {
			size_t len = xts_dlens[t];
			uint8_t ptx[64], cref[64], buf[64];
			for (i = 0; i < len; i++)
				ptx[i] = i + t;

			/* one-shot reference */
			cipher_multi(MBEDCRYPTO_CIPHER_AES_XTS, xkey, 256, 0,
					twk, 16, ptx, len, cref, &ol, 0);

			/* one-shot decrypt verify */
			CHECK(cipher_multi(MBEDCRYPTO_CIPHER_AES_XTS, xkey, 256, 1,
					twk, 16, cref, len, buf, &ol, 0) == 0
					&& ol == len && memcmp(buf, ptx, len) == 0, EBADMSG);

			/* in-place byte-by-byte enc+dec */
			memcpy(buf, ptx, len);
			CHECK(cipher_multi(MBEDCRYPTO_CIPHER_AES_XTS, xkey, 256, 0,
					twk, 16, buf, len, buf, &ol, 1) == 0
					&& ol == len && memcmp(buf, cref, len) == 0, EBADMSG);
			CHECK(cipher_multi(MBEDCRYPTO_CIPHER_AES_XTS, xkey, 256, 1,
					twk, 16, buf, len, buf, &ol, 1) == 0
					&& ol == len && memcmp(buf, ptx, len) == 0, EBADMSG);
		}
	}

	/* 5. Large-data multi-call in-place XTS roundtrip */
	{
		static uint8_t bigbuf[16384], pt_ref[16384], ct_ref[16384];
		uint8_t xk[32], tw[16];
		size_t olen;

		hex2bin("0123456789abcdef0123456789abcdef"
			"fedcba9876543210fedcba9876543210", xk, 32);
		hex2bin("00112233445566778899aabbccddeeff", tw, 16);

		size_t data_sizes[] = { 1024, 16384 };
		size_t chunk_sizes[] = { 17, 1024 };

		for (ds = 0; ds < sizeof(data_sizes)/sizeof(data_sizes[0]); ds++) {
			size_t dlen = data_sizes[ds];

			for (i = 0; i < dlen; i++)
				pt_ref[i] = i * 41 + 11;

			/* Reference one-shot */
			cipher_multi(MBEDCRYPTO_CIPHER_AES_XTS, xk, 256, 0,
				tw, 16, pt_ref, dlen, ct_ref, &olen, 0);

			for (cs = 0; cs < sizeof(chunk_sizes)/sizeof(chunk_sizes[0]); cs++) {
				size_t chunk = chunk_sizes[cs];
				if (chunk > dlen)
					continue;

				memcpy(bigbuf, pt_ref, dlen);
				CHECK(cipher_multi(MBEDCRYPTO_CIPHER_AES_XTS,
					xk, 256, 0, tw, 16,
					bigbuf, dlen, bigbuf, &olen, chunk) == 0
					&& olen == dlen
					&& memcmp(bigbuf, ct_ref, dlen) == 0, EBADMSG);

				memcpy(bigbuf, ct_ref, dlen);
				CHECK(cipher_multi(MBEDCRYPTO_CIPHER_AES_XTS,
					xk, 256, 1, tw, 16,
					bigbuf, dlen, bigbuf, &olen, chunk) == 0
					&& olen == dlen
					&& memcmp(bigbuf, pt_ref, dlen) == 0, EBADMSG);
			}
		}
	}

out:
	TEST_END();
}

static void test_des(void)
{
	TEST_START("DES/3DES");
	struct mbedcrypto_des_ctx dctx;
	struct mbedcrypto_des3_ctx d3ctx;
	uint8_t out[8], dec[8];

	/* DES ECB - NIST test */
	uint8_t dkey[8], dpt[8], dct[8];
	size_t i = 0, t = 0;
	hex2bin("0123456789abcdef", dkey, 8);
	hex2bin("4e6f772069732074", dpt, 8);
	hex2bin("3fa40e8a984d4815", dct, 8);

	mbedcrypto_des_init(&dctx);
	mbedcrypto_des_setkey(&dctx, dkey, MBEDCRYPTO_DES_ENCRYPT);
	mbedcrypto_des_ecb_crypt(&dctx, dpt, out);
	CHECK(memcmp(out, dct, 8) == 0, EBADMSG);
	mbedcrypto_des_cleanup(&dctx);

	mbedcrypto_des_init(&dctx);
	mbedcrypto_des_setkey(&dctx, dkey, MBEDCRYPTO_DES_DECRYPT);
	mbedcrypto_des_ecb_crypt(&dctx, dct, dec);
	CHECK(memcmp(dec, dpt, 8) == 0, EBADMSG);
	mbedcrypto_des_cleanup(&dctx);

	/* DES CBC KAT (key=0123456789abcdef, iv=0, pt=00..17) */
	{
		struct mbedcrypto_cipher_ctx cctx;
		uint8_t iv[8];
		uint8_t cbcpt[24], cbcct[24], cbcenc[24], cbcdec[24];
		size_t olen;

		memset(iv, 0, sizeof(iv));
		for (i = 0; i < 24; i++)
			cbcpt[i] = i;
		hex2bin("3260266c2cf202e279cf70cd1dac09a5"
			"b218e9ca8b9251f2", cbcct, 24);

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_DES_CBC, dkey, 64, 0);
		mbedcrypto_cipher_set_iv(&cctx, iv, 8);
		mbedcrypto_cipher_final(&cctx, cbcpt, 24, cbcenc, &olen);
		CHECK(olen == 24 && memcmp(cbcenc, cbcct, 24) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);

		memset(iv, 0, 8);
		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_DES_CBC, dkey, 64, 1);
		mbedcrypto_cipher_set_iv(&cctx, iv, 8);
		mbedcrypto_cipher_final(&cctx, cbcct, 24, cbcdec, &olen);
		CHECK(olen == 24 && memcmp(cbcdec, cbcpt, 24) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);

		/* DES CBC in-place */
		uint8_t buf[24];
		memcpy(buf, cbcpt, 24);
		memset(iv, 0, 8);
		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_DES_CBC, dkey, 64, 0);
		mbedcrypto_cipher_set_iv(&cctx, iv, 8);
		mbedcrypto_cipher_final(&cctx, buf, 24, buf, &olen);
		CHECK(memcmp(buf, cbcct, 24) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);

		/* DES CBC multi-update */
		uint8_t mu_out[24];
		memset(iv, 0, 8);
		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_DES_CBC, dkey, 64, 0);
		mbedcrypto_cipher_set_iv(&cctx, iv, 8);
		size_t total = 0;
		for (i = 0; i < 3; i++) {
			size_t ulen;
			mbedcrypto_cipher_update(&cctx, cbcpt + i * 8, 8, mu_out + total, &ulen);
			total += ulen;
		}
		size_t flen;
		mbedcrypto_cipher_final(&cctx, NULL, 0, mu_out + total, &flen);
		total += flen;
		CHECK(total == 24 && memcmp(mu_out, cbcct, 24) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);
	}

	/* 3DES ECB KAT (key=0123456789abcdef23456789abcdef014567890123456789) */
	uint8_t d3key[24];
	hex2bin("0123456789abcdef23456789abcdef014567890123456789", d3key, 24);

	mbedcrypto_des3_init(&d3ctx);
	mbedcrypto_des3_setkey(&d3ctx, d3key, MBEDCRYPTO_DES_ENCRYPT);
	mbedcrypto_des3_ecb_crypt(&d3ctx, dpt, out);
	CHECK(hexcmp(out, "f4d189bcd6957791", 8) == 0, EBADMSG);
	mbedcrypto_des3_cleanup(&d3ctx);

	mbedcrypto_des3_init(&d3ctx);
	mbedcrypto_des3_setkey(&d3ctx, d3key, MBEDCRYPTO_DES_DECRYPT);
	mbedcrypto_des3_ecb_crypt(&d3ctx, out, dec);
	CHECK(memcmp(dec, dpt, 8) == 0, EBADMSG);
	mbedcrypto_des3_cleanup(&d3ctx);

	/* 3DES CBC KAT (iv=0, pt=i^0xa5 for i=0..31) */
	{
		struct mbedcrypto_cipher_ctx cctx;
		uint8_t iv[8];
		uint8_t cbcpt[32], cbcct_exp[32], cbcenc[32], cbcdec[32];
		size_t olen;

		memset(iv, 0, sizeof(iv));
		for (i = 0; i < 32; i++)
			cbcpt[i] = i ^ 0xa5;
		hex2bin("5bb4073384aa7a13c2774bb3fe165bea"
			"f8f836a73aa8928e1a9883da5dd43959", cbcct_exp, 32);

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_DES3_CBC, d3key, 192, 0);
		mbedcrypto_cipher_set_iv(&cctx, iv, 8);
		mbedcrypto_cipher_final(&cctx, cbcpt, 32, cbcenc, &olen);
		CHECK(olen == 32 && memcmp(cbcenc, cbcct_exp, 32) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);

		memset(iv, 0, 8);
		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_DES3_CBC, d3key, 192, 1);
		mbedcrypto_cipher_set_iv(&cctx, iv, 8);
		mbedcrypto_cipher_final(&cctx, cbcct_exp, 32, cbcdec, &olen);
		CHECK(olen == 32 && memcmp(cbcdec, cbcpt, 32) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);

		/* 3DES CBC in-place */
		uint8_t buf[32];
		memcpy(buf, cbcpt, 32);
		memset(iv, 0, 8);
		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_DES3_CBC, d3key, 192, 0);
		mbedcrypto_cipher_set_iv(&cctx, iv, 8);
		mbedcrypto_cipher_final(&cctx, buf, 32, buf, &olen);
		CHECK(memcmp(buf, cbcct_exp, 32) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);
	}

	/* 3DES CTS multi-update + in-place (includes one-shot reference) */
	{
		uint8_t iv0[8];
		uint8_t ctspt3[32], ct_r3[32], buf_d[32];
		size_t ol;
		size_t cts3_lens[] = { 9, 12, 15, 16, 20, 24, 32 };

		memset(iv0, 0, sizeof(iv0));
		for (t = 0; t < sizeof(cts3_lens)/sizeof(cts3_lens[0]); t++) {
			size_t len = cts3_lens[t];
			for (i = 0; i < len; i++)
				ctspt3[i] = i + 0x30;

			/* reference encrypt */
			cipher_multi(MBEDCRYPTO_CIPHER_DES3_CTS, d3key, 192, 0,
					iv0, 8, ctspt3, len, ct_r3, &ol, 0);

			/* in-place byte-by-byte enc+dec */
			memcpy(buf_d, ctspt3, len);
			CHECK(cipher_multi(MBEDCRYPTO_CIPHER_DES3_CTS, d3key, 192, 0,
					iv0, 8, buf_d, len, buf_d, &ol, 1) == 0
					&& ol == len && memcmp(buf_d, ct_r3, len) == 0, EBADMSG);
			CHECK(cipher_multi(MBEDCRYPTO_CIPHER_DES3_CTS, d3key, 192, 1,
					iv0, 8, buf_d, len, buf_d, &ol, 1) == 0
					&& ol == len && memcmp(buf_d, ctspt3, len) == 0, EBADMSG);

			/* 3-byte chunks non-inplace */
			CHECK(cipher_multi(MBEDCRYPTO_CIPHER_DES3_CTS, d3key, 192, 0,
					iv0, 8, ctspt3, len, buf_d, &ol, 3) == 0
					&& ol == len && memcmp(buf_d, ct_r3, len) == 0, EBADMSG);
			CHECK(cipher_multi(MBEDCRYPTO_CIPHER_DES3_CTS, d3key, 192, 1,
					iv0, 8, ct_r3, len, buf_d, &ol, 3) == 0
					&& ol == len && memcmp(buf_d, ctspt3, len) == 0, EBADMSG);

			/* in-place 1blk(8)+final enc+dec */
			memcpy(buf_d, ctspt3, len);
			CHECK(cipher_split(MBEDCRYPTO_CIPHER_DES3_CTS, d3key, 192, 0,
					iv0, 8, buf_d, len, buf_d, &ol, 8) == 0
					&& ol == len && memcmp(buf_d, ct_r3, len) == 0, EBADMSG);
			CHECK(cipher_split(MBEDCRYPTO_CIPHER_DES3_CTS, d3key, 192, 1,
					iv0, 8, buf_d, len, buf_d, &ol, 8) == 0
					&& ol == len && memcmp(buf_d, ctspt3, len) == 0, EBADMSG);
		}
	}

out:
	TEST_END();
}

static void test_sm4(void)
{
	TEST_START("SM4");
	struct mbedcrypto_sm4_ctx ctx;
	uint8_t out[16], dec[16];
	uint8_t key[16], pt[16], ct_exp[16];
	size_t i = 0, t = 0;

	/* GB/T 32907-2016 - SM4 ECB */
	hex2bin("0123456789abcdeffedcba9876543210", key, 16);
	hex2bin("0123456789abcdeffedcba9876543210", pt, 16);
	hex2bin("681edf34d206965e86b3e94f536e4246", ct_exp, 16);

	mbedcrypto_sm4_setkey(&ctx, key, MBEDCRYPTO_SM4_ENCRYPT);
	mbedcrypto_sm4_ecb_crypt(&ctx, pt, out);
	CHECK(memcmp(out, ct_exp, 16) == 0, EBADMSG);
	mbedcrypto_sm4_cleanup(&ctx);

	mbedcrypto_sm4_setkey(&ctx, key, MBEDCRYPTO_SM4_DECRYPT);
	mbedcrypto_sm4_ecb_crypt(&ctx, ct_exp, dec);
	CHECK(memcmp(dec, pt, 16) == 0, EBADMSG);
	mbedcrypto_sm4_cleanup(&ctx);

	/* SM4 CBC KAT (key=0123..3210, iv=0, pt=i^0x5a) */
	{
		struct mbedcrypto_cipher_ctx cctx;
		uint8_t iv[16];
		size_t olen;
		uint8_t cbcpt[64], cbcct_exp[64], cbcenc[64], cbcdec[64];

		memset(iv, 0, sizeof(iv));
		for (i = 0; i < 64; i++)
			cbcpt[i] = i ^ 0x5a;
		hex2bin("1534bfcf6c21cfc0376ed10c5c4ea7e2"
			"6987c240606479a3be4f00b68eaa4bb8"
			"f2af53e485eed285a6dd28712d9bb7b4"
			"2fdc30be57d9bbb12e4e67a04e0bd175", cbcct_exp, 64);

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_SM4_CBC, key, 128, 0);
		mbedcrypto_cipher_set_iv(&cctx, iv, 16);
		mbedcrypto_cipher_final(&cctx, cbcpt, 64, cbcenc, &olen);
		CHECK(olen == 64 && memcmp(cbcenc, cbcct_exp, 64) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);

		memset(iv, 0, 16);
		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_SM4_CBC, key, 128, 1);
		mbedcrypto_cipher_set_iv(&cctx, iv, 16);
		mbedcrypto_cipher_final(&cctx, cbcct_exp, 64, cbcdec, &olen);
		CHECK(olen == 64 && memcmp(cbcdec, cbcpt, 64) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);

		/* SM4 CBC in-place */
		{
			uint8_t buf[64];
			memcpy(buf, cbcpt, 64);
			memset(iv, 0, 16);
			mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_SM4_CBC, key, 128, 0);
			mbedcrypto_cipher_set_iv(&cctx, iv, 16);
			mbedcrypto_cipher_final(&cctx, buf, 64, buf, &olen);
			CHECK(memcmp(buf, cbcct_exp, 64) == 0, EBADMSG);
			mbedcrypto_cipher_cleanup(&cctx);
		}
	}

	/* SM4 CTR KAT (key=0123..3210, nonce=00..01, pt=0..3f) */
	{
		struct mbedcrypto_cipher_ctx cctx;
		uint8_t nonce[16];
		memset(nonce, 0, 16); nonce[15] = 1;
		size_t olen;
		uint8_t ctrpt[64], ctrct_exp[64], ctrenc[64], ctrdec[64];
		for (i = 0; i < 64; i++)
			ctrpt[i] = i;
		hex2bin("4e5859f33b26bb173a92a55d94e596e3"
			"a3027e175a805e3a577c3472533a5fd2"
			"81043076af2bc175b3d48d3e1cec6ece"
			"aa142997c8f1127aa4f58a31443aaa05", ctrct_exp, 64);

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_SM4_CTR, key, 128, 0);
		mbedcrypto_cipher_set_iv(&cctx, nonce, 16);
		mbedcrypto_cipher_final(&cctx, ctrpt, 64, ctrenc, &olen);
		CHECK(olen == 64 && memcmp(ctrenc, ctrct_exp, 64) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_SM4_CTR, key, 128, 0);
		mbedcrypto_cipher_set_iv(&cctx, nonce, 16);
		mbedcrypto_cipher_final(&cctx, ctrct_exp, 64, ctrdec, &olen);
		CHECK(olen == 64 && memcmp(ctrdec, ctrpt, 64) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);

		/* SM4 CTR in-place */
		{
			uint8_t buf[64];
			memcpy(buf, ctrpt, 64);
			mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_SM4_CTR, key, 128, 0);
			mbedcrypto_cipher_set_iv(&cctx, nonce, 16);
			mbedcrypto_cipher_final(&cctx, buf, 64, buf, &olen);
			CHECK(memcmp(buf, ctrct_exp, 64) == 0, EBADMSG);
			mbedcrypto_cipher_cleanup(&cctx);
		}
	}

	/* SM4 CTS multi-update + in-place (includes one-shot reference) */
	{
		uint8_t iv0[16];
		uint8_t cts_pt[48], cts_ct[48], cts_buf[48];
		size_t ol;
		size_t sm4_cts_lens[] = { 17, 20, 31, 32, 33, 48 };

		memset(iv0, 0, sizeof(iv0));
		for (t = 0; t < sizeof(sm4_cts_lens)/sizeof(sm4_cts_lens[0]); t++) {
			size_t len = sm4_cts_lens[t];
			for (i = 0; i < len; i++)
				cts_pt[i] = i + 0x10;

			/* reference encrypt */
			cipher_multi(MBEDCRYPTO_CIPHER_SM4_CTS, key, 128, 0,
					iv0, 16, cts_pt, len, cts_ct, &ol, 0);

			/* in-place byte-by-byte enc+dec */
			memcpy(cts_buf, cts_pt, len);
			CHECK(cipher_multi(MBEDCRYPTO_CIPHER_SM4_CTS, key, 128, 0,
					iv0, 16, cts_buf, len, cts_buf, &ol, 1) == 0
					&& ol == len && memcmp(cts_buf, cts_ct, len) == 0, EBADMSG);
			CHECK(cipher_multi(MBEDCRYPTO_CIPHER_SM4_CTS, key, 128, 1,
					iv0, 16, cts_buf, len, cts_buf, &ol, 1) == 0
					&& ol == len && memcmp(cts_buf, cts_pt, len) == 0, EBADMSG);

			/* 5-byte chunks non-inplace enc+dec */
			CHECK(cipher_multi(MBEDCRYPTO_CIPHER_SM4_CTS, key, 128, 0,
					iv0, 16, cts_pt, len, cts_buf, &ol, 5) == 0
					&& ol == len && memcmp(cts_buf, cts_ct, len) == 0, EBADMSG);
			CHECK(cipher_multi(MBEDCRYPTO_CIPHER_SM4_CTS, key, 128, 1,
					iv0, 16, cts_ct, len, cts_buf, &ol, 5) == 0
					&& ol == len && memcmp(cts_buf, cts_pt, len) == 0, EBADMSG);

			/* in-place 1blk+final enc+dec */
			memcpy(cts_buf, cts_pt, len);
			CHECK(cipher_split(MBEDCRYPTO_CIPHER_SM4_CTS, key, 128, 0,
					iv0, 16, cts_buf, len, cts_buf, &ol, 16) == 0
					&& ol == len && memcmp(cts_buf, cts_ct, len) == 0, EBADMSG);
			CHECK(cipher_split(MBEDCRYPTO_CIPHER_SM4_CTS, key, 128, 1,
					iv0, 16, cts_buf, len, cts_buf, &ol, 16) == 0
					&& ol == len && memcmp(cts_buf, cts_pt, len) == 0, EBADMSG);

			/* in-place allbut1+final enc+dec */
			memcpy(cts_buf, cts_pt, len);
			CHECK(cipher_split(MBEDCRYPTO_CIPHER_SM4_CTS, key, 128, 0,
					iv0, 16, cts_buf, len, cts_buf, &ol, len - 1) == 0
					&& ol == len && memcmp(cts_buf, cts_ct, len) == 0, EBADMSG);
			CHECK(cipher_split(MBEDCRYPTO_CIPHER_SM4_CTS, key, 128, 1,
					iv0, 16, cts_buf, len, cts_buf, &ol, len - 1) == 0
					&& ol == len && memcmp(cts_buf, cts_pt, len) == 0, EBADMSG);
		}
	}

	/*
	 * SM4-GCM KAT: key=GB/T, iv=cafebabefacedbaddecaf888, aad=0001..07,
	 * pt=DATA_FOR_CRYPTO1 (96 bytes)
	 */
	{
		struct mbedcrypto_sm4_gcm_ctx sctx;
		uint8_t skey[16], siv[12], saad[8], spt[96], sct[96], stag[16];
		uint8_t enc_ct[96], enc_tag[16], dec_pt[96];

		hex2bin("0123456789abcdeffedcba9876543210", skey, 16);
		hex2bin("cafebabefacedbaddecaf888", siv, 12);
		hex2bin("0001020304050607", saad, 8);
		hex2bin("000102030405060708090a0b0c0d0e0f"
			"0a0b0c0d0e0f00010203040506070809"
			"0f0e0d0c0b0a09080706050403020100"
			"000102030405060708090a0b0c0d0e0f"
			"0a0b0c0d0e0f00010203040506070809"
			"0f0e0d0c0b0a09080706050403020100", spt, 96);
		hex2bin("43bfd22bb2780d1f4ef6b0caa955a269"
			"1d96a6de734feb434f5f3eee0311ebaf"
			"9d590d01c74f69ea712edac328dda68b"
			"958904e274789d6b1eca8848acb0a6f5"
			"ac7e2022be5cfe8bbc03c3e85f114b15"
			"09090e3400c01f0f3aca72e473ec9880", sct, 96);
		hex2bin("fef30e05d078887720436701c7ac29ff", stag, 16);

		mbedcrypto_sm4_gcm_setkey(&sctx, skey, 128);
		int r = mbedcrypto_sm4_gcm_encrypt(&sctx, siv, 12, saad, 8,
			spt, 96, enc_ct, enc_tag, 16);
		CHECK(r == 0, EBADMSG);
		CHECK(memcmp(enc_ct, sct, 96) == 0, EBADMSG);
		CHECK(memcmp(enc_tag, stag, 16) == 0, EBADMSG);
		mbedcrypto_sm4_gcm_cleanup(&sctx);

		mbedcrypto_sm4_gcm_setkey(&sctx, skey, 128);
		r = mbedcrypto_sm4_gcm_decrypt(&sctx, siv, 12, saad, 8,
			sct, 96, dec_pt, stag, 16);
		CHECK(r == 0, EBADMSG);
		CHECK(memcmp(dec_pt, spt, 96) == 0, EBADMSG);
		mbedcrypto_sm4_gcm_cleanup(&sctx);
	}

	/*
	 * SM4-CCM KAT: key=GB/T, nonce=008d493b..fa (13 bytes), aad=0001..07,
	 * pt=DATA_FOR_CRYPTO1 (96 bytes), tag=16 bytes
	 */
	{
		struct mbedcrypto_sm4_ccm_ctx sctx;
		uint8_t skey[16], snonce[13], saad[8], spt[96], sct[96], stag[16];
		uint8_t enc_ct[96], enc_tag[16], dec_pt[96];
		size_t olen;

		hex2bin("0123456789abcdeffedcba9876543210", skey, 16);
		hex2bin("008d493b30ae8b3c9696766cfa", snonce, 13);
		hex2bin("0001020304050607", saad, 8);
		hex2bin("000102030405060708090a0b0c0d0e0f"
			"0a0b0c0d0e0f00010203040506070809"
			"0f0e0d0c0b0a09080706050403020100"
			"000102030405060708090a0b0c0d0e0f"
			"0a0b0c0d0e0f00010203040506070809"
			"0f0e0d0c0b0a09080706050403020100", spt, 96);
		hex2bin("29b10384d58dc8b2c59aedce9af172ad"
			"b589e2337061c27a8f3697cd32a564da"
			"40dcc526e468dc661147d82d6229a873"
			"ed9dd7d51f157ff71d01bf27c962d6a9"
			"834ae3b002cc350735ae3fb4afb79585"
			"360cad55e49c41e823633f01f6a17b08", sct, 96);
		hex2bin("d1c4d3afc3910bd4a5b4ca04b187cb35", stag, 16);

		mbedcrypto_sm4_ccm_setkey(&sctx, skey, 128);
		mbedcrypto_sm4_ccm_start(&sctx, MBEDCRYPTO_SM4_ENCRYPT, snonce, 13);
		mbedcrypto_sm4_ccm_set_len(&sctx, 8, 96, 16);
		mbedcrypto_sm4_ccm_update_aad(&sctx, saad, 8);
		mbedcrypto_sm4_ccm_update(&sctx, spt, 96, enc_ct, &olen);
		int r = mbedcrypto_sm4_ccm_final(&sctx, enc_tag, 16);
		CHECK(r == 0, EBADMSG);
		CHECK(memcmp(enc_ct, sct, 96) == 0, EBADMSG);
		CHECK(memcmp(enc_tag, stag, 16) == 0, EBADMSG);
		mbedcrypto_sm4_ccm_cleanup(&sctx);

		mbedcrypto_sm4_ccm_setkey(&sctx, skey, 128);
		mbedcrypto_sm4_ccm_start(&sctx, MBEDCRYPTO_SM4_DECRYPT, snonce, 13);
		mbedcrypto_sm4_ccm_set_len(&sctx, 8, 96, 16);
		mbedcrypto_sm4_ccm_update_aad(&sctx, saad, 8);
		mbedcrypto_sm4_ccm_update(&sctx, sct, 96, dec_pt, &olen);
		r = mbedcrypto_sm4_ccm_final(&sctx, stag, 16);
		CHECK(r == 0, EBADMSG);
		CHECK(memcmp(dec_pt, spt, 96) == 0, EBADMSG);
		mbedcrypto_sm4_ccm_cleanup(&sctx);
	}

out:
	TEST_END();
}

static void test_gcm(void)
{
	TEST_START("AES-GCM");
	struct mbedcrypto_aes_gcm_ctx gctx;

	/* NIST SP 800-38D Test Case 4: AES-128, 96-bit IV, 160-bit AAD, 480-bit PT */
	uint8_t key[16], iv[12], aad[20], pt[64], ct[64], tag[16];
	uint8_t out[64], dtag[16], decpt[64];
	int t = 0;
	size_t d = 0, i = 0, off = 0;

	hex2bin("feffe9928665731c6d6a8f9467308308", key, 16);
	hex2bin("cafebabefacedbaddecaf888", iv, 12);
	hex2bin("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad, 20);
	hex2bin("d9313225f88406e5a55909c5aff5269a"
		"86a7a9531534f7da2e4c303d8a318a72"
		"1c3c0c95956809532fcf0e2449a6b525"
		"b16aedf5aa0de657ba637b39", pt, 60);
	hex2bin("42831ec2217774244b7221b784d0d49c"
		"e3aa212f2c02a4e035c17e2329aca12e"
		"21d514b25466931c7d8f6a5aac84aa05"
		"1ba30b396a0aac973d58e091", ct, 60);
	hex2bin("5bc94fbc3221a5db94fae95ae7121a47", tag, 16);

	/* One-shot encrypt */
	mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
	int ret = mbedcrypto_aes_gcm_encrypt(&gctx, iv, 12, aad, 20, pt, 60, out, dtag, 16);
	CHECK(ret == 0, ret);
	CHECK(memcmp(out, ct, 60) == 0, EBADMSG);
	CHECK(memcmp(dtag, tag, 16) == 0, EBADMSG);
	mbedcrypto_aes_gcm_cleanup(&gctx);

	/* One-shot decrypt */
	mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
	ret = mbedcrypto_aes_gcm_decrypt(&gctx, iv, 12, aad, 20, ct, 60, decpt, tag, 16);
	CHECK(ret == 0, ret);
	CHECK(memcmp(decpt, pt, 60) == 0, EBADMSG);
	mbedcrypto_aes_gcm_cleanup(&gctx);

	/* In-place encrypt then decrypt */
	{
		uint8_t buf[64], tg[16];
		memcpy(buf, pt, 60);
		mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
		mbedcrypto_aes_gcm_encrypt(&gctx, iv, 12, aad, 20, buf, 60, buf, tg, 16);
		CHECK(memcmp(buf, ct, 60) == 0, EBADMSG);
		CHECK(memcmp(tg, tag, 16) == 0, EBADMSG);
		mbedcrypto_aes_gcm_cleanup(&gctx);

		mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
		ret = mbedcrypto_aes_gcm_decrypt(&gctx, iv, 12, aad, 20, buf, 60, buf, tg, 16);
		CHECK(ret == 0, ret);
		CHECK(memcmp(buf, pt, 60) == 0, EBADMSG);
		mbedcrypto_aes_gcm_cleanup(&gctx);
	}

	/* Multi-part GCM */
	{
		uint8_t mp_out[64], mp_tag[16];
		size_t olen;
		mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
		mbedcrypto_aes_gcm_start(&gctx, MBEDCRYPTO_AES_ENCRYPT, iv, 12);
		mbedcrypto_aes_gcm_update_aad(&gctx, aad, 20);
		mbedcrypto_aes_gcm_update(&gctx, pt, 32, mp_out, &olen);
		mbedcrypto_aes_gcm_update(&gctx, pt + 32, 28, mp_out + 32, &olen);
		mbedcrypto_aes_gcm_final(&gctx, mp_tag, 16);
		CHECK(memcmp(mp_out, ct, 60) == 0, EBADMSG);
		CHECK(memcmp(mp_tag, tag, 16) == 0, EBADMSG);
		mbedcrypto_aes_gcm_cleanup(&gctx);
	}

	/* GCM with no AAD */
	{
		uint8_t noaad_ct[16], noaad_tag[16], noaad_pt[16];
		uint8_t simple_pt[16];
		memset(simple_pt, 0, 16);

		mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
		mbedcrypto_aes_gcm_encrypt(&gctx, iv, 12, NULL, 0, simple_pt, 16, noaad_ct, noaad_tag, 16);
		mbedcrypto_aes_gcm_cleanup(&gctx);

		mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
		ret = mbedcrypto_aes_gcm_decrypt(&gctx, iv, 12, NULL, 0, noaad_ct, 16, noaad_pt, noaad_tag, 16);
		CHECK(ret == 0, ret);
		CHECK(memcmp(noaad_pt, simple_pt, 16) == 0, EBADMSG);
		mbedcrypto_aes_gcm_cleanup(&gctx);
	}

	/* GCM with no plaintext (authentication-only) */
	{
		uint8_t auth_tag[16];
		mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
		mbedcrypto_aes_gcm_encrypt(&gctx, iv, 12, aad, 20, NULL, 0, NULL, auth_tag, 16);
		mbedcrypto_aes_gcm_cleanup(&gctx);

		/* Verify the auth-only tag */
		mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
		ret = mbedcrypto_aes_gcm_decrypt(&gctx, iv, 12, aad, 20, NULL, 0, NULL, auth_tag, 16);
		CHECK(ret == 0, ret);
		mbedcrypto_aes_gcm_cleanup(&gctx);
	}

	/* GCM with different tag sizes: 16, 12, 8, 4 */
	{
		int tag_sizes[] = { 16, 12, 8, 4 };
		for (t = 0; t < 4; t++) {
			uint8_t tct[16], ttag[16], tpt[16], spt[16] = {1,2,3,4};
			mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
			mbedcrypto_aes_gcm_encrypt(&gctx, iv, 12, NULL, 0, spt, 16, tct, ttag, tag_sizes[t]);
			mbedcrypto_aes_gcm_cleanup(&gctx);

			mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
			ret = mbedcrypto_aes_gcm_decrypt(&gctx, iv, 12, NULL, 0, tct, 16, tpt, ttag, tag_sizes[t]);
			CHECK(ret == 0 && memcmp(tpt, spt, 16) == 0, EBADMSG);
			mbedcrypto_aes_gcm_cleanup(&gctx);
		}
	}

	/* NIST SP 800-38D Test Case 16: AES-256, 96-bit IV, 160-bit AAD, 480-bit PT */
	{
		uint8_t k256[32], iv256[12], aad256[20], pt256[60], ct256[60], tag256[16];
		uint8_t enc_out[60], enc_tag[16], dec_out[60];

		hex2bin("feffe9928665731c6d6a8f9467308308"
			"feffe9928665731c6d6a8f9467308308", k256, 32);
		hex2bin("cafebabefacedbaddecaf888", iv256, 12);
		hex2bin("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad256, 20);
		hex2bin("d9313225f88406e5a55909c5aff5269a"
			"86a7a9531534f7da2e4c303d8a318a72"
			"1c3c0c95956809532fcf0e2449a6b525"
			"b16aedf5aa0de657ba637b39", pt256, 60);
		hex2bin("522dc1f099567d07f47f37a32a84427d"
			"643a8cdcbfe5c0c97598a2bd2555d1aa"
			"8cb08e48590dbb3da7b08b1056828838"
			"c5f61e6393ba7a0abcc9f662", ct256, 60);
		hex2bin("76fc6ece0f4e1768cddf8853bb2d551b", tag256, 16);

		mbedcrypto_aes_gcm_setkey(&gctx, k256, 256);
		ret = mbedcrypto_aes_gcm_encrypt(&gctx, iv256, 12, aad256, 20, pt256, 60, enc_out, enc_tag, 16);
		CHECK(ret == 0, ret);
		CHECK(memcmp(enc_out, ct256, 60) == 0, EBADMSG);
		CHECK(memcmp(enc_tag, tag256, 16) == 0, EBADMSG);
		mbedcrypto_aes_gcm_cleanup(&gctx);

		mbedcrypto_aes_gcm_setkey(&gctx, k256, 256);
		ret = mbedcrypto_aes_gcm_decrypt(&gctx, iv256, 12, aad256, 20, ct256, 60, dec_out, tag256, 16);
		CHECK(ret == 0, ret);
		CHECK(memcmp(dec_out, pt256, 60) == 0, EBADMSG);
		mbedcrypto_aes_gcm_cleanup(&gctx);
	}

	/* AES-192 GCM KAT (NIST SP 800-38D Test Case 8) */
	{
		uint8_t k192[24], iv192[12], aad192[20], pt192[60];
		uint8_t ct192[60], tag192[16], enc_out[60], enc_tag[16], dec_out[60];

		hex2bin("feffe9928665731c6d6a8f9467308308feffe9928665731c", k192, 24);
		hex2bin("cafebabefacedbaddecaf888", iv192, 12);
		hex2bin("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad192, 20);
		hex2bin("d9313225f88406e5a55909c5aff5269a"
			"86a7a9531534f7da2e4c303d8a318a72"
			"1c3c0c95956809532fcf0e2449a6b525"
			"b16aedf5aa0de657ba637b39", pt192, 60);
		hex2bin("3980ca0b3c00e841eb06fac4872a2757"
			"859e1ceaa6efd984628593b40ca1e19c"
			"7d773d00c144c525ac619d18c84a3f47"
			"18e2448b2fe324d9ccda2710", ct192, 60);
		hex2bin("2519498e80f1478f37ba55bd6d27618c", tag192, 16);

		mbedcrypto_aes_gcm_setkey(&gctx, k192, 192);
		ret = mbedcrypto_aes_gcm_encrypt(&gctx, iv192, 12, aad192, 20, pt192, 60, enc_out, enc_tag, 16);
		CHECK(ret == 0, ret);
		CHECK(memcmp(enc_out, ct192, 60) == 0, EBADMSG);
		CHECK(memcmp(enc_tag, tag192, 16) == 0, EBADMSG);
		mbedcrypto_aes_gcm_cleanup(&gctx);

		mbedcrypto_aes_gcm_setkey(&gctx, k192, 192);
		ret = mbedcrypto_aes_gcm_decrypt(&gctx, iv192, 12, aad192, 20, ct192, 60, dec_out, tag192, 16);
		CHECK(ret == 0, ret);
		CHECK(memcmp(dec_out, pt192, 60) == 0, EBADMSG);
		mbedcrypto_aes_gcm_cleanup(&gctx);
	}

	/* --- Extended coverage (merged from test_gcm_ext) --- */
	{
		struct mbedcrypto_aes_gcm_ctx gctx;
		uint8_t key[16], ct[64], tag[16], dec[64];
		int ret = 0;

		hex2bin("00000000000000000000000000000000", key, 16);

		/* GCM with 0-length plaintext (auth-only) via multi-part */
		{
			uint8_t iv[12];
			uint8_t aad[] = "additional data";
			uint8_t tag_check[16];

			memset(iv, 0, sizeof(iv));
			mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
			ret = mbedcrypto_aes_gcm_start(&gctx, MBEDCRYPTO_AES_ENCRYPT, iv, 12);
			CHECK(ret == 0, ret);
			mbedcrypto_aes_gcm_update_aad(&gctx, aad, sizeof(aad) - 1);
			mbedcrypto_aes_gcm_final(&gctx, tag, 16);
			mbedcrypto_aes_gcm_cleanup(&gctx);

			/* Verify tag with decrypt */
			mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
			ret = mbedcrypto_aes_gcm_start(&gctx, MBEDCRYPTO_AES_DECRYPT, iv, 12);
			mbedcrypto_aes_gcm_update_aad(&gctx, aad, sizeof(aad) - 1);
			mbedcrypto_aes_gcm_final(&gctx, tag_check, 16);
			CHECK(memcmp(tag, tag_check, 16) == 0, EBADMSG);
			mbedcrypto_aes_gcm_cleanup(&gctx);
		}

		/* GCM with 0-length AAD via multi-part */
		{
			uint8_t iv[12];
			uint8_t pt[16];
			uint8_t dec_tag[16];
			size_t olen = 0;

			memset(iv, 0, sizeof(iv));
			pt[0] = 0x01; pt[1] = 0x02; pt[2] = 0x03; pt[3] = 0x04;
			memset(pt + 4, 0, 12);
			mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
			ret = mbedcrypto_aes_gcm_start(&gctx, MBEDCRYPTO_AES_ENCRYPT, iv, 12);
			CHECK(ret == 0, ret);
			mbedcrypto_aes_gcm_update(&gctx, pt, 16, ct, &olen);
			mbedcrypto_aes_gcm_final(&gctx, tag, 16);
			mbedcrypto_aes_gcm_cleanup(&gctx);

			/* Decrypt */
			mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
			ret = mbedcrypto_aes_gcm_start(&gctx, MBEDCRYPTO_AES_DECRYPT, iv, 12);
			mbedcrypto_aes_gcm_update(&gctx, ct, 16, dec, &olen);
			mbedcrypto_aes_gcm_final(&gctx, dec_tag, 16);
			CHECK(memcmp(dec, pt, 16) == 0, EBADMSG);
			CHECK(memcmp(tag, dec_tag, 16) == 0, EBADMSG);
			mbedcrypto_aes_gcm_cleanup(&gctx);
		}

		/* GCM multi-block streaming vs one-shot */
		{
			uint8_t iv[12] = {1};
			uint8_t pt[48];
			for (i = 0; i < 48; i++)
				pt[i] = i;

			/* Encrypt in one shot */
			uint8_t ct_full[48], tag_full[16];
			mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
			mbedcrypto_aes_gcm_encrypt(&gctx, iv, 12, NULL, 0, pt, 48, ct_full, tag_full, 16);
			mbedcrypto_aes_gcm_cleanup(&gctx);

			/* Encrypt in 16-byte chunks via multi-part */
			uint8_t ct_chunk[48], tag_chunk[16];
			mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
			mbedcrypto_aes_gcm_start(&gctx, MBEDCRYPTO_AES_ENCRYPT, iv, 12);
			size_t off = 0;
			for (i = 0; i < 3; i++) {
				size_t o = 0;
				mbedcrypto_aes_gcm_update(&gctx, pt + i * 16, 16, ct_chunk + off, &o);
				off += o;
			}
			mbedcrypto_aes_gcm_final(&gctx, tag_chunk, 16);
			CHECK(memcmp(ct_full, ct_chunk, 48) == 0, EBADMSG);
			CHECK(memcmp(tag_full, tag_chunk, 16) == 0, EBADMSG);
			mbedcrypto_aes_gcm_cleanup(&gctx);
		}
	}

	/* --- Multi-update AAD tests --- */
	{
		struct mbedcrypto_aes_gcm_ctx gctx;
		uint8_t key[16], iv[12], aad[20], pt[60];
		uint8_t ct_ref[60], tag_ref[16];
		uint8_t ct_out[60], tag_out[16];

		hex2bin("feffe9928665731c6d6a8f9467308308", key, 16);
		hex2bin("cafebabefacedbaddecaf888", iv, 12);
		hex2bin("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad, 20);
		hex2bin("d9313225f88406e5a55909c5aff5269a"
			"86a7a9531534f7da2e4c303d8a318a72"
			"1c3c0c95956809532fcf0e2449a6b525"
			"b16aedf5aa0de657ba637b39", pt, 60);

		/* Reference: one-shot encrypt */
		mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
		mbedcrypto_aes_gcm_encrypt(&gctx, iv, 12, aad, 20, pt, 60, ct_ref, tag_ref, 16);
		mbedcrypto_aes_gcm_cleanup(&gctx);

		/* Multi-update AAD: split 20-byte AAD as 7+5+8 */
		mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
		mbedcrypto_aes_gcm_start(&gctx, MBEDCRYPTO_AES_ENCRYPT, iv, 12);
		mbedcrypto_aes_gcm_update_aad(&gctx, aad, 7);
		mbedcrypto_aes_gcm_update_aad(&gctx, aad + 7, 5);
		mbedcrypto_aes_gcm_update_aad(&gctx, aad + 12, 8);
		size_t olen;
		mbedcrypto_aes_gcm_update(&gctx, pt, 60, ct_out, &olen);
		mbedcrypto_aes_gcm_final(&gctx, tag_out, 16);
		CHECK(memcmp(ct_out, ct_ref, 60) == 0, EBADMSG);
		CHECK(memcmp(tag_out, tag_ref, 16) == 0, EBADMSG);
		mbedcrypto_aes_gcm_cleanup(&gctx);

		/* Multi-update AAD: byte-by-byte */
		mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
		mbedcrypto_aes_gcm_start(&gctx, MBEDCRYPTO_AES_ENCRYPT, iv, 12);
		for (i = 0; i < 20; i++)
			mbedcrypto_aes_gcm_update_aad(&gctx, aad + i, 1);
		mbedcrypto_aes_gcm_update(&gctx, pt, 60, ct_out, &olen);
		mbedcrypto_aes_gcm_final(&gctx, tag_out, 16);
		CHECK(memcmp(ct_out, ct_ref, 60) == 0, EBADMSG);
		CHECK(memcmp(tag_out, tag_ref, 16) == 0, EBADMSG);
		mbedcrypto_aes_gcm_cleanup(&gctx);
	}

	/* --- Multi-update partial block data tests --- */
	{
		struct mbedcrypto_aes_gcm_ctx gctx;
		uint8_t key[16], iv[12], aad[20], pt[60];
		uint8_t ct_ref[60], tag_ref[16];

		hex2bin("feffe9928665731c6d6a8f9467308308", key, 16);
		hex2bin("cafebabefacedbaddecaf888", iv, 12);
		hex2bin("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad, 20);
		hex2bin("d9313225f88406e5a55909c5aff5269a"
			"86a7a9531534f7da2e4c303d8a318a72"
			"1c3c0c95956809532fcf0e2449a6b525"
			"b16aedf5aa0de657ba637b39", pt, 60);

		/* Reference: one-shot encrypt */
		mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
		mbedcrypto_aes_gcm_encrypt(&gctx, iv, 12, aad, 20, pt, 60, ct_ref, tag_ref, 16);
		mbedcrypto_aes_gcm_cleanup(&gctx);

		/* Partial block multi-update: 3+7+13+5+4+16+12 = 60 */
		{
			uint8_t ct_out[60], tag_out[16];
			size_t chunks[] = { 3, 7, 13, 5, 4, 16, 12 };
			size_t off = 0, ct_off = 0;

			mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
			mbedcrypto_aes_gcm_start(&gctx, MBEDCRYPTO_AES_ENCRYPT, iv, 12);
			mbedcrypto_aes_gcm_update_aad(&gctx, aad, 20);
			for (i = 0; i < sizeof(chunks)/sizeof(chunks[0]); i++) {
				size_t o = 0;
				mbedcrypto_aes_gcm_update(&gctx, pt + off, chunks[i], ct_out + ct_off, &o);
				off += chunks[i];
				ct_off += o;
			}
			mbedcrypto_aes_gcm_final(&gctx, tag_out, 16);
			CHECK(memcmp(ct_out, ct_ref, 60) == 0, EBADMSG);
			CHECK(memcmp(tag_out, tag_ref, 16) == 0, EBADMSG);
			mbedcrypto_aes_gcm_cleanup(&gctx);
		}

		/* Byte-by-byte data update */
		{
			uint8_t ct_out[60], tag_out[16];
			size_t ct_off = 0;

			mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
			mbedcrypto_aes_gcm_start(&gctx, MBEDCRYPTO_AES_ENCRYPT, iv, 12);
			mbedcrypto_aes_gcm_update_aad(&gctx, aad, 20);
			for (i = 0; i < 60; i++) {
				size_t o = 0;
				mbedcrypto_aes_gcm_update(&gctx, pt + i, 1, ct_out + ct_off, &o);
				ct_off += o;
			}
			mbedcrypto_aes_gcm_final(&gctx, tag_out, 16);
			CHECK(memcmp(ct_out, ct_ref, 60) == 0, EBADMSG);
			CHECK(memcmp(tag_out, tag_ref, 16) == 0, EBADMSG);
			mbedcrypto_aes_gcm_cleanup(&gctx);
		}

		/* Combined: multi-update AD (7+5+8) + partial block data (3+7+13+5+4+16+12) */
		{
			uint8_t ct_out[60], tag_out[16];
			size_t chunks[] = { 3, 7, 13, 5, 4, 16, 12 };
			size_t off = 0, ct_off = 0;

			mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
			mbedcrypto_aes_gcm_start(&gctx, MBEDCRYPTO_AES_ENCRYPT, iv, 12);
			mbedcrypto_aes_gcm_update_aad(&gctx, aad, 7);
			mbedcrypto_aes_gcm_update_aad(&gctx, aad + 7, 5);
			mbedcrypto_aes_gcm_update_aad(&gctx, aad + 12, 8);
			for (i = 0; i < sizeof(chunks)/sizeof(chunks[0]); i++) {
				size_t o = 0;
				mbedcrypto_aes_gcm_update(&gctx, pt + off, chunks[i], ct_out + ct_off, &o);
				off += chunks[i];
				ct_off += o;
			}
			mbedcrypto_aes_gcm_final(&gctx, tag_out, 16);
			CHECK(memcmp(ct_out, ct_ref, 60) == 0, EBADMSG);
			CHECK(memcmp(tag_out, tag_ref, 16) == 0, EBADMSG);
			mbedcrypto_aes_gcm_cleanup(&gctx);
		}
	}

	/* In-place multi-part GCM encrypt/decrypt */
	{
		struct mbedcrypto_aes_gcm_ctx gctx;
		uint8_t gk[16], giv[12], gaad[20], gpt[60];
		uint8_t gct_ref[60], gtag_ref[16];

		hex2bin("feffe9928665731c6d6a8f9467308308", gk, 16);
		hex2bin("cafebabefacedbaddecaf888", giv, 12);
		hex2bin("feedfacedeadbeeffeedfacedeadbeefabaddad2", gaad, 20);
		hex2bin("d9313225f88406e5a55909c5aff5269a"
			"86a7a9531534f7da2e4c303d8a318a72"
			"1c3c0c95956809532fcf0e2449a6b525"
			"b16aedf5aa0de657ba637b39", gpt, 60);

		/* Reference */
		mbedcrypto_aes_gcm_setkey(&gctx, gk, 128);
		mbedcrypto_aes_gcm_encrypt(&gctx, giv, 12, gaad, 20, gpt, 60,
				gct_ref, gtag_ref, 16);
		mbedcrypto_aes_gcm_cleanup(&gctx);

		/* In-place 16-byte chunk encrypt */
		{
			uint8_t buf[60], tg[16];
			memcpy(buf, gpt, 60);
			mbedcrypto_aes_gcm_setkey(&gctx, gk, 128);
			mbedcrypto_aes_gcm_start(&gctx, MBEDCRYPTO_AES_ENCRYPT, giv, 12);
			mbedcrypto_aes_gcm_update_aad(&gctx, gaad, 20);
			size_t total = 0;
			for (off = 0; off < 60; off += 16) {
				size_t chunk = (off + 16 <= 60) ? 16 : (60 - off);
				size_t o;
				mbedcrypto_aes_gcm_update(&gctx, buf + off, chunk,
						buf + total, &o);
				total += o;
			}
			mbedcrypto_aes_gcm_final(&gctx, tg, 16);
			CHECK(memcmp(buf, gct_ref, 60) == 0
					&& memcmp(tg, gtag_ref, 16) == 0, EBADMSG);
			mbedcrypto_aes_gcm_cleanup(&gctx);

			/* In-place 16-byte chunk decrypt */
			mbedcrypto_aes_gcm_setkey(&gctx, gk, 128);
			mbedcrypto_aes_gcm_start(&gctx, MBEDCRYPTO_AES_DECRYPT, giv, 12);
			mbedcrypto_aes_gcm_update_aad(&gctx, gaad, 20);
			total = 0;
			for (off = 0; off < 60; off += 16) {
				size_t chunk = (off + 16 <= 60) ? 16 : (60 - off);
				size_t o;
				mbedcrypto_aes_gcm_update(&gctx, buf + off, chunk,
						buf + total, &o);
				total += o;
			}
			uint8_t dtg[16];
			mbedcrypto_aes_gcm_final(&gctx, dtg, 16);
			CHECK(memcmp(buf, gpt, 60) == 0
					&& memcmp(dtg, gtag_ref, 16) == 0, EBADMSG);
			mbedcrypto_aes_gcm_cleanup(&gctx);
		}

		/* In-place byte-by-byte encrypt+decrypt */
		{
			uint8_t buf[60], tg[16];
			memcpy(buf, gpt, 60);
			mbedcrypto_aes_gcm_setkey(&gctx, gk, 128);
			mbedcrypto_aes_gcm_start(&gctx, MBEDCRYPTO_AES_ENCRYPT, giv, 12);
			mbedcrypto_aes_gcm_update_aad(&gctx, gaad, 20);
			size_t total = 0;
			for (i = 0; i < 60; i++) {
				size_t o;
				mbedcrypto_aes_gcm_update(&gctx, buf + i, 1,
						buf + total, &o);
				total += o;
			}
			mbedcrypto_aes_gcm_final(&gctx, tg, 16);
			CHECK(memcmp(buf, gct_ref, 60) == 0
					&& memcmp(tg, gtag_ref, 16) == 0, EBADMSG);
			mbedcrypto_aes_gcm_cleanup(&gctx);

			mbedcrypto_aes_gcm_setkey(&gctx, gk, 128);
			mbedcrypto_aes_gcm_start(&gctx, MBEDCRYPTO_AES_DECRYPT, giv, 12);
			mbedcrypto_aes_gcm_update_aad(&gctx, gaad, 20);
			total = 0;
			for (i = 0; i < 60; i++) {
				size_t o;
				mbedcrypto_aes_gcm_update(&gctx, buf + i, 1,
						buf + total, &o);
				total += o;
			}
			uint8_t dtg[16];
			mbedcrypto_aes_gcm_final(&gctx, dtg, 16);
			CHECK(memcmp(buf, gpt, 60) == 0
					&& memcmp(dtg, gtag_ref, 16) == 0, EBADMSG);
			mbedcrypto_aes_gcm_cleanup(&gctx);
		}

		/* In-place partial chunks (3+7+13+5+4+16+12=60) enc+dec */
		{
			uint8_t buf[60], tg[16];
			size_t chunks[] = { 3, 7, 13, 5, 4, 16, 12 };
			memcpy(buf, gpt, 60);
			mbedcrypto_aes_gcm_setkey(&gctx, gk, 128);
			mbedcrypto_aes_gcm_start(&gctx, MBEDCRYPTO_AES_ENCRYPT, giv, 12);
			mbedcrypto_aes_gcm_update_aad(&gctx, gaad, 20);
			size_t off = 0, total = 0;
			for (i = 0; i < 7; i++) {
				size_t o;
				mbedcrypto_aes_gcm_update(&gctx, buf + off, chunks[i],
						buf + total, &o);
				off += chunks[i]; total += o;
			}
			mbedcrypto_aes_gcm_final(&gctx, tg, 16);
			CHECK(memcmp(buf, gct_ref, 60) == 0
					&& memcmp(tg, gtag_ref, 16) == 0, EBADMSG);
			mbedcrypto_aes_gcm_cleanup(&gctx);

			mbedcrypto_aes_gcm_setkey(&gctx, gk, 128);
			mbedcrypto_aes_gcm_start(&gctx, MBEDCRYPTO_AES_DECRYPT, giv, 12);
			mbedcrypto_aes_gcm_update_aad(&gctx, gaad, 20);
			off = 0; total = 0;
			for (i = 0; i < 7; i++) {
				size_t o;
				mbedcrypto_aes_gcm_update(&gctx, buf + off, chunks[i],
						buf + total, &o);
				off += chunks[i]; total += o;
			}
			uint8_t dtg[16];
			mbedcrypto_aes_gcm_final(&gctx, dtg, 16);
			CHECK(memcmp(buf, gpt, 60) == 0
					&& memcmp(dtg, gtag_ref, 16) == 0, EBADMSG);
			mbedcrypto_aes_gcm_cleanup(&gctx);
		}
	}

	/* Authentication failure: tampered ciphertext */
	{
		uint8_t tc[60], td[60];
		memcpy(tc, ct, 60);
		tc[10] ^= 0x01; /* flip one bit in ciphertext */
		mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
		int r = mbedcrypto_aes_gcm_decrypt(&gctx, iv, 12, aad, 20, tc, 60, td, tag, 16);
		CHECK(r != 0, EBADMSG);
		mbedcrypto_aes_gcm_cleanup(&gctx);
	}

	/* Authentication failure: tampered tag */
	{
		uint8_t tt[16], td[60];
		memcpy(tt, tag, 16);
		tt[0] ^= 0xFF;
		mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
		int r = mbedcrypto_aes_gcm_decrypt(&gctx, iv, 12, aad, 20, ct, 60, td, tt, 16);
		CHECK(r != 0, EBADMSG);
		mbedcrypto_aes_gcm_cleanup(&gctx);
	}

	/* Authentication failure: tampered AAD */
	{
		uint8_t ta[20], td[60];
		memcpy(ta, aad, 20);
		ta[5] ^= 0x01;
		mbedcrypto_aes_gcm_setkey(&gctx, key, 128);
		int r = mbedcrypto_aes_gcm_decrypt(&gctx, iv, 12, ta, 20, ct, 60, td, tag, 16);
		CHECK(r != 0, EBADMSG);
		mbedcrypto_aes_gcm_cleanup(&gctx);
	}

	/* Large-data GCM roundtrip (1KB, 4KB, 8KB) */
	{
		static uint8_t gpt[8192], gct[8192], gdec[8192], gtag[16], dtag[16];
		uint8_t gk[16], giv[12], gaad[32];

		for (i = 0; i < 16; i++)
			gk[i] = i * 13 + 5;
		for (i = 0; i < 12; i++)
			giv[i] = i + 1;
		for (i = 0; i < 32; i++)
			gaad[i] = i ^ 0xCC;
		for (i = 0; i < 8192; i++)
			gpt[i] = i * 29 + 7;

		size_t dlens[] = { 1024, 4096, 8192 };
		for (d = 0; d < 3; d++) {
			size_t dlen = dlens[d];

			/* One-shot encrypt reference */
			struct mbedcrypto_aes_gcm_ctx gc;
			mbedcrypto_aes_gcm_setkey(&gc, gk, 128);
			mbedcrypto_aes_gcm_encrypt(&gc, giv, 12, gaad, 32,
				gpt, dlen, gct, gtag, 16);
			mbedcrypto_aes_gcm_cleanup(&gc);

			/* One-shot decrypt roundtrip */
			mbedcrypto_aes_gcm_setkey(&gc, gk, 128);
			int r = mbedcrypto_aes_gcm_decrypt(&gc, giv, 12, gaad, 32,
				gct, dlen, gdec, gtag, 16);
			CHECK(r == 0 && memcmp(gdec, gpt, dlen) == 0, EBADMSG);
			mbedcrypto_aes_gcm_cleanup(&gc);

			/* Multi-part 512-byte chunks */
			mbedcrypto_aes_gcm_setkey(&gc, gk, 128);
			mbedcrypto_aes_gcm_start(&gc, MBEDCRYPTO_AES_ENCRYPT, giv, 12);
			mbedcrypto_aes_gcm_update_aad(&gc, gaad, 32);
			size_t total = 0;
			for (off = 0; off < dlen; off += 512) {
				size_t chunk = (off + 512 <= dlen) ? 512 : (dlen - off);
				size_t o;
				mbedcrypto_aes_gcm_update(&gc, gpt + off, chunk,
					gdec + total, &o);
				total += o;
			}
			mbedcrypto_aes_gcm_final(&gc, dtag, 16);
			CHECK(memcmp(gdec, gct, dlen) == 0
				&& memcmp(dtag, gtag, 16) == 0, EBADMSG);
			mbedcrypto_aes_gcm_cleanup(&gc);
		}
	}

out:
	TEST_END();
}

static void test_ccm(void)
{
	TEST_START("AES-CCM");
	struct mbedcrypto_aes_ccm_ctx cctx;

	uint8_t key[16];
	int ni = 0, ti = 0;
	size_t d = 0, i = 0, off = 0, t = 0;
	hex2bin("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", key, 16);

	/* Roundtrip with various nonce sizes and tag sizes */
	int nonce_sizes[] = { 7, 8, 9, 10, 11, 12, 13 };
	int tag_sizes[] = { 4, 6, 8, 10, 12, 14, 16 };

	for (ni = 0; ni < 7; ni++) {
		int nlen = nonce_sizes[ni];
		uint8_t nonce[13];
		for (i = 0; i < nlen; i++)
			nonce[i] = i + 1;

		for (ti = 0; ti < 7; ti++) {
			int tlen = tag_sizes[ti];
			uint8_t pt_data[32], ct_data[32], dec_data[32], tag_buf[16];
			size_t olen;
			for (i = 0; i < 32; i++)
				pt_data[i] = i ^ 0x55;

			/* Encrypt */
			mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
			mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, nonce, nlen);
			mbedcrypto_aes_ccm_set_len(&cctx, 0, 32, tlen);
			mbedcrypto_aes_ccm_update(&cctx, pt_data, 32, ct_data, &olen);
			int ret = mbedcrypto_aes_ccm_final(&cctx, tag_buf, tlen);
			CHECK(ret == 0, ret);
			/* KAT: verify against OpenSSL 3.0.13 reference */
			if (nlen == 7 && tlen == 4) {
				CHECK(hexcmp(ct_data, "dbc392854ef3e4f6d96f565b1458045633d0458ace43643611bd99a31464efa6", 32) == 0, EBADMSG);
				CHECK(hexcmp(tag_buf, "db5c6529", 4) == 0, EBADMSG);
			}
			mbedcrypto_aes_ccm_cleanup(&cctx);

			/* Decrypt */
			mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
			mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_DECRYPT, nonce, nlen);
			mbedcrypto_aes_ccm_set_len(&cctx, 0, 32, tlen);
			mbedcrypto_aes_ccm_update(&cctx, ct_data, 32, dec_data, &olen);
			ret = mbedcrypto_aes_ccm_final(&cctx, tag_buf, tlen);
			CHECK(ret == 0, ret);
			CHECK(memcmp(dec_data, pt_data, 32) == 0, EBADMSG);
			mbedcrypto_aes_ccm_cleanup(&cctx);
		}
	}

	/* CCM with AAD */
	{
		uint8_t nonce[8] = {1,2,3,4,5,6,7,8};
		uint8_t aad[16] = {0xaa, 0xbb, 0xcc};
		uint8_t pt_data[24], ct_data[24], dec_data[24], tag_buf[8];
		size_t olen;
		for (i = 0; i < 24; i++)
			pt_data[i] = i;

		mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
		mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, nonce, 8);
		mbedcrypto_aes_ccm_set_len(&cctx, 3, 24, 8);
		mbedcrypto_aes_ccm_update_aad(&cctx, aad, 3);
		mbedcrypto_aes_ccm_update(&cctx, pt_data, 24, ct_data, &olen);
		mbedcrypto_aes_ccm_final(&cctx, tag_buf, 8);
		/* KAT: verify against OpenSSL 3.0.13 reference */
		CHECK(hexcmp(ct_data, "4e3e13081da81f855e3cd86d572cbbdac52a880b49d7a6c5", 24) == 0, EBADMSG);
		CHECK(hexcmp(tag_buf, "6ed59701d77b8135", 8) == 0, EBADMSG);
		mbedcrypto_aes_ccm_cleanup(&cctx);

		mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
		mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_DECRYPT, nonce, 8);
		mbedcrypto_aes_ccm_set_len(&cctx, 3, 24, 8);
		mbedcrypto_aes_ccm_update_aad(&cctx, aad, 3);
		mbedcrypto_aes_ccm_update(&cctx, ct_data, 24, dec_data, &olen);
		int ret = mbedcrypto_aes_ccm_final(&cctx, tag_buf, 8);
		CHECK(ret == 0 && memcmp(dec_data, pt_data, 24) == 0, EBADMSG);
		mbedcrypto_aes_ccm_cleanup(&cctx);
	}

	/* CCM with different data lengths */
	{
		uint8_t nonce[12];
		size_t ccm_lens[] = { 1, 7, 15, 16, 17, 31, 32, 48 };

		memset(nonce, 0, sizeof(nonce));
		for (t = 0; t < sizeof(ccm_lens)/sizeof(ccm_lens[0]); t++) {
			size_t len = ccm_lens[t];
			uint8_t ccmpt[48], ccmct[48], ccmdec[48], ttag[8];
			size_t olen;
			for (i = 0; i < len; i++)
				ccmpt[i] = i + t;

			mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
			mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, nonce, 12);
			mbedcrypto_aes_ccm_set_len(&cctx, 0, len, 8);
			mbedcrypto_aes_ccm_update(&cctx, ccmpt, len, ccmct, &olen);
			mbedcrypto_aes_ccm_final(&cctx, ttag, 8);
			/* KAT: verify specific lengths against OpenSSL */
			if (len == 1 && t == 0) {
				CHECK(hexcmp(ccmct, "32", 1) == 0, EBADMSG);
				CHECK(hexcmp(ttag, "61666ad50f5055b2", 8) == 0, EBADMSG);
			}
			if (len == 48 && t == 7) {
				CHECK(hexcmp(ccmct, "35390672a2ace42e8cba0b547fbde5446df5a8a2f030389f89bebf25daeae8570e23f5c71131071992903437b30e10c3", 48) == 0, EBADMSG);
				CHECK(hexcmp(ttag, "9d4d750996b7600f", 8) == 0, EBADMSG);
			}
			mbedcrypto_aes_ccm_cleanup(&cctx);

			mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
			mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_DECRYPT, nonce, 12);
			mbedcrypto_aes_ccm_set_len(&cctx, 0, len, 8);
			mbedcrypto_aes_ccm_update(&cctx, ccmct, len, ccmdec, &olen);
			int ret = mbedcrypto_aes_ccm_final(&cctx, ttag, 8);
			CHECK(ret == 0 && memcmp(ccmdec, ccmpt, len) == 0, EBADMSG);
			mbedcrypto_aes_ccm_cleanup(&cctx);
		}
	}

	/* AES-256 CCM KAT (RFC 3610 style, key from NIST CAVP AES-256-CCM) */
	{
		uint8_t k256[32], nonce[7], aad_buf[8], pt_data[24], ct_data[24], tag_buf[4];
		uint8_t enc_ct[24], enc_tag[4], dec_pt[24];
		size_t olen;

		hex2bin("eda32f751456e33195f1f499cf2dc7c97ea127b6d488f211ccc5126fbb24afa6", k256, 32);
		hex2bin("a544218dadd3c1", nonce, 7);
		hex2bin("d3d5424e20fbec43", aad_buf, 8);
		hex2bin("4bbb61e0409802d003630e027a204e09862c3d5b40db2ba6", pt_data, 24);
		hex2bin("ab14fe5307729ea950578293ba5b620e2a3a1b3079935c71", ct_data, 24);
		hex2bin("b3d1fca2", tag_buf, 4);

		mbedcrypto_aes_ccm_setkey(&cctx, k256, 256);
		mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, nonce, 7);
		mbedcrypto_aes_ccm_set_len(&cctx, 8, 24, 4);
		mbedcrypto_aes_ccm_update_aad(&cctx, aad_buf, 8);
		mbedcrypto_aes_ccm_update(&cctx, pt_data, 24, enc_ct, &olen);
		int r = mbedcrypto_aes_ccm_final(&cctx, enc_tag, 4);
		CHECK(r == 0, EBADMSG);
		CHECK(memcmp(enc_ct, ct_data, 24) == 0, EBADMSG);
		CHECK(memcmp(enc_tag, tag_buf, 4) == 0, EBADMSG);
		mbedcrypto_aes_ccm_cleanup(&cctx);

		mbedcrypto_aes_ccm_setkey(&cctx, k256, 256);
		mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_DECRYPT, nonce, 7);
		mbedcrypto_aes_ccm_set_len(&cctx, 8, 24, 4);
		mbedcrypto_aes_ccm_update_aad(&cctx, aad_buf, 8);
		mbedcrypto_aes_ccm_update(&cctx, ct_data, 24, dec_pt, &olen);
		r = mbedcrypto_aes_ccm_final(&cctx, tag_buf, 4);
		CHECK(r == 0, EBADMSG);
		CHECK(memcmp(dec_pt, pt_data, 24) == 0, EBADMSG);
		mbedcrypto_aes_ccm_cleanup(&cctx);
	}

	/* AES-192 CCM KAT (NIST CAVP AES-192-CCM, Alen=8, Plen=24, Nlen=7, Tlen=4) */
	{
		uint8_t k192[24], nonce[7], aad_buf[8], pt_data[24], ct_data[24], tag_buf[4];
		uint8_t enc_ct[24], enc_tag[4], dec_pt[24];
		size_t olen;

		hex2bin("ceb009aea4454451feadf0e6b36f45555dd04723baa448e8", k192, 24);
		hex2bin("764043c49460b7", nonce, 7);
		hex2bin("6e80dd7f1badf3a1", aad_buf, 8);
		hex2bin("c0ff898b2016816e09e02484c4c4e22dce26217f4c7c0b0e", pt_data, 24);
		hex2bin("8222c1f01013726568819b391684ed1b8850973a0264a3e3", ct_data, 24);
		hex2bin("6af9902a", tag_buf, 4);

		mbedcrypto_aes_ccm_setkey(&cctx, k192, 192);
		mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, nonce, 7);
		mbedcrypto_aes_ccm_set_len(&cctx, 8, 24, 4);
		mbedcrypto_aes_ccm_update_aad(&cctx, aad_buf, 8);
		mbedcrypto_aes_ccm_update(&cctx, pt_data, 24, enc_ct, &olen);
		int r = mbedcrypto_aes_ccm_final(&cctx, enc_tag, 4);
		CHECK(r == 0, EBADMSG);
		CHECK(memcmp(enc_ct, ct_data, 24) == 0, EBADMSG);
		CHECK(memcmp(enc_tag, tag_buf, 4) == 0, EBADMSG);
		mbedcrypto_aes_ccm_cleanup(&cctx);

		mbedcrypto_aes_ccm_setkey(&cctx, k192, 192);
		mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_DECRYPT, nonce, 7);
		mbedcrypto_aes_ccm_set_len(&cctx, 8, 24, 4);
		mbedcrypto_aes_ccm_update_aad(&cctx, aad_buf, 8);
		mbedcrypto_aes_ccm_update(&cctx, ct_data, 24, dec_pt, &olen);
		r = mbedcrypto_aes_ccm_final(&cctx, tag_buf, 4);
		CHECK(r == 0, EBADMSG);
		CHECK(memcmp(dec_pt, pt_data, 24) == 0, EBADMSG);
		mbedcrypto_aes_ccm_cleanup(&cctx);
	}

	/* --- Extended coverage (merged from test_ccm_ext) --- */
	{
		struct mbedcrypto_aes_ccm_ctx cctx;
		uint8_t key[16];
		for (i = 0; i < 16; i++)
			key[i] = i;

		/* CCM with 7-byte nonce (minimum) and 4-byte tag (minimum) */
		{
			uint8_t nonce7[7];
			uint8_t pt[16], ct_buf[16], dec_buf[16], tag_buf[4];
			size_t olen;
			int ret = 0;

			nonce7[0] = 0x10;
			memset(nonce7 + 1, 0, 6);
			memset(pt, 0, sizeof(pt));
			mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
			mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, nonce7, 7);
			mbedcrypto_aes_ccm_set_len(&cctx, 0, 16, 4);
			mbedcrypto_aes_ccm_update(&cctx, pt, 16, ct_buf, &olen);
			ret = mbedcrypto_aes_ccm_final(&cctx, tag_buf, 4);
			CHECK(ret == 0, ret);
			/* KAT: verify against OpenSSL 3.0.13 reference */
			CHECK(hexcmp(ct_buf, "c6ebc153d81ba4df36158520ed0b9bc8", 16) == 0, EBADMSG);
			CHECK(hexcmp(tag_buf, "9ec59747", 4) == 0, EBADMSG);
			mbedcrypto_aes_ccm_cleanup(&cctx);

			mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
			mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_DECRYPT, nonce7, 7);
			mbedcrypto_aes_ccm_set_len(&cctx, 0, 16, 4);
			mbedcrypto_aes_ccm_update(&cctx, ct_buf, 16, dec_buf, &olen);
			ret = mbedcrypto_aes_ccm_final(&cctx, tag_buf, 4);
			CHECK(ret == 0 && memcmp(dec_buf, pt, 16) == 0, EBADMSG);
			mbedcrypto_aes_ccm_cleanup(&cctx);
		}

		/* CCM with 13-byte nonce and 16-byte tag */
		{
			uint8_t nonce13[13];
			for (i = 0; i < 13; i++)
				nonce13[i] = i + 0x20;
			uint8_t pt[32], ct_buf[32], dec_buf[32], tag_buf[16];
			size_t olen;
			for (i = 0; i < 32; i++)
				pt[i] = i ^ 0xBB;

			mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
			mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, nonce13, 13);
			mbedcrypto_aes_ccm_set_len(&cctx, 0, 32, 16);
			mbedcrypto_aes_ccm_update(&cctx, pt, 32, ct_buf, &olen);
			int ret = mbedcrypto_aes_ccm_final(&cctx, tag_buf, 16);
			CHECK(ret == 0, ret);
			/* KAT: verify against OpenSSL 3.0.13 reference */
			CHECK(hexcmp(ct_buf, "d10f2b7e84cc13dd81076dc6e391afd7b7412703d9e0cc3b796a39086aea3300", 32) == 0, EBADMSG);
			CHECK(hexcmp(tag_buf, "748fea33f452918915f479eea5f12c44", 16) == 0, EBADMSG);
			mbedcrypto_aes_ccm_cleanup(&cctx);

			mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
			mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_DECRYPT, nonce13, 13);
			mbedcrypto_aes_ccm_set_len(&cctx, 0, 32, 16);
			mbedcrypto_aes_ccm_update(&cctx, ct_buf, 32, dec_buf, &olen);
			ret = mbedcrypto_aes_ccm_final(&cctx, tag_buf, 16);
			CHECK(ret == 0 && memcmp(dec_buf, pt, 32) == 0, EBADMSG);
			mbedcrypto_aes_ccm_cleanup(&cctx);
		}

		/* CCM with AAD and various tag sizes */
		{
			uint8_t nonce[10] = {1,2,3,4,5,6,7,8,9,10};
			uint8_t aad[12] = "authdata!!!";
			uint8_t pt[20], ct_buf[20], dec_buf[20];
			for (i = 0; i < 20; i++)
				pt[i] = i;

			int tag_lens[] = { 6, 10, 14 };
			for (t = 0; t < 3; t++) {
				uint8_t tag_buf[16];
				size_t olen;

				mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
				mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, nonce, 10);
				mbedcrypto_aes_ccm_set_len(&cctx, 11, 20, tag_lens[t]);
				mbedcrypto_aes_ccm_update_aad(&cctx, aad, 11);
				mbedcrypto_aes_ccm_update(&cctx, pt, 20, ct_buf, &olen);
				mbedcrypto_aes_ccm_final(&cctx, tag_buf, tag_lens[t]);
				/* KAT: verify against OpenSSL 3.0.13 reference */
				CHECK(hexcmp(ct_buf, "f4ea76ca3e5dd14ab8ba56ee5e86c4f956e9bbdd", 20) == 0, EBADMSG);
				if (tag_lens[t] == 6)
					CHECK(hexcmp(tag_buf, "0dc26b3f78c1", 6) == 0, EBADMSG);
				else if (tag_lens[t] == 10)
					CHECK(hexcmp(tag_buf, "a2a3d05c024518715244", 10) == 0, EBADMSG);
				else if (tag_lens[t] == 14)
					CHECK(hexcmp(tag_buf, "9c4efe99ced2979f4a4bd3181e71", 14) == 0, EBADMSG);
				mbedcrypto_aes_ccm_cleanup(&cctx);

				mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
				mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_DECRYPT, nonce, 10);
				mbedcrypto_aes_ccm_set_len(&cctx, 11, 20, tag_lens[t]);
				mbedcrypto_aes_ccm_update_aad(&cctx, aad, 11);
				mbedcrypto_aes_ccm_update(&cctx, ct_buf, 20, dec_buf, &olen);
				int ret = mbedcrypto_aes_ccm_final(&cctx, tag_buf, tag_lens[t]);
				CHECK(ret == 0 && memcmp(dec_buf, pt, 20) == 0, EBADMSG);
				mbedcrypto_aes_ccm_cleanup(&cctx);
			}
		}
	}

	/* --- Multi-update AAD tests --- */
	{
		struct mbedcrypto_aes_ccm_ctx cctx;
		uint8_t key[16];
		hex2bin("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", key, 16);
		uint8_t nonce[8] = {1,2,3,4,5,6,7,8};
		uint8_t aad[16] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
		                   0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00};
		uint8_t pt[24], ct_ref[24], tag_ref[8];
		uint8_t ct_out[24], tag_out[8], dec_out[24];
		size_t olen;
		for (i = 0; i < 24; i++)
			pt[i] = i;

		/* Reference: single-shot AAD */
		mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
		mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, nonce, 8);
		mbedcrypto_aes_ccm_set_len(&cctx, 16, 24, 8);
		mbedcrypto_aes_ccm_update_aad(&cctx, aad, 16);
		mbedcrypto_aes_ccm_update(&cctx, pt, 24, ct_ref, &olen);
		mbedcrypto_aes_ccm_final(&cctx, tag_ref, 8);
		/* KAT: verify against OpenSSL 3.0.13 reference */
		CHECK(hexcmp(ct_ref, "4e3e13081da81f855e3cd86d572cbbdac52a880b49d7a6c5", 24) == 0, EBADMSG);
		CHECK(hexcmp(tag_ref, "295c34fe775f4927", 8) == 0, EBADMSG);
		mbedcrypto_aes_ccm_cleanup(&cctx);

		/* Multi-update AAD: split 16 bytes as 7+5+4 */
		mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
		mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, nonce, 8);
		mbedcrypto_aes_ccm_set_len(&cctx, 16, 24, 8);
		mbedcrypto_aes_ccm_update_aad(&cctx, aad, 7);
		mbedcrypto_aes_ccm_update_aad(&cctx, aad + 7, 5);
		mbedcrypto_aes_ccm_update_aad(&cctx, aad + 12, 4);
		mbedcrypto_aes_ccm_update(&cctx, pt, 24, ct_out, &olen);
		mbedcrypto_aes_ccm_final(&cctx, tag_out, 8);
		CHECK(memcmp(ct_out, ct_ref, 24) == 0, EBADMSG);
		CHECK(memcmp(tag_out, tag_ref, 8) == 0, EBADMSG);
		mbedcrypto_aes_ccm_cleanup(&cctx);

		/* Multi-update AAD: byte-by-byte */
		mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
		mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, nonce, 8);
		mbedcrypto_aes_ccm_set_len(&cctx, 16, 24, 8);
		for (i = 0; i < 16; i++)
			mbedcrypto_aes_ccm_update_aad(&cctx, aad + i, 1);
		mbedcrypto_aes_ccm_update(&cctx, pt, 24, ct_out, &olen);
		mbedcrypto_aes_ccm_final(&cctx, tag_out, 8);
		CHECK(memcmp(ct_out, ct_ref, 24) == 0, EBADMSG);
		CHECK(memcmp(tag_out, tag_ref, 8) == 0, EBADMSG);
		mbedcrypto_aes_ccm_cleanup(&cctx);

		/* Decrypt with multi-update AAD */
		mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
		mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_DECRYPT, nonce, 8);
		mbedcrypto_aes_ccm_set_len(&cctx, 16, 24, 8);
		mbedcrypto_aes_ccm_update_aad(&cctx, aad, 7);
		mbedcrypto_aes_ccm_update_aad(&cctx, aad + 7, 5);
		mbedcrypto_aes_ccm_update_aad(&cctx, aad + 12, 4);
		mbedcrypto_aes_ccm_update(&cctx, ct_ref, 24, dec_out, &olen);
		int ret = mbedcrypto_aes_ccm_final(&cctx, tag_ref, 8);
		CHECK(ret == 0 && memcmp(dec_out, pt, 24) == 0, EBADMSG);
		mbedcrypto_aes_ccm_cleanup(&cctx);
	}

	/* --- Multi-update partial block data tests --- */
	{
		struct mbedcrypto_aes_ccm_ctx cctx;
		uint8_t key[16];
		hex2bin("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", key, 16);
		uint8_t nonce[8] = {1,2,3,4,5,6,7,8};
		uint8_t aad[3] = {0xaa, 0xbb, 0xcc};
		uint8_t pt[24], ct_ref[24], tag_ref[8];
		size_t olen;
		for (i = 0; i < 24; i++)
			pt[i] = i;

		/* Reference: single-shot PT update */
		mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
		mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, nonce, 8);
		mbedcrypto_aes_ccm_set_len(&cctx, 3, 24, 8);
		mbedcrypto_aes_ccm_update_aad(&cctx, aad, 3);
		mbedcrypto_aes_ccm_update(&cctx, pt, 24, ct_ref, &olen);
		mbedcrypto_aes_ccm_final(&cctx, tag_ref, 8);
		mbedcrypto_aes_ccm_cleanup(&cctx);

		/* Partial block multi-update: 3+7+5+4+5 = 24 */
		{
			uint8_t ct_out[24], tag_out[8];
			size_t chunks[] = { 3, 7, 5, 4, 5 };
			size_t off = 0, ct_off = 0;

			mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
			mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, nonce, 8);
			mbedcrypto_aes_ccm_set_len(&cctx, 3, 24, 8);
			mbedcrypto_aes_ccm_update_aad(&cctx, aad, 3);
			for (i = 0; i < sizeof(chunks)/sizeof(chunks[0]); i++) {
				size_t o = 0;
				mbedcrypto_aes_ccm_update(&cctx, pt + off, chunks[i], ct_out + ct_off, &o);
				off += chunks[i];
				ct_off += o;
			}
			mbedcrypto_aes_ccm_final(&cctx, tag_out, 8);
			CHECK(memcmp(ct_out, ct_ref, 24) == 0, EBADMSG);
			CHECK(memcmp(tag_out, tag_ref, 8) == 0, EBADMSG);
			mbedcrypto_aes_ccm_cleanup(&cctx);
		}

		/* Byte-by-byte data update */
		{
			uint8_t ct_out[24], tag_out[8];
			size_t ct_off = 0;

			mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
			mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, nonce, 8);
			mbedcrypto_aes_ccm_set_len(&cctx, 3, 24, 8);
			mbedcrypto_aes_ccm_update_aad(&cctx, aad, 3);
			for (i = 0; i < 24; i++) {
				size_t o = 0;
				mbedcrypto_aes_ccm_update(&cctx, pt + i, 1, ct_out + ct_off, &o);
				ct_off += o;
			}
			mbedcrypto_aes_ccm_final(&cctx, tag_out, 8);
			CHECK(memcmp(ct_out, ct_ref, 24) == 0, EBADMSG);
			CHECK(memcmp(tag_out, tag_ref, 8) == 0, EBADMSG);
			mbedcrypto_aes_ccm_cleanup(&cctx);
		}

		/* Combined: multi-update AD (1+2) + partial block data (3+7+5+4+5) */
		{
			uint8_t ct_out[24], tag_out[8];
			size_t chunks[] = { 3, 7, 5, 4, 5 };
			size_t off = 0, ct_off = 0;

			mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
			mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, nonce, 8);
			mbedcrypto_aes_ccm_set_len(&cctx, 3, 24, 8);
			mbedcrypto_aes_ccm_update_aad(&cctx, aad, 1);
			mbedcrypto_aes_ccm_update_aad(&cctx, aad + 1, 2);
			for (i = 0; i < sizeof(chunks)/sizeof(chunks[0]); i++) {
				size_t o = 0;
				mbedcrypto_aes_ccm_update(&cctx, pt + off, chunks[i], ct_out + ct_off, &o);
				off += chunks[i];
				ct_off += o;
			}
			mbedcrypto_aes_ccm_final(&cctx, tag_out, 8);
			CHECK(memcmp(ct_out, ct_ref, 24) == 0, EBADMSG);
			CHECK(memcmp(tag_out, tag_ref, 8) == 0, EBADMSG);
			mbedcrypto_aes_ccm_cleanup(&cctx);
		}
	}

	/* In-place multi-part CCM encrypt/decrypt */
	{
		uint8_t ck[16], cn[8] = {1,2,3,4,5,6,7,8};
		uint8_t caad[3] = {0xaa, 0xbb, 0xcc};
		uint8_t cpt[24], cct_ref[24], ctag_ref[8];
		size_t ol;
		hex2bin("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", ck, 16);
		for (i = 0; i < 24; i++)
			cpt[i] = i;

		/* Reference */
		mbedcrypto_aes_ccm_setkey(&cctx, ck, 128);
		mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, cn, 8);
		mbedcrypto_aes_ccm_set_len(&cctx, 3, 24, 8);
		mbedcrypto_aes_ccm_update_aad(&cctx, caad, 3);
		mbedcrypto_aes_ccm_update(&cctx, cpt, 24, cct_ref, &ol);
		mbedcrypto_aes_ccm_final(&cctx, ctag_ref, 8);
		mbedcrypto_aes_ccm_cleanup(&cctx);

		/* In-place partial chunks (3+7+5+4+5=24) enc+dec */
		{
			uint8_t buf[24], tg[8];
			size_t chunks[] = { 3, 7, 5, 4, 5 };
			memcpy(buf, cpt, 24);
			mbedcrypto_aes_ccm_setkey(&cctx, ck, 128);
			mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, cn, 8);
			mbedcrypto_aes_ccm_set_len(&cctx, 3, 24, 8);
			mbedcrypto_aes_ccm_update_aad(&cctx, caad, 3);
			size_t off = 0, total = 0;
			for (i = 0; i < 5; i++) {
				size_t o;
				mbedcrypto_aes_ccm_update(&cctx, buf + off, chunks[i],
						buf + total, &o);
				off += chunks[i]; total += o;
			}
			mbedcrypto_aes_ccm_final(&cctx, tg, 8);
			CHECK(memcmp(buf, cct_ref, 24) == 0
					&& memcmp(tg, ctag_ref, 8) == 0, EBADMSG);
			mbedcrypto_aes_ccm_cleanup(&cctx);

			/* decrypt in-place */
			mbedcrypto_aes_ccm_setkey(&cctx, ck, 128);
			mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_DECRYPT, cn, 8);
			mbedcrypto_aes_ccm_set_len(&cctx, 3, 24, 8);
			mbedcrypto_aes_ccm_update_aad(&cctx, caad, 3);
			off = 0; total = 0;
			for (i = 0; i < 5; i++) {
				size_t o;
				mbedcrypto_aes_ccm_update(&cctx, buf + off, chunks[i],
						buf + total, &o);
				off += chunks[i]; total += o;
			}
			int r = mbedcrypto_aes_ccm_final(&cctx, ctag_ref, 8);
			CHECK(r == 0 && memcmp(buf, cpt, 24) == 0, EBADMSG);
			mbedcrypto_aes_ccm_cleanup(&cctx);
		}

		/* In-place byte-by-byte enc+dec */
		{
			uint8_t buf[24], tg[8];
			memcpy(buf, cpt, 24);
			mbedcrypto_aes_ccm_setkey(&cctx, ck, 128);
			mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, cn, 8);
			mbedcrypto_aes_ccm_set_len(&cctx, 3, 24, 8);
			mbedcrypto_aes_ccm_update_aad(&cctx, caad, 3);
			size_t total = 0;
			for (i = 0; i < 24; i++) {
				size_t o;
				mbedcrypto_aes_ccm_update(&cctx, buf + i, 1,
						buf + total, &o);
				total += o;
			}
			mbedcrypto_aes_ccm_final(&cctx, tg, 8);
			CHECK(memcmp(buf, cct_ref, 24) == 0
					&& memcmp(tg, ctag_ref, 8) == 0, EBADMSG);
			mbedcrypto_aes_ccm_cleanup(&cctx);

			mbedcrypto_aes_ccm_setkey(&cctx, ck, 128);
			mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_DECRYPT, cn, 8);
			mbedcrypto_aes_ccm_set_len(&cctx, 3, 24, 8);
			mbedcrypto_aes_ccm_update_aad(&cctx, caad, 3);
			total = 0;
			for (i = 0; i < 24; i++) {
				size_t o;
				mbedcrypto_aes_ccm_update(&cctx, buf + i, 1,
						buf + total, &o);
				total += o;
			}
			int r = mbedcrypto_aes_ccm_final(&cctx, ctag_ref, 8);
			CHECK(r == 0 && memcmp(buf, cpt, 24) == 0, EBADMSG);
			mbedcrypto_aes_ccm_cleanup(&cctx);
		}
	}

	/* Authentication failure: tampered ciphertext */
	{
		uint8_t nonce[8] = {1,2,3,4,5,6,7,8};
		uint8_t aad0[3] = {0xaa, 0xbb, 0xcc};
		uint8_t pt0[24], ct0[24], dec0[24], tag0[8];
		size_t olen;
		for (i = 0; i < 24; i++)
			pt0[i] = i;

		mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
		mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_ENCRYPT, nonce, 8);
		mbedcrypto_aes_ccm_set_len(&cctx, 3, 24, 8);
		mbedcrypto_aes_ccm_update_aad(&cctx, aad0, 3);
		mbedcrypto_aes_ccm_update(&cctx, pt0, 24, ct0, &olen);
		mbedcrypto_aes_ccm_final(&cctx, tag0, 8);
		mbedcrypto_aes_ccm_cleanup(&cctx);

		/* Tamper ciphertext */
		ct0[5] ^= 0x01;
		mbedcrypto_aes_ccm_setkey(&cctx, key, 128);
		mbedcrypto_aes_ccm_start(&cctx, MBEDCRYPTO_AES_DECRYPT, nonce, 8);
		mbedcrypto_aes_ccm_set_len(&cctx, 3, 24, 8);
		mbedcrypto_aes_ccm_update_aad(&cctx, aad0, 3);
		mbedcrypto_aes_ccm_update(&cctx, ct0, 24, dec0, &olen);
		uint8_t ctag2[8];
		int r = mbedcrypto_aes_ccm_final(&cctx, ctag2, 8);
		CHECK(r == 0 && memcmp(ctag2, tag0, 8) != 0, EBADMSG);
		mbedcrypto_aes_ccm_cleanup(&cctx);
	}

	/* Large-data CCM roundtrip (1KB, 4KB) */
	{
		static uint8_t cpt[4096], cct[4096], cdec[4096], ctag[16];
		uint8_t ck[16], cn[12], caad[32];

		for (i = 0; i < 16; i++)
			ck[i] = i * 11 + 3;
		for (i = 0; i < 12; i++)
			cn[i] = i + 0x10;
		for (i = 0; i < 32; i++)
			caad[i] = i ^ 0xBB;
		for (i = 0; i < 4096; i++)
			cpt[i] = i * 23 + 9;

		size_t dlens[] = { 1024, 4096 };
		for (d = 0; d < 2; d++) {
			size_t dlen = dlens[d];

			/* One-shot encrypt */
			struct mbedcrypto_aes_ccm_ctx cc;
			mbedcrypto_aes_ccm_setkey(&cc, ck, 128);
			mbedcrypto_aes_ccm_encrypt(&cc, cn, 12, caad, 32,
				cpt, dlen, cct, ctag, 16);
			/* KAT: verify 1KB against OpenSSL 3.0.13 reference */
			if (dlen == 1024) {
				CHECK(hexcmp(ctag, "ee750db73ab40719940971901344d2c3", 16) == 0, EBADMSG);
				CHECK(hexcmp(cct, "705563e1155d0acdb9ff4ef47f85e75d", 16) == 0, EBADMSG);
				CHECK(hexcmp(cct + 1008, "c311b5aad87f98d051eec276aa79d876", 16) == 0, EBADMSG);
			}
			mbedcrypto_aes_ccm_cleanup(&cc);

			/* One-shot decrypt */
			mbedcrypto_aes_ccm_setkey(&cc, ck, 128);
			int r = mbedcrypto_aes_ccm_decrypt(&cc, cn, 12, caad, 32,
				cct, dlen, cdec, ctag, 16);
			CHECK(r == 0 && memcmp(cdec, cpt, dlen) == 0, EBADMSG);
			mbedcrypto_aes_ccm_cleanup(&cc);

			/* Multi-part 100-byte chunks */
			mbedcrypto_aes_ccm_setkey(&cc, ck, 128);
			mbedcrypto_aes_ccm_start(&cc, MBEDCRYPTO_AES_ENCRYPT, cn, 12);
			mbedcrypto_aes_ccm_set_len(&cc, 32, dlen, 16);
			mbedcrypto_aes_ccm_update_aad(&cc, caad, 32);
			size_t total = 0;
			for (off = 0; off < dlen; off += 100) {
				size_t chunk = (off + 100 <= dlen) ? 100 : (dlen - off);
				size_t o;
				mbedcrypto_aes_ccm_update(&cc, cpt + off, chunk,
					cdec + total, &o);
				total += o;
			}
			uint8_t dtag[16];
			r = mbedcrypto_aes_ccm_final(&cc, dtag, 16);
			CHECK(r == 0 && memcmp(cdec, cct, dlen) == 0
				&& memcmp(dtag, ctag, 16) == 0, EBADMSG);
			mbedcrypto_aes_ccm_cleanup(&cc);
		}
	}

out:
	TEST_END();
}

static void test_cmac(void)
{
	TEST_START("CMAC");
	struct mbedcrypto_cmac_ctx cctx;

	/* NIST SP 800-38B - AES-128 CMAC */
	uint8_t key[16], mac[16];
	hex2bin("2b7e151628aed2a6abf7158809cf4f3c", key, 16);

	/* Empty message */
	mbedcrypto_cmac_setkey(&cctx, key, 128);
	mbedcrypto_cmac_final(&cctx, mac);
	CHECK(hexcmp(mac, "bb1d6929e95937287fa37d129b756746", 16) == 0, EBADMSG);
	mbedcrypto_cmac_cleanup(&cctx);

	/* 16-byte message */
	uint8_t msg16[16];
	hex2bin("6bc1bee22e409f96e93d7e117393172a", msg16, 16);
	mbedcrypto_cmac_setkey(&cctx, key, 128);
	mbedcrypto_cmac_update(&cctx, msg16, 16);
	mbedcrypto_cmac_final(&cctx, mac);
	CHECK(hexcmp(mac, "070a16b46b4d4144f79bdd9dd04a287c", 16) == 0, EBADMSG);
	mbedcrypto_cmac_cleanup(&cctx);

	/* 40-byte message (not block-aligned) */
	uint8_t msg40[40];
	hex2bin("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", msg40, 40);
	mbedcrypto_cmac_setkey(&cctx, key, 128);
	mbedcrypto_cmac_update(&cctx, msg40, 40);
	mbedcrypto_cmac_final(&cctx, mac);
	CHECK(hexcmp(mac, "dfa66747de9ae63030ca32611497c827", 16) == 0, EBADMSG);
	mbedcrypto_cmac_cleanup(&cctx);

	/* 64-byte message */
	uint8_t msg64[64];
	hex2bin("6bc1bee22e409f96e93d7e117393172a"
		"ae2d8a571e03ac9c9eb76fac45af8e51"
		"30c81c46a35ce411e5fbc1191a0a52ef"
		"f69f2445df4f9b17ad2b417be66c3710", msg64, 64);
	mbedcrypto_cmac_setkey(&cctx, key, 128);
	mbedcrypto_cmac_update(&cctx, msg64, 64);
	mbedcrypto_cmac_final(&cctx, mac);
	CHECK(hexcmp(mac, "51f0bebf7e3b9d92fc49741779363cfe", 16) == 0, EBADMSG);
	mbedcrypto_cmac_cleanup(&cctx);

	/* Streaming: 40 bytes in 3 parts */
	mbedcrypto_cmac_setkey(&cctx, key, 128);
	mbedcrypto_cmac_update(&cctx, msg40, 10);
	mbedcrypto_cmac_update(&cctx, msg40 + 10, 10);
	mbedcrypto_cmac_update(&cctx, msg40 + 20, 20);
	mbedcrypto_cmac_final(&cctx, mac);
	CHECK(hexcmp(mac, "dfa66747de9ae63030ca32611497c827", 16) == 0, EBADMSG);
	mbedcrypto_cmac_cleanup(&cctx);

	/* AES-256 CMAC */
	uint8_t key256[32];
	hex2bin("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key256, 32);
	mbedcrypto_cmac_setkey(&cctx, key256, 256);
	mbedcrypto_cmac_update(&cctx, msg16, 16);
	mbedcrypto_cmac_final(&cctx, mac);
	CHECK(hexcmp(mac, "28a7023f452e8f82bd4bf28d8c37c35c", 16) == 0, EBADMSG);
	mbedcrypto_cmac_cleanup(&cctx);

	/* AES-192 CMAC (NIST SP 800-38B) */
	uint8_t key192[24];
	hex2bin("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", key192, 24);
	mbedcrypto_cmac_setkey(&cctx, key192, 192);
	mbedcrypto_cmac_update(&cctx, msg16, 16);
	mbedcrypto_cmac_final(&cctx, mac);
	CHECK(hexcmp(mac, "9e99a7bf31e710900662f65e617c5184", 16) == 0, EBADMSG);
	mbedcrypto_cmac_cleanup(&cctx);

	/* Reset and re-use */
	mbedcrypto_cmac_setkey(&cctx, key, 128);
	mbedcrypto_cmac_update(&cctx, msg16, 16);
	mbedcrypto_cmac_final(&cctx, mac);
	CHECK(hexcmp(mac, "070a16b46b4d4144f79bdd9dd04a287c", 16) == 0, EBADMSG);
	mbedcrypto_cmac_reset(&cctx);
	mbedcrypto_cmac_update(&cctx, msg64, 64);
	mbedcrypto_cmac_final(&cctx, mac);
	CHECK(hexcmp(mac, "51f0bebf7e3b9d92fc49741779363cfe", 16) == 0, EBADMSG);
	mbedcrypto_cmac_cleanup(&cctx);

out:
	TEST_END();
}

static void test_chacha20(void)
{
	TEST_START("ChaCha20/Poly1305");
	uint8_t out[128];
	int i = 0;

	/* RFC 8439 Section 2.4.2 - ChaCha20 test vector */
	{
		uint8_t key[32], nonce[12];
		hex2bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key, 32);
		hex2bin("000000000000004a00000000", nonce, 12);
		const uint8_t *sunscreen = (const uint8_t *)
			"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
		size_t len = strlen((const char *)sunscreen);

		struct mbedcrypto_chacha20_ctx cctx;
		mbedcrypto_chacha20_init(&cctx);
		mbedcrypto_chacha20_setkey(&cctx, key);
		mbedcrypto_chacha20_set_nonce(&cctx, nonce, 1);
		mbedcrypto_chacha20_update(&cctx, sunscreen, len, out);
		CHECK(hexcmp(out, "6e2e359a2568f98041ba0728dd0d6981"
			"e97e7aec1d4360c20a27afccfd9fae0b"
			"f91b65c5524733ab8f593dabcd62b357"
			"1639d624e65152ab8f530c359f0861d807"
			"ca0dbf500d6a6156a38e088a22b65e52"
			"bc514d16ccf806818ce91ab77937365a"
			"f90bbf74a35be6b40b8eedf2785e42874d", len) == 0, EBADMSG);
		mbedcrypto_chacha20_cleanup(&cctx);
	}

	/* Poly1305 MAC - RFC 8439 Section 2.5.2 */
	{
		uint8_t key[32], tag[16];
		hex2bin("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", key, 32);
		const char *msg = "Cryptographic Forum Research Group";

		struct mbedcrypto_poly1305_ctx pctx;
		mbedcrypto_poly1305_init(&pctx);
		mbedcrypto_poly1305_setkey(&pctx, key);
		mbedcrypto_poly1305_update(&pctx, (const uint8_t *)msg, strlen(msg));
		mbedcrypto_poly1305_final(&pctx, tag);
		CHECK(hexcmp(tag, "a8061dc1305136c6c22b8baf0c0127a9", 16) == 0, EBADMSG);
		mbedcrypto_poly1305_cleanup(&pctx);
	}

	/* ChaCha20-Poly1305 AEAD - RFC 8439 Section 2.8.2 */
	{
		uint8_t key[32], nonce[12], aad[12], pt[114];
		hex2bin("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", key, 32);
		hex2bin("070000004041424344454647", nonce, 12);
		hex2bin("50515253c0c1c2c3c4c5c6c7", aad, 12);
		memcpy(pt, "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.", 114);

		uint8_t enc[114], enc_tag[16];
		struct mbedcrypto_chachapoly_ctx cpctx;
		mbedcrypto_chachapoly_init(&cpctx);
		mbedcrypto_chachapoly_setkey(&cpctx, key);
		mbedcrypto_chachapoly_start(&cpctx, nonce, MBEDCRYPTO_AES_ENCRYPT);
		mbedcrypto_chachapoly_update_aad(&cpctx, aad, 12);
		mbedcrypto_chachapoly_update(&cpctx, pt, 114, enc);
		mbedcrypto_chachapoly_final(&cpctx, enc_tag);
		CHECK(hexcmp(enc_tag, "1ae10b594f09e26a7e902ecbd0600691", 16) == 0, EBADMSG);
		mbedcrypto_chachapoly_cleanup(&cpctx);

		/* Decrypt and verify */
		uint8_t dec_buf[114], dec_tag[16];
		mbedcrypto_chachapoly_init(&cpctx);
		mbedcrypto_chachapoly_setkey(&cpctx, key);
		mbedcrypto_chachapoly_start(&cpctx, nonce, MBEDCRYPTO_AES_DECRYPT);
		mbedcrypto_chachapoly_update_aad(&cpctx, aad, 12);
		mbedcrypto_chachapoly_update(&cpctx, enc, 114, dec_buf);
		mbedcrypto_chachapoly_final(&cpctx, dec_tag);
		CHECK(memcmp(dec_buf, pt, 114) == 0, EBADMSG);
		CHECK(memcmp(dec_tag, enc_tag, 16) == 0, EBADMSG);
		mbedcrypto_chachapoly_cleanup(&cpctx);
	}

	/* ChaCha20 streaming: encrypt byte by byte */
	{
		uint8_t key[32], nonce[12];
		test_rng(NULL, key, 32);
		memset(nonce, 0, 12);
		uint8_t pt[64], ct_all[64], ct_bbb[64];

		for (i = 0; i < 64; i++)
			pt[i] = i;

		struct mbedcrypto_chacha20_ctx cctx;
		mbedcrypto_chacha20_init(&cctx);
		mbedcrypto_chacha20_setkey(&cctx, key);
		mbedcrypto_chacha20_set_nonce(&cctx, nonce, 0);
		mbedcrypto_chacha20_update(&cctx, pt, 64, ct_all);
		mbedcrypto_chacha20_cleanup(&cctx);

		mbedcrypto_chacha20_init(&cctx);
		mbedcrypto_chacha20_setkey(&cctx, key);
		mbedcrypto_chacha20_set_nonce(&cctx, nonce, 0);
		for (i = 0; i < 64; i++)
			mbedcrypto_chacha20_update(&cctx, pt + i, 1, ct_bbb + i);
		mbedcrypto_chacha20_cleanup(&cctx);

		CHECK(memcmp(ct_all, ct_bbb, 64) == 0, EBADMSG);
	}

	/* ChaCha20-Poly1305 authentication failure: tampered ciphertext */
	{
		uint8_t key[32], nonce[12], aad[8], pt[48], enc[48], tag[16];
		test_rng(NULL, key, 32);
		test_rng(NULL, nonce, 12);
		test_rng(NULL, aad, 8);
		for (i = 0; i < 48; i++)
			pt[i] = i;

		struct mbedcrypto_chachapoly_ctx cpctx;
		mbedcrypto_chachapoly_init(&cpctx);
		mbedcrypto_chachapoly_setkey(&cpctx, key);
		mbedcrypto_chachapoly_start(&cpctx, nonce, MBEDCRYPTO_AES_ENCRYPT);
		mbedcrypto_chachapoly_update_aad(&cpctx, aad, 8);
		mbedcrypto_chachapoly_update(&cpctx, pt, 48, enc);
		mbedcrypto_chachapoly_final(&cpctx, tag);
		mbedcrypto_chachapoly_cleanup(&cpctx);

		/* Tamper ciphertext and recompute tag -> tags should differ */
		uint8_t enc2[48], dec[48], dec_tag[16];
		memcpy(enc2, enc, 48);
		enc2[10] ^= 0x01;

		mbedcrypto_chachapoly_init(&cpctx);
		mbedcrypto_chachapoly_setkey(&cpctx, key);
		mbedcrypto_chachapoly_start(&cpctx, nonce, MBEDCRYPTO_AES_DECRYPT);
		mbedcrypto_chachapoly_update_aad(&cpctx, aad, 8);
		mbedcrypto_chachapoly_update(&cpctx, enc2, 48, dec);
		mbedcrypto_chachapoly_final(&cpctx, dec_tag);
		CHECK(memcmp(dec_tag, tag, 16) != 0, EBADMSG);
		mbedcrypto_chachapoly_cleanup(&cpctx);
	}

out:
	TEST_END();
}

static void test_pbkdf2(void)
{
	TEST_START("PBKDF2");
	uint8_t out[32];

	/* RFC 6070 Test Vector 1: PBKDF2-HMAC-SHA1 */
	int ret = mbedcrypto_pbkdf2_derive(MBEDCRYPTO_HASH_SHA1,
		(const uint8_t *)"password", 8,
		(const uint8_t *)"salt", 4, 1, out, 20);
	CHECK(ret == 0, ret);
	CHECK(hexcmp(out, "0c60c80f961f0e71f3a9b524af6012062fe037a6", 20) == 0, EBADMSG);

	/* RFC 6070 Test Vector 2: 2 iterations */
	ret = mbedcrypto_pbkdf2_derive(MBEDCRYPTO_HASH_SHA1,
		(const uint8_t *)"password", 8,
		(const uint8_t *)"salt", 4, 2, out, 20);
	CHECK(ret == 0, ret);
	CHECK(hexcmp(out, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", 20) == 0, EBADMSG);

	/* RFC 6070 Test Vector 3: 4096 iterations */
	ret = mbedcrypto_pbkdf2_derive(MBEDCRYPTO_HASH_SHA1,
		(const uint8_t *)"password", 8,
		(const uint8_t *)"salt", 4, 4096, out, 20);
	CHECK(ret == 0, ret);
	CHECK(hexcmp(out, "4b007901b765489abead49d926f721d065a429c1", 20) == 0, EBADMSG);

	/* PBKDF2-HMAC-SHA256 - RFC 7914 Sec 11 */
	ret = mbedcrypto_pbkdf2_derive(MBEDCRYPTO_HASH_SHA256,
		(const uint8_t *)"password", 8,
		(const uint8_t *)"salt", 4, 1, out, 32);
	CHECK(ret == 0, ret);
	CHECK(hexcmp(out, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b", 32) == 0, EBADMSG);

	/* Different output lengths */
	ret = mbedcrypto_pbkdf2_derive(MBEDCRYPTO_HASH_SHA256,
		(const uint8_t *)"pass", 4,
		(const uint8_t *)"sa", 2, 10, out, 16);
	CHECK(ret == 0, ret);

out:
	TEST_END();
}

static void test_hkdf(void)
{
	TEST_START("HKDF");
	uint8_t okm[82], prk[32];

	/* RFC 5869 Test Case 1 */
	uint8_t ikm1[22], salt1[13], info1[10];
	int i = 0;
	hex2bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", ikm1, 22);
	hex2bin("000102030405060708090a0b0c", salt1, 13);
	hex2bin("f0f1f2f3f4f5f6f7f8f9", info1, 10);

	int ret = mbedcrypto_hkdf_derive(salt1, 13, ikm1, 22, info1, 10, okm, 42);
	CHECK(ret == 0, ret);
	CHECK(hexcmp(okm, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", 42) == 0, EBADMSG);

	/* Separate extract + expand */
	ret = mbedcrypto_hkdf_extract(salt1, 13, ikm1, 22, prk);
	CHECK(ret == 0, ret);
	CHECK(hexcmp(prk, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", 32) == 0, EBADMSG);

	ret = mbedcrypto_hkdf_expand(prk, info1, 10, okm, 42);
	CHECK(ret == 0, ret);
	CHECK(hexcmp(okm, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", 42) == 0, EBADMSG);

	/* RFC 5869 Test Case 2 - longer inputs */
	uint8_t ikm2[80], salt2[80], info2[80];
	for (i = 0; i < 80; i++) {
		ikm2[i] = i;
		salt2[i] = 0x60 + i;
		info2[i] = 0xb0 + i;
	}
	ret = mbedcrypto_hkdf_derive(salt2, 80, ikm2, 80, info2, 80, okm, 82);
	CHECK(ret == 0, ret);
	CHECK(hexcmp(okm, "b11e398dc80327a1c8e7f78c596a4934"
		"4f012eda2d4efad8a050cc4c19afa97c"
		"59045a99cac7827271cb41c65e590e09"
		"da3275600c2f09b8367793a9aca3db71"
		"cc30c58179ec3e87c14c01d5c1f3434f"
		"1d87", 82) == 0, EBADMSG);

	/* Zero-length salt and info */
	ret = mbedcrypto_hkdf_derive(NULL, 0, ikm1, 22, NULL, 0, okm, 42);
	CHECK(ret == 0, ret);

out:
	TEST_END();
}

static void test_aes_siv(void)
{
	TEST_START("AES-SIV");
	struct mbedcrypto_aes_siv_ctx sctx;

	/* RFC 5297 A.1 - AES-SIV-CMAC-256 (key=256 bits = 32 bytes) */
	uint8_t key[32], aad[24], pt[14];
	size_t i = 0, t = 0;
	hex2bin("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", key, 32);
	hex2bin("101112131415161718191a1b1c1d1e1f2021222324252627", aad, 24);
	hex2bin("112233445566778899aabbccddee", pt, 14);

	uint8_t ct_out[14], tag_out[16], dec_out[14];
	mbedcrypto_aes_siv_init(&sctx);
	mbedcrypto_aes_siv_setkey(&sctx, key, 32);
	int ret = mbedcrypto_aes_siv_encrypt(&sctx, aad, 24, pt, 14, ct_out, tag_out);
	CHECK(ret == 0, ret);
	CHECK(hexcmp(tag_out, "85632d07c6e8f37f950acd320a2ecc93", 16) == 0, EBADMSG);
	CHECK(hexcmp(ct_out, "40c02b9690c4dc04daef7f6afe5c", 14) == 0, EBADMSG);
	mbedcrypto_aes_siv_cleanup(&sctx);

	/* Decrypt */
	mbedcrypto_aes_siv_init(&sctx);
	mbedcrypto_aes_siv_setkey(&sctx, key, 32);
	ret = mbedcrypto_aes_siv_decrypt(&sctx, aad, 24, ct_out, 14, dec_out, tag_out);
	CHECK(ret == 0, ret);
	CHECK(memcmp(dec_out, pt, 14) == 0, EBADMSG);
	mbedcrypto_aes_siv_cleanup(&sctx);

	/* Roundtrip with various lengths */
	size_t siv_lens[] = { 0, 1, 7, 15, 16, 17, 31, 32, 48 };
	for (t = 0; t < sizeof(siv_lens)/sizeof(siv_lens[0]); t++) {
		size_t len = siv_lens[t];
		uint8_t spt[48], sct[48], sdec[48], stag[16];
		for (i = 0; i < len; i++)
			spt[i] = i + t;

		mbedcrypto_aes_siv_init(&sctx);
		mbedcrypto_aes_siv_setkey(&sctx, key, 32);
		mbedcrypto_aes_siv_encrypt(&sctx, NULL, 0, spt, len, sct, stag);
		mbedcrypto_aes_siv_cleanup(&sctx);

		mbedcrypto_aes_siv_init(&sctx);
		mbedcrypto_aes_siv_setkey(&sctx, key, 32);
		ret = mbedcrypto_aes_siv_decrypt(&sctx, NULL, 0, sct, len, sdec, stag);
		CHECK(ret == 0, ret);
		if (len > 0)
			CHECK(memcmp(sdec, spt, len) == 0, EBADMSG);
		mbedcrypto_aes_siv_cleanup(&sctx);
	}

	/* AES-SIV-CMAC-384 roundtrip (48-byte key) */
	{
		uint8_t k48[48], spt[14], sct[14], sdec[14], stag[16];

		hex2bin("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"
			"6f6e6d6c6b6a6968"
			"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
			"0001020304050607", k48, 48);
		memcpy(spt, pt, 14);

		mbedcrypto_aes_siv_init(&sctx);
		mbedcrypto_aes_siv_setkey(&sctx, k48, 48);
		ret = mbedcrypto_aes_siv_encrypt(&sctx, aad, 24, spt, 14, sct, stag);
		CHECK(ret == 0, ret);
		mbedcrypto_aes_siv_cleanup(&sctx);

		mbedcrypto_aes_siv_init(&sctx);
		mbedcrypto_aes_siv_setkey(&sctx, k48, 48);
		ret = mbedcrypto_aes_siv_decrypt(&sctx, aad, 24, sct, 14, sdec, stag);
		CHECK(ret == 0, ret);
		CHECK(memcmp(sdec, spt, 14) == 0, EBADMSG);
		mbedcrypto_aes_siv_cleanup(&sctx);
	}

	/* AES-SIV-CMAC-512 roundtrip (64-byte key) */
	{
		uint8_t k64[64], spt[14], sct[14], sdec[14], stag[16];

		hex2bin("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"
			"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
			"00112233445566778899aabbccddeeff"
			"000102030405060708090a0b0c0d0e0f", k64, 64);
		memcpy(spt, pt, 14);

		mbedcrypto_aes_siv_init(&sctx);
		mbedcrypto_aes_siv_setkey(&sctx, k64, 64);
		ret = mbedcrypto_aes_siv_encrypt(&sctx, aad, 24, spt, 14, sct, stag);
		CHECK(ret == 0, ret);
		mbedcrypto_aes_siv_cleanup(&sctx);

		mbedcrypto_aes_siv_init(&sctx);
		mbedcrypto_aes_siv_setkey(&sctx, k64, 64);
		ret = mbedcrypto_aes_siv_decrypt(&sctx, aad, 24, sct, 14, sdec, stag);
		CHECK(ret == 0, ret);
		CHECK(memcmp(sdec, spt, 14) == 0, EBADMSG);
		mbedcrypto_aes_siv_cleanup(&sctx);
	}

	/* Authentication failure: tampered ciphertext */
	{
		uint8_t spt[14], sct[14], sdec[14], stag[16];
		memcpy(spt, pt, 14);
		mbedcrypto_aes_siv_init(&sctx);
		mbedcrypto_aes_siv_setkey(&sctx, key, 32);
		mbedcrypto_aes_siv_encrypt(&sctx, aad, 24, spt, 14, sct, stag);
		mbedcrypto_aes_siv_cleanup(&sctx);

		sct[3] ^= 0x01; /* tamper ciphertext */
		mbedcrypto_aes_siv_init(&sctx);
		mbedcrypto_aes_siv_setkey(&sctx, key, 32);
		ret = mbedcrypto_aes_siv_decrypt(&sctx, aad, 24, sct, 14, sdec, stag);
		CHECK(ret != 0, EBADMSG);
		mbedcrypto_aes_siv_cleanup(&sctx);
	}

	/* Authentication failure: tampered tag (SIV) */
	{
		uint8_t spt[14], sct[14], sdec[14], stag[16];
		memcpy(spt, pt, 14);
		mbedcrypto_aes_siv_init(&sctx);
		mbedcrypto_aes_siv_setkey(&sctx, key, 32);
		mbedcrypto_aes_siv_encrypt(&sctx, aad, 24, spt, 14, sct, stag);
		mbedcrypto_aes_siv_cleanup(&sctx);

		stag[0] ^= 0xFF; /* tamper SIV tag */
		mbedcrypto_aes_siv_init(&sctx);
		mbedcrypto_aes_siv_setkey(&sctx, key, 32);
		ret = mbedcrypto_aes_siv_decrypt(&sctx, aad, 24, sct, 14, sdec, stag);
		CHECK(ret != 0, EBADMSG);
		mbedcrypto_aes_siv_cleanup(&sctx);
	}

out:
	TEST_END();
}

#ifdef CONFIG_MBEDCRYPTO_SHA3
/* Ed25519 + SHA3-256 KAT: sign SHA3-256 hash of known message */
static const uint8_t ed25519_sha3_seed[] = {
	0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
	0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
	0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
	0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
};
static const uint8_t ed25519_sha3_pub[] = {
	0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
	0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
	0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
	0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
};
/* SHA3-256("test message for ed25519") */
static const uint8_t ed25519_sha3_msg[] = {
	0x5C, 0x11, 0xBB, 0x7E, 0x0F, 0xB0, 0xF2, 0x3F,
	0x5C, 0xF9, 0x03, 0x67, 0x03, 0xA3, 0x49, 0x7C,
	0x14, 0xAF, 0x9F, 0x71, 0xB6, 0xD6, 0x05, 0x9A,
	0x8B, 0xA4, 0xD2, 0x90, 0x06, 0x8D, 0xC0, 0xE5,
};
static const uint8_t ed25519_sha3_sig[] = {
	0xE5, 0x15, 0xF6, 0xC6, 0xA4, 0x5D, 0x16, 0x6A,
	0xBB, 0xDE, 0x79, 0xCF, 0xC8, 0xE1, 0x64, 0x06,
	0x2E, 0x2E, 0x7D, 0x52, 0xF0, 0xBB, 0xE3, 0x49,
	0x19, 0x94, 0xF7, 0x17, 0xD2, 0xA3, 0x87, 0xFF,
	0xB4, 0x94, 0x60, 0x67, 0x20, 0x95, 0x39, 0xB2,
	0xFF, 0xCB, 0xB0, 0x4A, 0x64, 0x5B, 0x09, 0x12,
	0x6F, 0x04, 0x9E, 0xDC, 0xE7, 0x63, 0x18, 0x47,
	0xFF, 0x43, 0x06, 0x48, 0x61, 0xD3, 0xF8, 0x04,
};
#endif

static void test_curve25519(void)
{
	TEST_START("Curve25519");
	size_t i = 0, t = 0;

	/* RFC 7748 Section 6.1 - X25519 DH */
	{
		uint8_t a_priv[32], a_pub[32], b_priv[32], b_pub[32];
		uint8_t secret_a[32], secret_b[32];
		hex2bin("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a_priv, 32);
		hex2bin("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b_priv, 32);

		mbedcrypto_x25519_calc_public(a_pub, a_priv);
		CHECK(hexcmp(a_pub, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", 32) == 0, EBADMSG);

		mbedcrypto_x25519_calc_public(b_pub, b_priv);
		CHECK(hexcmp(b_pub, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", 32) == 0, EBADMSG);

		mbedcrypto_x25519_calc_secret(secret_a, a_priv, b_pub);
		mbedcrypto_x25519_calc_secret(secret_b, b_priv, a_pub);
		CHECK(memcmp(secret_a, secret_b, 32) == 0, EBADMSG);
		CHECK(hexcmp(secret_a, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", 32) == 0, EBADMSG);
	}

	/* X25519 key generation and DH agreement */
	{
		uint8_t a_pub[32], a_priv[32], b_pub[32], b_priv[32];
		uint8_t sa[32], sb[32];
		mbedcrypto_x25519_gen_keypair(a_pub, a_priv, test_rng, NULL);
		mbedcrypto_x25519_gen_keypair(b_pub, b_priv, test_rng, NULL);
		mbedcrypto_x25519_calc_secret(sa, a_priv, b_pub);
		mbedcrypto_x25519_calc_secret(sb, b_priv, a_pub);
		CHECK(memcmp(sa, sb, 32) == 0, EBADMSG);
	}

	/* Ed25519 RFC 8032 Section 7.1 Test Vector 1 (known answer) */
	{
		uint8_t seed[32], priv[64], sig[64];
		uint8_t expected_pub[32], gen_pub[32];
		hex2bin("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed, 32);
		/* Public key verified against Python cryptography library */
		hex2bin("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", expected_pub, 32);

		/* Step 1: Check public key generation from known seed */
		int ret = mbedcrypto_ed25519_gen_keypair(gen_pub, priv, fixed_rng, seed);
		CHECK(ret == 0, ret);
		CHECK(memcmp(gen_pub, expected_pub, 32) == 0, EBADMSG);

		/* Step 2: Sign empty message */
		memcpy(priv, seed, 32);
		memcpy(priv + 32, expected_pub, 32);
		ret = mbedcrypto_ed25519_sign(sig, NULL, 0, priv);
		CHECK(ret == 0, ret);

		/* Step 3: Verify signature matches RFC 8032 expected value */
		CHECK(hexcmp(sig, "e5564300c360ac729086e2cc806e828a"
			"84877f1eb8e5d974d873e065224901555fb88215"
			"90a33bacc61e39701cf9b46bd25bf5f0595bbe24"
			"655141438e7a100b", 64) == 0, EBADMSG);

		ret = mbedcrypto_ed25519_verify(sig, NULL, 0, expected_pub);
		CHECK(ret == 0, ret);
	}

	/* Ed25519 sign/verify with generated keys */
	{
		uint8_t pub[32], priv[64];
		mbedcrypto_ed25519_gen_keypair(pub, priv, test_rng, NULL);

		uint8_t sig[64];
		const uint8_t msg[] = "test message for ed25519";
		int ret = mbedcrypto_ed25519_sign(sig, msg, sizeof(msg) - 1, priv);
		CHECK(ret == 0, ret);

		ret = mbedcrypto_ed25519_verify(sig, msg, sizeof(msg) - 1, pub);
		CHECK(ret == 0, ret);

		/* Tamper with message - should fail */
		uint8_t bad_msg[] = "test message for ed25519";
		bad_msg[0] = 'T';
		ret = mbedcrypto_ed25519_verify(sig, bad_msg, sizeof(bad_msg) - 1, pub);
		CHECK(ret != 0, EBADMSG);
	}

	/* Ed25519 with different message lengths */
	{
		uint8_t pub[32], priv[64], sig[64];
		mbedcrypto_ed25519_gen_keypair(pub, priv, test_rng, NULL);

		size_t lens[] = { 0, 1, 16, 64, 128, 255 };
		for (t = 0; t < sizeof(lens)/sizeof(lens[0]); t++) {
			uint8_t msg[256];
			for (i = 0; i < lens[t]; i++)
				msg[i] = i + t;
			int ret = mbedcrypto_ed25519_sign(sig, msg, lens[t], priv);
			CHECK(ret == 0, ret);
			ret = mbedcrypto_ed25519_verify(sig, msg, lens[t], pub);
			CHECK(ret == 0, ret);
		}
	}

	/* --- Extended coverage (merged from test_curve25519_ext) --- */

	/* RFC 8032 Section 7.1 - TEST_START 2 (1-byte message: 0x72) */
	{
		uint8_t seed[32], pub[32], priv[64], sig[64];
		hex2bin("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", seed, 32);

		int ret = mbedcrypto_ed25519_gen_keypair(pub, priv, fixed_rng, seed);
		CHECK(ret == 0, ret);
		CHECK(hexcmp(pub, "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", 32) == 0, EBADMSG);

		/* Reconstruct priv = seed || pub for sign */
		memcpy(priv, seed, 32);
		memcpy(priv + 32, pub, 32);

		uint8_t msg[1] = { 0x72 };
		ret = mbedcrypto_ed25519_sign(sig, msg, 1, priv);
		CHECK(ret == 0, ret);

		/* Verify signature matches RFC 8032 expected value */
		CHECK(hexcmp(sig, "92a009a9f0d4cab8720e820b5f642540"
			"a2b27b5416503f8fb3762223ebdb69da"
			"085ac1e43e15996e458f3613d0f11d8c"
			"387b2eaeb4302aeeb00d291612bb0c00",
			64) == 0, EBADMSG);

		ret = mbedcrypto_ed25519_verify(sig, msg, 1, pub);
		CHECK(ret == 0, ret);

		/* Tamper should fail */
		sig[0] ^= 1;
		ret = mbedcrypto_ed25519_verify(sig, msg, 1, pub);
		CHECK(ret != 0, EBADMSG);
	}

	/* Ed25519 multiple sign with same key: signatures differ when message differs */
	{
		uint8_t pub[32], priv[64], sig1[64], sig2[64];
		mbedcrypto_ed25519_gen_keypair(pub, priv, test_rng, NULL);

		uint8_t m1[16], m2[16];
		for (i = 0; i < 16; i++) { m1[i] = i; m2[i] = i + 0x80; }

		mbedcrypto_ed25519_sign(sig1, m1, 16, priv);
		mbedcrypto_ed25519_sign(sig2, m2, 16, priv);
		CHECK(memcmp(sig1, sig2, 64) != 0, EBADMSG);

		/* Same message => same sig (Ed25519 is deterministic) */
		uint8_t sig1b[64];
		mbedcrypto_ed25519_sign(sig1b, m1, 16, priv);
		CHECK(memcmp(sig1, sig1b, 64) == 0, EBADMSG);
	}

	/* X25519 edge: DH with self should produce consistent result */
	{
		uint8_t pub[32], priv[32], ss1[32], ss2[32];
		mbedcrypto_x25519_gen_keypair(pub, priv, test_rng, NULL);
		mbedcrypto_x25519_calc_secret(ss1, priv, pub);
		mbedcrypto_x25519_calc_secret(ss2, priv, pub);
		CHECK(memcmp(ss1, ss2, 32) == 0, EBADMSG);
	}

#ifdef CONFIG_MBEDCRYPTO_SHA3
	/* Ed25519 + SHA3-256 KAT: hash with SHA3, sign+verify */
	{
		struct mbedcrypto_sha3_ctx sha3ctx;
		uint8_t hash[32];
		uint8_t sig[MBEDCRYPTO_ED25519_SIG_SIZE];
		uint8_t priv[2 * MBEDCRYPTO_ED25519_KEY_SIZE];
		const char *raw_msg = "test message for ed25519";
		int ret = 0;

		mbedcrypto_sha3_init(&sha3ctx);
		ret = mbedcrypto_sha3_start(&sha3ctx,
				MBEDCRYPTO_SHA3_256);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_sha3_update(&sha3ctx,
				(const uint8_t *)raw_msg,
				strlen(raw_msg));
		CHECK(ret == 0, ret);
		ret = mbedcrypto_sha3_final(&sha3ctx, hash, 32);
		CHECK(ret == 0, ret);
		mbedcrypto_sha3_cleanup(&sha3ctx);
		CHECK(memcmp(hash, ed25519_sha3_msg, 32) == 0, EBADMSG);

		memcpy(priv, ed25519_sha3_seed, 32);
		memcpy(priv + 32, ed25519_sha3_pub, 32);

		ret = mbedcrypto_ed25519_sign(sig, hash, 32, priv);
		CHECK(ret == 0, ret);
		CHECK(memcmp(sig, ed25519_sha3_sig, 64) == 0, EBADMSG);
		ret = mbedcrypto_ed25519_verify(sig, hash, 32,
				ed25519_sha3_pub);
		CHECK(ret == 0, ret);
	}
#endif

out:
	TEST_END();
}

static void test_curve448(void)
{
	TEST_START("Curve448");
	int i = 0;

	/* X448 DH with known test vectors */
	{
		uint8_t a_priv[56], a_pub[56], b_priv[56], b_pub[56];
		uint8_t sa[56], sb[56];
		hex2bin("9a8f4925d1519f5775cf46971c765011"
			"4983dae6d66e68d980d9098c249f4ba3"
			"f734f54edc00125231ec7fd65debc752"
			"52a91ad7b2bb5280", a_priv, 56);
		hex2bin("1c306a7ac2a0e2e0990b294470cba339"
			"e6453772b075811d8fad0d1d6927c120"
			"bb5ee8972b0d3e21374c9c921b09d1b0"
			"366f10113ee85d2e", b_priv, 56);

		mbedcrypto_x448_calc_public(a_pub, a_priv);
		mbedcrypto_x448_calc_public(b_pub, b_priv);

		/* Expected values verified by OpenSSL + Python cryptography lib */
		CHECK(hexcmp(a_pub, "c98be8dafe33d38ff1a2145023b39ea5"
			"b47ce1cc06d11dc6948f7e6d70b95a53"
			"73c9f8e2d93aba3b7b60cfdf852bbd24"
			"b322d15c5a509aa3", 56) == 0, EBADMSG);

		mbedcrypto_x448_calc_secret(sa, a_priv, b_pub);
		mbedcrypto_x448_calc_secret(sb, b_priv, a_pub);
		CHECK(memcmp(sa, sb, 56) == 0, EBADMSG);
		CHECK(hexcmp(sa, "37ac1149d9ed6c16d99645948883c966"
			"ea4d7dcb0700dc508958e9cbb65a3746"
			"f6dcdf9848ae90213b30eadb8fe35045"
			"e7fe5efd5d4aa39b", 56) == 0, EBADMSG);
	}

	/* X448 key generation and DH agreement */
	{
		uint8_t a_pub[56], a_priv[56], b_pub[56], b_priv[56];
		uint8_t sa[56], sb[56];
		mbedcrypto_x448_gen_keypair(a_pub, a_priv, test_rng, NULL);
		mbedcrypto_x448_gen_keypair(b_pub, b_priv, test_rng, NULL);
		mbedcrypto_x448_calc_secret(sa, a_priv, b_pub);
		mbedcrypto_x448_calc_secret(sb, b_priv, a_pub);
		CHECK(memcmp(sa, sb, 56) == 0, EBADMSG);
	}

	/* Ed448 RFC 8032 Section 7.4 Test Vector 1 (known answer) */
	{
		uint8_t seed[57], priv[114], sig[114];
		uint8_t expected_pub[57], gen_pub[57];
		hex2bin("6c82a562cb808d10d632be89c8513ebf"
			"6c929f34ddfa8c9f63c9960ef6e348a3"
			"528c8a3fcc2f044e39a3fc5b94492f8f"
			"032e7549a20098f95b", seed, 57);
		hex2bin("5fd7449b59b461fd2ce787ec616ad46a"
			"1da1342485a70e1f8a0ea75d80e96778"
			"edf124769b46c7061bd6783df1e50f6c"
			"d1fa1abeafe8256180", expected_pub, 57);

		int ret = mbedcrypto_ed448_gen_keypair(gen_pub, priv, fixed_rng, seed);
		CHECK(ret == 0, ret);
		CHECK(memcmp(gen_pub, expected_pub, 57) == 0, EBADMSG);

		/* Reconstruct priv = seed || pub for sign */
		memcpy(priv, seed, 57);
		memcpy(priv + 57, expected_pub, 57);
		ret = mbedcrypto_ed448_sign(sig, NULL, 0, priv);
		CHECK(ret == 0, ret);

		/* Expected signature from RFC 8032 */
		CHECK(hexcmp(sig, "533a37f6bbe457251f023c0d88f976ae"
			"2dfb504a843e34d2074fd823d41a591f"
			"2b233f034f628281f2fd7a22ddd47d78"
			"28c59bd0a21bfd3980ff0d2028d4b18a"
			"9df63e006c5d1c2d345b925d8dc00b41"
			"04852db99ac5c7cdda8530a113a0f4db"
			"b61149f05a7363268c71d95808ff2e65"
			"2600", 114) == 0, EBADMSG);

		ret = mbedcrypto_ed448_verify(sig, NULL, 0, expected_pub);
		CHECK(ret == 0, ret);
	}

	/* Ed448 sign/verify */
	{
		uint8_t pub[57], priv[114], sig[114];
		mbedcrypto_ed448_gen_keypair(pub, priv, test_rng, NULL);

		const uint8_t msg[] = "test message for ed448";
		int ret = mbedcrypto_ed448_sign(sig, msg, sizeof(msg) - 1, priv);
		CHECK(ret == 0, ret);

		ret = mbedcrypto_ed448_verify(sig, msg, sizeof(msg) - 1, pub);
		CHECK(ret == 0, ret);

		/* Tamper check */
		uint8_t bad[sizeof(msg)];
		memcpy(bad, msg, sizeof(msg) - 1);
		bad[0] ^= 1;
		ret = mbedcrypto_ed448_verify(sig, bad, sizeof(msg) - 1, pub);
		CHECK(ret != 0, EBADMSG);
	}

	/* --- Extended coverage (merged from test_curve448_ext) --- */

	/* X448 additional DH tests */
	{
		uint8_t priv[56], pub[56];
		for (i = 0; i < 56; i++)
			priv[i] = i + 1;
		priv[0] &= 252;
		priv[55] |= 128;

		int ret = mbedcrypto_x448_calc_public(pub, priv);
		CHECK(ret == 0, ret);

		uint8_t shared[56];
		ret = mbedcrypto_x448_calc_secret(shared, priv, pub);
		CHECK(ret == 0, ret);

		uint8_t priv2[56], pub2[56], shared1[56], shared2[56];
		for (i = 0; i < 56; i++)
			priv2[i] = i + 100;
		priv2[0] &= 252;
		priv2[55] |= 128;
		mbedcrypto_x448_calc_public(pub2, priv2);

		mbedcrypto_x448_calc_secret(shared1, priv, pub2);
		mbedcrypto_x448_calc_secret(shared2, priv2, pub);
		CHECK(memcmp(shared1, shared2, 56) == 0, EBADMSG);
	}

	/* Ed448 long message (256 bytes) + tamper */
	{
		uint8_t pub[57], priv[114], sig[114];
		int ret = mbedcrypto_ed448_gen_keypair(pub, priv, test_rng, NULL);
		CHECK(ret == 0, ret);

		uint8_t msg_long[256];
		for (i = 0; i < 256; i++)
			msg_long[i] = i;
		ret = mbedcrypto_ed448_sign(sig, msg_long, 256, priv);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_ed448_verify(sig, msg_long, 256, pub);
		CHECK(ret == 0, ret);

		sig[50] ^= 1;
		ret = mbedcrypto_ed448_verify(sig, msg_long, 256, pub);
		CHECK(ret != 0, EBADMSG);
	}

#ifdef CONFIG_MBEDCRYPTO_SHA3
	/* Ed448 + SHA3-256: hash with SHA3, then sign+verify */
	{
		struct mbedcrypto_sha3_ctx sha3ctx;
		uint8_t hash[32];
		uint8_t sig[MBEDCRYPTO_ED448_SIG_SIZE];
		uint8_t pub[MBEDCRYPTO_ED448_KEY_SIZE];
		uint8_t priv[2 * MBEDCRYPTO_ED448_KEY_SIZE];
		const char *raw_msg = "test message for ed448";
		int ret = 0;

		mbedcrypto_sha3_init(&sha3ctx);
		ret = mbedcrypto_sha3_start(&sha3ctx,
				MBEDCRYPTO_SHA3_256);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_sha3_update(&sha3ctx,
				(const uint8_t *)raw_msg,
				strlen(raw_msg));
		CHECK(ret == 0, ret);
		ret = mbedcrypto_sha3_final(&sha3ctx, hash, 32);
		CHECK(ret == 0, ret);
		mbedcrypto_sha3_cleanup(&sha3ctx);

		mbedcrypto_ed448_gen_keypair(pub, priv,
				test_rng, NULL);
		ret = mbedcrypto_ed448_sign(sig, hash, 32, priv);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_ed448_verify(sig, hash, 32, pub);
		CHECK(ret == 0, ret);
	}
#endif

out:
	TEST_END();
}

static void test_rsa(void)
{
	TEST_START("RSA");
	struct mbedcrypto_rsa_ctx rctx;
	int ret = 0;
	size_t i = 0, t = 0;

	/*
	 * KAT: RSA-2048 PKCS#1 v1.5 SHA-256 verify with known key+signature.
	 * Key and signature generated by Python cryptography library.
	 * Message: "RSA-2048 PKCS#1 v1.5 SHA-256 KAT test message"
	 */
	{
		static const uint8_t rsa_kat_n[] = {
			0x9f, 0x9e, 0xaf, 0x5a, 0x1c, 0x76, 0xa8, 0x08,
			0xee, 0x48, 0x72, 0xbd, 0x26, 0x0b, 0x4a, 0x32,
			0x0b, 0xce, 0x5f, 0x53, 0xdf, 0xe8, 0x23, 0x3d,
			0x4c, 0x37, 0x9f, 0x46, 0x04, 0x36, 0x96, 0x37,
			0x6f, 0xcc, 0x25, 0x46, 0x1f, 0x72, 0xe1, 0xdb,
			0x98, 0x84, 0x10, 0x3c, 0x4d, 0xd9, 0xdd, 0x9d,
			0x05, 0x7e, 0xd5, 0xee, 0x3f, 0xfc, 0x83, 0x19,
			0xd6, 0xf1, 0x7a, 0x8b, 0x9d, 0x51, 0xbf, 0x87,
			0xaf, 0x44, 0x7e, 0xaf, 0x87, 0xb8, 0xbb, 0x1d,
			0xe2, 0xd7, 0x56, 0x2f, 0x62, 0x03, 0xcd, 0xbc,
			0x61, 0xf0, 0x09, 0x43, 0xf0, 0xf9, 0xe2, 0xc7,
			0x5d, 0xb6, 0xcf, 0xe6, 0x11, 0xeb, 0x56, 0xea,
			0xf6, 0x8c, 0xaf, 0x05, 0xdf, 0x41, 0x3d, 0xab,
			0x63, 0xf3, 0xb0, 0x22, 0xa6, 0x7b, 0x3e, 0x94,
			0x61, 0x18, 0xce, 0x31, 0xbb, 0x8c, 0xa3, 0x57,
			0x72, 0xaa, 0x35, 0xe0, 0xde, 0xe9, 0xa8, 0x3b,
			0x38, 0x8d, 0x1e, 0xbb, 0x86, 0xdb, 0xef, 0xa0,
			0x0d, 0x13, 0x05, 0xf8, 0xa2, 0xf2, 0x2c, 0xe3,
			0x5e, 0xe4, 0x32, 0x26, 0x78, 0xf3, 0x7e, 0x1d,
			0xf9, 0xab, 0x3c, 0xc5, 0x83, 0xfa, 0xae, 0x1d,
			0xfa, 0xa5, 0x91, 0xd3, 0x1f, 0xa0, 0x92, 0x86,
			0xfd, 0xbd, 0x89, 0x88, 0xd4, 0x51, 0xde, 0x8c,
			0x7a, 0x20, 0x51, 0x9b, 0x3f, 0xbc, 0x50, 0x5b,
			0x5e, 0xb2, 0xd7, 0xbd, 0xb1, 0x1a, 0x2e, 0x5a,
			0xcf, 0x1e, 0x07, 0x8b, 0x25, 0xbe, 0xa2, 0x6c,
			0x8e, 0x1a, 0x8b, 0x5c, 0xbf, 0xd6, 0xc2, 0xc4,
			0xb7, 0xfc, 0x34, 0xad, 0x71, 0xc1, 0x02, 0x66,
			0x37, 0xa7, 0x16, 0x7d, 0x95, 0x7e, 0x71, 0x5b,
			0xd7, 0xc4, 0x04, 0x6a, 0x01, 0x0e, 0x54, 0xf5,
			0x6b, 0x3e, 0xf4, 0x12, 0x44, 0xb0, 0x71, 0xa2,
			0x29, 0xfc, 0xff, 0xdc, 0xc9, 0xb0, 0x0e, 0x6b,
			0x66, 0xaf, 0xf8, 0xa8, 0xd2, 0x6d, 0x36, 0x55,
		};
		static const uint8_t rsa_kat_e[] = { 0x01, 0x00, 0x01 };
		/* SHA-256("RSA-2048 PKCS#1 v1.5 SHA-256 KAT test message") */
		static const uint8_t rsa_kat_hash[] = {
			0x1b, 0xd8, 0x79, 0xb4, 0x2d, 0x0d, 0xef, 0xf0,
			0x22, 0x99, 0x65, 0x7b, 0x89, 0x3c, 0x1c, 0x99,
			0xfc, 0xe0, 0x46, 0x5e, 0xae, 0xa3, 0x1d, 0x2f,
			0xfc, 0x71, 0xc9, 0xe9, 0x44, 0xab, 0xa2, 0x73,
		};
		static const uint8_t rsa_kat_sig[] = {
			0x31, 0xfe, 0x79, 0x0f, 0x6b, 0xc0, 0xb7, 0x23,
			0x36, 0x16, 0x58, 0xcf, 0xe2, 0xea, 0xd4, 0xb6,
			0xcc, 0xba, 0x8b, 0x5d, 0x81, 0x21, 0xa7, 0xc6,
			0xac, 0x48, 0x90, 0x82, 0x7e, 0x7f, 0x4e, 0x4b,
			0xcd, 0x67, 0x33, 0x8b, 0x33, 0x95, 0x38, 0xdf,
			0x29, 0x67, 0x71, 0x0b, 0x74, 0x65, 0x75, 0x80,
			0xff, 0x36, 0xf8, 0x5f, 0x5f, 0x87, 0xb9, 0x0f,
			0xa6, 0xe5, 0x52, 0x2d, 0xf5, 0x0a, 0x46, 0x35,
			0x01, 0xb1, 0x1a, 0xe8, 0x69, 0xfc, 0x57, 0x07,
			0x6e, 0xa0, 0xe7, 0xaa, 0x4c, 0xe2, 0xc6, 0x23,
			0x81, 0x67, 0xf3, 0x5c, 0x3b, 0xa3, 0xf2, 0xcd,
			0xb0, 0xd4, 0xda, 0x16, 0x27, 0xa4, 0x2a, 0x70,
			0xac, 0x61, 0xb4, 0x13, 0xa1, 0x56, 0x73, 0xbd,
			0xad, 0x0e, 0x1e, 0x6b, 0x74, 0xf5, 0x75, 0xc0,
			0xcc, 0x68, 0x91, 0xc5, 0x62, 0x40, 0x75, 0x32,
			0x65, 0xf6, 0x25, 0x6f, 0xaa, 0xd1, 0x57, 0x22,
			0x9a, 0x22, 0x61, 0xa7, 0x16, 0x41, 0x53, 0xc0,
			0x40, 0x03, 0x9b, 0x39, 0xdc, 0xd5, 0xe5, 0xf6,
			0x4e, 0x79, 0x3b, 0x7a, 0x35, 0x05, 0x36, 0xc4,
			0x19, 0x60, 0xb2, 0xcd, 0x66, 0x33, 0xdf, 0x14,
			0x32, 0xe1, 0x67, 0x4f, 0xd9, 0x05, 0xd0, 0xe1,
			0x40, 0x14, 0x99, 0xfb, 0xfa, 0xe2, 0x62, 0x1b,
			0x01, 0x92, 0x7f, 0x4a, 0x0c, 0x4b, 0xb5, 0xb6,
			0xf9, 0x8f, 0x9d, 0x56, 0x51, 0x9c, 0x98, 0x9f,
			0xca, 0x86, 0x86, 0x92, 0x9c, 0xca, 0x6b, 0xab,
			0x2d, 0x1c, 0xae, 0x3f, 0x2e, 0x68, 0x74, 0x06,
			0x6a, 0xe7, 0x21, 0x42, 0xe6, 0x43, 0x75, 0x75,
			0xac, 0x3a, 0xd6, 0x96, 0xe9, 0x87, 0xa2, 0x18,
			0xea, 0x4d, 0x6e, 0x3d, 0x8c, 0x6e, 0x2b, 0x22,
			0xdf, 0x98, 0x70, 0x40, 0xbf, 0xa8, 0xe5, 0xe7,
			0x66, 0x44, 0x87, 0x7a, 0xc3, 0xe6, 0xd4, 0x26,
			0x62, 0x5b, 0xa7, 0xd7, 0x94, 0x37, 0x92, 0x43,
		};

		struct mbedcrypto_rsa_ctx kat;
		mbedcrypto_rsa_init(&kat);
		ret = mbedcrypto_rsa_import_components(&kat,
			rsa_kat_n, sizeof(rsa_kat_n),
			NULL, 0, NULL, 0, NULL, 0,
			rsa_kat_e, sizeof(rsa_kat_e));
		CHECK(ret == 0, ret);

		mbedcrypto_rsa_configure(&kat, MBEDCRYPTO_RSA_PKCS1_V15,
			MBEDCRYPTO_RSA_HASH_SHA256);
		ret = mbedcrypto_rsa_verify(&kat, MBEDCRYPTO_RSA_HASH_SHA256,
			32, rsa_kat_hash, rsa_kat_sig);
		CHECK(ret == 0, ret);

		/* Tamper with hash - should fail */
		uint8_t bad_hash[32];
		memcpy(bad_hash, rsa_kat_hash, 32);
		bad_hash[0] ^= 1;
		ret = mbedcrypto_rsa_verify(&kat, MBEDCRYPTO_RSA_HASH_SHA256,
			32, bad_hash, rsa_kat_sig);
		CHECK(ret != 0, EBADMSG);

		mbedcrypto_rsa_cleanup(&kat);
	}

	/* Generate 1024-bit key for roundtrip and additional coverage */
	mbedcrypto_rsa_init(&rctx);
	ret = mbedcrypto_rsa_keygen(&rctx, test_rng, NULL, 1024, 65537);
	CHECK(ret == 0, ret);
	CHECK(mbedcrypto_rsa_len(&rctx) == 128, EBADMSG);

	/* PKCS#1 v1.5 sign + verify (SHA-256) */
	{
		uint8_t hash[32], sig[128];
		mbedcrypto_sha256_digest((const uint8_t *)"test message", 12, hash, 0);

		mbedcrypto_rsa_configure(&rctx, MBEDCRYPTO_RSA_PKCS1_V15, MBEDCRYPTO_RSA_HASH_SHA256);
		ret = mbedcrypto_rsa_sign(&rctx, test_rng, NULL,
			MBEDCRYPTO_RSA_HASH_SHA256, 32, hash, sig);
		CHECK(ret == 0, ret);

		ret = mbedcrypto_rsa_verify(&rctx,
			MBEDCRYPTO_RSA_HASH_SHA256, 32, hash, sig);
		CHECK(ret == 0, ret);

		/* Tamper with hash */
		hash[0] ^= 1;
		ret = mbedcrypto_rsa_verify(&rctx,
			MBEDCRYPTO_RSA_HASH_SHA256, 32, hash, sig);
		CHECK(ret != 0, EBADMSG);
		hash[0] ^= 1;
	}

	/* PKCS#1 v1.5 encrypt + decrypt */
	{
		uint8_t msg[64], enc[128], dec_buf[128];
		size_t dec_len;
		for (i = 0; i < 64; i++)
			msg[i] = i + 0x10;

		mbedcrypto_rsa_configure(&rctx, MBEDCRYPTO_RSA_PKCS1_V15, 0);
		ret = mbedcrypto_rsa_encrypt(&rctx, test_rng, NULL, 64, msg, enc);
		CHECK(ret == 0, ret);

		ret = mbedcrypto_rsa_decrypt(&rctx, test_rng, NULL,
			&dec_len, enc, dec_buf, 128);
		CHECK(ret == 0, ret);
		CHECK(dec_len == 64 && memcmp(dec_buf, msg, 64) == 0, EBADMSG);
	}

	/* OAEP encrypt + decrypt (PKCS#1 v2.1) */
	{
		uint8_t msg[32], enc[128], dec_buf[128];
		size_t dec_len;
		for (i = 0; i < 32; i++)
			msg[i] = i;

		mbedcrypto_rsa_configure(&rctx, MBEDCRYPTO_RSA_PKCS1_V21, MBEDCRYPTO_RSA_HASH_SHA256);
		ret = mbedcrypto_rsa_encrypt(&rctx, test_rng, NULL, 32, msg, enc);
		CHECK(ret == 0, ret);

		ret = mbedcrypto_rsa_decrypt(&rctx, test_rng, NULL,
			&dec_len, enc, dec_buf, 128);
		CHECK(ret == 0, ret);
		CHECK(dec_len == 32 && memcmp(dec_buf, msg, 32) == 0, EBADMSG);
	}

	/* RSA public/private raw operation roundtrip */
	{
		uint8_t in[128], out[128], back[128];
		memset(in, 0, 128);
		in[0] = 0; /* ensure < N */
		for (i = 1; i < 128; i++)
			in[i] = i;

		ret = mbedcrypto_rsa_raw_public(&rctx, in, out);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_rsa_raw_private(&rctx, test_rng, NULL, out, back);
		CHECK(ret == 0, ret);
		CHECK(memcmp(back, in, 128) == 0, EBADMSG);
	}

	/* Different message lengths for encrypt */
	{
		size_t enc_lens[] = { 1, 16, 32, 64, 86 };
		for (t = 0; t < sizeof(enc_lens)/sizeof(enc_lens[0]); t++) {
			uint8_t msg[128], enc[128], dec_buf[128];
			size_t dec_len;
			for (i = 0; i < enc_lens[t]; i++)
				msg[i] = i + t;

			mbedcrypto_rsa_configure(&rctx, MBEDCRYPTO_RSA_PKCS1_V15, 0);
			ret = mbedcrypto_rsa_encrypt(&rctx, test_rng, NULL,
				enc_lens[t], msg, enc);
			CHECK(ret == 0, ret);
			ret = mbedcrypto_rsa_decrypt(&rctx, test_rng, NULL,
				&dec_len, enc, dec_buf, 128);
			CHECK(ret == 0 && dec_len == enc_lens[t] && memcmp(dec_buf, msg, enc_lens[t]) == 0, EBADMSG);
		}
	}

	/* Sign with different hash algorithms */
	{
		int hash_ids[] = { MBEDCRYPTO_RSA_HASH_SHA1, MBEDCRYPTO_RSA_HASH_SHA256,
			MBEDCRYPTO_RSA_HASH_SHA384, MBEDCRYPTO_RSA_HASH_SHA512 };
		size_t hash_lens[] = { 20, 32, 48, 64 };
		for (t = 0; t < 4; t++) {
			uint8_t hash[64], sig[128];
			for (i = 0; i < hash_lens[t]; i++)
				hash[i] = i + t;

			mbedcrypto_rsa_configure(&rctx, MBEDCRYPTO_RSA_PKCS1_V15, hash_ids[t]);
			ret = mbedcrypto_rsa_sign(&rctx, test_rng, NULL,
				hash_ids[t], hash_lens[t], hash, sig);
			CHECK(ret == 0, ret);
			ret = mbedcrypto_rsa_verify(&rctx, hash_ids[t], hash_lens[t], hash, sig);
			CHECK(ret == 0, ret);
		}
	}

	mbedcrypto_rsa_cleanup(&rctx);

	/* RSA import raw and complete */
	{
		struct mbedcrypto_rsa_ctx gen, imp;
		mbedcrypto_rsa_init(&gen);
		mbedcrypto_rsa_keygen(&gen, test_rng, NULL, 1024, 65537);

		size_t nlen = mbedcrypto_rsa_len(&gen);
		uint8_t N[128], E[4], D[128], P[64], Q[64];
		mbedcrypto_bn_to_binary(&gen.N, N, nlen);
		mbedcrypto_bn_to_binary(&gen.E, E, mbedcrypto_bn_byte_count(&gen.E));
		mbedcrypto_bn_to_binary(&gen.D, D, nlen);
		size_t plen = mbedcrypto_bn_byte_count(&gen.P);
		size_t qlen = mbedcrypto_bn_byte_count(&gen.Q);
		mbedcrypto_bn_to_binary(&gen.P, P, plen);
		mbedcrypto_bn_to_binary(&gen.Q, Q, qlen);

		mbedcrypto_rsa_init(&imp);
		ret = mbedcrypto_rsa_import_components(&imp,
			N, nlen, P, plen, Q, qlen, D, nlen,
			E, mbedcrypto_bn_byte_count(&gen.E));
		CHECK(ret == 0, ret);
		ret = mbedcrypto_rsa_derive_crt(&imp);
		CHECK(ret == 0, ret);

		/* Verify imported key works */
		uint8_t hash[32] = {1,2,3,4}, sig[128];
		mbedcrypto_rsa_configure(&imp, MBEDCRYPTO_RSA_PKCS1_V15, MBEDCRYPTO_RSA_HASH_SHA256);
		ret = mbedcrypto_rsa_sign(&imp, test_rng, NULL,
			MBEDCRYPTO_RSA_HASH_SHA256, 32, hash, sig);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_rsa_verify(&imp, MBEDCRYPTO_RSA_HASH_SHA256, 32, hash, sig);
		CHECK(ret == 0, ret);

		mbedcrypto_rsa_cleanup(&gen);
		mbedcrypto_rsa_cleanup(&imp);
	}

	/* --- Extended coverage (merged from test_rsa_ext) --- */
	{
		/* RSA 2048-bit keygen + sign/verify */
		struct mbedcrypto_rsa_ctx rctx;
		mbedcrypto_rsa_init(&rctx);
		int ret = mbedcrypto_rsa_keygen(&rctx, test_rng, NULL, 2048, 65537);
		CHECK(ret == 0, ret);
		CHECK(mbedcrypto_rsa_len(&rctx) == 256, EBADMSG);

		/* PKCS v1.5 sign/verify with SHA-256 */
		{
			uint8_t hash[32], sig[256];
			for (i = 0; i < 32; i++)
				hash[i] = i;
			mbedcrypto_rsa_configure(&rctx, MBEDCRYPTO_RSA_PKCS1_V15, MBEDCRYPTO_RSA_HASH_SHA256);
			ret = mbedcrypto_rsa_sign(&rctx, test_rng, NULL,
				MBEDCRYPTO_RSA_HASH_SHA256, 32, hash, sig);
			CHECK(ret == 0, ret);
			ret = mbedcrypto_rsa_verify(&rctx,
				MBEDCRYPTO_RSA_HASH_SHA256, 32, hash, sig);
			CHECK(ret == 0, ret);

			/* Tamper */
			sig[100] ^= 1;
			ret = mbedcrypto_rsa_verify(&rctx,
				MBEDCRYPTO_RSA_HASH_SHA256, 32, hash, sig);
			CHECK(ret != 0, EBADMSG);
		}

		/* OAEP encrypt/decrypt 2048 */
		{
			uint8_t msg[128], enc[256], dec[256];
			size_t dec_len;
			for (i = 0; i < 128; i++)
				msg[i] = i ^ 0x55;
			mbedcrypto_rsa_configure(&rctx, MBEDCRYPTO_RSA_PKCS1_V21, MBEDCRYPTO_RSA_HASH_SHA256);
			ret = mbedcrypto_rsa_encrypt(&rctx, test_rng, NULL, 128, msg, enc);
			CHECK(ret == 0, ret);
			ret = mbedcrypto_rsa_decrypt(&rctx, test_rng, NULL,
				&dec_len, enc, dec, 256);
			CHECK(ret == 0, ret);
			CHECK(dec_len == 128 && memcmp(dec, msg, 128) == 0, EBADMSG);
		}

		/* Edge: encrypt empty message (0 bytes) */
		{
			uint8_t enc[256], dec[256];
			size_t dec_len;
			mbedcrypto_rsa_configure(&rctx, MBEDCRYPTO_RSA_PKCS1_V21, MBEDCRYPTO_RSA_HASH_SHA256);
			ret = mbedcrypto_rsa_encrypt(&rctx, test_rng, NULL, 0, NULL, enc);
			CHECK(ret == 0, ret);
			ret = mbedcrypto_rsa_decrypt(&rctx, test_rng, NULL,
				&dec_len, enc, dec, 256);
			CHECK(ret == 0 && dec_len == 0, EBADMSG);
		}

		/* RSA-PSS (PKCS#1 v2.1) sign + verify with SHA-256 */
		{
			uint8_t hash[32], sig[256];
			mbedcrypto_sha256_digest((const uint8_t *)"RSA-PSS test", 12, hash, 0);

			mbedcrypto_rsa_configure(&rctx, MBEDCRYPTO_RSA_PKCS1_V21, MBEDCRYPTO_RSA_HASH_SHA256);
			ret = mbedcrypto_rsa_sign(&rctx, test_rng, NULL,
				MBEDCRYPTO_RSA_HASH_SHA256, 32, hash, sig);
			CHECK(ret == 0, ret);

			ret = mbedcrypto_rsa_verify(&rctx,
				MBEDCRYPTO_RSA_HASH_SHA256, 32, hash, sig);
			CHECK(ret == 0, ret);

			/* Tamper with hash -> should fail */
			hash[0] ^= 1;
			ret = mbedcrypto_rsa_verify(&rctx,
				MBEDCRYPTO_RSA_HASH_SHA256, 32, hash, sig);
			CHECK(ret != 0, EBADMSG);
			hash[0] ^= 1;

			/* Tamper with signature -> should fail */
			sig[50] ^= 0x01;
			ret = mbedcrypto_rsa_verify(&rctx,
				MBEDCRYPTO_RSA_HASH_SHA256, 32, hash, sig);
			CHECK(ret != 0, EBADMSG);
		}

		/* RSA-PSS with SHA-384 */
		{
			uint8_t hash[48], sig[256];
			mbedcrypto_sha512_digest((const uint8_t *)"PSS SHA-384", 11, hash, 1);

			mbedcrypto_rsa_configure(&rctx, MBEDCRYPTO_RSA_PKCS1_V21, MBEDCRYPTO_RSA_HASH_SHA384);
			ret = mbedcrypto_rsa_sign(&rctx, test_rng, NULL,
				MBEDCRYPTO_RSA_HASH_SHA384, 48, hash, sig);
			CHECK(ret == 0, ret);
			ret = mbedcrypto_rsa_verify(&rctx,
				MBEDCRYPTO_RSA_HASH_SHA384, 48, hash, sig);
			CHECK(ret == 0, ret);
		}

		/* RSA-PSS with SHA-512 */
		{
			uint8_t hash[64], sig[256];
			mbedcrypto_sha512_digest((const uint8_t *)"PSS SHA-512", 11, hash, 0);

			mbedcrypto_rsa_configure(&rctx, MBEDCRYPTO_RSA_PKCS1_V21, MBEDCRYPTO_RSA_HASH_SHA512);
			ret = mbedcrypto_rsa_sign(&rctx, test_rng, NULL,
				MBEDCRYPTO_RSA_HASH_SHA512, 64, hash, sig);
			CHECK(ret == 0, ret);
			ret = mbedcrypto_rsa_verify(&rctx,
				MBEDCRYPTO_RSA_HASH_SHA512, 64, hash, sig);
			CHECK(ret == 0, ret);
		}

#ifdef CONFIG_MBEDCRYPTO_SHA3
		/* RSA PKCS v1.5 + SHA3 */
		{
			int sha3_ids[] = { MBEDCRYPTO_HASH_SHA3_224,
				MBEDCRYPTO_HASH_SHA3_256,
				MBEDCRYPTO_HASH_SHA3_384,
				MBEDCRYPTO_HASH_SHA3_512 };
			size_t sha3_lens[] = { 28, 32, 48, 64 };
			const char *sha3_names[] = { "sha3-224",
				"sha3-256", "sha3-384", "sha3-512" };

			for (t = 0; t < 4; t++) {
				uint8_t hash[64], sig[256];
				size_t i;

				for (i = 0; i < sha3_lens[t]; i++)
					hash[i] = i + t + 0x30;

				mbedcrypto_rsa_configure(&rctx,
					MBEDCRYPTO_RSA_PKCS1_V15,
					sha3_ids[t]);
				ret = mbedcrypto_rsa_sign(&rctx,
					test_rng, NULL,
					sha3_ids[t], sha3_lens[t],
					hash, sig);
				CHECK(ret == 0, ret,
					"rsa-pkcs15-%s sign",
					sha3_names[t]);
				ret = mbedcrypto_rsa_verify(&rctx,
					sha3_ids[t], sha3_lens[t],
					hash, sig);
				CHECK(ret == 0, ret,
					"rsa-pkcs15-%s verify",
					sha3_names[t]);
			}
		}

		/* RSA-PSS + SHA3 */
		{
			int sha3_ids[] = { MBEDCRYPTO_HASH_SHA3_256,
				MBEDCRYPTO_HASH_SHA3_512 };
			size_t sha3_lens[] = { 32, 64 };
			const char *sha3_names[] = { "sha3-256",
				"sha3-512" };

			for (t = 0; t < 2; t++) {
				uint8_t hash[64], sig[256];
				size_t i;

				for (i = 0; i < sha3_lens[t]; i++)
					hash[i] = i + t + 0x40;

				mbedcrypto_rsa_configure(&rctx,
					MBEDCRYPTO_RSA_PKCS1_V21,
					sha3_ids[t]);
				ret = mbedcrypto_rsa_sign(&rctx,
					test_rng, NULL,
					sha3_ids[t], sha3_lens[t],
					hash, sig);
				CHECK(ret == 0, ret,
					"rsa-pss-%s sign",
					sha3_names[t]);
				ret = mbedcrypto_rsa_verify(&rctx,
					sha3_ids[t], sha3_lens[t],
					hash, sig);
				CHECK(ret == 0, ret,
					"rsa-pss-%s verify",
					sha3_names[t]);
			}
		}
#endif

		mbedcrypto_rsa_cleanup(&rctx);
	}

out:
	TEST_END();
}

static void test_ecdsa(void)
{
	TEST_START("ECDSA");
	int c = 0;
	size_t i = 0;

	/*
	 * KAT: ECDSA P-256 SHA-256 verify with known key+signature.
	 * Key and signature generated by Python cryptography library.
	 * Message hash: SHA-256("ECDSA P-256 SHA-256 KAT test")
	 */
	{
		static const uint8_t ecdsa_kat_x[] = {
			0xee, 0xdc, 0xd7, 0xd1, 0xa5, 0x98, 0x1d, 0x28,
			0x18, 0x8d, 0x67, 0xbf, 0xda, 0x2f, 0xe5, 0x2a,
			0x96, 0xfb, 0x3c, 0xce, 0x34, 0x46, 0x6b, 0xfc,
			0x07, 0x0d, 0x59, 0x67, 0x4c, 0x0f, 0x9c, 0x33,
		};
		static const uint8_t ecdsa_kat_y[] = {
			0x05, 0x97, 0x50, 0x72, 0x6d, 0xa9, 0x56, 0xbd,
			0x1f, 0xb9, 0xcf, 0xb0, 0x1d, 0x51, 0xee, 0x09,
			0xed, 0x9e, 0x77, 0x1b, 0x23, 0x8e, 0xe9, 0xd2,
			0x2f, 0x3b, 0x98, 0xd8, 0x58, 0x78, 0x86, 0x50,
		};
		static const uint8_t ecdsa_kat_hash[] = {
			0x25, 0xcd, 0x72, 0x7b, 0x56, 0xd4, 0xe9, 0x05,
			0x5b, 0x1d, 0x57, 0x14, 0x4e, 0xd6, 0xf8, 0x94,
			0xa4, 0x2a, 0x71, 0xe4, 0xab, 0x32, 0xc8, 0x4e,
			0x9e, 0xe5, 0x54, 0x6e, 0xb4, 0x32, 0xe0, 0x1f,
		};
		static const uint8_t ecdsa_kat_sig_raw[] = {
			0xa9, 0xd3, 0x8d, 0x3f, 0x16, 0xd1, 0x2a, 0xef,
			0x76, 0x84, 0x9a, 0x77, 0xb0, 0x18, 0xbf, 0x10,
			0xad, 0x37, 0xdc, 0x56, 0xa6, 0xa5, 0x8f, 0xe6,
			0x55, 0x44, 0x75, 0xca, 0x58, 0xf6, 0x48, 0xdb,
			0x6d, 0x5c, 0xee, 0x06, 0x02, 0x59, 0x3f, 0x37,
			0x18, 0xaf, 0x7d, 0x93, 0xda, 0xb2, 0xfb, 0xb9,
			0xdd, 0xc3, 0xc1, 0x3e, 0x56, 0x48, 0xb1, 0x23,
			0x8a, 0x97, 0xa2, 0xc1, 0x67, 0xf7, 0xc1, 0xd7,
		};
		static const uint8_t ecdsa_kat_sig_der[] = {
			0x30, 0x45, 0x02, 0x21, 0x00, 0xa9, 0xd3, 0x8d,
			0x3f, 0x16, 0xd1, 0x2a, 0xef, 0x76, 0x84, 0x9a,
			0x77, 0xb0, 0x18, 0xbf, 0x10, 0xad, 0x37, 0xdc,
			0x56, 0xa6, 0xa5, 0x8f, 0xe6, 0x55, 0x44, 0x75,
			0xca, 0x58, 0xf6, 0x48, 0xdb, 0x02, 0x20, 0x6d,
			0x5c, 0xee, 0x06, 0x02, 0x59, 0x3f, 0x37, 0x18,
			0xaf, 0x7d, 0x93, 0xda, 0xb2, 0xfb, 0xb9, 0xdd,
			0xc3, 0xc1, 0x3e, 0x56, 0x48, 0xb1, 0x23, 0x8a,
			0x97, 0xa2, 0xc1, 0x67, 0xf7, 0xc1, 0xd7,
		};

		struct mbedcrypto_ecdsa_ctx kat;
		mbedcrypto_ecdsa_init(&kat);
		struct mbedcrypto_ecp_keypair *kp = (struct mbedcrypto_ecp_keypair *)&kat;
		int ret = mbedcrypto_ecp_load_group(&kp->grp, MBEDCRYPTO_ECP_DP_SECP256R1);
		CHECK(ret == 0, ret);
		mbedcrypto_bn_from_binary(&kp->Q.X, ecdsa_kat_x, 32);
		mbedcrypto_bn_from_binary(&kp->Q.Y, ecdsa_kat_y, 32);
		mbedcrypto_bn_set_word(&kp->Q.Z, 1);

		/* Verify raw signature */
		ret = mbedcrypto_ecdsa_verify(&kat, ecdsa_kat_hash, 32,
			ecdsa_kat_sig_raw, sizeof(ecdsa_kat_sig_raw));
		CHECK(ret == 0, ret);

		/* Verify DER signature */
		ret = mbedcrypto_ecdsa_verify_der(&kat, ecdsa_kat_hash, 32,
			ecdsa_kat_sig_der, sizeof(ecdsa_kat_sig_der));
		CHECK(ret == 0, ret);

		/* Tamper with hash - should fail */
		uint8_t bad[32];
		memcpy(bad, ecdsa_kat_hash, 32);
		bad[0] ^= 1;
		ret = mbedcrypto_ecdsa_verify(&kat, bad, 32,
			ecdsa_kat_sig_raw, sizeof(ecdsa_kat_sig_raw));
		CHECK(ret != 0, EBADMSG);

		mbedcrypto_ecdsa_cleanup(&kat);
	}

	/*
	 * KAT: ECDSA P-384 SHA-384 verify with known key+signature.
	 * Key and signature generated by Python cryptography library.
	 * Message hash: SHA-384("ECDSA P-384 KAT test message for mbedcrypto verification")
	 */
	{
		static const uint8_t p384_kat_x[] = {
			0xa0, 0x7d, 0x12, 0xd2, 0x86, 0x70, 0x5a, 0x13,
			0x4c, 0x16, 0xcb, 0xcf, 0x52, 0x54, 0x76, 0xf5,
			0x13, 0x9b, 0xdb, 0xce, 0x05, 0x10, 0x32, 0x21,
			0x02, 0x43, 0x29, 0x99, 0x81, 0x5a, 0x37, 0xa5,
			0xac, 0xf8, 0x34, 0xda, 0x83, 0x7a, 0x68, 0xfe,
			0x47, 0x00, 0x30, 0xc6, 0x04, 0xd8, 0xde, 0x2d,
		};
		static const uint8_t p384_kat_y[] = {
			0x1c, 0x66, 0xb9, 0x17, 0x05, 0x3c, 0x75, 0xe7,
			0xd4, 0x46, 0x4c, 0xcd, 0x11, 0x03, 0x1f, 0x7c,
			0x03, 0x4e, 0x80, 0xe6, 0x2a, 0x02, 0xe0, 0xb8,
			0x8a, 0x08, 0x65, 0xa1, 0x19, 0xb1, 0xfe, 0xe4,
			0xad, 0x3d, 0x12, 0xbc, 0xd5, 0x4e, 0xf1, 0x98,
			0xee, 0x2c, 0x70, 0x24, 0xca, 0x58, 0x97, 0x52,
		};
		static const uint8_t p384_kat_hash[] = {
			0x26, 0xf8, 0x41, 0x71, 0xf4, 0xdd, 0xb9, 0x45,
			0x3a, 0xca, 0xfa, 0x65, 0x5f, 0x01, 0x2c, 0xee,
			0x5f, 0xba, 0x69, 0xcf, 0xbc, 0x6a, 0x2e, 0xbc,
			0xb0, 0xbb, 0x24, 0xb4, 0x6e, 0xca, 0x76, 0x2f,
			0x69, 0x14, 0xd1, 0x5c, 0x96, 0x7b, 0x77, 0xbc,
			0x26, 0x92, 0x1b, 0xa4, 0xe6, 0x7a, 0x96, 0xd2,
		};
		static const uint8_t p384_kat_sig_raw[] = {
			0x36, 0x80, 0xec, 0x18, 0xae, 0xaf, 0xb4, 0xf0,
			0x2b, 0x4c, 0xc6, 0x87, 0xb0, 0x3e, 0xd7, 0xf9,
			0xfd, 0x80, 0xc8, 0x84, 0x67, 0x47, 0x9d, 0x3c,
			0xdb, 0x91, 0xed, 0x28, 0x3e, 0x9c, 0xcb, 0xd8,
			0x40, 0xbb, 0x8f, 0x09, 0xd5, 0x72, 0xa9, 0x51,
			0x94, 0x1c, 0x97, 0xd2, 0x97, 0xa0, 0x8c, 0x37,
			0x7e, 0xca, 0x57, 0x02, 0x90, 0xb0, 0xbe, 0x9d,
			0x15, 0xf3, 0xd8, 0x60, 0xc9, 0x10, 0xcf, 0x84,
			0xc4, 0x0a, 0x22, 0xa6, 0xc4, 0xd9, 0xc6, 0x2f,
			0x5c, 0x78, 0xee, 0x5b, 0x46, 0x93, 0x28, 0x15,
			0x23, 0x73, 0xb3, 0x32, 0xdc, 0xd9, 0x4e, 0x7d,
			0x6a, 0xfa, 0x5e, 0x3a, 0x73, 0x0d, 0x1c, 0xc3,
		};
		static const uint8_t p384_kat_sig_der[] = {
			0x30, 0x64, 0x02, 0x30, 0x36, 0x80, 0xec, 0x18,
			0xae, 0xaf, 0xb4, 0xf0, 0x2b, 0x4c, 0xc6, 0x87,
			0xb0, 0x3e, 0xd7, 0xf9, 0xfd, 0x80, 0xc8, 0x84,
			0x67, 0x47, 0x9d, 0x3c, 0xdb, 0x91, 0xed, 0x28,
			0x3e, 0x9c, 0xcb, 0xd8, 0x40, 0xbb, 0x8f, 0x09,
			0xd5, 0x72, 0xa9, 0x51, 0x94, 0x1c, 0x97, 0xd2,
			0x97, 0xa0, 0x8c, 0x37, 0x02, 0x30, 0x7e, 0xca,
			0x57, 0x02, 0x90, 0xb0, 0xbe, 0x9d, 0x15, 0xf3,
			0xd8, 0x60, 0xc9, 0x10, 0xcf, 0x84, 0xc4, 0x0a,
			0x22, 0xa6, 0xc4, 0xd9, 0xc6, 0x2f, 0x5c, 0x78,
			0xee, 0x5b, 0x46, 0x93, 0x28, 0x15, 0x23, 0x73,
			0xb3, 0x32, 0xdc, 0xd9, 0x4e, 0x7d, 0x6a, 0xfa,
			0x5e, 0x3a, 0x73, 0x0d, 0x1c, 0xc3,
		};

		struct mbedcrypto_ecdsa_ctx kat;
		mbedcrypto_ecdsa_init(&kat);
		struct mbedcrypto_ecp_keypair *kp = (struct mbedcrypto_ecp_keypair *)&kat;
		int ret = mbedcrypto_ecp_load_group(&kp->grp, MBEDCRYPTO_ECP_DP_SECP384R1);
		CHECK(ret == 0, ret);
		mbedcrypto_bn_from_binary(&kp->Q.X, p384_kat_x, 48);
		mbedcrypto_bn_from_binary(&kp->Q.Y, p384_kat_y, 48);
		mbedcrypto_bn_set_word(&kp->Q.Z, 1);

		ret = mbedcrypto_ecdsa_verify(&kat, p384_kat_hash, 48,
			p384_kat_sig_raw, sizeof(p384_kat_sig_raw));
		CHECK(ret == 0, ret);

		ret = mbedcrypto_ecdsa_verify_der(&kat, p384_kat_hash, 48,
			p384_kat_sig_der, sizeof(p384_kat_sig_der));
		CHECK(ret == 0, ret);

		uint8_t bad[48];
		memcpy(bad, p384_kat_hash, 48);
		bad[0] ^= 1;
		ret = mbedcrypto_ecdsa_verify(&kat, bad, 48,
			p384_kat_sig_raw, sizeof(p384_kat_sig_raw));
		CHECK(ret != 0, EBADMSG);

		mbedcrypto_ecdsa_cleanup(&kat);
	}

	/*
	 * KAT: ECDSA P-521 SHA-512 verify with known key+signature.
	 * Key and signature generated by Python cryptography library.
	 * Message hash: SHA-512("ECDSA P-521 KAT test message for mbedcrypto verification")
	 */
	{
		static const uint8_t p521_kat_x[] = {
			0x00, 0x33, 0xad, 0xe8, 0x6a, 0x8e, 0x3d, 0x74,
			0x98, 0xd3, 0xcb, 0xc6, 0xba, 0x3a, 0x4e, 0xa4,
			0xc8, 0x5a, 0x59, 0x0a, 0xa8, 0x04, 0x10, 0x1e,
			0x24, 0xda, 0xd3, 0x07, 0x18, 0xc1, 0xa4, 0x68,
			0xdf, 0x16, 0x1e, 0x57, 0xc9, 0x16, 0x4e, 0xcf,
			0xe5, 0x3c, 0xe3, 0x7e, 0x4b, 0x67, 0x8d, 0x2e,
			0x0c, 0x7c, 0x3d, 0x62, 0xd9, 0x81, 0x92, 0xdd,
			0x4f, 0x5f, 0x9a, 0x65, 0xaf, 0x6c, 0xc7, 0x98,
			0x3f, 0xbb,
		};
		static const uint8_t p521_kat_y[] = {
			0x01, 0x7d, 0xdc, 0x58, 0xe2, 0x2e, 0x80, 0xdf,
			0x9d, 0x35, 0xfd, 0xa8, 0xa2, 0x1a, 0xe0, 0x58,
			0xa5, 0x2f, 0xd3, 0x91, 0xd1, 0x9f, 0xca, 0x0d,
			0x30, 0xd5, 0x98, 0xa6, 0x5e, 0x09, 0x3d, 0x10,
			0x90, 0x6d, 0x11, 0xc8, 0x64, 0xa4, 0x2a, 0x6e,
			0x1a, 0x6a, 0x75, 0xad, 0x08, 0x77, 0xb7, 0xa1,
			0x7b, 0xc0, 0xad, 0x6c, 0x52, 0x70, 0x22, 0x05,
			0xd4, 0x7f, 0x3c, 0x1d, 0xf7, 0xfb, 0xf3, 0x7b,
			0x64, 0x33,
		};
		static const uint8_t p521_kat_hash[] = {
			0xfe, 0x8a, 0xdb, 0x63, 0x06, 0xad, 0xd5, 0x8a,
			0xf6, 0x38, 0x03, 0xff, 0xd0, 0x76, 0xf5, 0x17,
			0xeb, 0x1b, 0xfd, 0x0d, 0x5f, 0x8e, 0x3b, 0xa7,
			0xb0, 0x8f, 0x76, 0xf1, 0xdb, 0xcf, 0x43, 0x13,
			0x77, 0x44, 0xfd, 0xef, 0x95, 0x8f, 0xd7, 0xf9,
			0xb6, 0x60, 0x80, 0xca, 0x66, 0xb9, 0x62, 0x5d,
			0x4c, 0xa3, 0x51, 0x72, 0x5d, 0xba, 0x64, 0xb8,
			0xf6, 0xa3, 0x43, 0x8b, 0x51, 0x3c, 0xee, 0x3e,
		};
		static const uint8_t p521_kat_sig_raw[] = {
			0x00, 0x86, 0x69, 0xd1, 0xa2, 0xc0, 0x4c, 0xc1,
			0xb0, 0x72, 0xfb, 0x93, 0x28, 0x48, 0xe0, 0x10,
			0x4d, 0x14, 0x30, 0x45, 0xd2, 0x46, 0xb2, 0x7d,
			0x21, 0x8d, 0x53, 0xcd, 0x2d, 0x30, 0x59, 0xcd,
			0x12, 0xa3, 0xc8, 0x14, 0x46, 0x31, 0x8a, 0x5a,
			0x54, 0x62, 0x7d, 0x23, 0xf3, 0x86, 0x7a, 0xfb,
			0x43, 0x63, 0xdf, 0x03, 0x96, 0x57, 0x32, 0xbb,
			0xbd, 0xfb, 0xb1, 0x77, 0xad, 0x4a, 0xae, 0x27,
			0x62, 0x5c, 0x00, 0xc3, 0x8f, 0xa5, 0x9a, 0x56,
			0xe8, 0x7e, 0xcc, 0xea, 0xef, 0x27, 0x32, 0x92,
			0xfe, 0xf9, 0x8a, 0xdb, 0xd8, 0x43, 0x5e, 0x67,
			0x36, 0x1c, 0x74, 0x64, 0x78, 0xe6, 0x9c, 0xb5,
			0x38, 0x0d, 0xe2, 0x6a, 0x94, 0x37, 0xaa, 0x9e,
			0x2d, 0x06, 0x56, 0xab, 0xdf, 0x09, 0x14, 0x98,
			0xae, 0xd8, 0x93, 0x81, 0x9d, 0x8e, 0x84, 0x16,
			0xd8, 0x4a, 0xc3, 0x74, 0xca, 0x3f, 0x9c, 0x0a,
			0x96, 0xf1, 0x31, 0x4f,
		};
		static const uint8_t p521_kat_sig_der[] = {
			0x30, 0x81, 0x88, 0x02, 0x42, 0x00, 0x86, 0x69,
			0xd1, 0xa2, 0xc0, 0x4c, 0xc1, 0xb0, 0x72, 0xfb,
			0x93, 0x28, 0x48, 0xe0, 0x10, 0x4d, 0x14, 0x30,
			0x45, 0xd2, 0x46, 0xb2, 0x7d, 0x21, 0x8d, 0x53,
			0xcd, 0x2d, 0x30, 0x59, 0xcd, 0x12, 0xa3, 0xc8,
			0x14, 0x46, 0x31, 0x8a, 0x5a, 0x54, 0x62, 0x7d,
			0x23, 0xf3, 0x86, 0x7a, 0xfb, 0x43, 0x63, 0xdf,
			0x03, 0x96, 0x57, 0x32, 0xbb, 0xbd, 0xfb, 0xb1,
			0x77, 0xad, 0x4a, 0xae, 0x27, 0x62, 0x5c, 0x02,
			0x42, 0x00, 0xc3, 0x8f, 0xa5, 0x9a, 0x56, 0xe8,
			0x7e, 0xcc, 0xea, 0xef, 0x27, 0x32, 0x92, 0xfe,
			0xf9, 0x8a, 0xdb, 0xd8, 0x43, 0x5e, 0x67, 0x36,
			0x1c, 0x74, 0x64, 0x78, 0xe6, 0x9c, 0xb5, 0x38,
			0x0d, 0xe2, 0x6a, 0x94, 0x37, 0xaa, 0x9e, 0x2d,
			0x06, 0x56, 0xab, 0xdf, 0x09, 0x14, 0x98, 0xae,
			0xd8, 0x93, 0x81, 0x9d, 0x8e, 0x84, 0x16, 0xd8,
			0x4a, 0xc3, 0x74, 0xca, 0x3f, 0x9c, 0x0a, 0x96,
			0xf1, 0x31, 0x4f,
		};

		struct mbedcrypto_ecdsa_ctx kat;
		mbedcrypto_ecdsa_init(&kat);
		struct mbedcrypto_ecp_keypair *kp = (struct mbedcrypto_ecp_keypair *)&kat;
		int ret = mbedcrypto_ecp_load_group(&kp->grp, MBEDCRYPTO_ECP_DP_SECP521R1);
		CHECK(ret == 0, ret);
		mbedcrypto_bn_from_binary(&kp->Q.X, p521_kat_x, 66);
		mbedcrypto_bn_from_binary(&kp->Q.Y, p521_kat_y, 66);
		mbedcrypto_bn_set_word(&kp->Q.Z, 1);

		ret = mbedcrypto_ecdsa_verify(&kat, p521_kat_hash, 64,
			p521_kat_sig_raw, sizeof(p521_kat_sig_raw));
		CHECK(ret == 0, ret);

		ret = mbedcrypto_ecdsa_verify_der(&kat, p521_kat_hash, 64,
			p521_kat_sig_der, sizeof(p521_kat_sig_der));
		CHECK(ret == 0, ret);

		uint8_t bad[64];
		memcpy(bad, p521_kat_hash, 64);
		bad[0] ^= 1;
		ret = mbedcrypto_ecdsa_verify(&kat, bad, 64,
			p521_kat_sig_raw, sizeof(p521_kat_sig_raw));
		CHECK(ret != 0, EBADMSG);

		mbedcrypto_ecdsa_cleanup(&kat);
	}

	/* Test all supported curves (roundtrip) */
	int curves[] = {
		MBEDCRYPTO_ECP_DP_SECP256R1,
		MBEDCRYPTO_ECP_DP_SECP384R1,
		MBEDCRYPTO_ECP_DP_SECP521R1,
	};
	size_t hash_lens[] = { 32, 48, 64 };
	const char *curve_names[] = { "P-256", "P-384", "P-521" };

	for (c = 0; c < 3; c++) {
		struct mbedcrypto_ecdsa_ctx ectx;
		mbedcrypto_ecdsa_init(&ectx);

		/* Generate keypair via ecp_gen_key then cast */
		struct mbedcrypto_ecp_keypair *kp = (struct mbedcrypto_ecp_keypair *)&ectx;
		int ret = mbedcrypto_ecp_keygen(curves[c], kp, test_rng, NULL);
		CHECK(ret == 0, ret, "ecdsa-%s keygen",
			curve_names[c]);

		/* Sign */
		uint8_t hash[64], sig[256];
		size_t slen = sizeof(sig);
		for (i = 0; i < hash_lens[c]; i++)
			hash[i] = i + c;

		ret = mbedcrypto_ecdsa_sign_der(&ectx, 0, hash, hash_lens[c],
			sig, sizeof(sig), &slen, test_rng, NULL);
		CHECK(ret == 0, ret, "ecdsa-%s sign",
			curve_names[c]);

		/* Verify */
		ret = mbedcrypto_ecdsa_verify_der(&ectx, hash, hash_lens[c], sig, slen);
		CHECK(ret == 0, ret, "ecdsa-%s verify",
			curve_names[c]);

		/* Raw sign/verify */
		slen = sizeof(sig);
		ret = mbedcrypto_ecdsa_sign(&ectx, 0, hash, hash_lens[c],
			sig, sizeof(sig), &slen, test_rng, NULL);
		CHECK(ret == 0, ret, "ecdsa-%s raw-sign",
			curve_names[c]);
		ret = mbedcrypto_ecdsa_verify(&ectx, hash, hash_lens[c], sig, slen);
		CHECK(ret == 0, ret, "ecdsa-%s raw-verify",
			curve_names[c]);

		/* Tamper with hash - should fail */
		hash[0] ^= 1;
		ret = mbedcrypto_ecdsa_verify_der(&ectx, hash, hash_lens[c], sig, slen);
		CHECK(ret != 0, EBADMSG, "ecdsa-%s tamper",
			curve_names[c]);
		hash[0] ^= 1;

		mbedcrypto_ecdsa_cleanup(&ectx);
	}

	/* Additional curves: Brainpool */
	{
		struct mbedcrypto_ecdsa_ctx ectx;
		mbedcrypto_ecdsa_init(&ectx);
		struct mbedcrypto_ecp_keypair *kp = (struct mbedcrypto_ecp_keypair *)&ectx;
		int ret = mbedcrypto_ecp_keygen(MBEDCRYPTO_ECP_DP_BP256R1, kp, test_rng, NULL);
		CHECK(ret == 0, ret);

		uint8_t hash[32] = {1,2,3}, sig[128];
		size_t slen = sizeof(sig);
		ret = mbedcrypto_ecdsa_sign_der(&ectx, 0, hash, 32,
			sig, sizeof(sig), &slen, test_rng, NULL);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_ecdsa_verify_der(&ectx, hash, 32, sig, slen);
		CHECK(ret == 0, ret);
		mbedcrypto_ecdsa_cleanup(&ectx);
	}

	/* --- Extended coverage (merged from test_ecdsa_ext) --- */
	{
		/* Test additional curves: SECP192R1, BP384R1, BP512R1 */
		int curves[] = {
			MBEDCRYPTO_ECP_DP_SECP192R1,
			MBEDCRYPTO_ECP_DP_BP384R1,
			MBEDCRYPTO_ECP_DP_BP512R1,
		};
		size_t hlens[] = { 24, 48, 64 };
		const char *names[] = { "P-192", "BP-384", "BP-512" };

		for (c = 0; c < 3; c++) {
			struct mbedcrypto_ecdsa_ctx ectx;
			mbedcrypto_ecdsa_init(&ectx);
			struct mbedcrypto_ecp_keypair *kp = (struct mbedcrypto_ecp_keypair *)&ectx;
			int ret = mbedcrypto_ecp_keygen(curves[c], kp, test_rng, NULL);
			CHECK(ret == 0, ret, "ecdsa-%s keygen",
				names[c]);

			uint8_t hash[64], sig[256];
			size_t slen = sizeof(sig);
			for (i = 0; i < hlens[c]; i++)
				hash[i] = i + c;

			ret = mbedcrypto_ecdsa_sign_der(&ectx, 0, hash, hlens[c],
				sig, sizeof(sig), &slen, test_rng, NULL);
			CHECK(ret == 0, ret, "ecdsa-%s sign",
				names[c]);
			ret = mbedcrypto_ecdsa_verify_der(&ectx, hash, hlens[c], sig, slen);
			CHECK(ret == 0, ret, "ecdsa-%s verify",
				names[c]);

			/* Tamper */
			hash[0] ^= 1;
			ret = mbedcrypto_ecdsa_verify_der(&ectx, hash, hlens[c], sig, slen);
			CHECK(ret != 0, EBADMSG, "ecdsa-%s tamper",
				names[c]);
			mbedcrypto_ecdsa_cleanup(&ectx);
		}

		/* P-256 sign multiple messages with same key, verify cross-independence */
		{
			struct mbedcrypto_ecdsa_ctx ectx;
			mbedcrypto_ecdsa_init(&ectx);
			struct mbedcrypto_ecp_keypair *kp = (struct mbedcrypto_ecp_keypair *)&ectx;
			mbedcrypto_ecp_keygen(MBEDCRYPTO_ECP_DP_SECP256R1, kp, test_rng, NULL);

			uint8_t sig1[128], sig2[128];
			size_t slen1 = sizeof(sig1), slen2 = sizeof(sig2);
			uint8_t h1[32] = {1}, h2[32] = {2};

			mbedcrypto_ecdsa_sign_der(&ectx, 0, h1, 32,
				sig1, sizeof(sig1), &slen1, test_rng, NULL);
			mbedcrypto_ecdsa_sign_der(&ectx, 0, h2, 32,
				sig2, sizeof(sig2), &slen2, test_rng, NULL);

			/* sig1 should NOT verify h2 */
			int ret = mbedcrypto_ecdsa_verify_der(&ectx, h2, 32, sig1, slen1);
			CHECK(ret != 0, EBADMSG);
			/* sig2 should verify h2 */
			ret = mbedcrypto_ecdsa_verify_der(&ectx, h2, 32, sig2, slen2);
			CHECK(ret == 0, ret);
			mbedcrypto_ecdsa_cleanup(&ectx);
		}

#ifdef CONFIG_MBEDCRYPTO_SHA3
		/* ECDSA with SHA3 hashes */
		{
			struct mbedcrypto_ecdsa_ctx ectx;
			struct mbedcrypto_ecp_keypair *kp;

			mbedcrypto_ecdsa_init(&ectx);
			kp = (struct mbedcrypto_ecp_keypair *)&ectx;
			mbedcrypto_ecp_keygen(MBEDCRYPTO_ECP_DP_SECP256R1,
				kp, test_rng, NULL);

			/* SHA3-256 hash + sign/verify */
			{
				uint8_t msg[] = "ECDSA SHA3-256 test";
				uint8_t hash[32], sig[128];
				size_t slen = sizeof(sig);
				struct mbedcrypto_sha3_ctx sha3;
				int ret = 0;

				mbedcrypto_sha3_init(&sha3);
				mbedcrypto_sha3_start(&sha3,
					MBEDCRYPTO_SHA3_256);
				mbedcrypto_sha3_update(&sha3, msg,
					sizeof(msg) - 1);
				mbedcrypto_sha3_final(&sha3, hash, 32);
				mbedcrypto_sha3_cleanup(&sha3);

				ret = mbedcrypto_ecdsa_sign_der(&ectx, 0,
					hash, 32, sig, sizeof(sig),
					&slen, test_rng, NULL);
				CHECK(ret == 0, ret);
				ret = mbedcrypto_ecdsa_verify_der(&ectx,
					hash, 32, sig, slen);
				CHECK(ret == 0, ret);
			}

			/* SHA3-384 hash + sign/verify */
			{
				uint8_t msg[] = "ECDSA SHA3-384 test";
				uint8_t hash[48], sig[128];
				size_t slen = sizeof(sig);
				struct mbedcrypto_sha3_ctx sha3;
				int ret = 0;

				mbedcrypto_sha3_init(&sha3);
				mbedcrypto_sha3_start(&sha3,
					MBEDCRYPTO_SHA3_384);
				mbedcrypto_sha3_update(&sha3, msg,
					sizeof(msg) - 1);
				mbedcrypto_sha3_final(&sha3, hash, 48);
				mbedcrypto_sha3_cleanup(&sha3);

				ret = mbedcrypto_ecdsa_sign_der(&ectx, 0,
					hash, 48, sig, sizeof(sig),
					&slen, test_rng, NULL);
				CHECK(ret == 0, ret);
				ret = mbedcrypto_ecdsa_verify_der(&ectx,
					hash, 48, sig, slen);
				CHECK(ret == 0, ret);
			}

			mbedcrypto_ecdsa_cleanup(&ectx);
		}
#endif
	}

out:
	TEST_END();
}

static void test_ecdh(void)
{
	TEST_START("ECDH");
	int c = 0;

	/*
	 * KAT: ECDH P-256 shared secret.
	 * Reference: NIST CAVP ECC CDH Primitive, P-256, COUNT=0.
	 * Alice computes d * Bob_Q and verifies result equals ZIUT.
	 */
	{
		static const uint8_t p256_d[] = {
			0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xda,
			0xf8, 0x0d, 0x62, 0x14, 0x63, 0x2e, 0xea, 0xe0,
			0x3d, 0x90, 0x58, 0xaf, 0x1f, 0xb6, 0xd2, 0x2e,
			0xd8, 0x0b, 0xad, 0xb6, 0x2b, 0xc1, 0xa5, 0x34,
		};
		static const uint8_t p256_alice_x[] = {
			0x0e, 0xad, 0x21, 0x85, 0x90, 0x11, 0x9e, 0x88,
			0x76, 0xb2, 0x91, 0x46, 0xff, 0x89, 0xca, 0x61,
			0x77, 0x0c, 0x4e, 0xdb, 0xbf, 0x97, 0xd3, 0x8c,
			0xe3, 0x85, 0xed, 0x28, 0x1d, 0x86, 0x3d, 0xf8,
		};
		static const uint8_t p256_alice_y[] = {
			0x04, 0x6c, 0x4e, 0x4c, 0x75, 0xb4, 0x96, 0x5b,
			0x6a, 0x77, 0xf7, 0xcc, 0x07, 0x45, 0x4d, 0x3e,
			0x9d, 0x7b, 0x2a, 0x1d, 0xb8, 0xc2, 0xb8, 0x26,
			0xba, 0x3d, 0x2a, 0x6a, 0x30, 0xf1, 0x8b, 0xff,
		};
		static const uint8_t p256_bob_x[] = {
			0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c,
			0x5c, 0xc6, 0x32, 0xca, 0x65, 0x64, 0x0d, 0xb9,
			0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4,
			0x2c, 0xe7, 0xcc, 0x83, 0x88, 0x33, 0xd2, 0x87,
		};
		static const uint8_t p256_bob_y[] = {
			0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06,
			0x0d, 0xdb, 0x20, 0xba, 0x5c, 0x51, 0xdc, 0xc5,
			0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40, 0xdf, 0xe0,
			0x44, 0x17, 0x82, 0xca, 0xb8, 0x5f, 0xa4, 0xac,
		};
		static const uint8_t p256_z[] = {
			0x46, 0xfc, 0x62, 0x10, 0x64, 0x20, 0xff, 0x01,
			0x2e, 0x54, 0xa4, 0x34, 0xfb, 0xdd, 0x2d, 0x25,
			0xcc, 0xc5, 0x85, 0x20, 0x60, 0x56, 0x1e, 0x68,
			0x04, 0x0d, 0xd7, 0x77, 0x89, 0x97, 0xbd, 0x7b,
		};

		struct mbedcrypto_ecdh_ctx kat;
		mbedcrypto_ecdh_init(&kat);
		mbedcrypto_ecp_load_group(&kat.grp, MBEDCRYPTO_ECP_DP_SECP256R1);
		mbedcrypto_bn_from_binary(&kat.d, p256_d, 32);
		mbedcrypto_ecp_point_init(&kat.Q);
		mbedcrypto_bn_from_binary(&kat.Q.X, p256_alice_x, 32);
		mbedcrypto_bn_from_binary(&kat.Q.Y, p256_alice_y, 32);
		mbedcrypto_bn_set_word(&kat.Q.Z, 1);
		mbedcrypto_bn_from_binary(&kat.Qp.X, p256_bob_x, 32);
		mbedcrypto_bn_from_binary(&kat.Qp.Y, p256_bob_y, 32);
		mbedcrypto_bn_set_word(&kat.Qp.Z, 1);

		uint8_t shared[32];
		size_t slen;
		int ret = mbedcrypto_ecdh_derive_shared(&kat, &slen, shared, sizeof(shared), NULL, NULL);
		CHECK(ret == 0, ret);
		CHECK(slen == 32 && memcmp(shared, p256_z, 32) == 0, EBADMSG);

		mbedcrypto_ecdh_cleanup(&kat);
	}

	/*
	 * KAT: ECDH P-384 shared secret.
	 * Reference: NIST CAVP ECC CDH Primitive, P-384, COUNT=0.
	 */
	{
		static const uint8_t p384_d[] = {
			0x3c, 0xc3, 0x12, 0x2a, 0x68, 0xf0, 0xd9, 0x50,
			0x27, 0xad, 0x38, 0xc0, 0x67, 0x91, 0x6b, 0xa0,
			0xeb, 0x8c, 0x38, 0x89, 0x4d, 0x22, 0xe1, 0xb1,
			0x56, 0x18, 0xb6, 0x81, 0x8a, 0x66, 0x17, 0x74,
			0xad, 0x46, 0x3b, 0x20, 0x5d, 0xa8, 0x8c, 0xf6,
			0x99, 0xab, 0x4d, 0x43, 0xc9, 0xcf, 0x98, 0xa1,
		};
		static const uint8_t p384_alice_x[] = {
			0xa0, 0xc2, 0x7e, 0xc8, 0x93, 0x09, 0x2d, 0xea,
			0x1e, 0x1b, 0xd2, 0xcc, 0xfe, 0xd3, 0xcf, 0x94,
			0x5c, 0x81, 0x34, 0xed, 0x0c, 0x9f, 0x81, 0x31,
			0x1a, 0x0f, 0x4a, 0x05, 0x94, 0x2d, 0xb8, 0xdb,
			0xed, 0x8d, 0xd5, 0x9f, 0x26, 0x74, 0x71, 0xd5,
			0x46, 0x2a, 0xa1, 0x4f, 0xe7, 0x2d, 0xe8, 0x56,
		};
		static const uint8_t p384_alice_y[] = {
			0x85, 0x56, 0x49, 0x40, 0x98, 0x15, 0xbb, 0x91,
			0x42, 0x4e, 0xac, 0xa5, 0xfd, 0x76, 0xc9, 0x73,
			0x75, 0xd5, 0x75, 0xd1, 0x42, 0x2e, 0xc5, 0x3d,
			0x34, 0x3b, 0xd3, 0x3b, 0x84, 0x7f, 0xdf, 0x0c,
			0x11, 0x56, 0x96, 0x85, 0xb5, 0x28, 0xab, 0x25,
			0x49, 0x30, 0x15, 0x42, 0x8d, 0x7c, 0xf7, 0x2b,
		};
		static const uint8_t p384_bob_x[] = {
			0x98, 0x03, 0x80, 0x7f, 0x2f, 0x6d, 0x2f, 0xd9,
			0x66, 0xcd, 0xd0, 0x29, 0x0b, 0xd4, 0x10, 0xc0,
			0x19, 0x03, 0x52, 0xfb, 0xec, 0x7f, 0xf6, 0x24,
			0x7d, 0xe1, 0x30, 0x2d, 0xf8, 0x6f, 0x25, 0xd3,
			0x4f, 0xe4, 0xa9, 0x7b, 0xef, 0x60, 0xcf, 0xf5,
			0x48, 0x35, 0x5c, 0x01, 0x5d, 0xbb, 0x3e, 0x5f,
		};
		static const uint8_t p384_bob_y[] = {
			0xba, 0x26, 0xca, 0x69, 0xec, 0x2f, 0x5b, 0x5d,
			0x9d, 0xad, 0x20, 0xcc, 0x9d, 0xa7, 0x11, 0x38,
			0x3a, 0x9d, 0xbe, 0x34, 0xea, 0x3f, 0xa5, 0xa2,
			0xaf, 0x75, 0xb4, 0x65, 0x02, 0x62, 0x9a, 0xd5,
			0x4d, 0xd8, 0xb7, 0xd7, 0x3a, 0x8a, 0xbb, 0x06,
			0xa3, 0xa3, 0xbe, 0x47, 0xd6, 0x50, 0xcc, 0x99,
		};
		static const uint8_t p384_z[] = {
			0xd3, 0xc4, 0x2d, 0xbe, 0xd9, 0x1a, 0x13, 0xb2,
			0xd2, 0xe9, 0xaa, 0x6c, 0x29, 0x0c, 0x57, 0xcf,
			0xac, 0xcc, 0x29, 0x18, 0x84, 0xd5, 0x9b, 0x88,
			0x07, 0x85, 0xba, 0x81, 0x9d, 0x35, 0xba, 0xec,
			0xad, 0x64, 0xd0, 0x5a, 0x82, 0x45, 0x77, 0xfb,
			0xf5, 0xe6, 0x12, 0xa9, 0x7b, 0xfa, 0xf2, 0x35,
		};

		struct mbedcrypto_ecdh_ctx kat;
		mbedcrypto_ecdh_init(&kat);
		mbedcrypto_ecp_load_group(&kat.grp, MBEDCRYPTO_ECP_DP_SECP384R1);
		mbedcrypto_bn_from_binary(&kat.d, p384_d, 48);
		mbedcrypto_ecp_point_init(&kat.Q);
		mbedcrypto_bn_from_binary(&kat.Q.X, p384_alice_x, 48);
		mbedcrypto_bn_from_binary(&kat.Q.Y, p384_alice_y, 48);
		mbedcrypto_bn_set_word(&kat.Q.Z, 1);
		mbedcrypto_bn_from_binary(&kat.Qp.X, p384_bob_x, 48);
		mbedcrypto_bn_from_binary(&kat.Qp.Y, p384_bob_y, 48);
		mbedcrypto_bn_set_word(&kat.Qp.Z, 1);

		uint8_t shared[48];
		size_t slen;
		int ret = mbedcrypto_ecdh_derive_shared(&kat, &slen, shared, sizeof(shared), NULL, NULL);
		CHECK(ret == 0, ret);
		CHECK(slen == 48 && memcmp(shared, p384_z, 48) == 0, EBADMSG);

		mbedcrypto_ecdh_cleanup(&kat);
	}

	/*
	 * KAT: ECDH P-521 shared secret.
	 * Reference: NIST CAVP ECC CDH Primitive, P-521, COUNT=0.
	 */
	{
		static const uint8_t p521_d[] = {
			0x00, 0x37, 0xad, 0xe9, 0x31, 0x9a, 0x89, 0xf4,
			0xda, 0xbd, 0xb3, 0xef, 0x41, 0x1a, 0xac, 0xcc,
			0xa5, 0x12, 0x3c, 0x61, 0xac, 0xab, 0x57, 0xb5,
			0x39, 0x3d, 0xce, 0x47, 0x60, 0x81, 0x72, 0xa0,
			0x95, 0xaa, 0x85, 0xa3, 0x0f, 0xe1, 0xc2, 0x95,
			0x2c, 0x67, 0x71, 0xd9, 0x37, 0xba, 0x97, 0x77,
			0xf5, 0x95, 0x7b, 0x26, 0x39, 0xba, 0xb0, 0x72,
			0x46, 0x2f, 0x68, 0xc2, 0x7a, 0x57, 0x38, 0x2d,
			0x4a, 0x52,
		};
		static const uint8_t p521_bob_x[] = {
			0x00, 0xd0, 0xb3, 0x97, 0x5a, 0xc4, 0xb7, 0x99,
			0xf5, 0xbe, 0xa1, 0x6d, 0x5e, 0x13, 0xe9, 0xaf,
			0x97, 0x1d, 0x5e, 0x9b, 0x98, 0x4c, 0x9f, 0x39,
			0x72, 0x8b, 0x5e, 0x57, 0x39, 0x73, 0x5a, 0x21,
			0x9b, 0x97, 0xc3, 0x56, 0x43, 0x6a, 0xdc, 0x6e,
			0x95, 0xbb, 0x03, 0x52, 0xf6, 0xbe, 0x64, 0xa6,
			0xc2, 0x91, 0x2d, 0x4e, 0xf2, 0xd0, 0x43, 0x3c,
			0xed, 0x2b, 0x61, 0x71, 0x64, 0x00, 0x12, 0xd9,
			0x46, 0x0f,
		};
		static const uint8_t p521_bob_y[] = {
			0x01, 0x5c, 0x68, 0x22, 0x63, 0x83, 0x95, 0x6e,
			0x3b, 0xd0, 0x66, 0xe7, 0x97, 0xb6, 0x23, 0xc2,
			0x7c, 0xe0, 0xea, 0xc2, 0xf5, 0x51, 0xa1, 0x0c,
			0x2c, 0x72, 0x4d, 0x98, 0x52, 0x07, 0x7b, 0x87,
			0x22, 0x0b, 0x65, 0x36, 0xc5, 0xc4, 0x08, 0xa1,
			0xd2, 0xae, 0xbb, 0x8e, 0x86, 0xd6, 0x78, 0xae,
			0x49, 0xcb, 0x57, 0x09, 0x1f, 0x47, 0x32, 0x29,
			0x65, 0x79, 0xab, 0x44, 0xfc, 0xd1, 0x7f, 0x0f,
			0xc5, 0x6a,
		};
		static const uint8_t p521_z[] = {
			0x01, 0x14, 0x4c, 0x7d, 0x79, 0xae, 0x69, 0x56,
			0xbc, 0x8e, 0xdb, 0x8e, 0x7c, 0x78, 0x7c, 0x45,
			0x21, 0xcb, 0x08, 0x6f, 0xa6, 0x44, 0x07, 0xf9,
			0x78, 0x94, 0xe5, 0xe6, 0xb2, 0xd7, 0x9b, 0x04,
			0xd1, 0x42, 0x7e, 0x73, 0xca, 0x4b, 0xaa, 0x24,
			0x0a, 0x34, 0x78, 0x68, 0x59, 0x81, 0x0c, 0x06,
			0xb3, 0xc7, 0x15, 0xa3, 0xa8, 0xcc, 0x31, 0x51,
			0xf2, 0xbe, 0xe4, 0x17, 0x99, 0x6d, 0x19, 0xf3,
			0xdd, 0xea,
		};

		struct mbedcrypto_ecdh_ctx kat;
		mbedcrypto_ecdh_init(&kat);
		mbedcrypto_ecp_load_group(&kat.grp, MBEDCRYPTO_ECP_DP_SECP521R1);
		mbedcrypto_bn_from_binary(&kat.d, p521_d, 66);
		mbedcrypto_ecp_point_init(&kat.Q);
		mbedcrypto_bn_from_binary(&kat.Qp.X, p521_bob_x, 66);
		mbedcrypto_bn_from_binary(&kat.Qp.Y, p521_bob_y, 66);
		mbedcrypto_bn_set_word(&kat.Qp.Z, 1);

		uint8_t shared[66];
		size_t slen;
		int ret = mbedcrypto_ecdh_derive_shared(&kat, &slen, shared, sizeof(shared), NULL, NULL);
		CHECK(ret == 0, ret);
		CHECK(slen == 66 && memcmp(shared, p521_z, 66) == 0, EBADMSG);

		mbedcrypto_ecdh_cleanup(&kat);
	}

	/* --- Extended coverage (merged from test_ecdh_ext) --- */
	{
		int curves[] = {
			MBEDCRYPTO_ECP_DP_SECP521R1,
			MBEDCRYPTO_ECP_DP_BP256R1,
			MBEDCRYPTO_ECP_DP_BP384R1,
			MBEDCRYPTO_ECP_DP_BP512R1,
		};
		const char *names[] = { "P-521", "BP-256", "BP-384", "BP-512" };

		for (c = 0; c < 4; c++) {
			struct mbedcrypto_ecdh_ctx alice, bob;
			mbedcrypto_ecdh_init(&alice);
			mbedcrypto_ecdh_init(&bob);

			mbedcrypto_ecp_load_group(&alice.grp, curves[c]);
			mbedcrypto_ecp_load_group(&bob.grp, curves[c]);

			struct mbedcrypto_ecp_keypair kp_a, kp_b;
			mbedcrypto_ecp_keypair_init(&kp_a);
			mbedcrypto_ecp_keypair_init(&kp_b);
			int ret = mbedcrypto_ecp_keygen(curves[c], &kp_a, test_rng, NULL);
			CHECK(ret == 0, ret, "ecdh-%s keygen-a",
				names[c]);
			ret = mbedcrypto_ecp_keygen(curves[c], &kp_b, test_rng, NULL);
			CHECK(ret == 0, ret, "ecdh-%s keygen-b",
				names[c]);

			mbedcrypto_bn_copy(&alice.d, &kp_a.d);
			mbedcrypto_ecp_point_init(&alice.Q);
			mbedcrypto_bn_copy(&alice.Q.X, &kp_a.Q.X);
			mbedcrypto_bn_copy(&alice.Q.Y, &kp_a.Q.Y);
			mbedcrypto_bn_copy(&alice.Q.Z, &kp_a.Q.Z);

			mbedcrypto_bn_copy(&bob.d, &kp_b.d);
			mbedcrypto_ecp_point_init(&bob.Q);
			mbedcrypto_bn_copy(&bob.Q.X, &kp_b.Q.X);
			mbedcrypto_bn_copy(&bob.Q.Y, &kp_b.Q.Y);
			mbedcrypto_bn_copy(&bob.Q.Z, &kp_b.Q.Z);

			mbedcrypto_bn_copy(&alice.Qp.X, &kp_b.Q.X);
			mbedcrypto_bn_copy(&alice.Qp.Y, &kp_b.Q.Y);
			mbedcrypto_bn_copy(&alice.Qp.Z, &kp_b.Q.Z);

			mbedcrypto_bn_copy(&bob.Qp.X, &kp_a.Q.X);
			mbedcrypto_bn_copy(&bob.Qp.Y, &kp_a.Q.Y);
			mbedcrypto_bn_copy(&bob.Qp.Z, &kp_a.Q.Z);

			uint8_t sa[66], sb[66];
			size_t sa_len, sb_len;
			ret = mbedcrypto_ecdh_derive_shared(&alice, &sa_len, sa, sizeof(sa), test_rng, NULL);
			CHECK(ret == 0, ret, "ecdh-%s alice", names[c]);
			ret = mbedcrypto_ecdh_derive_shared(&bob, &sb_len, sb, sizeof(sb), test_rng, NULL);
			CHECK(ret == 0, ret, "ecdh-%s bob", names[c]);
			CHECK(sa_len == sb_len && memcmp(sa, sb, sa_len) == 0,
				EBADMSG, "ecdh-%s agree", names[c]);

			mbedcrypto_ecdh_cleanup(&alice);
			mbedcrypto_ecdh_cleanup(&bob);
			mbedcrypto_ecp_keypair_cleanup(&kp_a);
			mbedcrypto_ecp_keypair_cleanup(&kp_b);
		}
	}

out:
	TEST_END();
}

static void test_sm2dsa(void)
{
	TEST_START("SM2DSA");
	struct mbedcrypto_sm2dsa_ctx sctx;
	int ret = 0;
	int i = 0, m = 0;

	/*
	 * KAT: SM2DSA verify with known pubkey + hash + signature.
	 * Key: Alice's key from GB/T 32918.3 (sm2kep_da).
	 * e = SM3(Z || "SM2DSA KAT test"), IDA = "1234567812345678"
	 * Signature computed by pure Python SM2DSA implementation.
	 */
	{
		static const uint8_t sm2_kat_x[] = {
			0x16, 0x0e, 0x12, 0x89, 0x7d, 0xf4, 0xed, 0xb6,
			0x1d, 0xd8, 0x12, 0xfe, 0xb9, 0x67, 0x48, 0xfb,
			0xd3, 0xcc, 0xf4, 0xff, 0xe2, 0x6a, 0xa6, 0xf6,
			0xdb, 0x95, 0x40, 0xaf, 0x49, 0xc9, 0x42, 0x32,
		};
		static const uint8_t sm2_kat_y[] = {
			0x4a, 0x7d, 0xad, 0x08, 0xbb, 0x9a, 0x45, 0x95,
			0x31, 0x69, 0x4b, 0xeb, 0x20, 0xaa, 0x48, 0x9d,
			0x66, 0x49, 0x97, 0x5e, 0x1b, 0xfc, 0xf8, 0xc4,
			0x74, 0x1b, 0x78, 0xb4, 0xb2, 0x23, 0x00, 0x7f,
		};
		static const uint8_t sm2_kat_hash[] = {
			0x02, 0x1f, 0x94, 0x25, 0x39, 0xa6, 0xb1, 0x5c,
			0x03, 0xbd, 0x2e, 0xc6, 0x42, 0xd5, 0x25, 0x0b,
			0xba, 0x88, 0x74, 0x0f, 0x76, 0xe9, 0xa9, 0x87,
			0x0d, 0x68, 0x0f, 0xfe, 0x09, 0x2f, 0xc9, 0x2c,
		};
		static const uint8_t sm2_kat_sig_raw[] = {
			0x3c, 0xfa, 0x8b, 0x29, 0xb3, 0x96, 0x4d, 0x47,
			0x90, 0xae, 0xec, 0x41, 0x06, 0x90, 0x89, 0x2c,
			0x03, 0x19, 0xf5, 0xe7, 0x24, 0x94, 0xe3, 0xf9,
			0x4e, 0x8e, 0x88, 0x38, 0x95, 0x91, 0x9a, 0xc8,
			0xd6, 0x7b, 0x0e, 0x66, 0xa6, 0x0a, 0x60, 0x97,
			0xa2, 0xcd, 0xd0, 0xd2, 0xc3, 0xcb, 0x6a, 0x24,
			0x3c, 0x02, 0x00, 0x90, 0x80, 0xad, 0x82, 0xda,
			0x3e, 0xce, 0xe8, 0x82, 0x74, 0x70, 0x4f, 0x8a,
		};

		struct mbedcrypto_sm2dsa_ctx kat;
		mbedcrypto_sm2dsa_init(&kat);
		ret = mbedcrypto_sm2dsa_load_group(&kat);
		CHECK(ret == 0, ret);

		/* Import public key */
		ret = mbedcrypto_bn_from_binary(&kat.Q.X, sm2_kat_x, 32);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_bn_from_binary(&kat.Q.Y, sm2_kat_y, 32);
		CHECK(ret == 0, ret);
		mbedcrypto_bn_set_word(&kat.Q.Z, 1);

		/* Verify known raw signature */
		ret = mbedcrypto_sm2dsa_verify(&kat, sm2_kat_hash, 32,
			sm2_kat_sig_raw, sizeof(sm2_kat_sig_raw));
		CHECK(ret == 0, ret);

		/* Tamper with hash - should fail */
		uint8_t bad[32];
		memcpy(bad, sm2_kat_hash, 32);
		bad[0] ^= 1;
		ret = mbedcrypto_sm2dsa_verify(&kat, bad, 32,
			sm2_kat_sig_raw, sizeof(sm2_kat_sig_raw));
		CHECK(ret != 0, EBADMSG);

		mbedcrypto_sm2dsa_cleanup(&kat);
	}

	/* Roundtrip: keygen + sign/verify */
	mbedcrypto_sm2dsa_init(&sctx);
	ret = mbedcrypto_sm2dsa_load_group(&sctx);
	CHECK(ret == 0, ret);

	/* Generate key manually */
	ret = mbedcrypto_bn_random(&sctx.d, 32, test_rng, NULL);
	CHECK(ret == 0, ret);
	ret = mbedcrypto_bn_mod(&sctx.d, &sctx.d, &sctx.grp.N);
	CHECK(ret == 0, ret);
	ret = mbedcrypto_ecp_scalar_mul(&sctx.grp, &sctx.Q, &sctx.d, &sctx.grp.G, test_rng, NULL);
	CHECK(ret == 0, ret);

	/* Compute Z value */
	uint8_t z[32];
	ret = mbedcrypto_sm2_compute_z(&sctx, (const uint8_t *)"1234567812345678", 16, z);
	CHECK(ret == 0, ret);

	/* Sign with e = SM3(Z || msg) */
	uint8_t msg[] = "message digest";
	uint8_t hash[32];
	struct mbedcrypto_sm3_ctx sm3ctx;
	mbedcrypto_sm3_init(&sm3ctx);
	mbedcrypto_sm3_update(&sm3ctx, z, 32);
	mbedcrypto_sm3_update(&sm3ctx, msg, sizeof(msg) - 1);
	mbedcrypto_sm3_final(&sm3ctx, hash);
	mbedcrypto_sm3_cleanup(&sm3ctx);

	uint8_t sig[128];
	size_t slen = sizeof(sig);
	ret = mbedcrypto_sm2dsa_sign(&sctx, hash, 32, sig, sizeof(sig), &slen, test_rng, NULL);
	CHECK(ret == 0, ret);

	/* Verify */
	ret = mbedcrypto_sm2dsa_verify(&sctx, hash, 32, sig, slen);
	CHECK(ret == 0, ret);

	/* DER sign and verify */
	slen = sizeof(sig);
	ret = mbedcrypto_sm2dsa_sign_der(&sctx, hash, 32,
		sig, sizeof(sig), &slen, test_rng, NULL);
	CHECK(ret == 0, ret);
	ret = mbedcrypto_sm2dsa_verify_der(&sctx, hash, 32, sig, slen);
	CHECK(ret == 0, ret);

	/* Tamper - should fail */
	hash[0] ^= 1;
	ret = mbedcrypto_sm2dsa_verify(&sctx, hash, 32, sig, slen);
	CHECK(ret != 0, EBADMSG);
	hash[0] ^= 1;

	/* Multiple sign/verify with same key */
	for (m = 0; m < 3; m++) {
		uint8_t h[32];
		for (i = 0; i < 32; i++)
			h[i] = i + m * 13;
		slen = sizeof(sig);
		ret = mbedcrypto_sm2dsa_sign(&sctx, h, 32, sig, sizeof(sig), &slen, test_rng, NULL);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_sm2dsa_verify(&sctx, h, 32, sig, slen);
		CHECK(ret == 0, ret);
	}

	mbedcrypto_sm2dsa_cleanup(&sctx);

out:
	TEST_END();
}

static void test_sm2pke(void)
{
	TEST_START("SM2PKE");
	struct mbedcrypto_sm2pke_ctx pctx;
	int ret = 0;
	size_t i = 0, t = 0;

	/*
	 * KAT: SM2PKE decrypt with known private key and ciphertext.
	 * Key: Alice's key from GB/T 32918.3 (sm2kep_da).
	 * Plaintext: "SM2PKE KAT test!" (16 bytes)
	 * Ciphertext generated by pure Python SM2PKE implementation.
	 * Format: 04 || C1.X(32) || C1.Y(32) || C3(32) || C2(16) = 113 bytes
	 */
	{
		static const uint8_t sm2pke_kat_d[] = {
			0x81, 0xeb, 0x26, 0xe9, 0x41, 0xbb, 0x5a, 0xf1,
			0x6d, 0xf1, 0x16, 0x49, 0x5f, 0x90, 0x69, 0x52,
			0x72, 0xae, 0x2c, 0xd6, 0x3d, 0x6c, 0x4a, 0xe1,
			0x67, 0x84, 0x18, 0xbe, 0x48, 0x23, 0x00, 0x29,
		};
		static const uint8_t sm2pke_kat_x[] = {
			0x16, 0x0e, 0x12, 0x89, 0x7d, 0xf4, 0xed, 0xb6,
			0x1d, 0xd8, 0x12, 0xfe, 0xb9, 0x67, 0x48, 0xfb,
			0xd3, 0xcc, 0xf4, 0xff, 0xe2, 0x6a, 0xa6, 0xf6,
			0xdb, 0x95, 0x40, 0xaf, 0x49, 0xc9, 0x42, 0x32,
		};
		static const uint8_t sm2pke_kat_y[] = {
			0x4a, 0x7d, 0xad, 0x08, 0xbb, 0x9a, 0x45, 0x95,
			0x31, 0x69, 0x4b, 0xeb, 0x20, 0xaa, 0x48, 0x9d,
			0x66, 0x49, 0x97, 0x5e, 0x1b, 0xfc, 0xf8, 0xc4,
			0x74, 0x1b, 0x78, 0xb4, 0xb2, 0x23, 0x00, 0x7f,
		};
		static const uint8_t sm2pke_kat_ct[] = {
			0x04, 0xa0, 0x9e, 0xae, 0xe0, 0x1a, 0xf9, 0xea,
			0xa1, 0x98, 0xd1, 0xf0, 0xfe, 0xdb, 0x3f, 0x7e,
			0xa3, 0x33, 0x4d, 0xa5, 0x86, 0x4f, 0x53, 0x13,
			0x2a, 0x39, 0x26, 0x10, 0x3a, 0x25, 0x09, 0x42,
			0x89, 0x20, 0x4a, 0x1f, 0xa8, 0xb4, 0x17, 0x3b,
			0x68, 0xc3, 0x35, 0x42, 0x35, 0xa3, 0xae, 0x4d,
			0x98, 0xdb, 0x69, 0x68, 0xc2, 0xa4, 0xe2, 0x9e,
			0x0c, 0x97, 0xc7, 0xe8, 0xbf, 0xc6, 0x23, 0x02,
			0x4a, 0xac, 0x30, 0xd2, 0x82, 0x08, 0x1f, 0xd9,
			0xa9, 0xb6, 0x00, 0x48, 0xea, 0x71, 0x23, 0x87,
			0x18, 0x20, 0x9d, 0xe9, 0x11, 0x6c, 0xac, 0xaf,
			0xfa, 0x39, 0xcf, 0x72, 0xe0, 0xaf, 0xc3, 0xf4,
			0xb7, 0x8b, 0xee, 0xcc, 0xb9, 0xd4, 0xc2, 0xea,
			0x4e, 0xe1, 0xb7, 0x4a, 0xc7, 0x93, 0x9c, 0x7f,
			0x73,
		};
		static const uint8_t sm2pke_kat_pt[] = {
			0x53, 0x4d, 0x32, 0x50, 0x4b, 0x45, 0x20, 0x4b,
			0x41, 0x54, 0x20, 0x74, 0x65, 0x73, 0x74, 0x21,
		};

		struct mbedcrypto_sm2pke_ctx kat;
		mbedcrypto_sm2pke_init(&kat);
		ret = mbedcrypto_sm2pke_load_group(&kat);
		CHECK(ret == 0, ret);

		/* Import private key and public key */
		ret = mbedcrypto_bn_from_binary(&kat.d, sm2pke_kat_d, 32);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_bn_from_binary(&kat.Q.X, sm2pke_kat_x, 32);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_bn_from_binary(&kat.Q.Y, sm2pke_kat_y, 32);
		CHECK(ret == 0, ret);
		mbedcrypto_bn_set_word(&kat.Q.Z, 1);

		/* Decrypt known ciphertext and compare with expected plaintext */
		uint8_t dec[16];
		size_t dec_len = 0;
		ret = mbedcrypto_sm2pke_decrypt(&kat, sm2pke_kat_ct,
			sizeof(sm2pke_kat_ct), dec, &dec_len);
		CHECK(ret == 0, ret);
		CHECK(dec_len == sizeof(sm2pke_kat_pt) &&
			memcmp(dec, sm2pke_kat_pt, dec_len) == 0, EBADMSG);

		/* Tamper with C3 - should fail integrity check */
		uint8_t bad_ct[113];
		memcpy(bad_ct, sm2pke_kat_ct, sizeof(bad_ct));
		bad_ct[70] ^= 1;
		ret = mbedcrypto_sm2pke_decrypt(&kat, bad_ct,
			sizeof(bad_ct), dec, &dec_len);
		CHECK(ret != 0, EBADMSG);

		mbedcrypto_sm2pke_cleanup(&kat);
	}

	/* Roundtrip: keygen + encrypt/decrypt */
	mbedcrypto_sm2pke_init(&pctx);
	ret = mbedcrypto_sm2pke_load_group(&pctx);
	CHECK(ret == 0, ret);

	/* Check: ecp_check_pubkey validates the generator */
	ret = mbedcrypto_ecp_validate_point(&pctx.grp, &pctx.grp.G);
	CHECK(ret == 0, ret);

	/* Generate key manually */
	mbedcrypto_bn_random(&pctx.d, 32, test_rng, NULL);
	mbedcrypto_bn_mod(&pctx.d, &pctx.d, &pctx.grp.N);
	mbedcrypto_ecp_scalar_mul(&pctx.grp, &pctx.Q, &pctx.d, &pctx.grp.G, test_rng, NULL);

	/* Check Q = d*G is on curve */
	ret = mbedcrypto_ecp_validate_point(&pctx.grp, &pctx.Q);
	CHECK(ret == 0, ret);

	/* Encrypt/decrypt with various lengths */
	size_t pke_lens[] = { 1, 8, 16, 31, 32, 48, 64 };
	for (t = 0; t < sizeof(pke_lens)/sizeof(pke_lens[0]); t++) {
		size_t len = pke_lens[t];
		uint8_t pt[64], ct_buf[256], dec_buf[64];
		size_t ct_len = 0, dec_len = 0;
		for (i = 0; i < len; i++)
			pt[i] = i + t;

		ret = mbedcrypto_sm2pke_encrypt(&pctx, pt, len, ct_buf, &ct_len, test_rng, NULL);
		CHECK(ret == 0, ret);
		CHECK(ct_len > len, EBADMSG);

		/* Debug: parse C1 from ciphertext and check it */
		{
			struct mbedcrypto_ecp_point C1_dbg;
			mbedcrypto_ecp_point_init(&C1_dbg);
			mbedcrypto_bn_from_binary(&C1_dbg.X, ct_buf + 1, 32);
			mbedcrypto_bn_from_binary(&C1_dbg.Y, ct_buf + 33, 32);
			mbedcrypto_bn_set_word(&C1_dbg.Z, 1);
			int chk = mbedcrypto_ecp_validate_point(&pctx.grp, &C1_dbg);
			CHECK(chk == 0, EBADMSG);
			mbedcrypto_ecp_point_cleanup(&C1_dbg);
		}

		ret = mbedcrypto_sm2pke_decrypt(&pctx, ct_buf, ct_len, dec_buf, &dec_len);
		CHECK(ret == 0, ret);
		CHECK(dec_len == len && memcmp(dec_buf, pt, len) == 0, EBADMSG);
	}

	mbedcrypto_sm2pke_cleanup(&pctx);

out:
	TEST_END();
}

/* SM2KEP KAT vectors from GB/T 32918.3 */
static const uint8_t sm2kep_da[] = {
	0x81, 0xEB, 0x26, 0xE9, 0x41, 0xBB, 0x5A, 0xF1,
	0x6D, 0xF1, 0x16, 0x49, 0x5F, 0x90, 0x69, 0x52,
	0x72, 0xAE, 0x2C, 0xD6, 0x3D, 0x6C, 0x4A, 0xE1,
	0x67, 0x84, 0x18, 0xBE, 0x48, 0x23, 0x00, 0x29
};
static const uint8_t sm2kep_db[] = {
	0x73, 0x63, 0x5A, 0x1B, 0x4C, 0x05, 0xF9, 0x41,
	0xF6, 0x1B, 0xDD, 0x38, 0x3D, 0x8F, 0xCC, 0x89,
	0xD9, 0x5E, 0x1F, 0x2E, 0xAA, 0x3B, 0x9E, 0xE3,
	0x2A, 0x9E, 0x95, 0x71, 0xCE, 0xAA, 0xA2, 0xEC
};
static const uint8_t sm2kep_ra[] = {
	0xD4, 0xDE, 0x15, 0x47, 0x4D, 0xB7, 0x4D, 0x06,
	0x49, 0x1C, 0x44, 0x0D, 0x30, 0x5E, 0x01, 0x24,
	0x00, 0x99, 0x0F, 0x3E, 0x39, 0x0C, 0x7E, 0x87,
	0x15, 0x3C, 0x12, 0xDB, 0x2E, 0xA6, 0x0B, 0xB3
};
static const uint8_t sm2kep_rb[] = {
	0x25, 0xA9, 0x16, 0xBB, 0xF8, 0x8E, 0xCD, 0x8D,
	0xF3, 0x27, 0x14, 0xA9, 0x18, 0x4F, 0xC0, 0x9D,
	0x3B, 0xFA, 0x12, 0x11, 0xFE, 0xF9, 0xEF, 0x43,
	0xBD, 0x6E, 0x63, 0xF2, 0xDA, 0xC3, 0xEB, 0xE9
};
static const uint8_t sm2kep_id[] = {
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
};

static void test_sm2kep(void)
{
	TEST_START("SM2KEP");

	/* KAT: GB/T 32918.3 known-answer test */
	{
		struct mbedcrypto_ecp_keypair ka, kb, ea, eb;
		struct mbedcrypto_ecp_point peer_pub, peer_eph;
		struct mbedcrypto_sm2kep_parms pa, pb;
		uint8_t key_a[16], key_b[16];
		uint8_t conf_a[32], conf_b[32];
		int ret = 0;

		mbedcrypto_ecp_keypair_init(&ka);
		mbedcrypto_ecp_keypair_init(&kb);
		mbedcrypto_ecp_keypair_init(&ea);
		mbedcrypto_ecp_keypair_init(&eb);
		mbedcrypto_ecp_point_init(&peer_pub);
		mbedcrypto_ecp_point_init(&peer_eph);

		/* Load Alice's static key */
		ret = mbedcrypto_ecp_load_group(&ka.grp,
				MBEDCRYPTO_ECP_DP_SM2);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_bn_from_binary(&ka.d,
				sm2kep_da, 32);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_ecp_scalar_mul(&ka.grp, &ka.Q,
				&ka.d, &ka.grp.G, NULL, NULL);
		CHECK(ret == 0, ret);

		/* Load Bob's static key */
		ret = mbedcrypto_ecp_load_group(&kb.grp,
				MBEDCRYPTO_ECP_DP_SM2);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_bn_from_binary(&kb.d,
				sm2kep_db, 32);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_ecp_scalar_mul(&kb.grp, &kb.Q,
				&kb.d, &kb.grp.G, NULL, NULL);
		CHECK(ret == 0, ret);

		/* Load Alice's ephemeral key */
		ret = mbedcrypto_ecp_load_group(&ea.grp,
				MBEDCRYPTO_ECP_DP_SM2);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_bn_from_binary(&ea.d,
				sm2kep_ra, 32);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_ecp_scalar_mul(&ea.grp, &ea.Q,
				&ea.d, &ea.grp.G, NULL, NULL);
		CHECK(ret == 0, ret);

		/* Load Bob's ephemeral key */
		ret = mbedcrypto_ecp_load_group(&eb.grp,
				MBEDCRYPTO_ECP_DP_SM2);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_bn_from_binary(&eb.d,
				sm2kep_rb, 32);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_ecp_scalar_mul(&eb.grp, &eb.Q,
				&eb.d, &eb.grp.G, NULL, NULL);
		CHECK(ret == 0, ret);

		/* Bob (responder) derives key with Alice as peer */
		mbedcrypto_bn_copy(&peer_pub.X, &ka.Q.X);
		mbedcrypto_bn_copy(&peer_pub.Y, &ka.Q.Y);
		mbedcrypto_bn_copy(&peer_pub.Z, &ka.Q.Z);
		mbedcrypto_bn_copy(&peer_eph.X, &ea.Q.X);
		mbedcrypto_bn_copy(&peer_eph.Y, &ea.Q.Y);
		mbedcrypto_bn_copy(&peer_eph.Z, &ea.Q.Z);

		memset(&pb, 0, sizeof(pb));
		pb.is_initiator = 0;
		pb.initiator_id = sm2kep_id;
		pb.initiator_id_len = sizeof(sm2kep_id);
		pb.responder_id = sm2kep_id;
		pb.responder_id_len = sizeof(sm2kep_id);
		pb.out = key_b;
		pb.out_len = 16;
		pb.conf_out = conf_b;
		pb.conf_out_len = sizeof(conf_b);

		ret = mbedcrypto_sm2kep_derive(&kb, &eb,
				&peer_pub, &peer_eph, &pb);
		CHECK(ret == 0, ret);

		/* Alice (initiator) derives key with Bob as peer */
		mbedcrypto_bn_copy(&peer_pub.X, &kb.Q.X);
		mbedcrypto_bn_copy(&peer_pub.Y, &kb.Q.Y);
		mbedcrypto_bn_copy(&peer_pub.Z, &kb.Q.Z);
		mbedcrypto_bn_copy(&peer_eph.X, &eb.Q.X);
		mbedcrypto_bn_copy(&peer_eph.Y, &eb.Q.Y);
		mbedcrypto_bn_copy(&peer_eph.Z, &eb.Q.Z);

		memset(&pa, 0, sizeof(pa));
		pa.is_initiator = 1;
		pa.initiator_id = sm2kep_id;
		pa.initiator_id_len = sizeof(sm2kep_id);
		pa.responder_id = sm2kep_id;
		pa.responder_id_len = sizeof(sm2kep_id);
		pa.out = key_a;
		pa.out_len = 16;
		pa.conf_in = conf_b;
		pa.conf_in_len = pb.conf_out_len;
		pa.conf_out = conf_a;
		pa.conf_out_len = sizeof(conf_a);

		ret = mbedcrypto_sm2kep_derive(&ka, &ea,
				&peer_pub, &peer_eph, &pa);
		CHECK(ret == 0, ret);
		CHECK(memcmp(key_a, key_b, 16) == 0, EBADMSG);

		mbedcrypto_ecp_keypair_cleanup(&ka);
		mbedcrypto_ecp_keypair_cleanup(&kb);
		mbedcrypto_ecp_keypair_cleanup(&ea);
		mbedcrypto_ecp_keypair_cleanup(&eb);
		mbedcrypto_ecp_point_cleanup(&peer_pub);
		mbedcrypto_ecp_point_cleanup(&peer_eph);
	}

	struct mbedcrypto_ecp_keypair init_key, resp_key;
	struct mbedcrypto_ecp_keypair init_eph, resp_eph;
	const uint8_t *id_a = (const uint8_t *)"1234567812345678";
	const uint8_t *id_b = (const uint8_t *)"1234567812345678";
	size_t id_len = 16;
	int ret = 0;

	mbedcrypto_ecp_keypair_init(&init_key);
	mbedcrypto_ecp_keypair_init(&resp_key);
	mbedcrypto_ecp_keypair_init(&init_eph);
	mbedcrypto_ecp_keypair_init(&resp_eph);

	/* Generate static keys */
	ret = mbedcrypto_ecp_keygen(MBEDCRYPTO_ECP_DP_SM2,
		&init_key, test_rng, NULL);
	CHECK(ret == 0, ret);
	ret = mbedcrypto_ecp_keygen(MBEDCRYPTO_ECP_DP_SM2,
		&resp_key, test_rng, NULL);
	CHECK(ret == 0, ret);

	/* Generate ephemeral keys */
	ret = mbedcrypto_ecp_keygen(MBEDCRYPTO_ECP_DP_SM2,
		&init_eph, test_rng, NULL);
	CHECK(ret == 0, ret);
	ret = mbedcrypto_ecp_keygen(MBEDCRYPTO_ECP_DP_SM2,
		&resp_eph, test_rng, NULL);
	CHECK(ret == 0, ret);

	/* Test with different output key lengths */
	{
		size_t key_lens[] = { 16, 32, 48 };
		size_t t;

		for (t = 0; t < 3; t++) {
			size_t klen = key_lens[t];
			uint8_t key_a[48], key_b[48];
			uint8_t conf_a[32], conf_b[32];
			struct mbedcrypto_sm2kep_parms pa, pb;

			/* Initiator derives key */
			memset(&pa, 0, sizeof(pa));
			pa.is_initiator = 1;
			pa.initiator_id = id_a;
			pa.initiator_id_len = id_len;
			pa.responder_id = id_b;
			pa.responder_id_len = id_len;
			pa.out = key_a;
			pa.out_len = klen;
			pa.conf_out = conf_a;
			pa.conf_out_len = sizeof(conf_a);

			ret = mbedcrypto_sm2kep_derive(&init_key,
				&init_eph, &resp_key.Q,
				&resp_eph.Q, &pa);
			CHECK(ret == 0, ret);

			/* Responder derives key, verifies SA */
			memset(&pb, 0, sizeof(pb));
			pb.is_initiator = 0;
			pb.initiator_id = id_a;
			pb.initiator_id_len = id_len;
			pb.responder_id = id_b;
			pb.responder_id_len = id_len;
			pb.out = key_b;
			pb.out_len = klen;
			pb.conf_in = conf_a;
			pb.conf_in_len = sizeof(conf_a);
			pb.conf_out = conf_b;
			pb.conf_out_len = sizeof(conf_b);

			ret = mbedcrypto_sm2kep_derive(&resp_key,
				&resp_eph, &init_key.Q,
				&init_eph.Q, &pb);
			CHECK(ret == 0, ret);

			/* Derived keys must match */
			CHECK(memcmp(key_a, key_b, klen) == 0, EBADMSG);

			/* Initiator verifies SB */
			memset(&pa, 0, sizeof(pa));
			pa.is_initiator = 1;
			pa.initiator_id = id_a;
			pa.initiator_id_len = id_len;
			pa.responder_id = id_b;
			pa.responder_id_len = id_len;
			pa.out = key_a;
			pa.out_len = klen;
			pa.conf_in = conf_b;
			pa.conf_in_len = sizeof(conf_b);

			ret = mbedcrypto_sm2kep_derive(&init_key,
				&init_eph, &resp_key.Q,
				&resp_eph.Q, &pa);
			CHECK(ret == 0, ret);
		}
	}

	/* Tamper detection: corrupt peer ephemeral key */
	{
		uint8_t key_a[32], key_b[32];
		uint8_t conf_a[32];
		struct mbedcrypto_sm2kep_parms pa, pb;
		struct mbedcrypto_ecp_point bad_eph;

		mbedcrypto_ecp_point_init(&bad_eph);
		mbedcrypto_bn_copy(&bad_eph.X, &resp_eph.Q.X);
		mbedcrypto_bn_copy(&bad_eph.Y, &resp_eph.Q.Y);
		mbedcrypto_bn_copy(&bad_eph.Z, &resp_eph.Q.Z);

		/* Corrupt X coordinate */
		mbedcrypto_bn_set_word(&bad_eph.X, 1);

		memset(&pa, 0, sizeof(pa));
		pa.is_initiator = 1;
		pa.initiator_id = id_a;
		pa.initiator_id_len = id_len;
		pa.responder_id = id_b;
		pa.responder_id_len = id_len;
		pa.out = key_a;
		pa.out_len = 32;
		pa.conf_out = conf_a;
		pa.conf_out_len = sizeof(conf_a);

		ret = mbedcrypto_sm2kep_derive(&init_key, &init_eph,
			&resp_key.Q, &bad_eph, &pa);

		if (ret == 0) {
			/* Derive succeeded but keys must differ */
			memset(&pb, 0, sizeof(pb));
			pb.is_initiator = 0;
			pb.initiator_id = id_a;
			pb.initiator_id_len = id_len;
			pb.responder_id = id_b;
			pb.responder_id_len = id_len;
			pb.out = key_b;
			pb.out_len = 32;

			ret = mbedcrypto_sm2kep_derive(&resp_key,
				&resp_eph, &init_key.Q,
				&init_eph.Q, &pb);
			if (ret == 0)
				CHECK(memcmp(key_a, key_b, 32) != 0, EBADMSG);
		}

		mbedcrypto_ecp_point_cleanup(&bad_eph);
	}

	mbedcrypto_ecp_keypair_cleanup(&init_key);
	mbedcrypto_ecp_keypair_cleanup(&resp_key);
	mbedcrypto_ecp_keypair_cleanup(&init_eph);
	mbedcrypto_ecp_keypair_cleanup(&resp_eph);

out:
	TEST_END();
}

static void test_dh(void)
{
	TEST_START("DH");
	struct mbedcrypto_dh_ctx alice, bob;

	mbedcrypto_dh_init(&alice);
	mbedcrypto_dh_init(&bob);

	/* Use a small 512-bit safe prime for testing speed */
	const char *p_hex = "D4BCD52406F2C926"
		"B6DE529FE10F2DCA"
		"3C29B280E1B7D779"
		"27AFF781C7C56A53"
		"C917F57D44E97F78"
		"DEDC543E886E1B3A"
		"B39275C5B994A0B4"
		"A5B429F4B4B4A02B";
	const char *g_hex = "02";

	mbedcrypto_bn_from_hex(&alice.P, p_hex);
	mbedcrypto_bn_from_hex(&alice.G, g_hex);
	mbedcrypto_bn_from_hex(&bob.P, p_hex);
	mbedcrypto_bn_from_hex(&bob.G, g_hex);

	size_t plen = mbedcrypto_dh_len(&alice);
	uint8_t pub_a[64], pub_b[64];

	int ret = mbedcrypto_dh_gen_public(&alice, plen, pub_a, plen, test_rng, NULL);
	CHECK(ret == 0, ret);
	ret = mbedcrypto_dh_gen_public(&bob, plen, pub_b, plen, test_rng, NULL);
	CHECK(ret == 0, ret);

	/* Set peer public keys */
	mbedcrypto_bn_from_binary(&alice.GY, pub_b, plen);
	mbedcrypto_bn_from_binary(&bob.GY, pub_a, plen);

	/* Compute shared secrets */
	uint8_t sa[64], sb[64];
	size_t sa_len, sb_len;
	ret = mbedcrypto_dh_derive_shared(&alice, sa, sizeof(sa), &sa_len, test_rng, NULL);
	CHECK(ret == 0, ret);
	ret = mbedcrypto_dh_derive_shared(&bob, sb, sizeof(sb), &sb_len, test_rng, NULL);
	CHECK(ret == 0, ret);
	CHECK(sa_len == sb_len && memcmp(sa, sb, sa_len) == 0, EBADMSG);

	mbedcrypto_dh_cleanup(&alice);
	mbedcrypto_dh_cleanup(&bob);

out:
	TEST_END();
}

static void test_dsa(void)
{
	TEST_START("DSA");
	struct mbedcrypto_dsa_ctx dctx;
	int ret = 0;
	int i = 0, m = 0;

	/*
	 * KAT: DSA-1024/160 SHA-1 verify with known params+key+signature.
	 * Generated by Python cryptography library.
	 * Message hash: SHA-1("DSA KAT test message")
	 */
	{
		static const uint8_t dsa_kat_p[] = {
			0xdd, 0x3a, 0xc7, 0xc2, 0x2e, 0x3e, 0xb6, 0xa5,
			0x1a, 0x1e, 0x6a, 0x1d, 0x8c, 0x21, 0xb3, 0x69,
			0xb8, 0x42, 0x95, 0x16, 0x0f, 0xd3, 0x8b, 0xc5,
			0x75, 0xfb, 0xff, 0x1d, 0x6f, 0x36, 0xd7, 0xb4,
			0xf8, 0x16, 0x3b, 0xdb, 0xe1, 0xb3, 0x85, 0xa1,
			0xbe, 0x34, 0xa1, 0xc9, 0xb2, 0x17, 0x10, 0x47,
			0xa1, 0xc5, 0x21, 0xec, 0xf7, 0x4b, 0xdf, 0xa6,
			0x02, 0x70, 0xdb, 0xde, 0xe5, 0x34, 0x79, 0x36,
			0x17, 0xce, 0x80, 0xc4, 0xd1, 0x6c, 0x66, 0xf9,
			0x29, 0x6e, 0xf5, 0xea, 0x90, 0xd2, 0xee, 0x2d,
			0x3a, 0x43, 0x6b, 0x6e, 0xa7, 0xd4, 0xd6, 0x5b,
			0x13, 0x2b, 0xf9, 0x2b, 0xbb, 0x98, 0x60, 0xd0,
			0x22, 0x7f, 0xc9, 0x40, 0xd9, 0x69, 0x25, 0x7d,
			0x9a, 0x87, 0x4f, 0x7b, 0x75, 0x83, 0x35, 0x32,
			0x5f, 0x16, 0xaf, 0x3a, 0x44, 0x5c, 0x7c, 0x2c,
			0x05, 0xc6, 0xb8, 0x79, 0x43, 0x09, 0xd7, 0x19,
		};
		static const uint8_t dsa_kat_q[] = {
			0xb9, 0x26, 0xc3, 0x0a, 0xd3, 0xb8, 0xae, 0x0a,
			0x0a, 0xda, 0xa6, 0x96, 0x12, 0xb0, 0xd7, 0x02,
			0x75, 0xf6, 0x95, 0xc5,
		};
		static const uint8_t dsa_kat_g[] = {
			0x22, 0x84, 0x87, 0xd3, 0x7f, 0xc4, 0xbd, 0x48,
			0xfc, 0x26, 0x78, 0x30, 0x3d, 0xd6, 0xee, 0x86,
			0x07, 0x0e, 0x6b, 0xfc, 0xc2, 0x3c, 0x04, 0x9c,
			0x3e, 0xf6, 0x44, 0x91, 0xbf, 0x7c, 0x76, 0x48,
			0x91, 0x38, 0xf1, 0xea, 0xf1, 0x83, 0xb9, 0x34,
			0x09, 0x86, 0xe0, 0x4c, 0x01, 0x91, 0xbe, 0x9c,
			0xb3, 0x81, 0x44, 0xf2, 0x27, 0x0d, 0x35, 0xf7,
			0xe8, 0x64, 0x29, 0x06, 0xc6, 0x58, 0x60, 0x9d,
			0x2d, 0x8e, 0xd6, 0x7a, 0x42, 0x7f, 0x87, 0xc6,
			0x8e, 0x49, 0xb1, 0xcc, 0x7f, 0xd9, 0x54, 0x98,
			0x6d, 0xc1, 0x72, 0xbc, 0xc8, 0x7e, 0x3b, 0x5a,
			0xe0, 0x35, 0xd2, 0xf8, 0x7a, 0x99, 0xc3, 0xfa,
			0xf2, 0x39, 0x93, 0x7e, 0xe7, 0x7d, 0x95, 0x91,
			0x94, 0x6e, 0x0b, 0x00, 0x91, 0xaf, 0xfc, 0xc6,
			0x5d, 0xeb, 0x40, 0x0a, 0xc5, 0x68, 0x4e, 0x7c,
			0xa3, 0x62, 0xc4, 0x0e, 0x33, 0xef, 0x13, 0xcb,
		};
		static const uint8_t dsa_kat_y[] = {
			0x03, 0x83, 0x13, 0x76, 0x78, 0xf7, 0xa9, 0x14,
			0xb5, 0x4b, 0x3a, 0xd2, 0x11, 0x73, 0x32, 0x5d,
			0xd5, 0x41, 0xa9, 0x88, 0x4f, 0xfa, 0xf0, 0x61,
			0x35, 0xf5, 0x85, 0xce, 0xc1, 0x9c, 0xe0, 0x8a,
			0x47, 0xc2, 0x93, 0x67, 0x89, 0x4a, 0xa2, 0x10,
			0xa1, 0xb7, 0x13, 0x67, 0x44, 0xae, 0x48, 0xae,
			0x4b, 0x23, 0xed, 0xb8, 0x71, 0xd6, 0x80, 0x03,
			0x22, 0x2e, 0x04, 0xae, 0x3a, 0x2d, 0x2f, 0x2f,
			0x58, 0x7d, 0x8e, 0x38, 0x3e, 0x36, 0x9f, 0xd0,
			0xe8, 0x7f, 0x44, 0x0a, 0x1a, 0xfb, 0x1e, 0x3e,
			0x8e, 0x52, 0xa9, 0x7a, 0xa1, 0x9a, 0x2a, 0xf7,
			0x63, 0xc6, 0xc6, 0x6c, 0x07, 0xe7, 0xb8, 0x19,
			0xce, 0x39, 0x08, 0x11, 0xa3, 0xd2, 0xe7, 0x01,
			0xbd, 0xa8, 0x1c, 0x90, 0xe5, 0xd8, 0xae, 0xaa,
			0xbb, 0x7e, 0x91, 0x6d, 0x35, 0xea, 0x3e, 0x3d,
			0x8e, 0xde, 0x60, 0x6c, 0x95, 0xf8, 0xc8, 0xd5,
		};
		/* SHA-1("DSA KAT test message") */
		static const uint8_t dsa_kat_hash[] = {
			0x90, 0x2c, 0xd0, 0x6a, 0xd5, 0xbd, 0x24, 0x7c,
			0xd6, 0xc5, 0xde, 0xd0, 0xc8, 0x76, 0x8a, 0x6c,
			0x21, 0xa5, 0x74, 0xe1,
		};
		static const uint8_t dsa_kat_sig_raw[] = {
			0x45, 0x99, 0x57, 0x62, 0xce, 0xda, 0x62, 0xa1,
			0xf7, 0xdf, 0xdf, 0xd8, 0x1d, 0x0c, 0x1d, 0xd5,
			0x0d, 0xe1, 0x70, 0x0b, 0x77, 0x76, 0x7a, 0x23,
			0x2a, 0x32, 0x87, 0xeb, 0xcb, 0x93, 0x95, 0xf9,
			0xab, 0x5a, 0x6c, 0xca, 0xf8, 0x82, 0xb3, 0x4b,
		};
		static const uint8_t dsa_kat_sig_der[] = {
			0x30, 0x2c, 0x02, 0x14, 0x45, 0x99, 0x57, 0x62,
			0xce, 0xda, 0x62, 0xa1, 0xf7, 0xdf, 0xdf, 0xd8,
			0x1d, 0x0c, 0x1d, 0xd5, 0x0d, 0xe1, 0x70, 0x0b,
			0x02, 0x14, 0x77, 0x76, 0x7a, 0x23, 0x2a, 0x32,
			0x87, 0xeb, 0xcb, 0x93, 0x95, 0xf9, 0xab, 0x5a,
			0x6c, 0xca, 0xf8, 0x82, 0xb3, 0x4b,
		};

		struct mbedcrypto_dsa_ctx kat;
		mbedcrypto_dsa_init(&kat);
		ret = mbedcrypto_dsa_import_components(&kat,
			dsa_kat_p, sizeof(dsa_kat_p),
			dsa_kat_q, sizeof(dsa_kat_q),
			dsa_kat_g, sizeof(dsa_kat_g),
			dsa_kat_y, sizeof(dsa_kat_y),
			NULL, 0);
		CHECK(ret == 0, ret);

		/* Verify raw signature */
		ret = mbedcrypto_dsa_verify(&kat, 20, dsa_kat_hash,
			dsa_kat_sig_raw, sizeof(dsa_kat_sig_raw));
		CHECK(ret == 0, ret);

		/* Verify DER signature */
		ret = mbedcrypto_dsa_verify_der(&kat, 20, dsa_kat_hash,
			dsa_kat_sig_der, sizeof(dsa_kat_sig_der));
		CHECK(ret == 0, ret);

		/* Tamper with hash - should fail */
		uint8_t bad[20];
		memcpy(bad, dsa_kat_hash, 20);
		bad[0] ^= 1;
		ret = mbedcrypto_dsa_verify(&kat, 20, bad,
			dsa_kat_sig_raw, sizeof(dsa_kat_sig_raw));
		CHECK(ret != 0, EBADMSG);

		mbedcrypto_dsa_cleanup(&kat);
	}

	/* Roundtrip: generate params + keygen + sign/verify */
	mbedcrypto_dsa_init(&dctx);

	/* Generate 1024/160 DSA params */
	ret = mbedcrypto_dsa_gen_params(&dctx, test_rng, NULL, 1024);
	CHECK(ret == 0, ret);

	ret = mbedcrypto_dsa_keygen(&dctx, test_rng, NULL);
	CHECK(ret == 0, ret);

	ret = mbedcrypto_dsa_validate_pubkey(&dctx);
	CHECK(ret == 0, ret);
	ret = mbedcrypto_dsa_validate_privkey(&dctx);
	CHECK(ret == 0, ret);

	/* Sign and verify */
	uint8_t hash[20], sig[256];
	size_t slen;
	for (i = 0; i < 20; i++)
		hash[i] = i + 1;

	ret = mbedcrypto_dsa_sign(&dctx, test_rng, NULL, 20, hash, sig, &slen);
	CHECK(ret == 0, ret);

	ret = mbedcrypto_dsa_verify(&dctx, 20, hash, sig, slen);
	CHECK(ret == 0, ret);

	/* DER sign and verify */
	slen = sizeof(sig);
	ret = mbedcrypto_dsa_sign_der(&dctx, test_rng, NULL, 20, hash,
		sig, sizeof(sig), &slen);
	CHECK(ret == 0, ret);
	ret = mbedcrypto_dsa_verify_der(&dctx, 20, hash, sig, slen);
	CHECK(ret == 0, ret);

	/* Tamper */
	hash[0] ^= 1;
	ret = mbedcrypto_dsa_verify(&dctx, 20, hash, sig, slen);
	CHECK(ret != 0, EBADMSG);
	hash[0] ^= 1;

	/* Multiple sign/verify */
	for (m = 0; m < 3; m++) {
		uint8_t h[20];
		for (i = 0; i < 20; i++)
			h[i] = i + m * 17;
		slen = sizeof(sig);
		ret = mbedcrypto_dsa_sign(&dctx, test_rng, NULL, 20, h, sig, &slen);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_dsa_verify(&dctx, 20, h, sig, slen);
		CHECK(ret == 0, ret);
	}

	/* Export and re-import */
	{
		struct mbedcrypto_dsa_ctx imp;
		mbedcrypto_dsa_init(&imp);

		size_t plen = mbedcrypto_bn_byte_count(&dctx.P);
		size_t qlen = mbedcrypto_bn_byte_count(&dctx.Q);
		size_t glen = mbedcrypto_bn_byte_count(&dctx.G);
		size_t ylen = mbedcrypto_bn_byte_count(&dctx.Y);
		size_t xlen = mbedcrypto_bn_byte_count(&dctx.X);

		uint8_t P[128], Q[32], G[128], Y[128], X[32];
		mbedcrypto_bn_to_binary(&dctx.P, P, plen);
		mbedcrypto_bn_to_binary(&dctx.Q, Q, qlen);
		mbedcrypto_bn_to_binary(&dctx.G, G, glen);
		mbedcrypto_bn_to_binary(&dctx.Y, Y, ylen);
		mbedcrypto_bn_to_binary(&dctx.X, X, xlen);

		ret = mbedcrypto_dsa_import_components(&imp, P, plen, Q, qlen, G, glen, Y, ylen, X, xlen);
		CHECK(ret == 0, ret);

		uint8_t sig2[256];
		size_t slen2;
		ret = mbedcrypto_dsa_sign(&imp, test_rng, NULL, 20, hash, sig2, &slen2);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_dsa_verify(&imp, 20, hash, sig2, slen2);
		CHECK(ret == 0, ret);

		mbedcrypto_dsa_cleanup(&imp);
	}

	mbedcrypto_dsa_cleanup(&dctx);

out:
	TEST_END();
}

static void test_bignum(void)
{
	TEST_START("Bignum");
	struct mbedcrypto_bignum A, B, C, D;
	mbedcrypto_bn_init(&A);
	mbedcrypto_bn_init(&B);
	mbedcrypto_bn_init(&C);
	mbedcrypto_bn_init(&D);

	/* set_word and comparison */
	mbedcrypto_bn_set_word(&A, 42);
	CHECK(mbedcrypto_bn_cmp_word(&A, 42) == 0, EBADMSG);
	CHECK(mbedcrypto_bn_cmp_word(&A, 41) > 0, EBADMSG);
	CHECK(mbedcrypto_bn_cmp_word(&A, 43) < 0, EBADMSG);

	/* Negative */
	mbedcrypto_bn_set_word(&A, -7);
	CHECK(mbedcrypto_bn_cmp_word(&A, -7) == 0, EBADMSG);
	CHECK(mbedcrypto_bn_cmp_word(&A, 0) < 0, EBADMSG);

	/* add */
	mbedcrypto_bn_set_word(&A, 100);
	mbedcrypto_bn_set_word(&B, 200);
	mbedcrypto_bn_add(&C, &A, &B);
	CHECK(mbedcrypto_bn_cmp_word(&C, 300) == 0, EBADMSG);

	/* add_int */
	mbedcrypto_bn_add_word(&C, &A, 50);
	CHECK(mbedcrypto_bn_cmp_word(&C, 150) == 0, EBADMSG);

	/* sub */
	mbedcrypto_bn_sub(&C, &B, &A);
	CHECK(mbedcrypto_bn_cmp_word(&C, 100) == 0, EBADMSG);

	/* mul */
	mbedcrypto_bn_set_word(&A, 12);
	mbedcrypto_bn_set_word(&B, 13);
	mbedcrypto_bn_mul(&C, &A, &B);
	CHECK(mbedcrypto_bn_cmp_word(&C, 156) == 0, EBADMSG);

	/* mul_int */
	mbedcrypto_bn_mul_word(&C, &A, 7);
	CHECK(mbedcrypto_bn_cmp_word(&C, 84) == 0, EBADMSG);

	/* div */
	mbedcrypto_bn_set_word(&A, 100);
	mbedcrypto_bn_set_word(&B, 7);
	mbedcrypto_bn_div(&C, &D, &A, &B);
	CHECK(mbedcrypto_bn_cmp_word(&C, 14) == 0, EBADMSG);
	CHECK(mbedcrypto_bn_cmp_word(&D, 2) == 0, EBADMSG);

	/* mod */
	mbedcrypto_bn_set_word(&A, 123);
	mbedcrypto_bn_set_word(&B, 17);
	mbedcrypto_bn_mod(&C, &A, &B);
	CHECK(mbedcrypto_bn_cmp_word(&C, 4) == 0, EBADMSG);

	/* Bitlen */
	mbedcrypto_bn_set_word(&A, 255);
	CHECK(mbedcrypto_bn_bit_count(&A) == 8, EBADMSG);
	mbedcrypto_bn_set_word(&A, 256);
	CHECK(mbedcrypto_bn_bit_count(&A) == 9, EBADMSG);

	/* Size (bytes) */
	mbedcrypto_bn_set_word(&A, 255);
	CHECK(mbedcrypto_bn_byte_count(&A) == 1, EBADMSG);
	mbedcrypto_bn_set_word(&A, 256);
	CHECK(mbedcrypto_bn_byte_count(&A) == 2, EBADMSG);

	/* Shift */
	mbedcrypto_bn_set_word(&A, 1);
	mbedcrypto_bn_lshift(&A, 10);
	CHECK(mbedcrypto_bn_cmp_word(&A, 1024) == 0, EBADMSG);
	mbedcrypto_bn_rshift(&A, 5);
	CHECK(mbedcrypto_bn_cmp_word(&A, 32) == 0, EBADMSG);

	/* test_bit / assign_bit */
	mbedcrypto_bn_set_word(&A, 0);
	mbedcrypto_bn_assign_bit(&A, 7, 1);
	CHECK(mbedcrypto_bn_cmp_word(&A, 128) == 0, EBADMSG);
	CHECK(mbedcrypto_bn_test_bit(&A, 7) == 1, EBADMSG);
	CHECK(mbedcrypto_bn_test_bit(&A, 6) == 0, EBADMSG);

	/* exp_mod: 2^10 mod 1009 = 15 (1024 mod 1009) */
	mbedcrypto_bn_set_word(&A, 2);
	mbedcrypto_bn_set_word(&B, 10);
	mbedcrypto_bn_set_word(&C, 1009); /* must be odd for Montgomery */
	mbedcrypto_bn_modpow(&D, &A, &B, &C, NULL);
	CHECK(mbedcrypto_bn_cmp_word(&D, 15) == 0, EBADMSG);

	/* exp_mod larger: 3^100 mod 997 */
	mbedcrypto_bn_set_word(&A, 3);
	mbedcrypto_bn_set_word(&B, 100);
	mbedcrypto_bn_set_word(&C, 997);
	mbedcrypto_bn_modpow(&D, &A, &B, &C, NULL);
	/* 3^100 mod 997 = 250 (verified with Python: pow(3,100,997)==250) */
	CHECK(mbedcrypto_bn_cmp_word(&D, 250) == 0, EBADMSG);

	/* inv_mod: 3 * x = 1 (mod 7) -> x = 5 */
	mbedcrypto_bn_set_word(&A, 3);
	mbedcrypto_bn_set_word(&B, 7);
	mbedcrypto_bn_modinv(&C, &A, &B);
	CHECK(mbedcrypto_bn_cmp_word(&C, 5) == 0, EBADMSG);

	/* GCD */
	mbedcrypto_bn_set_word(&A, 48);
	mbedcrypto_bn_set_word(&B, 18);
	mbedcrypto_bn_gcd(&C, &A, &B);
	CHECK(mbedcrypto_bn_cmp_word(&C, 6) == 0, EBADMSG);

	/* Load/Save hex */
	mbedcrypto_bn_from_hex(&A, "DEADBEEF");
	uint8_t buf[4];
	mbedcrypto_bn_to_binary(&A, buf, 4);
	CHECK(hexcmp(buf, "deadbeef", 4) == 0, EBADMSG);

	/* Load/Save binary */
	uint8_t bin[] = {0x01, 0x02, 0x03};
	mbedcrypto_bn_from_binary(&A, bin, 3);
	CHECK(mbedcrypto_bn_cmp_word(&A, 0x010203) == 0, EBADMSG);
	uint8_t wbuf[3];
	mbedcrypto_bn_to_binary(&A, wbuf, 3);
	CHECK(memcmp(wbuf, bin, 3) == 0, EBADMSG);

	/* Load/Save LE binary */
	uint8_t le[] = {0x03, 0x02, 0x01};
	mbedcrypto_bn_from_binary_le(&A, le, 3);
	CHECK(mbedcrypto_bn_cmp_word(&A, 0x010203) == 0, EBADMSG);
	uint8_t le_out[3];
	mbedcrypto_bn_to_binary_le(&A, le_out, 3);
	CHECK(memcmp(le_out, le, 3) == 0, EBADMSG);

	/* Copy and swap */
	mbedcrypto_bn_set_word(&A, 42);
	mbedcrypto_bn_set_word(&B, 99);
	mbedcrypto_bn_copy(&C, &A);
	CHECK(mbedcrypto_bn_cmp_word(&C, 42) == 0, EBADMSG);
	mbedcrypto_bn_swap(&A, &B);
	CHECK(mbedcrypto_bn_cmp_word(&A, 99) == 0, EBADMSG);
	CHECK(mbedcrypto_bn_cmp_word(&B, 42) == 0, EBADMSG);

	/* cmp_magnitude */
	mbedcrypto_bn_set_word(&A, -42);
	mbedcrypto_bn_set_word(&B, 42);
	CHECK(mbedcrypto_bn_cmp_magnitude(&A, &B) == 0, EBADMSG);
	mbedcrypto_bn_set_word(&A, -43);
	CHECK(mbedcrypto_bn_cmp_magnitude(&A, &B) > 0, EBADMSG);

	/* Grow/shrink */
	mbedcrypto_bn_set_word(&A, 1);
	int ret = mbedcrypto_bn_expand(&A, 16);
	CHECK(ret == 0, ret);
	CHECK(A.used >= 16, EBADMSG);
	ret = mbedcrypto_bn_shrink(&A, 1);
	CHECK(ret == 0, ret);

	/* In-place aliasing: C = A + A */
	mbedcrypto_bn_set_word(&A, 50);
	mbedcrypto_bn_add(&A, &A, &A);
	CHECK(mbedcrypto_bn_cmp_word(&A, 100) == 0, EBADMSG);

	/* In-place: C = A * A */
	mbedcrypto_bn_set_word(&A, 7);
	mbedcrypto_bn_mul(&A, &A, &A);
	CHECK(mbedcrypto_bn_cmp_word(&A, 49) == 0, EBADMSG);

	/* In-place: sub A = A - B */
	mbedcrypto_bn_set_word(&A, 100);
	mbedcrypto_bn_set_word(&B, 30);
	mbedcrypto_bn_sub(&A, &A, &B);
	CHECK(mbedcrypto_bn_cmp_word(&A, 70) == 0, EBADMSG);

	/* fill_random */
	mbedcrypto_bn_random(&A, 16, test_rng, NULL);
	CHECK(mbedcrypto_bn_bit_count(&A) > 0, EBADMSG);
	CHECK(mbedcrypto_bn_byte_count(&A) <= 16, EBADMSG);

	mbedcrypto_bn_cleanup(&A);
	mbedcrypto_bn_cleanup(&B);
	mbedcrypto_bn_cleanup(&C);
	mbedcrypto_bn_cleanup(&D);

	/* --- Extended coverage (merged from test_bignum_ext) --- */
	{
		struct mbedcrypto_bignum A, B, C, U, V;
		mbedcrypto_bn_init(&A);
		mbedcrypto_bn_init(&B);
		mbedcrypto_bn_init(&C);
		mbedcrypto_bn_init(&U);
		mbedcrypto_bn_init(&V);

		/* bn_is_prime: known primes */
		mbedcrypto_bn_set_word(&A, 2);
		int ret = mbedcrypto_bn_test_prime(&A, 10, test_rng, NULL);
		CHECK(ret == 0, ret);

		mbedcrypto_bn_set_word(&A, 7);
		ret = mbedcrypto_bn_test_prime(&A, 10, test_rng, NULL);
		CHECK(ret == 0, ret);

		mbedcrypto_bn_set_word(&A, 104729); /* prime */
		ret = mbedcrypto_bn_test_prime(&A, 10, test_rng, NULL);
		CHECK(ret == 0, ret);

		/* bn_is_prime: known composites */
		mbedcrypto_bn_set_word(&A, 4);
		ret = mbedcrypto_bn_test_prime(&A, 10, test_rng, NULL);
		CHECK(ret != 0, EBADMSG);

		mbedcrypto_bn_set_word(&A, 100);
		ret = mbedcrypto_bn_test_prime(&A, 10, test_rng, NULL);
		CHECK(ret != 0, EBADMSG);

		mbedcrypto_bn_set_word(&A, 561); /* Carmichael number */
		ret = mbedcrypto_bn_test_prime(&A, 10, test_rng, NULL);
		CHECK(ret != 0, EBADMSG);

		/* bn_gen_prime: generate a 64-bit prime */
		ret = mbedcrypto_bn_gen_prime(&A, 64, 0, test_rng, NULL);
		CHECK(ret == 0, ret);
		CHECK(mbedcrypto_bn_bit_count(&A) <= 64, EBADMSG);
		ret = mbedcrypto_bn_test_prime(&A, 20, test_rng, NULL);
		CHECK(ret == 0, ret);

		/* bn_gcd_ext: verify u*x + v*y = gcd */
		mbedcrypto_bn_set_word(&A, 240);
		mbedcrypto_bn_set_word(&B, 46);
		ret = mbedcrypto_bn_egcd(&C, &U, &V, &A, &B);
		CHECK(ret == 0, ret);
		CHECK(mbedcrypto_bn_cmp_word(&C, 2) == 0, EBADMSG);

		/* Verify u*240 + v*46 = 2 */
		struct mbedcrypto_bignum T1, T2, T3;
		mbedcrypto_bn_init(&T1);
		mbedcrypto_bn_init(&T2);
		mbedcrypto_bn_init(&T3);
		mbedcrypto_bn_mul(&T1, &U, &A); /* u*240 */
		mbedcrypto_bn_mul(&T2, &V, &B); /* v*46 */
		mbedcrypto_bn_add(&T3, &T1, &T2);
		CHECK(mbedcrypto_bn_cmp(&T3, &C) == 0, EBADMSG);
		mbedcrypto_bn_cleanup(&T1);
		mbedcrypto_bn_cleanup(&T2);
		mbedcrypto_bn_cleanup(&T3);

		/* Large number arithmetic: 2^256 * 2^256 = 2^512 */
		mbedcrypto_bn_set_word(&A, 1);
		mbedcrypto_bn_lshift(&A, 256);
		mbedcrypto_bn_mul(&C, &A, &A);
		CHECK(mbedcrypto_bn_bit_count(&C) == 513, EBADMSG);

		/* Division: 2^512 / 2^256 = 2^256 */
		struct mbedcrypto_bignum Q, R;
		mbedcrypto_bn_init(&Q);
		mbedcrypto_bn_init(&R);
		mbedcrypto_bn_div(&Q, &R, &C, &A);
		CHECK(mbedcrypto_bn_cmp(&Q, &A) == 0, EBADMSG);
		CHECK(mbedcrypto_bn_cmp_word(&R, 0) == 0, EBADMSG);
		mbedcrypto_bn_cleanup(&Q);
		mbedcrypto_bn_cleanup(&R);

		/* Negative arithmetic: (-3) + 5 = 2 */
		mbedcrypto_bn_set_word(&A, -3);
		mbedcrypto_bn_set_word(&B, 5);
		mbedcrypto_bn_add(&C, &A, &B);
		CHECK(mbedcrypto_bn_cmp_word(&C, 2) == 0, EBADMSG);

		/* (-3) * (-5) = 15 */
		mbedcrypto_bn_set_word(&A, -3);
		mbedcrypto_bn_set_word(&B, -5);
		mbedcrypto_bn_mul(&C, &A, &B);
		CHECK(mbedcrypto_bn_cmp_word(&C, 15) == 0, EBADMSG);

		/* Mod with negative: (-7) mod 3 = 2 (always non-negative) */
		mbedcrypto_bn_set_word(&A, -7);
		mbedcrypto_bn_set_word(&B, 3);
		mbedcrypto_bn_mod(&C, &A, &B);
		CHECK(mbedcrypto_bn_cmp_word(&C, 2) == 0, EBADMSG);

		mbedcrypto_bn_cleanup(&A);
		mbedcrypto_bn_cleanup(&B);
		mbedcrypto_bn_cleanup(&C);
		mbedcrypto_bn_cleanup(&U);
		mbedcrypto_bn_cleanup(&V);
	}

out:
	TEST_END();
}

static void test_ecp(void)
{
	TEST_START("ECP");
	struct mbedcrypto_ecp_group grp;
	struct mbedcrypto_ecp_point R;
	struct mbedcrypto_bignum m;
	int i = 0;

	mbedcrypto_ecp_group_init(&grp);
	mbedcrypto_ecp_point_init(&R);
	mbedcrypto_bn_init(&m);

	/* Load all supported groups */
	int groups[] = {
		MBEDCRYPTO_ECP_DP_SECP192R1,
		MBEDCRYPTO_ECP_DP_SECP256R1,
		MBEDCRYPTO_ECP_DP_SECP384R1,
		MBEDCRYPTO_ECP_DP_SECP521R1,
		MBEDCRYPTO_ECP_DP_BP256R1,
		MBEDCRYPTO_ECP_DP_BP384R1,
		MBEDCRYPTO_ECP_DP_BP512R1,
	};
	const char *group_names[] = {
		"P-192", "P-256", "P-384", "P-521",
		"BP-256", "BP-384", "BP-512",
	};

	for (i = 0; i < 7; i++) {
		int ret = mbedcrypto_ecp_load_group(&grp, groups[i]);
		CHECK(ret == 0, ret, "load %s",
			group_names[i]);

		/* Check generator is on curve */
		ret = mbedcrypto_ecp_validate_point(&grp, &grp.G);
		CHECK(ret == 0, ret, "%s G on curve",
			group_names[i]);

		/* Scalar multiply: R = 1 * G = G */
		mbedcrypto_bn_set_word(&m, 1);
		ret = mbedcrypto_ecp_scalar_mul(&grp, &R, &m, &grp.G, test_rng, NULL);
		CHECK(ret == 0, ret, "%s 1*G",
			group_names[i]);
		ret = mbedcrypto_ecp_validate_point(&grp, &R);
		CHECK(ret == 0, ret, "%s 1*G on curve",
			group_names[i]);

		/* R = N * G should be point at infinity */
		ret = mbedcrypto_ecp_scalar_mul(&grp, &R, &grp.N, &grp.G, test_rng, NULL);
		CHECK(ret == 0, ret, "%s N*G",
			group_names[i]);
		CHECK(mbedcrypto_ecp_is_infinity(&R), EBADMSG,
			"%s N*G not inf", group_names[i]);

		mbedcrypto_ecp_group_cleanup(&grp);
		mbedcrypto_ecp_group_init(&grp);
	}

	/* ECP keypair generation */
	for (i = 0; i < 3; i++) { /* P-192, P-256, P-384 */
		struct mbedcrypto_ecp_keypair kp;
		mbedcrypto_ecp_keypair_init(&kp);
		int ret = mbedcrypto_ecp_keygen(groups[i], &kp, test_rng, NULL);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_ecp_validate_point(&kp.grp, &kp.Q);
		CHECK(ret == 0, ret);
		mbedcrypto_ecp_keypair_cleanup(&kp);
	}

	/* muladd: R = m*P + n*Q */
	{
		mbedcrypto_ecp_load_group(&grp, MBEDCRYPTO_ECP_DP_SECP256R1);
		struct mbedcrypto_ecp_point P, Q, R2;
		struct mbedcrypto_bignum m2, n;
		mbedcrypto_ecp_point_init(&P);
		mbedcrypto_ecp_point_init(&Q);
		mbedcrypto_ecp_point_init(&R2);
		mbedcrypto_bn_init(&m2);
		mbedcrypto_bn_init(&n);

		/* P = 2*G, Q = 3*G */
		mbedcrypto_bn_set_word(&m2, 2);
		mbedcrypto_ecp_scalar_mul(&grp, &P, &m2, &grp.G, test_rng, NULL);
		mbedcrypto_bn_set_word(&m2, 3);
		mbedcrypto_ecp_scalar_mul(&grp, &Q, &m2, &grp.G, test_rng, NULL);

		/* R = 1*P + 1*Q = 2G + 3G = 5G */
		mbedcrypto_bn_set_word(&m2, 1);
		mbedcrypto_bn_set_word(&n, 1);
		mbedcrypto_ecp_dual_scalar_mul(&grp, &R, &m2, &P, &n, &Q);

		/* Compare with 5*G */
		mbedcrypto_bn_set_word(&m2, 5);
		mbedcrypto_ecp_scalar_mul(&grp, &R2, &m2, &grp.G, test_rng, NULL);

		CHECK(mbedcrypto_bn_cmp(&R.X, &R2.X) == 0 && mbedcrypto_bn_cmp(&R.Y, &R2.Y) == 0, EBADMSG);

		mbedcrypto_ecp_point_cleanup(&P);
		mbedcrypto_ecp_point_cleanup(&Q);
		mbedcrypto_ecp_point_cleanup(&R2);
		mbedcrypto_bn_cleanup(&m2);
		mbedcrypto_bn_cleanup(&n);
		mbedcrypto_ecp_group_cleanup(&grp);
	}

	mbedcrypto_ecp_point_cleanup(&R);
	mbedcrypto_bn_cleanup(&m);

	/* --- Extended coverage (merged from test_ecp_ext) --- */
	{
		/* SM2 curve test */
		struct mbedcrypto_ecp_group grp;
		mbedcrypto_ecp_group_init(&grp);
		int ret = mbedcrypto_ecp_load_group(&grp, MBEDCRYPTO_ECP_DP_SM2);
		CHECK(ret == 0, ret);
		CHECK(grp.pbits == 256, EBADMSG);

		/* Generator should be on curve */
		ret = mbedcrypto_ecp_validate_point(&grp, &grp.G);
		CHECK(ret == 0, ret);

		/* N*G should be zero (identity) */
		struct mbedcrypto_ecp_point R;
		mbedcrypto_ecp_point_init(&R);
		ret = mbedcrypto_ecp_scalar_mul(&grp, &R, &grp.N, &grp.G, test_rng, NULL);
		CHECK(ret == 0, ret);
		CHECK(mbedcrypto_ecp_is_infinity(&R), EBADMSG);

		mbedcrypto_ecp_point_cleanup(&R);
		mbedcrypto_ecp_group_cleanup(&grp);

		/* SECP192R1: basic mul/check */
		mbedcrypto_ecp_group_init(&grp);
		ret = mbedcrypto_ecp_load_group(&grp, MBEDCRYPTO_ECP_DP_SECP192R1);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_ecp_validate_point(&grp, &grp.G);
		CHECK(ret == 0, ret);

		/* 1*G = G */
		struct mbedcrypto_bignum one;
		mbedcrypto_bn_init(&one);
		mbedcrypto_bn_set_word(&one, 1);
		mbedcrypto_ecp_point_init(&R);
		ret = mbedcrypto_ecp_scalar_mul(&grp, &R, &one, &grp.G, test_rng, NULL);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_ecp_validate_point(&grp, &R);
		CHECK(ret == 0, ret);

		mbedcrypto_bn_cleanup(&one);
		mbedcrypto_ecp_point_cleanup(&R);
		mbedcrypto_ecp_group_cleanup(&grp);

		/* All 7 SW curves + SM2: keygen and check (skip P192/P256/P384 already tested above) */
		int all_curves[] = {
			MBEDCRYPTO_ECP_DP_SECP521R1,
			MBEDCRYPTO_ECP_DP_BP256R1, MBEDCRYPTO_ECP_DP_BP384R1,
			MBEDCRYPTO_ECP_DP_BP512R1, MBEDCRYPTO_ECP_DP_SM2,
		};
		const char *curve_names[] = {
			"P521", "BP256", "BP384", "BP512", "SM2"
		};
		for (i = 0; i < 5; i++) {
			struct mbedcrypto_ecp_keypair kp;
			mbedcrypto_ecp_keypair_init(&kp);
			ret = mbedcrypto_ecp_keygen(all_curves[i], &kp, test_rng, NULL);
			CHECK(ret == 0, ret, "ecp-%s keygen",
				curve_names[i]);
			ret = mbedcrypto_ecp_validate_point(&kp.grp, &kp.Q);
			CHECK(ret == 0, ret, "ecp-%s Q on curve",
				curve_names[i]);
			mbedcrypto_ecp_keypair_cleanup(&kp);
		}
	}

out:
	TEST_END();
}

static void test_cipher_dispatch(void)
{
	TEST_START("cipher_dispatch");
	struct mbedcrypto_cipher_ctx cctx;
	size_t cs = 0, i = 0, t = 0;

	/* Test all cipher types with roundtrip */
	struct {
		int type;
		const char *name;
		int keybits;
		size_t pt_len;   /* must be multiple of block for ECB/CBC */
		int needs_iv;
		size_t iv_len;
	} tests[] = {
		{ MBEDCRYPTO_CIPHER_AES_ECB, "AES-ECB-128", 128, 16, 0, 0 },
		{ MBEDCRYPTO_CIPHER_AES_ECB, "AES-ECB-192", 192, 32, 0, 0 },
		{ MBEDCRYPTO_CIPHER_AES_ECB, "AES-ECB-256", 256, 48, 0, 0 },
		{ MBEDCRYPTO_CIPHER_AES_CBC, "AES-CBC-128", 128, 32, 1, 16 },
		{ MBEDCRYPTO_CIPHER_AES_CBC, "AES-CBC-256", 256, 64, 1, 16 },
		{ MBEDCRYPTO_CIPHER_AES_CTR, "AES-CTR-128", 128, 17, 1, 16 },
		{ MBEDCRYPTO_CIPHER_AES_CTR, "AES-CTR-256", 256, 33, 1, 16 },
		{ MBEDCRYPTO_CIPHER_AES_CTS, "AES-CTS-128", 128, 20, 1, 16 },
		{ MBEDCRYPTO_CIPHER_AES_XTS, "AES-XTS-256", 256, 32, 1, 16 },
		{ MBEDCRYPTO_CIPHER_AES_XTS, "AES-XTS-512", 512, 17, 1, 16 },
		{ MBEDCRYPTO_CIPHER_DES_ECB, "DES-ECB", 64, 8, 0, 0 },
		{ MBEDCRYPTO_CIPHER_DES_CBC, "DES-CBC", 64, 24, 1, 8 },
		{ MBEDCRYPTO_CIPHER_DES3_ECB, "3DES-ECB", 192, 16, 0, 0 },
		{ MBEDCRYPTO_CIPHER_DES3_CBC, "3DES-CBC", 192, 32, 1, 8 },
		{ MBEDCRYPTO_CIPHER_DES3_CTS, "3DES-CTS", 192, 20, 1, 8 },
		{ MBEDCRYPTO_CIPHER_SM4_ECB, "SM4-ECB", 128, 16, 0, 0 },
		{ MBEDCRYPTO_CIPHER_SM4_CBC, "SM4-CBC", 128, 48, 1, 16 },
		{ MBEDCRYPTO_CIPHER_SM4_CTR, "SM4-CTR", 128, 25, 1, 16 },
		{ MBEDCRYPTO_CIPHER_SM4_CTS, "SM4-CTS", 128, 20, 1, 16 },
	};

	for (t = 0; t < sizeof(tests)/sizeof(tests[0]); t++) {
		uint8_t key[64], iv[16], pt[64], ct_buf[64], dec_buf[64];
		size_t olen_enc = 0, olen_dec = 0, olen_f = 0;

		/* Generate key and data */
		for (i = 0; i < tests[t].keybits / 8; i++)
			key[i] = i + t;
		for (i = 0; i < tests[t].pt_len; i++)
			pt[i] = i ^ 0xAA;
		memset(iv, 0, 16);

		/* Encrypt */
		int ret = mbedcrypto_cipher_init(&cctx, tests[t].type, key, tests[t].keybits, 0);
		CHECK(ret == 0, ret);
		if (tests[t].needs_iv) {
			memset(iv, 0, 16);
			mbedcrypto_cipher_set_iv(&cctx, iv, tests[t].iv_len);
		}
		ret = mbedcrypto_cipher_update(&cctx, pt, tests[t].pt_len, ct_buf, &olen_enc);
		CHECK(ret == 0, ret);
		size_t olen_tail = 0;
		ret = mbedcrypto_cipher_final(&cctx, NULL, 0, ct_buf + olen_enc, &olen_tail);
		CHECK(ret == 0, ret);
		olen_enc += olen_tail;
		mbedcrypto_cipher_cleanup(&cctx);

		/* Decrypt */
		ret = mbedcrypto_cipher_init(&cctx, tests[t].type, key, tests[t].keybits, 1);
		CHECK(ret == 0, ret);
		if (tests[t].needs_iv) {
			memset(iv, 0, 16);
			mbedcrypto_cipher_set_iv(&cctx, iv, tests[t].iv_len);
		}
		ret = mbedcrypto_cipher_update(&cctx, ct_buf, olen_enc, dec_buf, &olen_dec);
		CHECK(ret == 0, ret);
		ret = mbedcrypto_cipher_final(&cctx, NULL, 0, dec_buf + olen_dec, &olen_f);
		CHECK(ret == 0, ret);
		olen_dec += olen_f;
		CHECK(olen_dec == tests[t].pt_len && memcmp(dec_buf, pt, tests[t].pt_len) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);
	}

	/* cipher_reset test */
	{
		uint8_t key[16], iv[16];
		uint8_t pt1[16];
		uint8_t ct1[16], ct1b[16];
		size_t olen;

		memset(iv, 0, sizeof(iv));
		memset(pt1, 0, sizeof(pt1));
		pt1[0] = 1;
		for (i = 0; i < 16; i++)
			key[i] = i;

		mbedcrypto_cipher_init(&cctx, MBEDCRYPTO_CIPHER_AES_CBC, key, 128, 0);
		mbedcrypto_cipher_set_iv(&cctx, iv, 16);
		mbedcrypto_cipher_update(&cctx, pt1, 16, ct1, &olen);
		size_t dummy = 0;
		mbedcrypto_cipher_final(&cctx, NULL, 0, NULL, &dummy);

		/* Reset and encrypt same data - should get same ct with same IV */
		mbedcrypto_cipher_reset(&cctx);
		memset(iv, 0, 16);
		mbedcrypto_cipher_set_iv(&cctx, iv, 16);
		mbedcrypto_cipher_update(&cctx, pt1, 16, ct1b, &olen);
		mbedcrypto_cipher_final(&cctx, NULL, 0, NULL, &dummy);
		CHECK(memcmp(ct1, ct1b, 16) == 0, EBADMSG);
		mbedcrypto_cipher_cleanup(&cctx);
	}

	/* --- Extended coverage (merged from test_cipher_dispatch_ext) --- */
	/* (Removed: SM4-CTS/CTR and 3DES-CTS/CBC already covered in main loop) */

	/* --- Large-data multi-call roundtrip for all cipher modes --- */
	{
		static uint8_t bigpt[8192], bigct[8192], bigdec[8192], bigip[8192];
		uint8_t bkey[64], biv[16];
		size_t olen;

		for (i = 0; i < 64; i++)
			bkey[i] = i * 7 + 3;
		for (i = 0; i < 8192; i++)
			bigpt[i] = i * 31 + 19;

		struct {
			int type;
			const char *name;
			int keybits;
			size_t iv_len;
			size_t dlen;     /* test data length */
			int blk_align;   /* 1=must be block-aligned */
		} big_tests[] = {
			{ MBEDCRYPTO_CIPHER_AES_CBC, "cbc128", 128, 16, 4096, 1 },
			{ MBEDCRYPTO_CIPHER_AES_CBC, "cbc256", 256, 16, 8192, 1 },
			{ MBEDCRYPTO_CIPHER_AES_CTR, "ctr128", 128, 16, 4096, 0 },
			{ MBEDCRYPTO_CIPHER_AES_CTR, "ctr256", 256, 16, 8192, 0 },
			{ MBEDCRYPTO_CIPHER_AES_CTS, "cts128", 128, 16, 4096, 0 },
			{ MBEDCRYPTO_CIPHER_AES_CTS, "cts256", 256, 16, 8192, 0 },
			{ MBEDCRYPTO_CIPHER_AES_XTS, "xts256", 256, 16, 4096, 0 },
			{ MBEDCRYPTO_CIPHER_AES_ECB, "ecb256", 256, 0, 4096, 1 },
			{ MBEDCRYPTO_CIPHER_DES3_CBC, "3des-cbc", 192, 8, 1024, 1 },
			{ MBEDCRYPTO_CIPHER_DES3_CTS, "3des-cts", 192, 8, 1024, 0 },
			{ MBEDCRYPTO_CIPHER_SM4_CBC, "sm4-cbc", 128, 16, 1024, 1 },
			{ MBEDCRYPTO_CIPHER_SM4_CTR, "sm4-ctr", 128, 16, 1024, 0 },
			{ MBEDCRYPTO_CIPHER_SM4_CTS, "sm4-cts", 128, 16, 1024, 0 },
		};
		size_t big_chunks[] = { 1, 5, 16, 17, 48, 100, 512 };

		for (t = 0; t < sizeof(big_tests)/sizeof(big_tests[0]); t++) {
			size_t dlen = big_tests[t].dlen;

			/* Adjust non-aligned for block modes */
			if (!big_tests[t].blk_align && dlen > 17)
				dlen -= 1; /* use odd length */

			/* Reference one-shot encrypt */
			memset(biv, 0, 16);
			cipher_multi(big_tests[t].type, bkey,
				big_tests[t].keybits, 0,
				biv, big_tests[t].iv_len,
				bigpt, dlen, bigct, &olen, 0);

			/* One-shot decrypt verify */
			memset(biv, 0, 16);
			CHECK(cipher_multi(big_tests[t].type, bkey,
				big_tests[t].keybits, 1,
				biv, big_tests[t].iv_len,
				bigct, dlen, bigdec, &olen, 0) == 0
				&& olen == dlen
				&& memcmp(bigdec, bigpt, dlen) == 0, EBADMSG);

			for (cs = 0; cs < sizeof(big_chunks)/sizeof(big_chunks[0]); cs++) {
				size_t chunk = big_chunks[cs];
				if (chunk > dlen)
					continue;

				/* Multi-call separate buffers */
				memset(biv, 0, 16);
				CHECK(cipher_multi(big_tests[t].type, bkey,
					big_tests[t].keybits, 0,
					biv, big_tests[t].iv_len,
					bigpt, dlen, bigdec, &olen, chunk) == 0
					&& olen == dlen
					&& memcmp(bigdec, bigct, dlen) == 0, EBADMSG);

				/* Multi-call in-place */
				memcpy(bigip, bigpt, dlen);
				memset(biv, 0, 16);
				CHECK(cipher_multi(big_tests[t].type, bkey,
					big_tests[t].keybits, 0,
					biv, big_tests[t].iv_len,
					bigip, dlen, bigip, &olen, chunk) == 0
					&& olen == dlen
					&& memcmp(bigip, bigct, dlen) == 0, EBADMSG);

				memcpy(bigip, bigct, dlen);
				memset(biv, 0, 16);
				CHECK(cipher_multi(big_tests[t].type, bkey,
					big_tests[t].keybits, 1,
					biv, big_tests[t].iv_len,
					bigip, dlen, bigip, &olen, chunk) == 0
					&& olen == dlen
					&& memcmp(bigip, bigpt, dlen) == 0, EBADMSG);
			}
		}
	}

out:
	TEST_END();
}

static void test_mac_dispatch(void)
{
	TEST_START("mac_dispatch");
	struct mbedcrypto_mac_ctx mctx;
	uint8_t mac[16], mac1[16];
	uint8_t key[16], msg[16];
	uint8_t des_key[8];
	uint8_t des_msg[8];
	uint8_t des3_key[24];
	uint8_t key256[32];
	size_t maclen = sizeof(mac);
	int ret = 0;
	int i = 0;

	/* AES-CMAC via mac dispatch */
	hex2bin("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
	hex2bin("6bc1bee22e409f96e93d7e117393172a", msg, 16);

	ret = mbedcrypto_mac_init(&mctx, MBEDCRYPTO_CMAC_AES, key, 128);
	CHECK(ret == 0, ret);
	mbedcrypto_mac_update(&mctx, msg, 16);
	mbedcrypto_mac_final(&mctx, mac, &maclen);
	CHECK(hexcmp(mac, "070a16b46b4d4144f79bdd9dd04a287c", 16) == 0, EBADMSG);
	mbedcrypto_mac_cleanup(&mctx);

	/* AES CBC-MAC no-pad */
	ret = mbedcrypto_mac_init(&mctx, MBEDCRYPTO_CMAC_AES_CBC_NOPAD, key, 128);
	CHECK(ret == 0, ret);
	mbedcrypto_mac_update(&mctx, msg, 16);
	mbedcrypto_mac_final(&mctx, mac, &maclen);
	CHECK(maclen == 16, EBADMSG);
	mbedcrypto_mac_cleanup(&mctx);

	/* DES CBC-MAC */
	hex2bin("0123456789abcdef", des_key, 8);
	ret = mbedcrypto_mac_init(&mctx, MBEDCRYPTO_CMAC_DES_CBC_NOPAD, des_key, 64);
	CHECK(ret == 0, ret);
	memset(des_msg, 0, sizeof(des_msg));
	mbedcrypto_mac_update(&mctx, des_msg, 8);
	mbedcrypto_mac_final(&mctx, mac, &maclen);
	CHECK(maclen == 8, EBADMSG);
	mbedcrypto_mac_cleanup(&mctx);

	/* 3DES CBC-MAC */
	hex2bin("0123456789abcdef23456789abcdef014567890123456789", des3_key, 24);
	ret = mbedcrypto_mac_init(&mctx, MBEDCRYPTO_CMAC_DES3_CBC_NOPAD, des3_key, 192);
	CHECK(ret == 0, ret);
	mbedcrypto_mac_update(&mctx, des_msg, 8);
	mbedcrypto_mac_final(&mctx, mac, &maclen);
	CHECK(maclen == 8, EBADMSG);
	mbedcrypto_mac_cleanup(&mctx);

	/* mac_reset test */
	ret = mbedcrypto_mac_init(&mctx, MBEDCRYPTO_CMAC_AES, key, 128);
	mbedcrypto_mac_update(&mctx, msg, 16);
	maclen = sizeof(mac);
	mbedcrypto_mac_final(&mctx, mac, &maclen);
	memcpy(mac1, mac, 16);

	mbedcrypto_mac_reset(&mctx);
	mbedcrypto_mac_update(&mctx, msg, 16);
	maclen = sizeof(mac);
	mbedcrypto_mac_final(&mctx, mac, &maclen);
	CHECK(memcmp(mac, mac1, 16) == 0, EBADMSG);
	mbedcrypto_mac_cleanup(&mctx);

	/* AES-256 CMAC via dispatch */
	hex2bin("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key256, 32);
	ret = mbedcrypto_mac_init(&mctx, MBEDCRYPTO_CMAC_AES, key256, 256);
	CHECK(ret == 0, ret);
	mbedcrypto_mac_update(&mctx, msg, 16);
	mbedcrypto_mac_final(&mctx, mac, &maclen);
	CHECK(hexcmp(mac, "28a7023f452e8f82bd4bf28d8c37c35c", 16) == 0, EBADMSG);
	mbedcrypto_mac_cleanup(&mctx);

	/* --- Extended coverage (merged from test_mac_dispatch_ext) --- */
	{
		struct mbedcrypto_mac_ctx mctx, mctx2;
		uint8_t mac[16], mac2[16];
		uint8_t key[16], msg[20];
		uint8_t des_key[8];
		uint8_t des3_key[24];
		uint8_t key192[24];
		size_t maclen;
		size_t maclen2;
		int ret = 0;

		for (i = 0; i < 16; i++)
			key[i] = i;
		for (i = 0; i < 20; i++)
			msg[i] = i ^ 0x55;

		/* AES CBC-MAC with PKCS5 padding (non-block-aligned input) */
		ret = mbedcrypto_mac_init(&mctx, MBEDCRYPTO_CMAC_AES_CBC_PKCS5, key, 128);
		CHECK(ret == 0, ret);
		mbedcrypto_mac_update(&mctx, msg, 20);
		maclen = sizeof(mac);
		mbedcrypto_mac_final(&mctx, mac, &maclen);
		CHECK(maclen == 16, EBADMSG);

		/* Reset and verify consistency */
		maclen2 = sizeof(mac2);
		mbedcrypto_mac_reset(&mctx);
		mbedcrypto_mac_update(&mctx, msg, 20);
		mbedcrypto_mac_final(&mctx, mac2, &maclen2);
		CHECK(memcmp(mac, mac2, 16) == 0, EBADMSG);
		mbedcrypto_mac_cleanup(&mctx);

		/* DES CBC-MAC with PKCS5 padding */
		for (i = 0; i < 8; i++)
			des_key[i] = i + 0x10;
		ret = mbedcrypto_mac_init(&mctx, MBEDCRYPTO_CMAC_DES_CBC_PKCS5, des_key, 64);
		CHECK(ret == 0, ret);
		mbedcrypto_mac_update(&mctx, msg, 11);
		maclen = sizeof(mac);
		mbedcrypto_mac_final(&mctx, mac, &maclen);
		CHECK(maclen == 8, EBADMSG);
		mbedcrypto_mac_cleanup(&mctx);

		/* 3DES CBC-MAC with PKCS5 padding */
		for (i = 0; i < 24; i++)
			des3_key[i] = i + 0x20;
		ret = mbedcrypto_mac_init(&mctx, MBEDCRYPTO_CMAC_DES3_CBC_PKCS5, des3_key, 192);
		CHECK(ret == 0, ret);
		mbedcrypto_mac_update(&mctx, msg, 13);
		maclen = sizeof(mac);
		mbedcrypto_mac_final(&mctx, mac, &maclen);
		CHECK(maclen == 8, EBADMSG);
		mbedcrypto_mac_cleanup(&mctx);

		/* AES-192 CMAC */
		for (i = 0; i < 24; i++)
			key192[i] = i + 0x30;
		ret = mbedcrypto_mac_init(&mctx, MBEDCRYPTO_CMAC_AES, key192, 192);
		CHECK(ret == 0, ret);
		mbedcrypto_mac_update(&mctx, msg, 16);
		maclen = sizeof(mac);
		mbedcrypto_mac_final(&mctx, mac, &maclen);
		CHECK(maclen == 16, EBADMSG);
		mbedcrypto_mac_cleanup(&mctx);

		/* Streaming MAC: byte-by-byte update */
		ret = mbedcrypto_mac_init(&mctx, MBEDCRYPTO_CMAC_AES, key, 128);
		for (i = 0; i < 16; i++)
			mbedcrypto_mac_update(&mctx, msg + i, 1);
		maclen = sizeof(mac);
		mbedcrypto_mac_final(&mctx, mac, &maclen);

		/* Compare with single-shot */
		mbedcrypto_mac_init(&mctx2, MBEDCRYPTO_CMAC_AES, key, 128);
		mbedcrypto_mac_update(&mctx2, msg, 16);
		maclen2 = sizeof(mac2);
		mbedcrypto_mac_final(&mctx2, mac2, &maclen2);
		CHECK(memcmp(mac, mac2, 16) == 0, EBADMSG);
		mbedcrypto_mac_cleanup(&mctx);
		mbedcrypto_mac_cleanup(&mctx2);
	}

out:
	TEST_END();
}

static void test_base64(void)
{
	TEST_START("Base64");
	size_t i = 0;

	/* Decode test vectors */
	struct { const char *input; const char *expected; } tests[] = {
		{ "", "" },
		{ "Zg==", "f" },
		{ "Zm8=", "fo" },
		{ "Zm9v", "foo" },
		{ "Zm9vYg==", "foob" },
		{ "Zm9vYmE=", "fooba" },
		{ "Zm9vYmFy", "foobar" },
	};

	for (i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
		uint8_t out[64];
		size_t olen;
		int ret = mbedcrypto_base64_decode(out, sizeof(out), &olen,
			(const uint8_t *)tests[i].input, strlen(tests[i].input));
		CHECK(ret == 0, ret);
		CHECK(olen == strlen(tests[i].expected), EBADMSG);
		CHECK(memcmp(out, tests[i].expected, olen) == 0, EBADMSG);
	}

	/* Invalid base64 should fail */
	{
		uint8_t out[64];
		size_t olen;
		int ret = mbedcrypto_base64_decode(out, sizeof(out), &olen,
			(const uint8_t *)"!!invalid!!", 11);
		CHECK(ret != 0, EBADMSG);
	}

	/* Buffer too small */
	{
		uint8_t out[2]; /* too small for "foobar" */
		size_t olen;
		int ret = mbedcrypto_base64_decode(out, sizeof(out), &olen,
			(const uint8_t *)"Zm9vYmFy", 8);
		CHECK(ret != 0, EBADMSG);
	}

out:
	TEST_END();
}

static void test_ct_utils(void)
{
	TEST_START("ct_utils");

	/* ct_memcmp: equal buffers */
	uint8_t a[32], b[32];
	int i = 0;
	for (i = 0; i < 32; i++)
		a[i] = b[i] = i;
	CHECK(mbedcrypto_ct_memcmp(a, b, 32) == 0, EBADMSG);

	/* ct_memcmp: different buffers */
	b[15] ^= 1;
	CHECK(mbedcrypto_ct_memcmp(a, b, 32) != 0, EBADMSG);
	b[15] ^= 1;

	/* ct_memcmp: first byte different */
	b[0] ^= 0x80;
	CHECK(mbedcrypto_ct_memcmp(a, b, 32) != 0, EBADMSG);
	b[0] ^= 0x80;

	/* ct_memcmp: last byte different */
	b[31] ^= 1;
	CHECK(mbedcrypto_ct_memcmp(a, b, 32) != 0, EBADMSG);
	b[31] ^= 1;

	/* ct_memcmp: zero length */
	CHECK(mbedcrypto_ct_memcmp(a, b, 0) == 0, EBADMSG);

	/* ct_cond_select: mask=0 selects src0 */
	uint8_t src0[16], src1[16], dest[16];
	for (i = 0; i < 16; i++) { src0[i] = i; src1[i] = 0xFF - i; }
	mbedcrypto_ct_cond_select(dest, src0, src1, 16, 0x00);
	CHECK(memcmp(dest, src0, 16) == 0, EBADMSG);

	/* ct_cond_select: mask=0xFF selects src1 */
	mbedcrypto_ct_cond_select(dest, src0, src1, 16, 0xFF);
	CHECK(memcmp(dest, src1, 16) == 0, EBADMSG);

out:
	TEST_END();
}

static void test_asn1(void)
{
	TEST_START("ASN1");
	struct mbedcrypto_bignum X;
	mbedcrypto_bn_init(&X);

	/* Write/read integer roundtrip for small value */
	{
		uint8_t buf[64];
		uint8_t *p = buf + sizeof(buf);
		mbedcrypto_bn_set_word(&X, 0x1234);
		int wlen = mbedcrypto_asn1_write_bn(&p, buf, &X);
		CHECK(wlen > 0, EBADMSG);

		/* Read it back */
		struct mbedcrypto_bignum Y;
		mbedcrypto_bn_init(&Y);
		const uint8_t *rp = p;
		int ret = mbedcrypto_asn1_read_bn(&rp, buf + sizeof(buf), &Y);
		CHECK(ret == 0, ret);
		CHECK(mbedcrypto_bn_cmp(&X, &Y) == 0, EBADMSG);
		mbedcrypto_bn_cleanup(&Y);
	}

	/* Write/read large integer */
	{
		uint8_t buf[256];
		uint8_t *p = buf + sizeof(buf);
		mbedcrypto_bn_from_hex(&X, "DEADBEEFCAFEBABE0123456789ABCDEF");
		int wlen = mbedcrypto_asn1_write_bn(&p, buf, &X);
		CHECK(wlen > 0, EBADMSG);

		struct mbedcrypto_bignum Y;
		mbedcrypto_bn_init(&Y);
		const uint8_t *rp = p;
		int ret = mbedcrypto_asn1_read_bn(&rp, buf + sizeof(buf), &Y);
		CHECK(ret == 0, ret);
		CHECK(mbedcrypto_bn_cmp(&X, &Y) == 0, EBADMSG);
		mbedcrypto_bn_cleanup(&Y);
	}

	/* write_tag + write_len + get_tag roundtrip */
	{
		uint8_t buf[32];
		uint8_t *p = buf + sizeof(buf);
		int lret = mbedcrypto_asn1_write_len(&p, buf, 10);
		CHECK(lret > 0, EBADMSG);
		int tret = mbedcrypto_asn1_write_tag(&p, buf, MBEDCRYPTO_ASN1_SEQUENCE);
		CHECK(tret == 1, EBADMSG);

		const uint8_t *rp = p;
		size_t len = 0;
		int ret = mbedcrypto_asn1_read_tag(&rp, buf + sizeof(buf), &len, MBEDCRYPTO_ASN1_SEQUENCE);
		CHECK(ret == 0, ret);
		CHECK(len == 10, EBADMSG);
	}

	/* get_tag with wrong tag should fail */
	{
		uint8_t buf[8];
		uint8_t *p = buf + sizeof(buf);
		mbedcrypto_asn1_write_len(&p, buf, 5);
		mbedcrypto_asn1_write_tag(&p, buf, MBEDCRYPTO_ASN1_INTEGER);
		const uint8_t *rp = p;
		size_t len = 0;
		int ret = mbedcrypto_asn1_read_tag(&rp, buf + sizeof(buf), &len, MBEDCRYPTO_ASN1_SEQUENCE);
		CHECK(ret != 0, EBADMSG);
	}

	mbedcrypto_bn_cleanup(&X);
out:
	TEST_END();
}

static void test_pkparse(void)
{
	TEST_START("pkparse");

	/* RSA: generate key, export N/E/D/P/Q to DER, re-import via pkparse */
	{
		struct mbedcrypto_rsa_ctx gen, imp;
		mbedcrypto_rsa_init(&gen);
		int ret = mbedcrypto_rsa_keygen(&gen, test_rng, NULL, 1024, 65537);
		CHECK(ret == 0, ret);

		/*
		 * Build a bare PKCS#1 RSAPublicKey DER:
		 * SEQUENCE { INTEGER N, INTEGER E }
		 */
		uint8_t der[512];
		uint8_t *p = der + sizeof(der);
		int elen = mbedcrypto_asn1_write_bn(&p, der, &gen.E);
		int nlen = mbedcrypto_asn1_write_bn(&p, der, &gen.N);
		int slen = mbedcrypto_asn1_write_len(&p, der, (elen + nlen));
		int tlen = mbedcrypto_asn1_write_tag(&p, der, MBEDCRYPTO_ASN1_SEQUENCE);
		size_t total = elen + nlen + slen + tlen;

		/* Parse public key */
		mbedcrypto_rsa_init(&imp);
		ret = mbedcrypto_pk_decode_rsa_pubkey_der(&imp, p, total);
		CHECK(ret == 0, ret);
		CHECK(mbedcrypto_bn_cmp(&gen.N, &imp.N) == 0, EBADMSG);
		CHECK(mbedcrypto_bn_cmp(&gen.E, &imp.E) == 0, EBADMSG);
		mbedcrypto_rsa_cleanup(&imp);
		mbedcrypto_rsa_cleanup(&gen);
	}

	/* EC: parse uncompressed public key point */
	{
		struct mbedcrypto_ecp_keypair kp, imp;
		mbedcrypto_ecp_keypair_init(&kp);
		int ret = mbedcrypto_ecp_keygen(MBEDCRYPTO_ECP_DP_SECP256R1, &kp, test_rng, NULL);
		CHECK(ret == 0, ret);

		/* Export uncompressed point: 04 || X || Y */
		size_t plen = mbedcrypto_bn_byte_count(&kp.grp.P);
		uint8_t pt[133]; /* 1 + 2*66 max for P-521 */
		pt[0] = 0x04;
		mbedcrypto_bn_to_binary(&kp.Q.X, pt + 1, plen);
		mbedcrypto_bn_to_binary(&kp.Q.Y, pt + 1 + plen, plen);

		mbedcrypto_ecp_keypair_init(&imp);
		ret = mbedcrypto_pk_decode_ec_pubkey(&imp, MBEDCRYPTO_ECP_DP_SECP256R1, pt, 1 + 2*plen);
		CHECK(ret == 0, ret);
		CHECK(mbedcrypto_bn_cmp(&kp.Q.X, &imp.Q.X) == 0, EBADMSG);
		CHECK(mbedcrypto_bn_cmp(&kp.Q.Y, &imp.Q.Y) == 0, EBADMSG);
		mbedcrypto_ecp_keypair_cleanup(&imp);

		/* Parse private key scalar */
		size_t dlen = mbedcrypto_bn_byte_count(&kp.d);
		uint8_t dbuf[66];
		mbedcrypto_bn_to_binary(&kp.d, dbuf, dlen);

		mbedcrypto_ecp_keypair_init(&imp);
		ret = mbedcrypto_pk_decode_ec_privkey(&imp, MBEDCRYPTO_ECP_DP_SECP256R1, dbuf, dlen);
		CHECK(ret == 0, ret);
		CHECK(mbedcrypto_bn_cmp(&kp.d, &imp.d) == 0, EBADMSG);
		mbedcrypto_ecp_keypair_cleanup(&imp);

		mbedcrypto_ecp_keypair_cleanup(&kp);
	}

	/* DH: parse DER params */
	{
		struct mbedcrypto_dh_ctx dctx, imp;
		mbedcrypto_dh_init(&dctx);

		/* Use small known P and G for test */
		mbedcrypto_bn_from_hex(&dctx.P, "FFFFFFFFFFFFFFFFC90FDAA22168C234"
			"C4C6628B80DC1CD129024E088A67CC74"
			"020BBEA63B139B22514A08798E3404DD"
			"EF9519B3CD3A431B302B0A6DF25F1437"
			"4FE1356D6D51C245E485B576625E7EC6"
			"F44C42E9A637ED6B0BFF5CB6F406B7ED"
			"EE386BFB5A899FA5AE9F24117C4B1FE6"
			"49286651ECE65381FFFFFFFFFFFFFFFF"); /* RFC 2409 */
		mbedcrypto_bn_set_word(&dctx.G, 2);

		/* Build DER: SEQUENCE { INTEGER P, INTEGER G } */
		uint8_t der[512];
		uint8_t *p = der + sizeof(der);
		int glen = mbedcrypto_asn1_write_bn(&p, der, &dctx.G);
		int plen = mbedcrypto_asn1_write_bn(&p, der, &dctx.P);
		int slen = mbedcrypto_asn1_write_len(&p, der, (glen + plen));
		int tlen = mbedcrypto_asn1_write_tag(&p, der, MBEDCRYPTO_ASN1_SEQUENCE);
		size_t total = glen + plen + slen + tlen;

		mbedcrypto_dh_init(&imp);
		int ret = mbedcrypto_pk_decode_dh_params_der(&imp, p, total);
		CHECK(ret == 0, ret);
		CHECK(mbedcrypto_bn_cmp(&dctx.P, &imp.P) == 0, EBADMSG);
		CHECK(mbedcrypto_bn_cmp(&dctx.G, &imp.G) == 0, EBADMSG);
		mbedcrypto_dh_cleanup(&imp);
		mbedcrypto_dh_cleanup(&dctx);
	}

out:
	TEST_END();
}


#define BENCH_ITERATIONS 10000
#define BENCH_HASH_SIZE  1024
#define BENCH_CIPHER_SIZE 1024

static double get_time_sec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void perf_hashes(void)
{
	uint8_t data[BENCH_HASH_SIZE], out[64];
	double t0, elapsed;
	int i;

	memset(data, 0xA5, sizeof(data));
	printf("\n--- Hash Performance (%d x %d B) ---\n",
		BENCH_ITERATIONS, BENCH_HASH_SIZE);

	t0 = get_time_sec();
	for (i = 0; i < BENCH_ITERATIONS; i++)
		mbedcrypto_md5_digest(data, BENCH_HASH_SIZE, out);
	elapsed = get_time_sec() - t0;
	printf("  %-16s %.1f MB/s\n", "MD5", (double)BENCH_ITERATIONS * BENCH_HASH_SIZE / elapsed / 1e6);

	t0 = get_time_sec();
	for (i = 0; i < BENCH_ITERATIONS; i++)
		mbedcrypto_sha1_digest(data, BENCH_HASH_SIZE, out);
	elapsed = get_time_sec() - t0;
	printf("  %-16s %.1f MB/s\n", "SHA-1", (double)BENCH_ITERATIONS * BENCH_HASH_SIZE / elapsed / 1e6);

	t0 = get_time_sec();
	for (i = 0; i < BENCH_ITERATIONS; i++)
		mbedcrypto_sha256_digest(data, BENCH_HASH_SIZE, out, 0);
	elapsed = get_time_sec() - t0;
	printf("  %-16s %.1f MB/s\n", "SHA-256", (double)BENCH_ITERATIONS * BENCH_HASH_SIZE / elapsed / 1e6);

	t0 = get_time_sec();
	for (i = 0; i < BENCH_ITERATIONS; i++)
		mbedcrypto_sha256_digest(data, BENCH_HASH_SIZE, out, 1);
	elapsed = get_time_sec() - t0;
	printf("  %-16s %.1f MB/s\n", "SHA-224", (double)BENCH_ITERATIONS * BENCH_HASH_SIZE / elapsed / 1e6);

	t0 = get_time_sec();
	for (i = 0; i < BENCH_ITERATIONS; i++)
		mbedcrypto_sha512_digest(data, BENCH_HASH_SIZE, out, 0);
	elapsed = get_time_sec() - t0;
	printf("  %-16s %.1f MB/s\n", "SHA-512", (double)BENCH_ITERATIONS * BENCH_HASH_SIZE / elapsed / 1e6);

	t0 = get_time_sec();
	for (i = 0; i < BENCH_ITERATIONS; i++)
		mbedcrypto_sha512_digest(data, BENCH_HASH_SIZE, out, 1);
	elapsed = get_time_sec() - t0;
	printf("  %-16s %.1f MB/s\n", "SHA-384", (double)BENCH_ITERATIONS * BENCH_HASH_SIZE / elapsed / 1e6);

	t0 = get_time_sec();
	for (i = 0; i < BENCH_ITERATIONS; i++) {
		struct mbedcrypto_sha3_ctx s3;
		mbedcrypto_sha3_init(&s3);
		mbedcrypto_sha3_start(&s3, MBEDCRYPTO_SHA3_224);
		mbedcrypto_sha3_update(&s3, data, BENCH_HASH_SIZE);
		mbedcrypto_sha3_final(&s3, out, 28);
		mbedcrypto_sha3_cleanup(&s3);
	}
	elapsed = get_time_sec() - t0;
	printf("  %-16s %.1f MB/s\n", "SHA3-224", (double)BENCH_ITERATIONS * BENCH_HASH_SIZE / elapsed / 1e6);

	t0 = get_time_sec();
	for (i = 0; i < BENCH_ITERATIONS; i++) {
		struct mbedcrypto_sha3_ctx s3;
		mbedcrypto_sha3_init(&s3);
		mbedcrypto_sha3_start(&s3, MBEDCRYPTO_SHA3_256);
		mbedcrypto_sha3_update(&s3, data, BENCH_HASH_SIZE);
		mbedcrypto_sha3_final(&s3, out, 32);
		mbedcrypto_sha3_cleanup(&s3);
	}
	elapsed = get_time_sec() - t0;
	printf("  %-16s %.1f MB/s\n", "SHA3-256", (double)BENCH_ITERATIONS * BENCH_HASH_SIZE / elapsed / 1e6);

	t0 = get_time_sec();
	for (i = 0; i < BENCH_ITERATIONS; i++) {
		struct mbedcrypto_sha3_ctx s3;
		mbedcrypto_sha3_init(&s3);
		mbedcrypto_sha3_start(&s3, MBEDCRYPTO_SHA3_384);
		mbedcrypto_sha3_update(&s3, data, BENCH_HASH_SIZE);
		mbedcrypto_sha3_final(&s3, out, 48);
		mbedcrypto_sha3_cleanup(&s3);
	}
	elapsed = get_time_sec() - t0;
	printf("  %-16s %.1f MB/s\n", "SHA3-384", (double)BENCH_ITERATIONS * BENCH_HASH_SIZE / elapsed / 1e6);

	t0 = get_time_sec();
	for (i = 0; i < BENCH_ITERATIONS; i++) {
		struct mbedcrypto_sha3_ctx s3;
		mbedcrypto_sha3_init(&s3);
		mbedcrypto_sha3_start(&s3, MBEDCRYPTO_SHA3_512);
		mbedcrypto_sha3_update(&s3, data, BENCH_HASH_SIZE);
		mbedcrypto_sha3_final(&s3, out, 64);
		mbedcrypto_sha3_cleanup(&s3);
	}
	elapsed = get_time_sec() - t0;
	printf("  %-16s %.1f MB/s\n", "SHA3-512", (double)BENCH_ITERATIONS * BENCH_HASH_SIZE / elapsed / 1e6);

	t0 = get_time_sec();
	for (i = 0; i < BENCH_ITERATIONS; i++)
		mbedcrypto_sm3_digest(data, BENCH_HASH_SIZE, out);
	elapsed = get_time_sec() - t0;
	printf("  %-16s %.1f MB/s\n", "SM3", (double)BENCH_ITERATIONS * BENCH_HASH_SIZE / elapsed / 1e6);
}

static void perf_mac(void)
{
	uint8_t data[BENCH_CIPHER_SIZE], mac[64], key[32];
	double t0, elapsed;
	int i;
	size_t t = 0;

	memset(data, 0xA5, sizeof(data));
	memset(key, 0x5A, sizeof(key));
	printf("\n--- MAC Performance (%d x %d B) ---\n",
		BENCH_ITERATIONS, BENCH_CIPHER_SIZE);

	/* HMAC variants via dispatch API */
	{
		struct {
			int algo;
			const char *name;
			int keylen;
		} hmac_tests[] = {
			{ MBEDCRYPTO_HASH_MD5,    "HMAC-MD5",    16 },
			{ MBEDCRYPTO_HASH_SHA1,   "HMAC-SHA1",   20 },
			{ MBEDCRYPTO_HASH_SHA224, "HMAC-SHA224",  32 },
			{ MBEDCRYPTO_HASH_SHA256, "HMAC-SHA256",  32 },
			{ MBEDCRYPTO_HASH_SHA384, "HMAC-SHA384",  32 },
			{ MBEDCRYPTO_HASH_SHA512, "HMAC-SHA512",  32 },
			{ MBEDCRYPTO_HASH_SM3,    "HMAC-SM3",    32 },
		};
		for (t = 0; t < sizeof(hmac_tests)/sizeof(hmac_tests[0]); t++) {
			t0 = get_time_sec();
			for (i = 0; i < BENCH_ITERATIONS; i++) {
				struct mbedcrypto_hmac_ctx hctx;
				mbedcrypto_hmac_init(&hctx, hmac_tests[t].algo, key, hmac_tests[t].keylen);
				mbedcrypto_hmac_update(&hctx, data, BENCH_CIPHER_SIZE);
				mbedcrypto_hmac_final(&hctx, mac);
				mbedcrypto_hmac_cleanup(&hctx);
			}
			elapsed = get_time_sec() - t0;
			printf("  %-16s %.1f MB/s\n", hmac_tests[t].name,
				(double)BENCH_ITERATIONS * BENCH_CIPHER_SIZE / elapsed / 1e6);
		}
	}

	/* AES-CMAC */
	t0 = get_time_sec();
	for (i = 0; i < BENCH_ITERATIONS; i++) {
		struct mbedcrypto_cmac_ctx cctx;
		mbedcrypto_cmac_setkey(&cctx, key, 128);
		mbedcrypto_cmac_update(&cctx, data, BENCH_CIPHER_SIZE);
		mbedcrypto_cmac_final(&cctx, mac);
		mbedcrypto_cmac_cleanup(&cctx);
	}
	elapsed = get_time_sec() - t0;
	printf("  %-16s %.1f MB/s\n", "AES-CMAC-128", (double)BENCH_ITERATIONS * BENCH_CIPHER_SIZE / elapsed / 1e6);

	/* MAC dispatch: CBC-MAC modes */
	{
		struct {
			int type;
			const char *name;
			int keybits;
		} mac_tests[] = {
			{ MBEDCRYPTO_CMAC_AES_CBC_NOPAD,  "CBC-MAC-AES",   128 },
			{ MBEDCRYPTO_CMAC_AES_CBC_PKCS5,  "CBC-MAC-AES-P5", 128 },
			{ MBEDCRYPTO_CMAC_DES3_CBC_NOPAD, "CBC-MAC-3DES",  192 },
		};
		for (t = 0; t < sizeof(mac_tests)/sizeof(mac_tests[0]); t++) {
			t0 = get_time_sec();
			for (i = 0; i < BENCH_ITERATIONS; i++) {
				struct mbedcrypto_mac_ctx mctx;
				size_t mlen;
				mbedcrypto_mac_init(&mctx, mac_tests[t].type, key, mac_tests[t].keybits);
				mbedcrypto_mac_update(&mctx, data, BENCH_CIPHER_SIZE);
				mbedcrypto_mac_final(&mctx, mac, &mlen);
				mbedcrypto_mac_cleanup(&mctx);
			}
			elapsed = get_time_sec() - t0;
			printf("  %-16s %.1f MB/s\n", mac_tests[t].name,
				(double)BENCH_ITERATIONS * BENCH_CIPHER_SIZE / elapsed / 1e6);
		}
	}
}

static void perf_ciphers(void)
{
	uint8_t key[64], iv[16], data[BENCH_CIPHER_SIZE], out[BENCH_CIPHER_SIZE + 32];
	double t0, elapsed;
	int i, N = BENCH_ITERATIONS;
	size_t t = 0;

	memset(key, 0x5A, sizeof(key));
	memset(iv, 0, sizeof(iv));
	memset(data, 0xB7, sizeof(data));

	struct {
		int type;
		const char *name;
		int keybits;
		size_t iv_len;
	} tests[] = {
		{ MBEDCRYPTO_CIPHER_AES_ECB, "AES-128-ECB", 128, 0 },
		{ MBEDCRYPTO_CIPHER_AES_CBC, "AES-128-CBC", 128, 16 },
		{ MBEDCRYPTO_CIPHER_AES_CTR, "AES-128-CTR", 128, 16 },
		{ MBEDCRYPTO_CIPHER_AES_CTS, "AES-128-CTS", 128, 16 },
		{ MBEDCRYPTO_CIPHER_AES_XTS, "AES-128-XTS", 128, 16 },
		{ MBEDCRYPTO_CIPHER_AES_ECB, "AES-192-ECB", 192, 0 },
		{ MBEDCRYPTO_CIPHER_AES_CBC, "AES-192-CBC", 192, 16 },
		{ MBEDCRYPTO_CIPHER_AES_CTR, "AES-192-CTR", 192, 16 },
		{ MBEDCRYPTO_CIPHER_AES_CTS, "AES-192-CTS", 192, 16 },
		{ MBEDCRYPTO_CIPHER_AES_XTS, "AES-192-XTS", 192, 16 },
		{ MBEDCRYPTO_CIPHER_AES_ECB, "AES-256-ECB", 256, 0 },
		{ MBEDCRYPTO_CIPHER_AES_CBC, "AES-256-CBC", 256, 16 },
		{ MBEDCRYPTO_CIPHER_AES_CTR, "AES-256-CTR", 256, 16 },
		{ MBEDCRYPTO_CIPHER_AES_CTS, "AES-256-CTS", 256, 16 },
		{ MBEDCRYPTO_CIPHER_AES_XTS, "AES-256-XTS", 256, 16 },
		{ MBEDCRYPTO_CIPHER_SM4_ECB, "SM4-ECB", 128, 0 },
		{ MBEDCRYPTO_CIPHER_SM4_CBC, "SM4-CBC", 128, 16 },
		{ MBEDCRYPTO_CIPHER_SM4_CTR, "SM4-CTR", 128, 16 },
		{ MBEDCRYPTO_CIPHER_SM4_CTS, "SM4-CTS", 128, 16 },
		{ MBEDCRYPTO_CIPHER_DES_ECB, "DES-ECB", 64, 0 },
		{ MBEDCRYPTO_CIPHER_DES_CBC, "DES-CBC", 64, 8 },
		{ MBEDCRYPTO_CIPHER_DES3_ECB, "3DES-ECB", 192, 0 },
		{ MBEDCRYPTO_CIPHER_DES3_CBC, "3DES-CBC", 192, 8 },
		{ MBEDCRYPTO_CIPHER_DES3_CTS, "3DES-CTS", 192, 8 },
	};

	printf("\n--- Cipher Performance (%d x %d B) ---\n", N, BENCH_CIPHER_SIZE);

	for (t = 0; t < sizeof(tests)/sizeof(tests[0]); t++) {
		struct mbedcrypto_cipher_ctx cctx;
		size_t olen, olen2;

		mbedcrypto_cipher_init(&cctx, tests[t].type, key, tests[t].keybits, 0);
		if (tests[t].iv_len)
			mbedcrypto_cipher_set_iv(&cctx, iv, tests[t].iv_len);

		t0 = get_time_sec();
		for (i = 0; i < N; i++) {
			mbedcrypto_cipher_reset(&cctx);
			if (tests[t].iv_len)
				mbedcrypto_cipher_set_iv(&cctx, iv, tests[t].iv_len);
			mbedcrypto_cipher_update(&cctx, data, BENCH_CIPHER_SIZE, out, &olen);
			mbedcrypto_cipher_final(&cctx, NULL, 0, out + olen, &olen2);
		}
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.1f MB/s\n", tests[t].name,
			(double)N * BENCH_CIPHER_SIZE / elapsed / 1e6);
		mbedcrypto_cipher_cleanup(&cctx);
	}

#ifdef CONFIG_MBEDCRYPTO_CHACHA20
	/* ChaCha20 stream cipher */
	{
		struct mbedcrypto_chacha20_ctx cc20;
		uint8_t cc20_nonce[12];

		memset(cc20_nonce, 0, sizeof(cc20_nonce));
		mbedcrypto_chacha20_init(&cc20);
		mbedcrypto_chacha20_setkey(&cc20, key);

		t0 = get_time_sec();
		for (i = 0; i < N; i++) {
			mbedcrypto_chacha20_set_nonce(&cc20, cc20_nonce, 0);
			mbedcrypto_chacha20_update(&cc20, data, BENCH_CIPHER_SIZE, out);
		}
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.1f MB/s\n", "ChaCha20",
			(double)N * BENCH_CIPHER_SIZE / elapsed / 1e6);
		mbedcrypto_chacha20_cleanup(&cc20);
	}
#endif
}

static void perf_aead(void)
{
	uint8_t key[32], iv[12], aad[16], data[BENCH_CIPHER_SIZE];
	uint8_t out[BENCH_CIPHER_SIZE + 16], tag[16];
	double t0, elapsed;
	int i, N = BENCH_ITERATIONS / 10;
	int k = 0;

	memset(key, 0x5A, sizeof(key));
	memset(iv, 0, sizeof(iv));
	memset(aad, 0xAA, sizeof(aad));
	memset(data, 0xB7, sizeof(data));

	printf("\n--- AEAD Performance (%d x %d B) ---\n", N, BENCH_CIPHER_SIZE);

	/* AES-GCM (128, 256) */
	{
		int gcm_keys[] = { 128, 256 };
		const char *gcm_names[] = { "AES-128-GCM", "AES-256-GCM" };
		for (k = 0; k < 2; k++) {
			struct mbedcrypto_aes_gcm_ctx gctx;
			mbedcrypto_aes_gcm_setkey(&gctx, key, gcm_keys[k]);

			t0 = get_time_sec();
			for (i = 0; i < N; i++)
				mbedcrypto_aes_gcm_encrypt(&gctx, iv, 12, aad, 16,
					data, BENCH_CIPHER_SIZE, out, tag, 16);
			elapsed = get_time_sec() - t0;
			printf("  %-16s %.1f MB/s\n", gcm_names[k],
				(double)N * BENCH_CIPHER_SIZE / elapsed / 1e6);
		}
	}

	/* AES-CCM (128, 256) */
	{
		int ccm_keys[] = { 128, 256 };
		const char *ccm_names[] = { "AES-128-CCM", "AES-256-CCM" };
		for (k = 0; k < 2; k++) {
			struct mbedcrypto_aes_ccm_ctx cctx;
			uint8_t nonce[8];

			memset(nonce, 0, sizeof(nonce));
			mbedcrypto_aes_ccm_setkey(&cctx, key, ccm_keys[k]);

			t0 = get_time_sec();
			for (i = 0; i < N; i++)
				mbedcrypto_aes_ccm_encrypt(&cctx, nonce, 8, aad, 16,
					data, BENCH_CIPHER_SIZE, out, tag, 8);
			elapsed = get_time_sec() - t0;
			printf("  %-16s %.1f MB/s\n", ccm_names[k],
				(double)N * BENCH_CIPHER_SIZE / elapsed / 1e6);
			mbedcrypto_aes_ccm_cleanup(&cctx);
		}
	}

#ifdef CONFIG_MBEDCRYPTO_CHACHA20
	/* ChaCha20-Poly1305 */
	{
		struct mbedcrypto_chachapoly_ctx cpctx;

		mbedcrypto_chachapoly_init(&cpctx);
		mbedcrypto_chachapoly_setkey(&cpctx, key);

		t0 = get_time_sec();
		for (i = 0; i < N; i++) {
			mbedcrypto_chachapoly_start(&cpctx, iv, MBEDCRYPTO_AES_ENCRYPT);
			mbedcrypto_chachapoly_update_aad(&cpctx, aad, 16);
			mbedcrypto_chachapoly_update(&cpctx, data, BENCH_CIPHER_SIZE, out);
			mbedcrypto_chachapoly_final(&cpctx, tag);
		}
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.1f MB/s\n", "ChaCha20-Poly",
			(double)N * BENCH_CIPHER_SIZE / elapsed / 1e6);
		mbedcrypto_chachapoly_cleanup(&cpctx);
	}
#endif

#ifdef CONFIG_MBEDCRYPTO_AES_SIV
	/* AES-SIV (256, 512) */
	{
		uint8_t siv_key[64];
		int siv_keylens[] = { 32, 64 };
		const char *siv_names[] = { "AES-128-SIV", "AES-256-SIV" };
		memset(siv_key, 0x5A, sizeof(siv_key));

		for (k = 0; k < 2; k++) {
			struct mbedcrypto_aes_siv_ctx sctx;
			mbedcrypto_aes_siv_init(&sctx);
			mbedcrypto_aes_siv_setkey(&sctx, siv_key, siv_keylens[k]);

			t0 = get_time_sec();
			for (i = 0; i < N; i++)
				mbedcrypto_aes_siv_encrypt(&sctx, aad, 16,
					data, BENCH_CIPHER_SIZE, out, tag);
			elapsed = get_time_sec() - t0;
			printf("  %-16s %.1f MB/s\n", siv_names[k],
				(double)N * BENCH_CIPHER_SIZE / elapsed / 1e6);
			mbedcrypto_aes_siv_cleanup(&sctx);
		}
	}
#endif
}

static void perf_rsa(void)
{
	int rsa_bits[] = { 2048, 3072, 4096 };
	int sign_n[] = { 100, 50, 20 };
	int verify_n[] = { 1000, 500, 200 };
	uint8_t hash[32], sig[512];
	double t0, elapsed;
	int i = 0, k = 0;

	mbedcrypto_sha256_digest((const uint8_t *)"bench", 5, hash, 0);

	for (k = 0; k < 3; k++) {
		printf("\n--- RSA-%d Performance ---\n", rsa_bits[k]);
		struct mbedcrypto_rsa_ctx rsa;

		mbedcrypto_rsa_init(&rsa);
		t0 = get_time_sec();
		mbedcrypto_rsa_keygen(&rsa, test_rng, NULL, rsa_bits[k], 65537);
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.1f ms\n", "Keygen", elapsed * 1000);

		t0 = get_time_sec();
		for (i = 0; i < sign_n[k]; i++)
			mbedcrypto_rsa_sign(&rsa, test_rng, NULL,
				MBEDCRYPTO_RSA_HASH_SHA256, 32, hash, sig);
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.2f ms/op\n", "Sign", elapsed * 1000 / sign_n[k]);

		t0 = get_time_sec();
		for (i = 0; i < verify_n[k]; i++)
			mbedcrypto_rsa_verify(&rsa, MBEDCRYPTO_RSA_HASH_SHA256, 32, hash, sig);
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.3f ms/op\n", "Verify", elapsed * 1000 / verify_n[k]);

		mbedcrypto_rsa_cleanup(&rsa);
	}
}

static void perf_ecdsa(void)
{
	int i = 0;
	size_t c = 0;
	struct {
		int curve;
		const char *name;
		int n;
	} curves[] = {
		{ MBEDCRYPTO_ECP_DP_SECP256R1, "ECDSA P-256", 100 },
		{ MBEDCRYPTO_ECP_DP_SECP384R1, "ECDSA P-384", 50 },
		{ MBEDCRYPTO_ECP_DP_SECP521R1, "ECDSA P-521", 20 },
	};
	uint8_t hash[32], sig[256];
	size_t sig_len;
	double t0, elapsed;

	mbedcrypto_sha256_digest((const uint8_t *)"bench", 5, hash, 0);

	for (c = 0; c < sizeof(curves)/sizeof(curves[0]); c++) {
		printf("\n--- %s Performance ---\n", curves[c].name);
		struct mbedcrypto_ecdsa_ctx ecdsa;
		struct mbedcrypto_ecp_keypair *kp = (struct mbedcrypto_ecp_keypair *)&ecdsa;
		int n = curves[c].n;

		mbedcrypto_ecdsa_init(&ecdsa);
		t0 = get_time_sec();
		mbedcrypto_ecp_keygen(curves[c].curve, kp, test_rng, NULL);
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.1f ms\n", "Keygen", elapsed * 1000);

		t0 = get_time_sec();
		for (i = 0; i < n; i++) {
			sig_len = sizeof(sig);
			mbedcrypto_ecdsa_sign_der(&ecdsa, 0, hash, 32,
				sig, sizeof(sig), &sig_len, test_rng, NULL);
		}
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.2f ms/op\n", "Sign", elapsed * 1000 / n);

		t0 = get_time_sec();
		for (i = 0; i < n; i++)
			mbedcrypto_ecdsa_verify_der(&ecdsa, hash, 32, sig, sig_len);
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.2f ms/op\n", "Verify", elapsed * 1000 / n);

		mbedcrypto_ecdsa_cleanup(&ecdsa);
	}
}

static void perf_sm2dsa(void)
{
	int i = 0;
	printf("\n--- SM2DSA Performance ---\n");
	struct mbedcrypto_sm2dsa_ctx sm2;
	uint8_t hash[32], sig[128];
	size_t sig_len;
	double t0, elapsed;
	int n = 100;

	mbedcrypto_sm2dsa_init(&sm2);
	mbedcrypto_sm2dsa_load_group(&sm2);
	mbedcrypto_ecp_keygen(MBEDCRYPTO_ECP_DP_SM2,
		(struct mbedcrypto_ecp_keypair *)&sm2, test_rng, NULL);
	mbedcrypto_sha256_digest((const uint8_t *)"sm2bench", 8, hash, 0);

	t0 = get_time_sec();
	for (i = 0; i < n; i++) {
		sig_len = sizeof(sig);
		mbedcrypto_sm2dsa_sign(&sm2, hash, 32,
			sig, sizeof(sig), &sig_len, test_rng, NULL);
	}
	elapsed = get_time_sec() - t0;
	printf("  %-16s %.2f ms/op\n", "Sign", elapsed * 1000 / n);

	t0 = get_time_sec();
	for (i = 0; i < n; i++)
		mbedcrypto_sm2dsa_verify(&sm2, hash, 32, sig, sig_len);
	elapsed = get_time_sec() - t0;
	printf("  %-16s %.2f ms/op\n", "Verify", elapsed * 1000 / n);

	mbedcrypto_sm2dsa_cleanup(&sm2);
}

static void perf_sm2kep(void)
{
	int i = 0;
	printf("\n--- SM2KEP Performance ---\n");
	struct mbedcrypto_ecp_keypair init_key, resp_key;
	struct mbedcrypto_ecp_keypair init_eph, resp_eph;
	uint8_t key_out[32], conf_out[32];
	struct mbedcrypto_sm2kep_parms p;
	double t0, elapsed;
	int n = 20;

	mbedcrypto_ecp_keypair_init(&init_key);
	mbedcrypto_ecp_keypair_init(&resp_key);
	mbedcrypto_ecp_keypair_init(&init_eph);
	mbedcrypto_ecp_keypair_init(&resp_eph);

	mbedcrypto_ecp_keygen(MBEDCRYPTO_ECP_DP_SM2,
		&init_key, test_rng, NULL);
	mbedcrypto_ecp_keygen(MBEDCRYPTO_ECP_DP_SM2,
		&resp_key, test_rng, NULL);
	mbedcrypto_ecp_keygen(MBEDCRYPTO_ECP_DP_SM2,
		&init_eph, test_rng, NULL);
	mbedcrypto_ecp_keygen(MBEDCRYPTO_ECP_DP_SM2,
		&resp_eph, test_rng, NULL);

	memset(&p, 0, sizeof(p));
	p.is_initiator = 1;
	p.initiator_id = (const uint8_t *)"1234567812345678";
	p.initiator_id_len = 16;
	p.responder_id = (const uint8_t *)"1234567812345678";
	p.responder_id_len = 16;
	p.out = key_out;
	p.out_len = 32;
	p.conf_out = conf_out;
	p.conf_out_len = sizeof(conf_out);

	t0 = get_time_sec();
	for (i = 0; i < n; i++)
		mbedcrypto_sm2kep_derive(&init_key, &init_eph,
			&resp_key.Q, &resp_eph.Q, &p);
	elapsed = get_time_sec() - t0;
	printf("  %-16s %.2f ms/op\n", "Derive", elapsed * 1000 / n);

	mbedcrypto_ecp_keypair_cleanup(&init_key);
	mbedcrypto_ecp_keypair_cleanup(&resp_key);
	mbedcrypto_ecp_keypair_cleanup(&init_eph);
	mbedcrypto_ecp_keypair_cleanup(&resp_eph);
}

static void perf_dsa(void)
{
	int dsa_bits[] = { 1024, 2048 };
	int dsa_n[] = { 100, 20 };
	uint8_t hash[32], sig[512];
	size_t slen;
	double t0, elapsed;
	int i = 0, k = 0;

	memset(hash, 0x55, 32);

	for (k = 0; k < 2; k++) {
		printf("\n--- DSA-%d Performance ---\n", dsa_bits[k]);
		struct mbedcrypto_dsa_ctx dctx;
		int n = dsa_n[k];

		mbedcrypto_dsa_init(&dctx);
		t0 = get_time_sec();
		mbedcrypto_dsa_gen_params(&dctx, test_rng, NULL, dsa_bits[k]);
		mbedcrypto_dsa_keygen(&dctx, test_rng, NULL);
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.1f ms\n", "Keygen", elapsed * 1000);

		int hlen = (dsa_bits[k] <= 1024) ? 20 : 32;

		t0 = get_time_sec();
		for (i = 0; i < n; i++) {
			slen = sizeof(sig);
			mbedcrypto_dsa_sign(&dctx, test_rng, NULL, hlen, hash, sig, &slen);
		}
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.2f ms/op\n", "Sign", elapsed * 1000 / n);

		t0 = get_time_sec();
		for (i = 0; i < n; i++)
			mbedcrypto_dsa_verify(&dctx, hlen, hash, sig, slen);
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.2f ms/op\n", "Verify", elapsed * 1000 / n);

		mbedcrypto_dsa_cleanup(&dctx);
	}
}

static void perf_keyex(void)
{
	double t0, elapsed;
	int n = 100;
	int c = 0, i = 0, k = 0;

	printf("\n--- Key Exchange Performance ---\n");

#ifdef CONFIG_MBEDCRYPTO_CURVE25519
	/* X25519 */
	{
		uint8_t a_pub[32], a_priv[32], b_pub[32], b_priv[32], secret[32];
		mbedcrypto_x25519_gen_keypair(a_pub, a_priv, test_rng, NULL);
		mbedcrypto_x25519_gen_keypair(b_pub, b_priv, test_rng, NULL);

		t0 = get_time_sec();
		for (i = 0; i < n; i++)
			mbedcrypto_x25519_calc_secret(secret, a_priv, b_pub);
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.2f ms/op\n", "X25519", elapsed * 1000 / n);
	}

	/* Ed25519 sign/verify */
	{
		uint8_t pub[32], priv[64], sig[64];
		uint8_t msg[32];
		memset(msg, 0x42, sizeof(msg));
		mbedcrypto_ed25519_gen_keypair(pub, priv, test_rng, NULL);

		t0 = get_time_sec();
		for (i = 0; i < n; i++)
			mbedcrypto_ed25519_sign(sig, msg, sizeof(msg), priv);
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.2f ms/op\n", "Ed25519 Sign", elapsed * 1000 / n);

		t0 = get_time_sec();
		for (i = 0; i < n; i++)
			mbedcrypto_ed25519_verify(sig, msg, sizeof(msg), pub);
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.2f ms/op\n", "Ed25519 Verify", elapsed * 1000 / n);
	}
#endif

#ifdef CONFIG_MBEDCRYPTO_CURVE448
	/* X448 */
	{
		uint8_t a_pub[56], a_priv[56], b_pub[56], b_priv[56], secret[56];
		mbedcrypto_x448_gen_keypair(a_pub, a_priv, test_rng, NULL);
		mbedcrypto_x448_gen_keypair(b_pub, b_priv, test_rng, NULL);

		t0 = get_time_sec();
		for (i = 0; i < n; i++)
			mbedcrypto_x448_calc_secret(secret, a_priv, b_pub);
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.2f ms/op\n", "X448", elapsed * 1000 / n);
	}

	/* Ed448 sign/verify */
	{
		uint8_t pub[57], priv[114], sig[114];
		uint8_t msg[32];
		memset(msg, 0x42, sizeof(msg));
		mbedcrypto_ed448_gen_keypair(pub, priv, test_rng, NULL);

		t0 = get_time_sec();
		for (i = 0; i < n; i++)
			mbedcrypto_ed448_sign(sig, msg, sizeof(msg), priv);
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.2f ms/op\n", "Ed448 Sign", elapsed * 1000 / n);

		t0 = get_time_sec();
		for (i = 0; i < n; i++)
			mbedcrypto_ed448_verify(sig, msg, sizeof(msg), pub);
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.2f ms/op\n", "Ed448 Verify", elapsed * 1000 / n);
	}
#endif

	/* ECDH P-256 / P-384 */
	{
		int ecdh_curves[] = { MBEDCRYPTO_ECP_DP_SECP256R1, MBEDCRYPTO_ECP_DP_SECP384R1 };
		const char *ecdh_names[] = { "ECDH P-256", "ECDH P-384" };
		int ecdh_n[] = { 100, 50 };

		for (c = 0; c < 2; c++) {
			struct mbedcrypto_ecdh_ctx ectx;
			struct mbedcrypto_ecp_keypair kp_a, kp_b;
			uint8_t secret[66];
			size_t slen;

			mbedcrypto_ecdh_init(&ectx);
			mbedcrypto_ecp_keypair_init(&kp_a);
			mbedcrypto_ecp_keypair_init(&kp_b);
			mbedcrypto_ecp_load_group(&ectx.grp, ecdh_curves[c]);
			mbedcrypto_ecp_keygen(ecdh_curves[c], &kp_a, test_rng, NULL);
			mbedcrypto_ecp_keygen(ecdh_curves[c], &kp_b, test_rng, NULL);
			mbedcrypto_bn_copy(&ectx.d, &kp_a.d);
			mbedcrypto_bn_copy(&ectx.Qp.X, &kp_b.Q.X);
			mbedcrypto_bn_copy(&ectx.Qp.Y, &kp_b.Q.Y);
			mbedcrypto_bn_copy(&ectx.Qp.Z, &kp_b.Q.Z);

			t0 = get_time_sec();
			for (i = 0; i < ecdh_n[c]; i++)
				mbedcrypto_ecdh_derive_shared(&ectx, &slen, secret, sizeof(secret),
					test_rng, NULL);
			elapsed = get_time_sec() - t0;
			printf("  %-16s %.2f ms/op\n", ecdh_names[c], elapsed * 1000 / ecdh_n[c]);

			mbedcrypto_ecp_keypair_cleanup(&kp_a);
			mbedcrypto_ecp_keypair_cleanup(&kp_b);
			mbedcrypto_ecdh_cleanup(&ectx);
		}
	}

#ifdef CONFIG_MBEDCRYPTO_SM2
	/* SM2PKE */
	{
		struct mbedcrypto_sm2pke_ctx pctx;
		uint8_t pt[32], ct[256], dec[32];
		size_t ct_len, dec_len;

		memset(pt, 0x42, sizeof(pt));
		mbedcrypto_sm2pke_init(&pctx);
		mbedcrypto_sm2pke_load_group(&pctx);
		mbedcrypto_ecp_keygen(MBEDCRYPTO_ECP_DP_SM2,
			(struct mbedcrypto_ecp_keypair *)&pctx, test_rng, NULL);

		t0 = get_time_sec();
		for (i = 0; i < n; i++)
			mbedcrypto_sm2pke_encrypt(&pctx, pt, 32, ct, &ct_len,
				test_rng, NULL);
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.2f ms/op\n", "SM2PKE Enc", elapsed * 1000 / n);

		t0 = get_time_sec();
		for (i = 0; i < n; i++)
			mbedcrypto_sm2pke_decrypt(&pctx, ct, ct_len, dec, &dec_len);
		elapsed = get_time_sec() - t0;
		printf("  %-16s %.2f ms/op\n", "SM2PKE Dec", elapsed * 1000 / n);

		mbedcrypto_sm2pke_cleanup(&pctx);
	}
#endif

	/* DH-2048 / DH-3072 */
	{
		const char *dh_primes[] = {
			/* RFC 3526 group 14 (2048-bit) */
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
			"15728E5A8AACAA68FFFFFFFFFFFFFFFF",
			/* RFC 3526 group 15 (3072-bit) */
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
			"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
			"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
			"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
			"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
			"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
			"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
		};
		const char *dh_names[] = { "DH-2048", "DH-3072" };
		int dh_n[] = { 20, 10 };

		for (k = 0; k < 2; k++) {
			struct mbedcrypto_dh_ctx dh_a, dh_b;
			uint8_t pub_a[384], pub_b[384], sa[384];
			size_t sa_len;

			mbedcrypto_dh_init(&dh_a);
			mbedcrypto_dh_init(&dh_b);
			mbedcrypto_bn_from_hex(&dh_a.P, dh_primes[k]);
			mbedcrypto_bn_set_word(&dh_a.G, 2);
			mbedcrypto_bn_copy(&dh_b.P, &dh_a.P);
			mbedcrypto_bn_copy(&dh_b.G, &dh_a.G);

			size_t plen = mbedcrypto_dh_len(&dh_a);
			int nd = dh_n[k];

			printf("\n--- %s Performance ---\n", dh_names[k]);

			/* Keygen (make_public) */
			t0 = get_time_sec();
			for (i = 0; i < nd; i++)
				mbedcrypto_dh_gen_public(&dh_a, plen, pub_a, plen,
					test_rng, NULL);
			elapsed = get_time_sec() - t0;
			printf("  %-16s %.2f ms/op\n", "Keygen", elapsed * 1000 / nd);

			/* Key exchange (calc_secret) */
			mbedcrypto_dh_gen_public(&dh_b, plen, pub_b, plen,
				test_rng, NULL);
			mbedcrypto_bn_from_binary(&dh_a.GY, pub_b, plen);

			t0 = get_time_sec();
			for (i = 0; i < nd; i++)
				mbedcrypto_dh_derive_shared(&dh_a, sa, sizeof(sa),
					&sa_len, test_rng, NULL);
			elapsed = get_time_sec() - t0;
			printf("  %-16s %.2f ms/op\n", "Derive", elapsed * 1000 / nd);

			mbedcrypto_dh_cleanup(&dh_a);
			mbedcrypto_dh_cleanup(&dh_b);
		}
	}
}

static void perf_bignum(void)
{
	int i = 0;
	printf("\n--- Bignum Performance ---\n");
	struct mbedcrypto_bignum A, E, N, X;
	double t0, elapsed;

	mbedcrypto_bn_init(&A);
	mbedcrypto_bn_init(&E);
	mbedcrypto_bn_init(&N);
	mbedcrypto_bn_init(&X);

	mbedcrypto_bn_from_hex(&N,
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA9"
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB43");
	mbedcrypto_bn_from_hex(&A,
		"123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
		"123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
		"123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
		"123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0");
	mbedcrypto_bn_from_hex(&E,
		"FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"
		"FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"
		"FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"
		"FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210");

	int n = 100;
	t0 = get_time_sec();
	for (i = 0; i < n; i++)
		mbedcrypto_bn_modpow(&X, &A, &E, &N, NULL);
	elapsed = get_time_sec() - t0;
	printf("  %-16s %.1f ms/op\n", "exp_mod 2048", elapsed * 1000 / n);

	mbedcrypto_bn_cleanup(&A);
	mbedcrypto_bn_cleanup(&E);
	mbedcrypto_bn_cleanup(&N);
	mbedcrypto_bn_cleanup(&X);
}

int mbedcrypto_test(int perf)
{
	setbuf(stdout, NULL);
	TLOG("----------------------------------------\n");
	TLOG("  mbedcrypto comprehensive test suite\n");
	TLOG("----------------------------------------\n");

	test_md5();
	test_sha1();
	test_sha256();
	test_sha512();
	test_sm3();
	test_sha3();
	test_hash_dispatch();

	test_hmac();
	test_cmac();

	test_aes_ecb();
	test_aes_cbc();
	test_aes_ctr();
	test_aes_cts();
	test_aes_xts();
	test_des();
	test_sm4();

	test_gcm();
	test_ccm();
	test_chacha20();

	test_pbkdf2();
	test_hkdf();

	test_aes_siv();
	test_curve25519();
	test_curve448();

	test_rsa();
	test_ecdsa();
	test_ecdh();
	test_sm2dsa();
	test_sm2pke();
	test_sm2kep();
	test_dh();
	test_dsa();

	test_bignum();
	test_ecp();

	test_cipher_dispatch();
	test_mac_dispatch();

	test_base64();

	test_ct_utils();
	test_asn1();
	test_pkparse();

	test_summary();

	if (perf) {
		/* Performance benchmarks */
		printf("\n---------- PERFORMANCE BENCHMARKS ----------\n");
		perf_hashes();
		perf_mac();
		perf_ciphers();
		perf_aead();
		perf_rsa();
		perf_ecdsa();
		perf_sm2dsa();
		perf_sm2kep();
		perf_dsa();
		perf_keyex();
		perf_bignum();
	}

	return g_test_stats.failed_tests ? 1 : 0;
}
