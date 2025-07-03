// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * GlobalPlatform TEE Crypto Operation APIs
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syslimits.h>

#include <syscall.h>
#include <dirent.h>
#include <utrace.h>
#include <pthread.h>

#include <tee_internal_api.h>
#include <mbedtee_memcmp.h>

#include "tee_api_priv.h"

int tee_prng(void *p_rng, unsigned char *output, size_t len)
{
	if (getentropy(output, len) == 0)
		return 0;

	return errno;
}

static inline int __TEE_Algo2Class(uint32_t algorithm)
{
	/*
	 * Algorithms with class bits that don't match their
	 * actual operation class - handle them explicitly.
	 */
	if (algorithm == TEE_ALG_SM2_PKE)
		return TEE_OPERATION_ASYMMETRIC_CIPHER;
	if (algorithm == TEE_ALG_SM2_KEP)
		return TEE_OPERATION_KEY_DERIVATION;
	if (algorithm == TEE_ALG_CHACHA20_POLY1305)
		return TEE_OPERATION_AE;
	if (algorithm == TEE_ALG_HKDF)
		return TEE_OPERATION_KEY_DERIVATION;
	return (algorithm >> 28) & 0xF;
}

static int __TEE_Algo2Usage(uint32_t algo, uint32_t mode)
{
	int ret = -1;
	int opsClass = __TEE_Algo2Class(algo);

	switch (opsClass) {
	case TEE_OPERATION_CIPHER:
	case TEE_OPERATION_AE:
	case TEE_OPERATION_ASYMMETRIC_CIPHER:
		if (mode == TEE_MODE_ENCRYPT)
			ret = TEE_USAGE_ENCRYPT;
		else if (mode == TEE_MODE_DECRYPT)
			ret = TEE_USAGE_DECRYPT;
		break;

	case TEE_OPERATION_MAC:
		if (mode == TEE_MODE_MAC)
			ret = TEE_USAGE_MAC;
		break;

	case TEE_OPERATION_DIGEST:
		ret = 0;
		break;

	case TEE_OPERATION_ASYMMETRIC_SIGNATURE:
		if (mode == TEE_MODE_VERIFY)
			ret = TEE_USAGE_VERIFY;
		else if (mode == TEE_MODE_SIGN)
			ret = TEE_USAGE_SIGN;
		break;

	case TEE_OPERATION_KEY_DERIVATION:
		if (mode == TEE_MODE_DERIVE)
			ret = TEE_USAGE_DERIVE;
		break;

	default:
		break;
	}

	if (algo == TEE_ALG_RSA_NOPAD) {
		if (mode == TEE_MODE_DECRYPT)
			ret |= TEE_USAGE_SIGN;
		else if (mode == TEE_MODE_ENCRYPT)
			ret |= TEE_USAGE_VERIFY;
	}

	return ret;
}

static inline TEE_Result __TEE_PanicOnEINVAL(int ret, TEE_Result on_einval)
{
	return ret == -EINVAL ? on_einval : TEE_PANIC_CRYPTO_FAILURE;
}

static inline TEE_Result __TEE_AsymRet(TEE_Result ret,
		TEE_Result non_success_ok)
{
	if (ret == TEE_SUCCESS || ret == non_success_ok)
		return ret;

	if (ret == -EINVAL)
		return __TEE_PanicOrReturn(TEE_PANIC_BAD_PARAMETERS);

	if (ret == TEE_PANIC_INVALID_ALG ||
	    ret == TEE_PANIC_BAD_INPUT_LENGTH ||
	    ret == TEE_PANIC_BAD_PARAMETERS)
		return __TEE_PanicOrReturn(ret);

	/* Programmer errors: bad handle, wrong state/class/mode, unsupported key type */
	if (ret == -EBADF || ret == -ENOSR || ret == -ENOTSUP)
		TEE_Panic(ret);

	/* Crypto/hardware failure */
	return __TEE_PanicOrReturn(TEE_PANIC_CRYPTO_FAILURE);
}

/*
 * Sorted lookup table for mapping algorithm ID to object type.
 *
 * priv: type for SIGN/DECRYPT/DERIVE/DIGEST or mode-independent.
 * pub:  type for VERIFY/ENCRYPT. 0 means mode-independent (use priv).
 *
 * Table MUST be sorted by algo in ascending order for binary search.
 */
struct algo_to_type {
	uint32_t algo;
	uint32_t priv;
	uint32_t pub;
};

static const struct algo_to_type __algo2type[] = {
	/* 0x10000010 */ {TEE_ALG_AES_ECB_NOPAD, TEE_TYPE_AES, 0},
	/* 0x10000011 */ {TEE_ALG_DES_ECB_NOPAD, TEE_TYPE_DES, 0},
	/* 0x10000013 */ {TEE_ALG_DES3_ECB_NOPAD, TEE_TYPE_DES3, 0},
	/* 0x10000014 */ {TEE_ALG_SM4_ECB_NOPAD, TEE_TYPE_SM4, 0},
	/* 0x10000015 */ {TEE_ALG_SM4_ECB_PKCS5, TEE_TYPE_SM4, 0},
	/* 0x10000016 */ {TEE_ALG_CHACHA20, TEE_TYPE_CHACHA20, 0},
	/* 0x10000017 */ {TEE_ALG_CHACHA20_POLY1305, TEE_TYPE_CHACHA20, 0},
	/* 0x10000110 */ {TEE_ALG_AES_CBC_NOPAD, TEE_TYPE_AES, 0},
	/* 0x10000111 */ {TEE_ALG_DES_CBC_NOPAD, TEE_TYPE_DES, 0},
	/* 0x10000112 */ {TEE_ALG_AES_CBC_PKCS5, TEE_TYPE_AES, 0},
	/* 0x10000113 */ {TEE_ALG_DES3_CBC_NOPAD, TEE_TYPE_DES3, 0},
	/* 0x10000114 */ {TEE_ALG_SM4_CBC_NOPAD, TEE_TYPE_SM4, 0},
	/* 0x10000115 */ {TEE_ALG_SM4_CBC_PKCS5, TEE_TYPE_SM4, 0},
	/* 0x10000118 */ {TEE_ALG_DES_CBC_PKCS5, TEE_TYPE_DES, 0},
	/* 0x10000119 */ {TEE_ALG_DES3_CBC_PKCS5, TEE_TYPE_DES3, 0},
	/* 0x10000210 */ {TEE_ALG_AES_CTR, TEE_TYPE_AES, 0},
	/* 0x10000214 */ {TEE_ALG_SM4_CTR, TEE_TYPE_SM4, 0},
	/* 0x10000310 */ {TEE_ALG_AES_CTS, TEE_TYPE_AES, 0},
	/* 0x10000410 */ {TEE_ALG_AES_XTS, TEE_TYPE_AES, 0},

	/* 0x30000001 */ {TEE_ALG_HMAC_MD5, TEE_TYPE_HMAC_MD5, 0},
	/* 0x30000002 */ {TEE_ALG_HMAC_SHA1, TEE_TYPE_HMAC_SHA1, 0},
	/* 0x30000003 */ {TEE_ALG_HMAC_SHA224, TEE_TYPE_HMAC_SHA224, 0},
	/* 0x30000004 */ {TEE_ALG_HMAC_SHA256, TEE_TYPE_HMAC_SHA256, 0},
	/* 0x30000005 */ {TEE_ALG_HMAC_SHA384, TEE_TYPE_HMAC_SHA384, 0},
	/* 0x30000006 */ {TEE_ALG_HMAC_SHA512, TEE_TYPE_HMAC_SHA512, 0},
	/* 0x30000007 */ {TEE_ALG_HMAC_SM3, TEE_TYPE_HMAC_SM3, 0},
	/* 0x30000008 */ {TEE_ALG_HMAC_SHA3_224, TEE_TYPE_HMAC_SHA3_224, 0},
	/* 0x30000009 */ {TEE_ALG_HMAC_SHA3_256, TEE_TYPE_HMAC_SHA3_256, 0},
	/* 0x3000000A */ {TEE_ALG_HMAC_SHA3_384, TEE_TYPE_HMAC_SHA3_384, 0},
	/* 0x3000000B */ {TEE_ALG_HMAC_SHA3_512, TEE_TYPE_HMAC_SHA3_512, 0},
	/* 0x30000020 */ {TEE_ALG_POLY1305, TEE_TYPE_POLY1305, 0},
	/* 0x30000110 */ {TEE_ALG_AES_CBC_MAC_NOPAD, TEE_TYPE_AES, 0},
	/* 0x30000111 */ {TEE_ALG_DES_CBC_MAC_NOPAD, TEE_TYPE_DES, 0},
	/* 0x30000113 */ {TEE_ALG_DES3_CBC_MAC_NOPAD, TEE_TYPE_DES3, 0},
	/* 0x30000510 */ {TEE_ALG_AES_CBC_MAC_PKCS5, TEE_TYPE_AES, 0},
	/* 0x30000511 */ {TEE_ALG_DES_CBC_MAC_PKCS5, TEE_TYPE_DES, 0},
	/* 0x30000513 */ {TEE_ALG_DES3_CBC_MAC_PKCS5, TEE_TYPE_DES3, 0},
	/* 0x30000610 */ {TEE_ALG_AES_CMAC, TEE_TYPE_AES, 0},

	/* 0x40000710 */ {TEE_ALG_AES_CCM, TEE_TYPE_AES, 0},
	/* 0x40000714 */ {TEE_ALG_SM4_CCM, TEE_TYPE_SM4, 0},
	/* 0x40000810 */ {TEE_ALG_AES_GCM, TEE_TYPE_AES, 0},
	/* 0x40000814 */ {TEE_ALG_SM4_GCM, TEE_TYPE_SM4, 0},

	/* 0x50000001 */ {TEE_ALG_MD5, TEE_TYPE_DATA, TEE_TYPE_ILLEGAL_VALUE},
	/* 0x50000002 */ {TEE_ALG_SHA1, TEE_TYPE_DATA, TEE_TYPE_ILLEGAL_VALUE},
	/* 0x50000003 */ {TEE_ALG_SHA224, TEE_TYPE_DATA, TEE_TYPE_ILLEGAL_VALUE},
	/* 0x50000004 */ {TEE_ALG_SHA256, TEE_TYPE_DATA, TEE_TYPE_ILLEGAL_VALUE},
	/* 0x50000005 */ {TEE_ALG_SHA384, TEE_TYPE_DATA, TEE_TYPE_ILLEGAL_VALUE},
	/* 0x50000006 */ {TEE_ALG_SHA512, TEE_TYPE_DATA, TEE_TYPE_ILLEGAL_VALUE},
	/* 0x50000007 */ {TEE_ALG_SM3, TEE_TYPE_DATA, TEE_TYPE_ILLEGAL_VALUE},
	/* 0x50000008 */ {TEE_ALG_SHA3_224, TEE_TYPE_DATA, TEE_TYPE_ILLEGAL_VALUE},
	/* 0x50000009 */ {TEE_ALG_SHA3_256, TEE_TYPE_DATA, TEE_TYPE_ILLEGAL_VALUE},
	/* 0x5000000A */ {TEE_ALG_SHA3_384, TEE_TYPE_DATA, TEE_TYPE_ILLEGAL_VALUE},
	/* 0x5000000B */ {TEE_ALG_SHA3_512, TEE_TYPE_DATA, TEE_TYPE_ILLEGAL_VALUE},
	/* 0x5000000C */ {TEE_ALG_SHA256_192, TEE_TYPE_DATA, TEE_TYPE_ILLEGAL_VALUE},

	/* 0x60000030 */ {TEE_ALG_RSA_NOPAD, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x60000045 */ {TEE_ALG_SM2_KEP, TEE_TYPE_SM2_KEP_KEYPAIR, TEE_TYPE_ILLEGAL_VALUE},
	/* 0x60000130 */ {TEE_ALG_RSAES_PKCS1_V1_5, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x60210230 */ {TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x60310230 */ {TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x60410230 */ {TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x60510230 */ {TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x60610230 */ {TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x60810230 */ {TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_224, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x60910230 */ {TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_256, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x60A10230 */ {TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_384, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x60B10230 */ {TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_512, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},

	/* 0x70001042 */ {TEE_ALG_ECDSA_SHA1, TEE_TYPE_ECDSA_KEYPAIR, TEE_TYPE_ECDSA_PUBLIC_KEY},
	/* 0x70001830 */ {TEE_ALG_RSASSA_PKCS1_V1_5_MD5, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x70002042 */ {TEE_ALG_ECDSA_SHA224, TEE_TYPE_ECDSA_KEYPAIR, TEE_TYPE_ECDSA_PUBLIC_KEY},
	/* 0x70002131 */ {TEE_ALG_DSA_SHA1, TEE_TYPE_DSA_KEYPAIR, TEE_TYPE_DSA_PUBLIC_KEY},
	/* 0x70002830 */ {TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x70003042 */ {TEE_ALG_ECDSA_SHA256, TEE_TYPE_ECDSA_KEYPAIR, TEE_TYPE_ECDSA_PUBLIC_KEY},
	/* 0x70003131 */ {TEE_ALG_DSA_SHA224, TEE_TYPE_DSA_KEYPAIR, TEE_TYPE_DSA_PUBLIC_KEY},
	/* 0x70003830 */ {TEE_ALG_RSASSA_PKCS1_V1_5_SHA224, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x70004042 */ {TEE_ALG_ECDSA_SHA384, TEE_TYPE_ECDSA_KEYPAIR, TEE_TYPE_ECDSA_PUBLIC_KEY},
	/* 0x70004131 */ {TEE_ALG_DSA_SHA256, TEE_TYPE_DSA_KEYPAIR, TEE_TYPE_DSA_PUBLIC_KEY},
	/* 0x70004830 */ {TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x70005042 */ {TEE_ALG_ECDSA_SHA512, TEE_TYPE_ECDSA_KEYPAIR, TEE_TYPE_ECDSA_PUBLIC_KEY},
	/* 0x70005830 */ {TEE_ALG_RSASSA_PKCS1_V1_5_SHA384, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x70006042 */ {TEE_ALG_ECDSA_SHA3_224, TEE_TYPE_ECDSA_KEYPAIR, TEE_TYPE_ECDSA_PUBLIC_KEY},
	/* 0x70006043 */ {TEE_ALG_ED25519, TEE_TYPE_ED25519_KEYPAIR, TEE_TYPE_ED25519_PUBLIC_KEY},
	/* 0x70006044 */ {TEE_ALG_ED448, TEE_TYPE_ED448_KEYPAIR, TEE_TYPE_ED448_PUBLIC_KEY},
	/* 0x70006045 */ {TEE_ALG_SM2_DSA_SM3, TEE_TYPE_SM2_DSA_KEYPAIR, TEE_TYPE_SM2_DSA_PUBLIC_KEY},
	/* 0x70006830 */ {TEE_ALG_RSASSA_PKCS1_V1_5_SHA512, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x70007042 */ {TEE_ALG_ECDSA_SHA3_256, TEE_TYPE_ECDSA_KEYPAIR, TEE_TYPE_ECDSA_PUBLIC_KEY},
	/* 0x70008042 */ {TEE_ALG_ECDSA_SHA3_384, TEE_TYPE_ECDSA_KEYPAIR, TEE_TYPE_ECDSA_PUBLIC_KEY},
	/* 0x70008131 */ {TEE_ALG_DSA_SHA3_224, TEE_TYPE_DSA_KEYPAIR, TEE_TYPE_DSA_PUBLIC_KEY},
	/* 0x70008830 */ {TEE_ALG_RSASSA_PKCS1_V1_5_SHA3_224, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x70009042 */ {TEE_ALG_ECDSA_SHA3_512, TEE_TYPE_ECDSA_KEYPAIR, TEE_TYPE_ECDSA_PUBLIC_KEY},
	/* 0x70009131 */ {TEE_ALG_DSA_SHA3_256, TEE_TYPE_DSA_KEYPAIR, TEE_TYPE_DSA_PUBLIC_KEY},
	/* 0x70009830 */ {TEE_ALG_RSASSA_PKCS1_V1_5_SHA3_256, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x7000A131 */ {TEE_ALG_DSA_SHA3_384, TEE_TYPE_DSA_KEYPAIR, TEE_TYPE_DSA_PUBLIC_KEY},
	/* 0x7000A830 */ {TEE_ALG_RSASSA_PKCS1_V1_5_SHA3_384, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x7000B131 */ {TEE_ALG_DSA_SHA3_512, TEE_TYPE_DSA_KEYPAIR, TEE_TYPE_DSA_PUBLIC_KEY},
	/* 0x7000B830 */ {TEE_ALG_RSASSA_PKCS1_V1_5_SHA3_512, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x70212930 */ {TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x70313930 */ {TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x70414930 */ {TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x70515930 */ {TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x70616930 */ {TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x70818930 */ {TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_224, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x70919930 */ {TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_256, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x70A1A930 */ {TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_384, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},
	/* 0x70B1B930 */ {TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_512, TEE_TYPE_RSA_KEYPAIR, TEE_TYPE_RSA_PUBLIC_KEY},

	/* 0x80000032 */ {TEE_ALG_DH_DERIVE_SHARED_SECRET, TEE_TYPE_DH_KEYPAIR, TEE_TYPE_ILLEGAL_VALUE},
	/* 0x80000042 */ {TEE_ALG_ECDH_DERIVE_SHARED_SECRET, TEE_TYPE_ECDH_KEYPAIR, TEE_TYPE_ILLEGAL_VALUE},
	/* 0x80000044 */ {TEE_ALG_X25519, TEE_TYPE_X25519_KEYPAIR, TEE_TYPE_ILLEGAL_VALUE},
	/* 0x80000045 */ {TEE_ALG_X448, TEE_TYPE_X448_KEYPAIR, TEE_TYPE_ILLEGAL_VALUE},
	/* 0x80000046 */ {TEE_ALG_SM2_PKE, TEE_TYPE_SM2_PKE_KEYPAIR, TEE_TYPE_SM2_PKE_PUBLIC_KEY},
	/* 0x80000047 */ {TEE_ALG_HKDF, TEE_TYPE_HKDF, TEE_TYPE_ILLEGAL_VALUE},
};

#define NR_ALGO2TYPE (sizeof(__algo2type) / sizeof(__algo2type[0]))

static const struct algo_to_type *algo2type_find(uint32_t algo)
{
	int lo = 0, hi = NR_ALGO2TYPE - 1;

	while (lo <= hi) {
		int mid = (lo + hi) / 2;

		if (__algo2type[mid].algo < algo)
			lo = mid + 1;
		else if (__algo2type[mid].algo > algo)
			hi = mid - 1;
		else
			return &__algo2type[mid];
	}
	return NULL;
}

static int __TEE_Algo2Type(uint32_t algo, uint32_t mode)
{
	const struct algo_to_type *e = algo2type_find(algo);

	if (!e)
		return TEE_TYPE_ILLEGAL_VALUE;

	/* Mode-independent (symmetric cipher, MAC, AEAD) */
	if (e->pub == 0)
		return e->priv;

	/* Digest: only valid for TEE_MODE_DIGEST */
	if (e->priv == TEE_TYPE_DATA)
		return (mode == TEE_MODE_DIGEST) ?
			TEE_TYPE_DATA : TEE_TYPE_ILLEGAL_VALUE;

	/* Mode-dependent asymmetric / key derivation */
	switch (mode) {
	case TEE_MODE_SIGN:
	case TEE_MODE_DECRYPT:
	case TEE_MODE_DERIVE:
		return e->priv;
	case TEE_MODE_VERIFY:
	case TEE_MODE_ENCRYPT:
		return e->pub;
	default:
		return TEE_TYPE_ILLEGAL_VALUE;
	}
}

static int __TEE_MbedDigestOf(uint32_t algorithm)
{
	int type = MBEDCRYPTO_HASH_NONE;

	switch (algorithm) {
	case TEE_ALG_MD5:
		type = MBEDCRYPTO_HASH_MD5;
		break;
	case TEE_ALG_SHA1:
		type = MBEDCRYPTO_HASH_SHA1;
		break;
	case TEE_ALG_SHA224:
		type = MBEDCRYPTO_HASH_SHA224;
		break;
	case TEE_ALG_SHA256:
		type = MBEDCRYPTO_HASH_SHA256;
		break;
	case TEE_ALG_SHA384:
		type = MBEDCRYPTO_HASH_SHA384;
		break;
	case TEE_ALG_SHA512:
		type = MBEDCRYPTO_HASH_SHA512;
		break;
	case TEE_ALG_SM3:
		type = MBEDCRYPTO_HASH_SM3;
		break;
	case TEE_ALG_SHA3_224:
		type = MBEDCRYPTO_HASH_SHA3_224;
		break;
	case TEE_ALG_SHA3_256:
		type = MBEDCRYPTO_HASH_SHA3_256;
		break;
	case TEE_ALG_SHA3_384:
		type = MBEDCRYPTO_HASH_SHA3_384;
		break;
	case TEE_ALG_SHA3_512:
		type = MBEDCRYPTO_HASH_SHA3_512;
		break;
	case TEE_ALG_SHA256_192:
		type = MBEDCRYPTO_HASH_SHA256;
		break;
	default:
		break;
	}

	return type;
}

static int __TEE_MbedDigestInit(
	struct tee_operation *ops, int md_type)
{
	int ret = -1;

	/* re-start the digest state */
	if (ops->ctx)
		return mbedcrypto_hash_init(ops->ctx, md_type);

	ops->ctx = TEE_Malloc(sizeof(struct mbedcrypto_hash_ctx),
				  TEE_MALLOC_NO_FILL | TEE_MALLOC_NO_SHARE);
	if (!ops->ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	ops->info.digestLength = mbedcrypto_hash_size(md_type);
	if (ops->info.digestLength == 0) {
		ret = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	ret = mbedcrypto_hash_init(ops->ctx, md_type);
	if (ret != 0) {
		if (ret == -ENOMEM)
			ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	return 0;
out:
	TEE_Free(ops->ctx);
	ops->ctx = NULL;
	return ret;
}

static int __TEE_DigestInit(struct tee_operation *ops)
{
	int type = __TEE_MbedDigestOf(ops->info.algorithm);
	int ret;

	if (type == MBEDCRYPTO_HASH_NONE)
		return TEE_ERROR_NOT_SUPPORTED;

	ret = __TEE_MbedDigestInit(ops, type);
	if (ret != 0)
		return ret;

	/* SHA-256/192 uses SHA-256 internally but truncates to 24 bytes */
	if (ops->info.algorithm == TEE_ALG_SHA256_192)
		ops->info.digestLength = 24;

	return 0;
}

static void __TEE_DigestExtractClear(struct tee_operation *ops)
{
	ops->info.handleState &= ~TEE_HANDLE_FLAG_EXTRACTING;
	ops->digest_extract_len = 0;
	ops->digest_extract_offs = 0;
	TEE_MemFill(ops->digest_extract_buf, 0, sizeof(ops->digest_extract_buf));
}

TEE_Result TEE_AllocateOperation(
	TEE_OperationHandle *operation,
	uint32_t algorithm, uint32_t mode,
	uint32_t maxKeySize)
{
	TEE_Result ret = TEE_ERROR_OUT_OF_MEMORY;
	int type = -1, usage = -1, opsclass = -1;
	struct tee_operation *ops = NULL;
	const struct object_attr *t = NULL;

	/* assumptive objectType */
	type = __TEE_Algo2Type(algorithm, mode);
	t = object_attr_of(type);
	if (!t)
		return TEE_ERROR_NOT_SUPPORTED;

	opsclass = __TEE_Algo2Class(algorithm);

	usage = __TEE_Algo2Usage(algorithm, mode);
	if (usage < 0)
		return TEE_ERROR_NOT_SUPPORTED;

	if ((maxKeySize < t->min_size) ||
		(maxKeySize > t->max_size) ||
		(maxKeySize % t->quantum))
		return TEE_ERROR_NOT_SUPPORTED;

	object_lock();
	ops = object_alloc(sizeof(struct tee_operation));
	if (ops) {
		ops->info.mode = mode;
		ops->info.algorithm = algorithm;
		ops->info.requiredKeyUsage = usage;
		ops->info.operationClass = opsclass;
		ops->info.maxKeySize = maxKeySize;
		ops->operationState = TEE_OPERATION_STATE_INITIAL;
		ops->objectType = type;
		__TEE_DigestExtractClear(ops);

		if (mode == TEE_MODE_DIGEST) {
			ret = __TEE_DigestInit(ops);
			if (ret != 0)
				goto out;
			ops->info.handleState |= TEE_HANDLE_FLAG_KEY_SET | TEE_HANDLE_FLAG_INITIALIZED;
		}

		if ((algorithm == TEE_ALG_AES_XTS) || (algorithm == TEE_ALG_SM2_KEP))
			ops->info.handleState |= TEE_HANDLE_FLAG_EXPECT_TWO_KEYS;

		*operation = (TEE_OperationHandle)ops->tag.idx;
		ret = TEE_SUCCESS;
	}

out:
	if (ret != TEE_SUCCESS)
		object_free(ops);
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_NOT_SUPPORTED &&
		ret != TEE_ERROR_OUT_OF_MEMORY)
		TEE_Panic(ret);
	return ret;
}

/*
 * Map TEE AE algorithm to mbedcrypto AEAD identifier.
 */
static int __TEE_Algo2AeadId(uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_AES_GCM:
		return MBEDCRYPTO_AEAD_AES_GCM;
	case TEE_ALG_AES_CCM:
		return MBEDCRYPTO_AEAD_AES_CCM;
	case TEE_ALG_SM4_GCM:
		return MBEDCRYPTO_AEAD_SM4_GCM;
	case TEE_ALG_SM4_CCM:
		return MBEDCRYPTO_AEAD_SM4_CCM;
	case TEE_ALG_CHACHA20_POLY1305:
		return MBEDCRYPTO_AEAD_CHACHA20_POLY1305;
	default:
		return -1;
	}
}

static inline int __TEE_IsCCM(uint32_t algo)
{
	return algo == TEE_ALG_AES_CCM || algo == TEE_ALG_SM4_CCM;
}

/*
 * Helper to identify HMAC algorithms.
 */
static inline int __TEE_IsHMAC(uint32_t algorithm)
{
	switch (algorithm) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
	case TEE_ALG_HMAC_SM3:
	case TEE_ALG_HMAC_SHA3_224:
	case TEE_ALG_HMAC_SHA3_256:
	case TEE_ALG_HMAC_SHA3_384:
	case TEE_ALG_HMAC_SHA3_512:
		return 1;
	default:
		return 0;
	}
}

void TEE_FreeOperation(TEE_OperationHandle operation)
{
	struct tee_operation *ops = NULL;

	if (operation == TEE_HANDLE_NULL)
		return;

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		object_unlock();
		TEE_Panic(EBADF);
	}

	TEE_FreeTransientObject(ops->key);
	TEE_FreeTransientObject(ops->key2);

	/* Free internal resources before freeing the context struct */
	if (ops->ctx) {
		switch (ops->info.operationClass) {
		case TEE_OPERATION_DIGEST:
			mbedcrypto_hash_cleanup(ops->ctx);
			break;
		case TEE_OPERATION_CIPHER:
			mbedcrypto_cipher_cleanup(ops->ctx);
			break;
		case TEE_OPERATION_MAC:
			if (__TEE_IsHMAC(ops->info.algorithm))
				mbedcrypto_hmac_cleanup(ops->ctx);
			else if (ops->info.algorithm == TEE_ALG_POLY1305)
				mbedcrypto_poly1305_cleanup(ops->ctx);
			else
				mbedcrypto_mac_cleanup(ops->ctx);
			break;
		case TEE_OPERATION_AE:
			mbedcrypto_aead_cleanup(ops->ctx);
			break;
		default:
			break;
		}
		TEE_Free(ops->ctx);
	}
	__TEE_DigestExtractClear(ops);
	object_free(ops);

	object_unlock();
}

void TEE_GetOperationInfo(
	TEE_OperationHandle operation,
	TEE_OperationInfo *operationInfo)
{
	struct tee_operation *ops = NULL;

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		object_unlock();
		TEE_Panic(EBADF);
	}

	memcpy(operationInfo, &ops->info,
		sizeof(TEE_OperationInfo));

	if (ops->info.handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS) {
		operationInfo->keySize = 0;
		operationInfo->requiredKeyUsage = 0;
	}

	object_unlock();
}

TEE_Result TEE_GetOperationInfoMultiple(
	TEE_OperationHandle operation,
	TEE_OperationInfoMultiple *operationInfoMultiple,
	size_t *operationSize)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint32_t nkeys = 0, expected = 1, i = 0;
	struct tee_object *obj = NULL;
	struct tee_operation *ops = NULL;

	if ((operation == TEE_HANDLE_NULL) ||
		(!operationInfoMultiple) ||
		(!operationSize)) {
		ret = -EINVAL;
		goto out;
	}

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if (*operationSize < sizeof(TEE_OperationInfoMultiple)) {
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	nkeys = (*operationSize - sizeof(TEE_OperationInfoMultiple)) /
			sizeof(TEE_OperationInfoKey);

	TEE_MemFill(operationInfoMultiple, 0, *operationSize);

	for (i = 0; i < nkeys; i++) {
		operationInfoMultiple->keyInformation[i].keySize = 0;
		operationInfoMultiple->keyInformation[i].requiredKeyUsage = 0;
	}

	LMSG("operationSize %d, ops->key %p ops->key2 %p\n", *operationSize, ops->key, ops->key2);

	if (ops->info.mode == TEE_MODE_DIGEST)
		expected = 0;
	else if (ops->info.handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS)
		expected = 2;

	if (expected > nkeys) {
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	if (expected > 0) {
		obj = object_of(ops->key);
		if (obj) {
			operationInfoMultiple->keyInformation[0].keySize =
				obj->info.objectSize;
		}
		operationInfoMultiple->keyInformation[0].requiredKeyUsage =
				ops->info.requiredKeyUsage;

		if (expected > 1) {
			obj = object_of(ops->key2);
			if (obj) {
				operationInfoMultiple->keyInformation[1].keySize =
						obj->info.objectSize;
			}
			operationInfoMultiple->keyInformation[1].requiredKeyUsage =
						ops->info.requiredKeyUsage;
		}
	}

	operationInfoMultiple->numberOfKeys = expected;

	operationInfoMultiple->algorithm = ops->info.algorithm;
	operationInfoMultiple->operationClass = ops->info.operationClass;
	operationInfoMultiple->mode = ops->info.mode;
	operationInfoMultiple->digestLength = ops->info.digestLength;
	operationInfoMultiple->maxKeySize = ops->info.maxKeySize;
	operationInfoMultiple->handleState = ops->info.handleState;
	operationInfoMultiple->operationState = ops->operationState;

	ret = TEE_SUCCESS;

out:
	object_unlock();
	if ((ret != TEE_SUCCESS) &&
		(ret != TEE_ERROR_SHORT_BUFFER))
		TEE_Panic(ret);
	return ret;
}

static TEE_Result __TEE_ResetOperation(TEE_OperationHandle operation)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if (ops->info.mode != TEE_MODE_DIGEST &&
	    !(ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		ret = -EINVAL;
		goto out;
	}

	ops->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
	ops->operationState = TEE_OPERATION_STATE_INITIAL;

	if (ops->info.mode == TEE_MODE_DIGEST) {
		__TEE_DigestExtractClear(ops);
		/* re-start the digest state */
		mbedcrypto_hash_init(ops->ctx, ((struct mbedcrypto_hash_ctx *)ops->ctx)->algo);
		ops->info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
	} else if (ops->info.operationClass == TEE_OPERATION_AE && ops->ctx) {
		mbedcrypto_aead_cleanup(ops->ctx);
		TEE_Free(ops->ctx);
		ops->ctx = NULL;
	}

	ret = TEE_SUCCESS;

out:
	object_unlock();
	return ret;
}

void TEE_ResetOperation(TEE_OperationHandle operation)
{
	TEE_Result ret = __TEE_ResetOperation(operation);

	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

TEE_Result TEE_ResetOperation_PS(TEE_OperationHandle operation)
{
	TEE_Result ret = __TEE_ResetOperation(operation);

	/* All current error paths in __TEE_ResetOperation are programmer errors. */
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);

	return TEE_SUCCESS;
}

TEE_Result TEE_SetOperationKey(
	TEE_OperationHandle operation,
	TEE_ObjectHandle key)
{
	int ret = TEE_ERROR_GENERIC;
	TEE_Result panic_code = 0; /* 0 = programmer error: always panic */
	struct tee_object *obj = NULL;
	struct tee_operation *ops = NULL;
	uint32_t usage = 0;

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->operationState != TEE_OPERATION_STATE_INITIAL) ||
		(ops->info.handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS) ||
		(ops->info.mode == TEE_MODE_DIGEST)) {
		ret = -EINVAL;
		goto out;
	}

	if (key == TEE_HANDLE_NULL) {
		TEE_ResetTransientObject(ops->key);
		ops->key = TEE_HANDLE_NULL;
		ops->info.keySize = 0;
		ops->info.handleState &= ~TEE_HANDLE_FLAG_KEY_SET;
		object_unlock();
		return TEE_SUCCESS;
	}

	obj = object_of(key);
	if (!obj) {
		ret = -ENOSR;
		goto out;
	}

	if (!(obj->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		ret = -EINVAL;
		goto out;
	}

	usage = ops->info.requiredKeyUsage;

	LMSG("maxKeySize %u objectSize %u\n",
		ops->info.maxKeySize, obj->info.objectSize);
	LMSG("requsage %x objectUsage %x\n",
		usage, obj->info.objectUsage);

	/*
	 * Split key compatibility checks so each maps to the correct
	 * TEE_PANIC_xxxx code (GP v1.4 Sec. 5.3, TEE_SetOperationKey table).
	 */
	if ((obj->info.objectType | TEE_TYPE_PRIVATE_KEY_FLAG) !=
		(ops->objectType | TEE_TYPE_PRIVATE_KEY_FLAG)) {
		/* Key type not compatible with algorithm */
		ret = panic_code = TEE_PANIC_INVALID_ALG;
		goto out;
	}

	if (ops->info.maxKeySize < obj->info.objectSize) {
		/* Key size not compatible with operation size */
		ret = panic_code = TEE_PANIC_INVALID_SIZE;
		goto out;
	}

	if ((obj->info.objectUsage & usage) != usage) {
		/* Key usage not compatible with the operation mode */
		ret = panic_code = TEE_PANIC_INVALID_MODE;
		goto out;
	}

	if (ops->key != TEE_HANDLE_NULL) {
		TEE_ResetTransientObject(ops->key);
		ops->info.handleState &= ~TEE_HANDLE_FLAG_KEY_SET;
	} else {
		ret = TEE_AllocateTransientObject(obj->info.objectType,
			ops->info.maxKeySize, &ops->key);
		if (ret != TEE_SUCCESS)
			goto out;
	}
	ret = TEE_CopyObjectAttributes1(ops->key, key);
	if (ret != TEE_SUCCESS) {
		/* Software crypto/object-copy failure during key copy */
		ret = panic_code = TEE_PANIC_CRYPTO_FAILURE;
		goto out;
	}

	ops->info.keySize = obj->info.objectSize;
	ops->info.handleState |= TEE_HANDLE_FLAG_KEY_SET;

out:
	object_unlock();
	if (ret == TEE_SUCCESS ||
		ret == TEE_ERROR_CORRUPT_OBJECT ||
		ret == TEE_ERROR_STORAGE_NOT_AVAILABLE)
		return ret;
	return __TEE_PanicOrDie(ret, panic_code);
}

TEE_Result TEE_SetOperationKey2(
	TEE_OperationHandle operation,
	TEE_ObjectHandle key1,
	TEE_ObjectHandle key2)
{
	int ret = TEE_ERROR_GENERIC;
	TEE_Result panic_code = 0; /* 0 = programmer error: always panic */
	struct tee_object *obj1 = NULL, *obj2 = NULL;
	struct tee_operation *ops = NULL;
	uint32_t usage = 0;

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->operationState != TEE_OPERATION_STATE_INITIAL) ||
		!(ops->info.handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS)) {
		ret = -EINVAL;
		goto out;
	}

	if ((key1 == TEE_HANDLE_NULL) &&
		(key2 == TEE_HANDLE_NULL)) {
		TEE_ResetTransientObject(ops->key);
		TEE_ResetTransientObject(ops->key2);
		ops->key = TEE_HANDLE_NULL;
		ops->key2 = TEE_HANDLE_NULL;
		ops->info.keySize = 0;
		ops->info.handleState &= ~TEE_HANDLE_FLAG_KEY_SET;
		object_unlock();
		return TEE_SUCCESS;
	} else if ((key1 == TEE_HANDLE_NULL)
			|| (key2 == TEE_HANDLE_NULL)) {
		ret = -ENOSR;
		goto out;
	} else if (key1 == key2) {
		ret = TEE_ERROR_SECURITY;
		goto out;
	}

	obj1 = object_of(key1);
	obj2 = object_of(key2);
	if ((!obj1) || (!obj2)) {
		ret = -ENOSR;
		goto out;
	}

	if (!(obj1->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) ||
		!(obj2->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		ret = -EINVAL;
		goto out;
	}

	if (obj1->info.objectSize != obj2->info.objectSize) {
		/* Keys have different sizes - not compatible */
		ret = panic_code = TEE_PANIC_INVALID_SIZE_2;
		goto out;
	}

	if (obj1->info.objectType != obj2->info.objectType) {
		/* Keys have different types - algorithm mismatch */
		ret = panic_code = TEE_PANIC_INVALID_ALG_2;
		goto out;
	}

	usage = ops->info.requiredKeyUsage;

	/*
	 * Split key compatibility checks so each maps to the correct
	 * TEE_PANIC_xxxx code (GP v1.4 Sec. 5.3, TEE_SetOperationKey2 table).
	 */
	if (ops->objectType != obj1->info.objectType) {
		/* Key type not compatible with algorithm */
		ret = panic_code = TEE_PANIC_INVALID_ALG;
		goto out;
	}

	if (ops->info.maxKeySize < obj1->info.objectSize) {
		/* Key size not compatible with operation size */
		ret = panic_code = TEE_PANIC_INVALID_SIZE;
		goto out;
	}

	if ((obj1->info.objectUsage & usage) != usage) {
		/* Key1 usage not compatible with the operation mode */
		ret = panic_code = TEE_PANIC_INVALID_MODE;
		goto out;
	}

	if ((obj2->info.objectUsage & usage) != usage) {
		/* Key2 usage not compatible with the operation mode */
		ret = panic_code = TEE_PANIC_INVALID_MODE_2;
		goto out;
	}

	TEE_ResetTransientObject(ops->key);
	TEE_ResetTransientObject(ops->key2);
	ops->info.handleState &= ~TEE_HANDLE_FLAG_KEY_SET;

	if (ops->key == TEE_HANDLE_NULL) {
		ret = TEE_AllocateTransientObject(obj1->info.objectType,
			ops->info.maxKeySize, &ops->key);
		if (ret != TEE_SUCCESS)
			goto out;
	}

	if (ops->key2 == TEE_HANDLE_NULL) {
		ret = TEE_AllocateTransientObject(obj2->info.objectType,
			ops->info.maxKeySize, &ops->key2);
		if (ret != TEE_SUCCESS)
			goto out;
	}

	ret = TEE_CopyObjectAttributes1(ops->key, key1);
	if (ret != TEE_SUCCESS) {
		/* Software crypto/object-copy failure during key copy */
		ret = panic_code = TEE_PANIC_CRYPTO_FAILURE;
		goto out;
	}
	ret = TEE_CopyObjectAttributes1(ops->key2, key2);
	if (ret != TEE_SUCCESS) {
		/* Software crypto/object-copy failure during key copy */
		ret = panic_code = TEE_PANIC_CRYPTO_FAILURE;
		goto out;
	}

	ops->info.handleState |= TEE_HANDLE_FLAG_KEY_SET;
	ops->info.keySize = obj1->info.objectSize;

out:
	object_unlock();
	if (ret == TEE_SUCCESS ||
		ret == TEE_ERROR_SECURITY ||
		ret == TEE_ERROR_CORRUPT_OBJECT ||
		ret == TEE_ERROR_CORRUPT_OBJECT_2 ||
		ret == TEE_ERROR_STORAGE_NOT_AVAILABLE ||
		ret == TEE_ERROR_STORAGE_NOT_AVAILABLE_2)
		return ret;
	return __TEE_PanicOrDie(ret, panic_code);
}

static int __TEE_CopyOperation(
	TEE_OperationHandle dstOperation,
	TEE_OperationHandle srcOperation)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *sops = NULL;
	struct tee_operation *dops = NULL;

	object_lock();
	dops = object_of(dstOperation);
	sops = object_of(srcOperation);

	if ((!sops) || (!dops)) {
		ret = -EBADF;
		goto out;
	}

	/* Separate checks so _PS callers can return specific TEE_PANIC_xxxx codes */
	if (sops->info.algorithm != dops->info.algorithm) {
		ret = TEE_PANIC_INVALID_ALG;
		goto out;
	}

	if (sops->info.mode != dops->info.mode) {
		ret = TEE_PANIC_INVALID_MODE;
		goto out;
	}

	if (sops->info.keySize > dops->info.maxKeySize) {
		ret = TEE_PANIC_INVALID_SIZE;
		goto out;
	}

	if (sops->info.mode != TEE_MODE_DIGEST) {
		if (!(sops->info.handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS))
			ret = TEE_SetOperationKey(dstOperation, sops->key);
		else
			ret = TEE_SetOperationKey2(dstOperation, sops->key, sops->key2);
	} else {
		ret = __TEE_DigestInit(dops);
		if (ret != 0)
			goto out;
		mbedcrypto_hash_clone(dops->ctx, sops->ctx);
	}

	dops->info.handleState = sops->info.handleState;
	dops->operationState = sops->operationState;

	ret = 0;

out:
	object_unlock();
	return ret;
}

void TEE_CopyOperation(
	TEE_OperationHandle dstOperation,
	TEE_OperationHandle srcOperation)
{
	int ret = __TEE_CopyOperation(dstOperation, srcOperation);

	if (ret != 0)
		TEE_Panic(ret);
}

TEE_Result TEE_CopyOperation_PS(
	TEE_OperationHandle dstOperation,
	TEE_OperationHandle srcOperation)
{
	int ret = __TEE_CopyOperation(dstOperation, srcOperation);

	if (ret != 0) {
		/*
		 * EBADF: bad handle - programmer error, always panic.
		 * TEE_PANIC_xxxx codes from __TEE_CopyOperation: return them
		 * directly regardless of mask state (_PS semantics).
		 */
		if (ret == -EBADF)
			TEE_Panic(ret);
		return (TEE_Result)ret;
	}

	return TEE_SUCCESS;
}

static int __TEE_MbedEccCurveOf(int curve)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		return MBEDCRYPTO_ECP_DP_SECP192R1;
	case TEE_ECC_CURVE_NIST_P224:
		return MBEDCRYPTO_ECP_DP_NONE; /* SECP224R1 not supported */
	case TEE_ECC_CURVE_NIST_P256:
		return MBEDCRYPTO_ECP_DP_SECP256R1;
	case TEE_ECC_CURVE_NIST_P384:
		return MBEDCRYPTO_ECP_DP_SECP384R1;
	case TEE_ECC_CURVE_NIST_P521:
		return MBEDCRYPTO_ECP_DP_SECP521R1;
	case TEE_ECC_CURVE_BSI_P256r1:
		return MBEDCRYPTO_ECP_DP_BP256R1;
	case TEE_ECC_CURVE_BSI_P384r1:
		return MBEDCRYPTO_ECP_DP_BP384R1;
	case TEE_ECC_CURVE_BSI_P512r1:
		return MBEDCRYPTO_ECP_DP_BP512R1;
	case TEE_ECC_CURVE_25519:
		return MBEDCRYPTO_ECP_DP_CURVE25519;
	case TEE_ECC_CURVE_SM2:
		return MBEDCRYPTO_ECP_DP_SM2;
	default:
		return MBEDCRYPTO_ECP_DP_NONE;
	}
}

TEE_Result TEE_IsAlgorithmSupported(
	uint32_t algId, uint32_t element)
{
	switch (algId) {
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CBC_PKCS5:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_AES_CTS:
	case TEE_ALG_AES_XTS:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CMAC:
	case TEE_ALG_AES_CCM:
	case TEE_ALG_AES_GCM:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES_CBC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA3_224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA3_256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA3_384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA3_512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_512:
	case TEE_ALG_RSAES_PKCS1_V1_5:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_512:
	case TEE_ALG_RSA_NOPAD:
	case TEE_ALG_DSA_SHA1:
	case TEE_ALG_DSA_SHA224:
	case TEE_ALG_DSA_SHA256:
	case TEE_ALG_DSA_SHA3_224:
	case TEE_ALG_DSA_SHA3_256:
	case TEE_ALG_DSA_SHA3_384:
	case TEE_ALG_DSA_SHA3_512:
	case TEE_ALG_DH_DERIVE_SHARED_SECRET:
	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
	case TEE_ALG_SM3:
	case TEE_ALG_HMAC_SM3:
	case TEE_ALG_SM4_ECB_NOPAD:
	case TEE_ALG_SM4_CBC_NOPAD:
	case TEE_ALG_SM4_CTR:
	case TEE_ALG_SM4_ECB_PKCS5:
	case TEE_ALG_SM4_CBC_PKCS5:
	case TEE_ALG_SM4_GCM:
	case TEE_ALG_SM4_CCM:
	case TEE_ALG_SM2_DSA_SM3:
	case TEE_ALG_SM2_PKE:
	case TEE_ALG_SM2_KEP:
	case TEE_ALG_CHACHA20_POLY1305:
	case TEE_ALG_CHACHA20:
	case TEE_ALG_POLY1305:
	case TEE_ALG_SHA3_224:
	case TEE_ALG_SHA3_256:
	case TEE_ALG_SHA3_384:
	case TEE_ALG_SHA3_512:
	case TEE_ALG_HMAC_SHA3_224:
	case TEE_ALG_HMAC_SHA3_256:
	case TEE_ALG_HMAC_SHA3_384:
	case TEE_ALG_HMAC_SHA3_512:
	case TEE_ALG_SHA256_192:
	case TEE_ALG_HKDF:
		return TEE_SUCCESS;
	case TEE_ALG_ECDSA_SHA1:
	case TEE_ALG_ECDSA_SHA224:
	case TEE_ALG_ECDSA_SHA256:
	case TEE_ALG_ECDSA_SHA384:
	case TEE_ALG_ECDSA_SHA512:
	case TEE_ALG_ECDSA_SHA3_224:
	case TEE_ALG_ECDSA_SHA3_256:
	case TEE_ALG_ECDSA_SHA3_384:
	case TEE_ALG_ECDSA_SHA3_512:
	case TEE_ALG_ECDH_DERIVE_SHARED_SECRET:
		if (__TEE_MbedEccCurveOf(element) != MBEDCRYPTO_ECP_DP_NONE)
			return TEE_SUCCESS;
		return TEE_ERROR_NOT_SUPPORTED;
	case TEE_ALG_ED25519:
	case TEE_ALG_X25519:
	case TEE_ALG_ED448:
	case TEE_ALG_X448:
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

typedef int (*edx_keygen_fn_t)(uint8_t *, uint8_t *,
	mbedcrypto_rng_fn, void *);

static int __TEE_GenEdxKeypair(struct tee_object *obj,
	edx_keygen_fn_t gen_fn, size_t key_size,
	size_t priv_buf_size, uint32_t curve)
{
	uint8_t pub[MBEDCRYPTO_ED448_KEY_SIZE];
	uint8_t priv[2 * MBEDCRYPTO_ED448_KEY_SIZE];
	unsigned char *D = NULL, *X = NULL;
	int ret;

	ret = gen_fn(pub, priv, tee_prng, NULL);
	if (ret != 0)
		return ret;

	D = TEE_Malloc(key_size, TEE_MALLOC_FILL_ZERO);
	X = TEE_Malloc(key_size, TEE_MALLOC_FILL_ZERO);
	if (!D || !X) {
		TEE_Free(D); TEE_Free(X);
		return -ENOMEM;
	}

	memcpy(D, priv, key_size);
	memcpy(X, pub, key_size);
	memset(priv, 0, priv_buf_size);

	TEE_InitRefAttribute(&obj->attr[0], TEE_ATTR_ECC_PRIVATE_VALUE,
				D, key_size);
	TEE_InitRefAttribute(&obj->attr[1], TEE_ATTR_ECC_PUBLIC_VALUE_X,
				X, key_size);
	TEE_InitValueAttribute(&obj->attr[2], TEE_ATTR_ECC_CURVE, curve, 0);
	return 0;
}

TEE_Result TEE_GenerateKey(TEE_ObjectHandle object,
	uint32_t keySize, TEE_Attribute *params, uint32_t paramCount)
{
	uint32_t i = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct tee_object *obj = NULL;
	const struct object_attr *t = NULL;
	struct mbedcrypto_rsa_ctx rsa = {0};
	struct mbedcrypto_dh_ctx dhm = {0};
	struct mbedcrypto_dsa_ctx dsa = {0};
	struct mbedcrypto_ecp_keypair ecp = {0};

	if ((paramCount > 0) && (!params))
		return TEE_ERROR_BAD_PARAMETERS;

	object_lock();
	obj = object_of(object);
	if (!obj) {
		ret = -EBADF;
		goto out;
	}

	t = object_attr_of(obj->info.objectType);
	if (!t) {
		ret = -ENOTSUP;
		goto out;
	}

	if ((keySize < t->min_size) ||
		(keySize > obj->info.maxObjectSize)) {
		ret = -ENOTSUP;
		goto out;
	}

	if ((obj->info.objectType == TEE_TYPE_DATA) ||
		(obj->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) ||
		(obj->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		ret = -EINVAL;
		goto out;
	}

	if (t->attr_ids[0] == TEE_ATTR_SECRET_VALUE) {
		unsigned char *key = NULL;

		keySize >>= 3;
		key = TEE_Malloc(keySize, TEE_MALLOC_FILL_ZERO);
		if (!key) {
			ret = -ENOMEM;
			goto out;
		}

		TEE_GenerateRandom(key, keySize);
		TEE_InitRefAttribute(obj->attr, TEE_ATTR_SECRET_VALUE, key, keySize);
		obj->info.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
		obj->info.objectSize = keySize << 3;
		object_unlock();
		return TEE_SUCCESS;
	}

	switch (obj->info.objectType) {
	case TEE_TYPE_RSA_KEYPAIR: {
		int exponent = 65537, eidx = 0;
		unsigned char *N = NULL, *E = NULL;
		unsigned char *D = NULL, *P = NULL, *Q = NULL;
		unsigned char *DP = NULL, *DQ = NULL, *QP = NULL;
		size_t n_len = 0, e_len = 0;

		mbedcrypto_rsa_init(&rsa);

		for (i = 0; i < paramCount; i++) {
			if (params[i].attributeID == TEE_ATTR_RSA_PUBLIC_EXPONENT) {
				exponent = 0;
				e_len = params[i].content.ref.length;
				if (e_len > sizeof(int)) {
					ret = TEE_ERROR_BAD_PARAMETERS;
					goto out;
				}
				for (eidx = 0; eidx < e_len; eidx++) {
					exponent |= *(unsigned char *)(params[i].content.ref.buffer
							+ eidx) << ((e_len - eidx - 1) * 8);
				}
				break;
			}
		}

		/* FIPS 186-4 if 2^16 < exponent < 2^256 and nbits = 2048 or nbits = 3072. */
		if (exponent <= 65536 || (exponent % 2) == 0) {
			DMSG("exponent invalid %x(%d)\n", exponent, exponent);
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}

		ret = mbedcrypto_rsa_keygen(&rsa, tee_prng,
					NULL, keySize, exponent);
		if (ret != 0) {
			if (ret == (-EINVAL))
				ret = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}

		n_len = mbedcrypto_rsa_len(&rsa);
		e_len = mbedcrypto_bn_byte_count(&rsa.E);

		N = TEE_Malloc(n_len, TEE_MALLOC_FILL_ZERO);
		E = TEE_Malloc(e_len, TEE_MALLOC_FILL_ZERO);
		D = TEE_Malloc(n_len, TEE_MALLOC_FILL_ZERO);
		P = TEE_Malloc(n_len, TEE_MALLOC_FILL_ZERO);
		Q = TEE_Malloc(n_len, TEE_MALLOC_FILL_ZERO);
		DP = TEE_Malloc(n_len, TEE_MALLOC_FILL_ZERO);
		DQ = TEE_Malloc(n_len, TEE_MALLOC_FILL_ZERO);
		QP = TEE_Malloc(n_len, TEE_MALLOC_FILL_ZERO);
		if (!N || !E || !D || !P || !Q || !DP || !DQ || !QP) {
			ret = -ENOMEM;
			TEE_Free(N); TEE_Free(E); TEE_Free(D); TEE_Free(P);
			TEE_Free(Q); TEE_Free(DP); TEE_Free(DQ); TEE_Free(QP);
			goto out;
		}

		mbedcrypto_bn_to_binary(&rsa.N, N, n_len);
		mbedcrypto_bn_to_binary(&rsa.E, E, e_len);
		mbedcrypto_bn_to_binary(&rsa.D, D, n_len);
		mbedcrypto_bn_to_binary(&rsa.P, P, n_len);
		mbedcrypto_bn_to_binary(&rsa.Q, Q, n_len);
		mbedcrypto_bn_to_binary(&rsa.DP, DP, n_len);
		mbedcrypto_bn_to_binary(&rsa.DQ, DQ, n_len);
		mbedcrypto_bn_to_binary(&rsa.QP, QP, n_len);

		TEE_InitRefAttribute(&obj->attr[0], TEE_ATTR_RSA_MODULUS, N, n_len);
		TEE_InitRefAttribute(&obj->attr[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, E, e_len);
		TEE_InitRefAttribute(&obj->attr[2], TEE_ATTR_RSA_PRIVATE_EXPONENT, D, n_len);
		TEE_InitRefAttribute(&obj->attr[3], TEE_ATTR_RSA_PRIME1, P, n_len);
		TEE_InitRefAttribute(&obj->attr[4], TEE_ATTR_RSA_PRIME2, Q, n_len);
		TEE_InitRefAttribute(&obj->attr[5], TEE_ATTR_RSA_EXPONENT1, DP, n_len);
		TEE_InitRefAttribute(&obj->attr[6], TEE_ATTR_RSA_EXPONENT2, DQ, n_len);
		TEE_InitRefAttribute(&obj->attr[7], TEE_ATTR_RSA_COEFFICIENT, QP, n_len);
		break;
	}

	case TEE_TYPE_DSA_KEYPAIR: {
		unsigned char *P = NULL, *Q = NULL;
		unsigned char *G = NULL, *Y = NULL, *X = NULL;
		size_t p_len = 0, q_len = 0, g_len = 0, y_len = 0, x_len = 0;

		mbedcrypto_dsa_init(&dsa);
		for (i = 0; i < paramCount; i++) {
			if (params[i].attributeID == TEE_ATTR_DSA_PRIME) {
				if (mbedcrypto_bn_from_binary(&dsa.P,
					params[i].content.ref.buffer,
					params[i].content.ref.length) != 0) {
					ret = -ENOMEM;
					goto out;
				}
			} else if (params[i].attributeID == TEE_ATTR_DSA_SUBPRIME) {
				if (mbedcrypto_bn_from_binary(&dsa.Q,
					params[i].content.ref.buffer,
					params[i].content.ref.length) != 0) {
					ret = -ENOMEM;
					goto out;
				}
			} else if (params[i].attributeID == TEE_ATTR_DSA_BASE) {
				if (mbedcrypto_bn_from_binary(&dsa.G,
					params[i].content.ref.buffer,
					params[i].content.ref.length) != 0) {
					ret = -ENOMEM;
					goto out;
				}
			}
		}

		ret = mbedcrypto_dsa_keygen(&dsa, tee_prng, NULL);
		if (ret != 0)
			goto out;

		p_len = mbedcrypto_bn_byte_count(&dsa.P);
		q_len = mbedcrypto_bn_byte_count(&dsa.Q);
		g_len = mbedcrypto_bn_byte_count(&dsa.G);
		x_len = mbedcrypto_bn_byte_count(&dsa.X);
		y_len = mbedcrypto_bn_byte_count(&dsa.Y);

		P = TEE_Malloc(p_len, TEE_MALLOC_FILL_ZERO);
		Q = TEE_Malloc(q_len, TEE_MALLOC_FILL_ZERO);
		G = TEE_Malloc(g_len, TEE_MALLOC_FILL_ZERO);
		X = TEE_Malloc(x_len, TEE_MALLOC_FILL_ZERO);
		Y = TEE_Malloc(y_len, TEE_MALLOC_FILL_ZERO);
		if (!Y || !X || !G || !P || !Q) {
			ret = -ENOMEM;
			TEE_Free(Y); TEE_Free(X); TEE_Free(G); TEE_Free(P); TEE_Free(Q);
			goto out;
		}

		mbedcrypto_bn_to_binary(&dsa.P, P, p_len);
		mbedcrypto_bn_to_binary(&dsa.Q, Q, q_len);
		mbedcrypto_bn_to_binary(&dsa.G, G, g_len);
		mbedcrypto_bn_to_binary(&dsa.X, X, x_len);
		mbedcrypto_bn_to_binary(&dsa.Y, Y, y_len);

		TEE_InitRefAttribute(&obj->attr[0], TEE_ATTR_DSA_PRIME, P, p_len);
		TEE_InitRefAttribute(&obj->attr[1], TEE_ATTR_DSA_SUBPRIME, Q, q_len);
		TEE_InitRefAttribute(&obj->attr[2], TEE_ATTR_DSA_BASE, G, g_len);
		TEE_InitRefAttribute(&obj->attr[3], TEE_ATTR_DSA_PRIVATE_VALUE, X, x_len);
		TEE_InitRefAttribute(&obj->attr[4], TEE_ATTR_DSA_PUBLIC_VALUE, Y, y_len);
		break;
	}

	case TEE_TYPE_DH_KEYPAIR: {
		unsigned char *P = NULL, *G = NULL;
		unsigned char *X = NULL, *GX = NULL;
		size_t g_len = 0, p_len = 0, xbits = 0;

		mbedcrypto_dh_init(&dhm);
		for (i = 0; i < paramCount; i++) {
			if (params[i].attributeID == TEE_ATTR_DH_PRIME) {
				if (mbedcrypto_bn_from_binary(&dhm.P,
					params[i].content.ref.buffer,
					params[i].content.ref.length) != 0) {
					ret = -ENOMEM;
					goto out;
				}
			} else if (params[i].attributeID == TEE_ATTR_DH_BASE) {
				if (mbedcrypto_bn_from_binary(&dhm.G,
					params[i].content.ref.buffer,
					params[i].content.ref.length) != 0) {
					ret = -ENOMEM;
					goto out;
				}
			} else if (params[i].attributeID == TEE_ATTR_DH_X_BITS) {
				xbits = params[i].content.value.a;
			}
		}

		p_len = mbedcrypto_bn_byte_count(&dhm.P);
		g_len = mbedcrypto_bn_byte_count(&dhm.G);

		if ((g_len == 0) || (p_len == 0)) {
			ret = -EINVAL;
			goto out;
		}

		if (xbits == 0)
			xbits = p_len * 8;

		GX = TEE_Malloc(p_len, TEE_MALLOC_FILL_ZERO);
		if (!GX) {
			ret = -ENOMEM;
			goto out;
		}

		ret = mbedcrypto_dh_gen_public(&dhm, (xbits + 7) >> 3, GX, p_len, tee_prng, NULL);
		if (ret != 0) {
			TEE_Free(GX);
			goto out;
		}

		P = TEE_Malloc(p_len, TEE_MALLOC_FILL_ZERO);
		G = TEE_Malloc(g_len, TEE_MALLOC_FILL_ZERO);
		X = TEE_Malloc(p_len, TEE_MALLOC_FILL_ZERO);
		if (!P || !X || !G) {
			ret = -ENOMEM;
			TEE_Free(GX); TEE_Free(X); TEE_Free(G); TEE_Free(P);
			goto out;
		}

		mbedcrypto_bn_to_binary(&dhm.P, P, p_len);
		mbedcrypto_bn_to_binary(&dhm.G, G, g_len);
		mbedcrypto_bn_to_binary(&dhm.X, X, p_len);

		TEE_InitRefAttribute(&obj->attr[0], TEE_ATTR_DH_PRIME, P, p_len);
		TEE_InitRefAttribute(&obj->attr[1], TEE_ATTR_DH_BASE, G, g_len);
		TEE_InitRefAttribute(&obj->attr[2], TEE_ATTR_DH_PUBLIC_VALUE, GX, p_len);
		TEE_InitRefAttribute(&obj->attr[3], TEE_ATTR_DH_PRIVATE_VALUE, X, p_len);
		TEE_InitValueAttribute(&obj->attr[5], TEE_ATTR_DH_X_BITS,
						mbedcrypto_bn_bit_count(&dhm.X), 0);
		break;
	}

	case TEE_TYPE_ECDSA_KEYPAIR:
	case TEE_TYPE_ECDH_KEYPAIR:
	case TEE_TYPE_SM2_DSA_KEYPAIR:
	case TEE_TYPE_SM2_KEP_KEYPAIR:
	case TEE_TYPE_SM2_PKE_KEYPAIR: {
		int curve = -1, mbedcurve = MBEDCRYPTO_ECP_DP_NONE;
		unsigned char *D = NULL;
		unsigned char *X = NULL, *Y = NULL;
		size_t d_len = 0, x_len = 0, y_len = 0;

		mbedcrypto_ecp_keypair_init(&ecp);

		for (i = 0; i < paramCount; i++) {
			if (params[i].attributeID == TEE_ATTR_ECC_CURVE) {
				curve = params[i].content.value.a;
				mbedcurve = __TEE_MbedEccCurveOf(curve);
				break;
			}
		}

		/* SM2 has only one curve -> default if not specified */
		if (mbedcurve == MBEDCRYPTO_ECP_DP_NONE &&
		    (obj->info.objectType == TEE_TYPE_SM2_DSA_KEYPAIR ||
		     obj->info.objectType == TEE_TYPE_SM2_KEP_KEYPAIR ||
		     obj->info.objectType == TEE_TYPE_SM2_PKE_KEYPAIR)) {
			mbedcurve = MBEDCRYPTO_ECP_DP_SM2;
		}

		ret = mbedcrypto_ecp_keygen(mbedcurve, &ecp, tee_prng, NULL);
		if (ret != 0)
			goto out;

		d_len = mbedcrypto_bn_byte_count(&ecp.d);
		x_len = mbedcrypto_bn_byte_count(&ecp.Q.X);
		y_len = mbedcrypto_bn_byte_count(&ecp.Q.Y);

		D = TEE_Malloc(d_len, TEE_MALLOC_FILL_ZERO);
		X = TEE_Malloc(x_len, TEE_MALLOC_FILL_ZERO);
		Y = TEE_Malloc(y_len, TEE_MALLOC_FILL_ZERO);
		if (!D || !X || !Y) {
			ret = -ENOMEM;
			TEE_Free(D); TEE_Free(X); TEE_Free(Y);
			goto out;
		}

		mbedcrypto_bn_to_binary(&ecp.d, D, d_len);
		mbedcrypto_bn_to_binary(&ecp.Q.X, X, x_len);
		mbedcrypto_bn_to_binary(&ecp.Q.Y, Y, y_len);

		TEE_InitRefAttribute(&obj->attr[0], TEE_ATTR_ECC_PRIVATE_VALUE, D, d_len);
		TEE_InitRefAttribute(&obj->attr[1], TEE_ATTR_ECC_PUBLIC_VALUE_X, X, x_len);
		TEE_InitRefAttribute(&obj->attr[2], TEE_ATTR_ECC_PUBLIC_VALUE_Y, Y, y_len);
		TEE_InitValueAttribute(&obj->attr[3], TEE_ATTR_ECC_CURVE, curve, 0);
		break;
	}

	case TEE_TYPE_ED25519_KEYPAIR:
		ret = __TEE_GenEdxKeypair(obj, mbedcrypto_ed25519_gen_keypair,
				MBEDCRYPTO_ED25519_KEY_SIZE,
				2 * MBEDCRYPTO_ED25519_KEY_SIZE,
				TEE_ECC_CURVE_25519);
		if (ret != 0)
			goto out;
		break;

	case TEE_TYPE_X25519_KEYPAIR:
		ret = __TEE_GenEdxKeypair(obj, mbedcrypto_x25519_gen_keypair,
				MBEDCRYPTO_X25519_KEY_SIZE,
				MBEDCRYPTO_X25519_KEY_SIZE,
				TEE_ECC_CURVE_25519);
		if (ret != 0)
			goto out;
		break;

	case TEE_TYPE_ED448_KEYPAIR:
		ret = __TEE_GenEdxKeypair(obj, mbedcrypto_ed448_gen_keypair,
				MBEDCRYPTO_ED448_KEY_SIZE,
				2 * MBEDCRYPTO_ED448_KEY_SIZE,
				TEE_ECC_CURVE_448);
		if (ret != 0)
			goto out;
		break;

	case TEE_TYPE_X448_KEYPAIR:
		ret = __TEE_GenEdxKeypair(obj, mbedcrypto_x448_gen_keypair,
				MBEDCRYPTO_X448_KEY_SIZE,
				MBEDCRYPTO_X448_KEY_SIZE,
				TEE_ECC_CURVE_448);
		if (ret != 0)
			goto out;
		break;

	default:
		ret = -ENOTSUP;
		goto out;
	}

	obj->info.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
	obj->info.objectSize = keySize;

out:
	object_unlock();
	mbedcrypto_rsa_cleanup(&rsa);
	mbedcrypto_dh_cleanup(&dhm);
	mbedcrypto_dsa_cleanup(&dsa);
	mbedcrypto_ecp_keypair_cleanup(&ecp);
	if (ret == TEE_SUCCESS || ret == TEE_ERROR_BAD_PARAMETERS)
		return ret;
	/* Programmer errors: bad handle, wrong state/type, unsupported */
	if (ret == -EBADF || ret == -ENOTSUP || ret == -EINVAL)
		TEE_Panic(ret);
	/* Crypto/hardware failure */
	return __TEE_PanicOrReturn(TEE_PANIC_CRYPTO_FAILURE);
}

static int __TEE_DigestUpdate(TEE_OperationHandle operation,
	void *chunk, size_t chunkSize)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->info.mode != TEE_MODE_DIGEST) ||
		(ops->operationState == TEE_OPERATION_STATE_EXTRACTING) ||
		((!chunk) && chunkSize != 0)) {
		ret = -EINVAL;
		goto out;
	}

	ops->operationState = TEE_OPERATION_STATE_ACTIVE;

	ret = mbedcrypto_hash_update(ops->ctx, chunk, chunkSize);

out:
	object_unlock();
	return ret;
}

void TEE_DigestUpdate(TEE_OperationHandle operation,
	void *chunk, size_t chunkSize)
{
	int ret = __TEE_DigestUpdate(operation, chunk, chunkSize);

	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

TEE_Result TEE_DigestUpdate_PS(TEE_OperationHandle operation,
	void *chunk, size_t chunkSize)
{
	int ret = __TEE_DigestUpdate(operation, chunk, chunkSize);

	if (ret != 0) {
		/* EBADF/EINVAL: programmer error - always panic */
		if (ret == -EBADF || ret == -EINVAL)
			TEE_Panic(ret);
		/* Crypto/hardware failure: always return TEE_PANIC_xxxx (_PS) */
		return TEE_PANIC_CRYPTO_FAILURE;
	}

	return TEE_SUCCESS;
}

TEE_Result TEE_DigestDoFinal(TEE_OperationHandle operation,
	void *chunk, size_t chunkLen, void *hash, size_t *hashLen)
{
	int ret = TEE_ERROR_GENERIC;
	TEE_Result panic_code = 0; /* 0 = programmer error: always panic */
	struct tee_operation *ops = NULL;

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->info.mode != TEE_MODE_DIGEST) ||
		(ops->operationState == TEE_OPERATION_STATE_EXTRACTING && chunkLen != 0) ||
		((!hash) || (!hashLen)) ||
		((!chunk) && chunkLen != 0)) {
		ret = -EINVAL;
		goto out;
	}

	if (*hashLen < ops->info.digestLength) {
		*hashLen = ops->info.digestLength;
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	ret = mbedcrypto_hash_update(ops->ctx, chunk, chunkLen);
	if (ret != 0) {
		panic_code = TEE_PANIC_CRYPTO_FAILURE;
		goto out;
	}

	ret = mbedcrypto_hash_final(ops->ctx, hash);
	if (ret != 0) {
		panic_code = TEE_PANIC_CRYPTO_FAILURE;
		goto out;
	}

	*hashLen = ops->info.digestLength;

	/* re-start the digest state */
	__TEE_DigestExtractClear(ops);
	mbedcrypto_hash_init(ops->ctx, ((struct mbedcrypto_hash_ctx *)ops->ctx)->algo);
	ops->operationState = TEE_OPERATION_STATE_INITIAL;

	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret == TEE_SUCCESS || ret == TEE_ERROR_SHORT_BUFFER)
		return ret;
	return __TEE_PanicOrDie(ret, panic_code);
}

TEE_Result TEE_DigestExtract(TEE_OperationHandle operation,
	void *hash, size_t *hashLen)
{
	int ret = TEE_ERROR_GENERIC;
	TEE_Result panic_code = 0; /* 0 = programmer error: always panic */
	struct tee_operation *ops = NULL;
	struct mbedcrypto_hash_ctx shadow;
	size_t len = 0;
	size_t left_len = 0;

	if (!hash || !hashLen)
		TEE_Panic(EINVAL);

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->info.mode != TEE_MODE_DIGEST) || !ops->ctx) {
		ret = -EINVAL;
		goto out;
	}

	if (!(ops->info.handleState & TEE_HANDLE_FLAG_EXTRACTING)) {
		if (ops->info.digestLength > sizeof(ops->digest_extract_buf)) {
			panic_code = TEE_PANIC_CRYPTO_FAILURE;
			goto out;
		}

		TEE_MemFill(&shadow, 0, sizeof(shadow));
		mbedcrypto_hash_clone(&shadow, ops->ctx);

		ret = mbedcrypto_hash_final(&shadow, ops->digest_extract_buf);
		mbedcrypto_hash_cleanup(&shadow);
		if (ret != 0) {
			panic_code = TEE_PANIC_CRYPTO_FAILURE;
			goto out;
		}

		ops->digest_extract_len = ops->info.digestLength;
		ops->digest_extract_offs = 0;
		ops->info.handleState |= TEE_HANDLE_FLAG_EXTRACTING;
		ops->operationState = TEE_OPERATION_STATE_EXTRACTING;
	}

	left_len = ops->digest_extract_len - ops->digest_extract_offs;
	len = left_len;
	if (len > *hashLen)
		len = *hashLen;
	memcpy(hash, &ops->digest_extract_buf[ops->digest_extract_offs], len);
	*hashLen = len;
	ops->digest_extract_offs += len;
	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret == TEE_SUCCESS)
		return ret;
	return __TEE_PanicOrDie(ret, panic_code);
}

/*
 * Unified cipher dispatch - maps TEE algorithm -> mbedcrypto cipher type
 */
static int __TEE_MbedCipherOf(uint32_t algorithm)
{
	switch (algorithm) {
	case TEE_ALG_AES_ECB_NOPAD: return MBEDCRYPTO_CIPHER_AES_ECB;
	case TEE_ALG_AES_CBC_NOPAD: return MBEDCRYPTO_CIPHER_AES_CBC;
	case TEE_ALG_AES_CTR:       return MBEDCRYPTO_CIPHER_AES_CTR;
	case TEE_ALG_AES_CTS:       return MBEDCRYPTO_CIPHER_AES_CTS;
	case TEE_ALG_AES_XTS:       return MBEDCRYPTO_CIPHER_AES_XTS;
	case TEE_ALG_DES_ECB_NOPAD:  return MBEDCRYPTO_CIPHER_DES_ECB;
	case TEE_ALG_DES_CBC_NOPAD:  return MBEDCRYPTO_CIPHER_DES_CBC;
	case TEE_ALG_DES3_ECB_NOPAD: return MBEDCRYPTO_CIPHER_DES3_ECB;
	case TEE_ALG_DES3_CBC_NOPAD: return MBEDCRYPTO_CIPHER_DES3_CBC;
	case TEE_ALG_SM4_ECB_NOPAD:  return MBEDCRYPTO_CIPHER_SM4_ECB;
	case TEE_ALG_SM4_CBC_NOPAD:  return MBEDCRYPTO_CIPHER_SM4_CBC;
	case TEE_ALG_SM4_CTR:        return MBEDCRYPTO_CIPHER_SM4_CTR;
	case TEE_ALG_AES_CBC_PKCS5:  return MBEDCRYPTO_CIPHER_AES_CBC_PKCS5;
	case TEE_ALG_DES_CBC_PKCS5:  return MBEDCRYPTO_CIPHER_DES_CBC_PKCS5;
	case TEE_ALG_DES3_CBC_PKCS5: return MBEDCRYPTO_CIPHER_DES3_CBC_PKCS5;
	case TEE_ALG_SM4_ECB_PKCS5:  return MBEDCRYPTO_CIPHER_SM4_ECB_PKCS5;
	case TEE_ALG_SM4_CBC_PKCS5:  return MBEDCRYPTO_CIPHER_SM4_CBC_PKCS5;
	case TEE_ALG_CHACHA20:       return MBEDCRYPTO_CIPHER_CHACHA20;
	default: return -1;
	}
}

static int __TEE_IsCipherPadding(uint32_t algorithm)
{
	switch (algorithm) {
	case TEE_ALG_AES_CBC_PKCS5:
	case TEE_ALG_DES_CBC_PKCS5:
	case TEE_ALG_DES3_CBC_PKCS5:
	case TEE_ALG_SM4_ECB_PKCS5:
	case TEE_ALG_SM4_CBC_PKCS5:
		return 1;
	default:
		return 0;
	}
}

/*
 * Unified cipher-based MAC dispatch - maps TEE algorithm -> mbedcrypto cmac type
 */
static int __TEE_MbedMacOf(uint32_t algorithm)
{
	switch (algorithm) {
	case TEE_ALG_AES_CMAC:          return MBEDCRYPTO_CMAC_AES;
	case TEE_ALG_AES_CBC_MAC_NOPAD: return MBEDCRYPTO_CMAC_AES_CBC_NOPAD;
	case TEE_ALG_AES_CBC_MAC_PKCS5: return MBEDCRYPTO_CMAC_AES_CBC_PKCS5;
	case TEE_ALG_DES_CBC_MAC_NOPAD:  return MBEDCRYPTO_CMAC_DES_CBC_NOPAD;
	case TEE_ALG_DES_CBC_MAC_PKCS5:  return MBEDCRYPTO_CMAC_DES_CBC_PKCS5;
	case TEE_ALG_DES3_CBC_MAC_NOPAD: return MBEDCRYPTO_CMAC_DES3_CBC_NOPAD;
	case TEE_ALG_DES3_CBC_MAC_PKCS5: return MBEDCRYPTO_CMAC_DES3_CBC_PKCS5;
	default: return -1;
	}
}

/*
 * Map TEE HMAC algorithm -> mbedcrypto_hash_algo for the underlying hash
 */
static int __TEE_MbedHMACHashOf(uint32_t algorithm)
{
	switch (algorithm) {
	case TEE_ALG_HMAC_MD5:    return MBEDCRYPTO_HASH_MD5;
	case TEE_ALG_HMAC_SHA1:   return MBEDCRYPTO_HASH_SHA1;
	case TEE_ALG_HMAC_SHA224: return MBEDCRYPTO_HASH_SHA224;
	case TEE_ALG_HMAC_SHA256: return MBEDCRYPTO_HASH_SHA256;
	case TEE_ALG_HMAC_SHA384: return MBEDCRYPTO_HASH_SHA384;
	case TEE_ALG_HMAC_SHA512: return MBEDCRYPTO_HASH_SHA512;
	case TEE_ALG_HMAC_SM3:      return MBEDCRYPTO_HASH_SM3;
	case TEE_ALG_HMAC_SHA3_224:  return MBEDCRYPTO_HASH_SHA3_224;
	case TEE_ALG_HMAC_SHA3_256:  return MBEDCRYPTO_HASH_SHA3_256;
	case TEE_ALG_HMAC_SHA3_384:  return MBEDCRYPTO_HASH_SHA3_384;
	case TEE_ALG_HMAC_SHA3_512:  return MBEDCRYPTO_HASH_SHA3_512;
	default: return MBEDCRYPTO_HASH_NONE;
	}
}

/*
 * Unified cipher MAC init
 */
static int __TEE_MbedCipherMacInit(
	struct tee_operation *ops, int mac_type)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_object *obj = NULL;
	int key_size = 0;
	unsigned char key_buffer[32] = {0};

	/* re-start */
	if (ops->ctx) {
		ret = mbedcrypto_mac_reset(ops->ctx);
		goto out;
	}

	obj = object_of(ops->key);
	if (!obj) {
		ret = -ENOSR;
		goto out;
	}

	key_size = ops->info.keySize;
	memcpy(key_buffer, obj->attr[0].content.ref.buffer, key_size / 8);

	/* 2-key triple DES: key1|key2 -> key1|key2|key1 */
	if ((mac_type == MBEDCRYPTO_CMAC_DES3_CBC_NOPAD ||
		mac_type == MBEDCRYPTO_CMAC_DES3_CBC_PKCS5) && key_size == 128)
		memcpy(key_buffer + 16, key_buffer, 8);

	ops->ctx = TEE_Malloc(sizeof(struct mbedcrypto_mac_ctx),
				  TEE_MALLOC_NO_FILL | TEE_MALLOC_NO_SHARE);
	if (!ops->ctx) {
		ret = -ENOMEM;
		goto out;
	}

	ret = mbedcrypto_mac_init(ops->ctx, mac_type, key_buffer, key_size);
	if (ret != 0) {
		mbedcrypto_mac_cleanup(ops->ctx);
		TEE_Free(ops->ctx);
		ops->ctx = NULL;
	}

out:
	memset(key_buffer, 0, sizeof(key_buffer));
	return ret;
}

/*
 * Unified cipher init - all AES/DES/DES3/SM4 modes go through here
 */
static int __TEE_MbedCipherInit(
	struct tee_operation *ops, int cipher_type,
	void *IV, size_t IVLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_object *obj = NULL;
	int key_size = 0, mode = 0;
	unsigned char key_buffer[64] = {0};

	/* re-start the cipher state */
	if (ops->ctx) {
		if (IV && IVLen) {
			ret = mbedcrypto_cipher_set_iv(ops->ctx, IV, IVLen);
			if (ret != 0) {
				ret = -EMSGSIZE;
				goto out;
			}
		}
		mbedcrypto_cipher_reset(ops->ctx);
		ret = 0;
		goto out;
	}

	obj = object_of(ops->key);
	if (!obj) {
		ret = -ENOSR;
		goto out;
	}

	key_size = ops->info.keySize;
	memcpy(key_buffer, obj->attr[0].content.ref.buffer, key_size / 8);

	/* Two-key mode (AES-XTS) */
	if (ops->info.handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS) {
		obj = object_of(ops->key2);
		if (!obj) {
			ret = -ENOSR;
			goto out;
		}
		memcpy(&key_buffer[key_size / 8], obj->attr[0].content.ref.buffer, key_size / 8);
		key_size *= 2;
	}

	/* 2-key triple DES: key1|key2 -> key1|key2|key1 */
	if ((cipher_type == MBEDCRYPTO_CIPHER_DES3_ECB ||
		cipher_type == MBEDCRYPTO_CIPHER_DES3_CBC ||
		cipher_type == MBEDCRYPTO_CIPHER_DES3_CTS ||
		cipher_type == MBEDCRYPTO_CIPHER_DES3_CBC_PKCS5) && key_size == 128) {
		memcpy(key_buffer + 16, key_buffer, 8);
		key_size = 192;
	}

	if (ops->info.mode == TEE_MODE_DECRYPT)
		mode = MBEDCRYPTO_DECRYPT;

	ops->ctx = TEE_Malloc(sizeof(struct mbedcrypto_cipher_ctx),
				  TEE_MALLOC_NO_FILL | TEE_MALLOC_NO_SHARE);
	if (!ops->ctx) {
		ret = -ENOMEM;
		goto out;
	}

	ret = mbedcrypto_cipher_init(ops->ctx, cipher_type,
			key_buffer, key_size, mode);
	if (ret != 0)
		goto out;

	if (IV && IVLen) {
		ret = mbedcrypto_cipher_set_iv(ops->ctx, IV, IVLen);
		if (ret != 0) {
			ret = -EMSGSIZE;
			goto out;
		}
	}

out:
	memset(key_buffer, 0, sizeof(key_buffer));
	if (ret != 0 && ops->ctx) {
		mbedcrypto_cipher_cleanup(ops->ctx);
		TEE_Free(ops->ctx);
		ops->ctx = NULL;
	}
	return ret;
}

static int __TEE_CipherInit(TEE_OperationHandle operation, void *IV, size_t IVLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;
	int cipher = -1;

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_CIPHER) ||
		!(ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		ret = -EINVAL;
		goto out;
	}

	LMSG("algo:%x stat:%x %s ksz:%d iv:%p ivlen:%d\n", ops->info.algorithm,
		ops->info.handleState, ops->info.mode ? "decrypt" : "encrypt",
		ops->info.keySize, IV, IVLen);

	cipher = __TEE_MbedCipherOf(ops->info.algorithm);
	if (cipher == -1) {
		ret = -ENOTSUP;
		goto out;
	}

	ops->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
	ops->operationState = TEE_OPERATION_STATE_INITIAL;

	ret = __TEE_MbedCipherInit(ops, cipher, IV, IVLen);
	if (ret != 0)
		goto out;

	ops->info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
	ops->operationState = TEE_OPERATION_STATE_ACTIVE;

	ret = 0;

out:
	object_unlock();
	return ret;
}

void TEE_CipherInit(TEE_OperationHandle operation, void *IV, size_t IVLen)
{
	int ret = __TEE_CipherInit(operation, IV, IVLen);

	if (ret != 0)
		TEE_Panic(ret);
}

TEE_Result TEE_CipherInit_PS(TEE_OperationHandle operation, void *IV, size_t IVLen)
{
	int ret = __TEE_CipherInit(operation, IV, IVLen);

	if (ret != 0) {
		if (ret == -EMSGSIZE)
			return TEE_PANIC_BAD_IV;
		/* EBADF/EINVAL/ENOTSUP: programmer error - always panic */
		if (ret == -EBADF || ret == -EINVAL || ret == -ENOTSUP)
			TEE_Panic(ret);
		return TEE_PANIC_CRYPTO_FAILURE;
	}

	return TEE_SUCCESS;
}

TEE_Result TEE_CipherUpdate(TEE_OperationHandle operation,
	void *srcData, size_t srcLen, void *destData, size_t *destLen)
{
	int ret = TEE_ERROR_GENERIC;
	TEE_Result panic_code = 0; /* 0 = programmer error: always panic */
	struct tee_operation *ops = NULL;

	if (!destLen || (*destLen < srcLen))
		return TEE_ERROR_SHORT_BUFFER;

	if (((srcLen > 0) && (!srcData)) ||
		((*destLen > 0) && (!destData)))
		TEE_Panic(EINVAL);

	if (INVALID_BUFF(srcData, destData, srcLen))
		return __TEE_PanicOrReturn(TEE_PANIC_NOT_DISJOINT);

	LMSG("ops %ld - src:%p ilen:%d dst:%p olen:%d\n", (uintptr_t)operation,
			srcData, srcLen, destData, *destLen);

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	LMSG("ccops->info.algorithm 0x%x\n", ops->info.algorithm);

	if ((ops->info.operationClass != TEE_OPERATION_CIPHER) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) ||
		(ops->operationState != TEE_OPERATION_STATE_ACTIVE)) {
		ret = -EINVAL;
		goto out;
	}

	ret = mbedcrypto_cipher_update(ops->ctx, srcData, srcLen, destData, destLen);
	if (ret != 0) {
		panic_code = __TEE_PanicOnEINVAL(ret, TEE_PANIC_BAD_INPUT_LENGTH);
		goto out;
	}

	LMSG("ops %ld - src:%p ilen:%d dst:%p olen:%d\n", (uintptr_t)operation,
		srcData, srcLen, destData, *destLen);

out:
	object_unlock();
	if (ret == TEE_SUCCESS || ret == TEE_ERROR_SHORT_BUFFER ||
		ret == TEE_ERROR_DATA_TO_WRITE)
		return ret;
	return __TEE_PanicOrDie(ret, panic_code);
}

TEE_Result TEE_CipherDoFinal(TEE_OperationHandle operation,
	void *srcData, size_t srcLen, void *destData, size_t *destLen)
{
	int ret = TEE_ERROR_GENERIC;
	TEE_Result panic_code = 0; /* 0 = programmer error: always panic */
	struct tee_operation *ops = NULL;

	if (destData) {
		if (!destLen || (*destLen < srcLen))
			return TEE_ERROR_SHORT_BUFFER;
	}

	if ((srcLen > 0) && (!srcData))
		TEE_Panic(EINVAL);

	if (INVALID_BUFF(srcData, destData, srcLen))
		return __TEE_PanicOrReturn(TEE_PANIC_NOT_DISJOINT);

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	LMSG("ops %ld - src:%p ilen:%d dst:%p olen:%d\n", (uintptr_t)operation,
		srcData, srcLen, destData, destLen ? *destLen : 0);

	if ((ops->info.operationClass != TEE_OPERATION_CIPHER) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) ||
		(ops->operationState != TEE_OPERATION_STATE_ACTIVE)) {
		ret = -EINVAL;
		goto out;
	}

	ret = mbedcrypto_cipher_final(ops->ctx,
		srcData, srcLen, destData, destLen);
	if (ret != 0) {
		panic_code = __TEE_PanicOnEINVAL(ret,
			TEE_PANIC_BAD_INPUT_LENGTH);
		if (ret == -EINVAL &&
		    ops->info.mode == TEE_MODE_DECRYPT &&
		    __TEE_IsCipherPadding(ops->info.algorithm))
			panic_code = TEE_PANIC_BAD_CIPHERTEXT;
		goto out;
	}

	LMSG("ops %ld - src:%p ilen:%d dst:%p olen:%d\n", (uintptr_t)operation,
			srcData, srcLen, destData, destLen ? *destLen : 0);

	ops->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
	ops->operationState = TEE_OPERATION_STATE_INITIAL;
	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret == TEE_SUCCESS || ret == TEE_ERROR_SHORT_BUFFER ||
		ret == TEE_ERROR_DATA_TO_WRITE)
		return ret;
	return __TEE_PanicOrDie(ret, panic_code);
}

static int __TEE_MbedHMACInit(
	struct tee_operation *ops, int md_type)
{
	int ret = -1;
	struct tee_object *obj = NULL;

	obj = object_of(ops->key);
	if (!obj) {
		ret = -ENOSR;
		goto out;
	}

	/* re-start the hmac state */
	if (ops->ctx)
		return mbedcrypto_hmac_init(ops->ctx, md_type,
			obj->attr[0].content.ref.buffer,
			ops->info.keySize / 8);

	ops->ctx = TEE_Malloc(sizeof(struct mbedcrypto_hmac_ctx),
				  TEE_MALLOC_NO_FILL | TEE_MALLOC_NO_SHARE);
	if (!ops->ctx) {
		ret = -ENOMEM;
		goto out;
	}

	ops->info.digestLength = mbedcrypto_hash_size(md_type);

	ret = mbedcrypto_hmac_init(ops->ctx, md_type,
			obj->attr[0].content.ref.buffer,
			ops->info.keySize / 8);
	if (ret != 0)
		goto out;

out:
	if (ret != 0) {
		mbedcrypto_hmac_cleanup(ops->ctx);
		TEE_Free(ops->ctx);
		ops->ctx = NULL;
	}
	return ret;
}

static int __TEE_MACInit(TEE_OperationHandle operation, void *IV, size_t IVLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;
	int htype, mac_type;

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_MAC) ||
		!(ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		ret = -EINVAL;
		goto out;
	}

	/* No supported MAC algorithm uses an IV */
	if (IVLen != 0) {
		ret = -EMSGSIZE;
		goto out;
	}

	ops->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
	ops->operationState = TEE_OPERATION_STATE_INITIAL;

	/* HMAC path */
	htype = __TEE_MbedHMACHashOf(ops->info.algorithm);
	if (htype != MBEDCRYPTO_HASH_NONE) {
		ret = __TEE_MbedHMACInit(ops, htype);
		if (ret != 0)
			goto out;
	} else if (ops->info.algorithm == TEE_ALG_POLY1305) {
		/* Standalone Poly1305 MAC */
		struct tee_object *obj = object_of(ops->key);

		if (!obj) {
			ret = -ENOSR;
			goto out;
		}

		if (!ops->ctx) {
			ops->ctx = TEE_Malloc(
				sizeof(struct mbedcrypto_poly1305_ctx),
				TEE_MALLOC_NO_FILL | TEE_MALLOC_NO_SHARE);
			if (!ops->ctx) {
				ret = -ENOMEM;
				goto out;
			}
		}
		mbedcrypto_poly1305_init(ops->ctx);
		ret = mbedcrypto_poly1305_setkey(ops->ctx,
				obj->attr[0].content.ref.buffer);
		if (ret != 0) {
			TEE_Free(ops->ctx);
			ops->ctx = NULL;
			goto out;
		}
		ops->info.digestLength = MBEDCRYPTO_POLY1305_TAG_SIZE;
	} else {
		/* Cipher-based MAC path (CMAC, CBC-MAC, DES-MAC) */
		mac_type = __TEE_MbedMacOf(ops->info.algorithm);
		if (mac_type == -1) {
			ret = -ENOTSUP;
			goto out;
		}
		ret = __TEE_MbedCipherMacInit(ops, mac_type);
		if (ret != 0)
			goto out;
	}

	ops->info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
	ops->operationState = TEE_OPERATION_STATE_ACTIVE;

out:
	object_unlock();
	return ret;
}

void TEE_MACInit(TEE_OperationHandle operation, void *IV, size_t IVLen)
{
	int ret = __TEE_MACInit(operation, IV, IVLen);

	if (ret != 0)
		TEE_Panic(ret);
}

TEE_Result TEE_MACInit_PS(TEE_OperationHandle operation, void *IV, size_t IVLen)
{
	int ret = __TEE_MACInit(operation, IV, IVLen);

	if (ret != 0) {
		if (ret == -EMSGSIZE)
			return TEE_PANIC_BAD_IV;
		/* EBADF/EINVAL/ENOTSUP: programmer error - always panic */
		if (ret == -EBADF || ret == -EINVAL || ret == -ENOTSUP)
			TEE_Panic(ret);
		/* Crypto/hardware failure: always return TEE_PANIC_xxxx (_PS) */
		return TEE_PANIC_CRYPTO_FAILURE;
	}

	return TEE_SUCCESS;
}

static int __TEE_MACUpdate(TEE_OperationHandle operation, void *chunk, size_t chunkSize)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_MAC) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) ||
		(ops->operationState != TEE_OPERATION_STATE_ACTIVE)) {
		ret = -EINVAL;
		goto out;
	}

	if ((chunkSize > 0) && (!chunk)) {
		ret = -EINVAL;
		goto out;
	}

	if (INVALID_BUFF(chunk, chunk, chunkSize)) {
		ret = -EFAULT;
		goto out;
	}

	LMSG("ops->info.algorithm 0x%x\n", ops->info.algorithm);

	if (__TEE_IsHMAC(ops->info.algorithm))
		ret = mbedcrypto_hmac_update(ops->ctx, chunk, chunkSize);
	else if (ops->info.algorithm == TEE_ALG_POLY1305)
		ret = mbedcrypto_poly1305_update(ops->ctx, chunk, chunkSize);
	else
		ret = mbedcrypto_mac_update(ops->ctx, chunk, chunkSize);

out:
	object_unlock();
	return ret;
}

void TEE_MACUpdate(TEE_OperationHandle operation, void *chunk, size_t chunkSize)
{
	int ret = __TEE_MACUpdate(operation, chunk, chunkSize);

	if (ret != 0)
		TEE_Panic(ret);
}

TEE_Result TEE_MACUpdate_PS(TEE_OperationHandle operation, void *chunk, size_t chunkSize)
{
	int ret = __TEE_MACUpdate(operation, chunk, chunkSize);

	if (ret != 0) {
		/* EBADF/EINVAL/EFAULT: programmer error - always panic */
		if (ret == -EBADF || ret == -EINVAL || ret == -EFAULT)
			TEE_Panic(ret);
		/* Crypto/hardware failure: always return TEE_PANIC_xxxx (_PS) */
		return TEE_PANIC_CRYPTO_FAILURE;
	}

	return TEE_SUCCESS;
}

TEE_Result TEE_MACComputeFinal(TEE_OperationHandle operation,
	void *message, size_t messageLen, void *mac, size_t *macLen)
{
	int ret = TEE_ERROR_GENERIC;
	TEE_Result panic_code = 0; /* 0 = programmer error: always panic */
	struct tee_operation *ops = NULL;

	object_lock();

	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_MAC) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) ||
		(ops->operationState != TEE_OPERATION_STATE_ACTIVE)) {
		ret = -EINVAL;
		goto out;
	}

	if ((messageLen > 0) && (!message)) {
		ret = -EINVAL;
		goto out;
	}

	if (INVALID_BUFF(message, message, messageLen)) {
		ret = -EFAULT;
		goto out;
	}

	LMSG("ops->info.algorithm 0x%x\n", ops->info.algorithm);

	if (__TEE_IsHMAC(ops->info.algorithm)) {
		struct mbedcrypto_hmac_ctx *ctx = ops->ctx;

		if (*macLen < mbedcrypto_hash_size(ctx->algo)) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		if (messageLen > 0) {
			ret = mbedcrypto_hmac_update(ctx, message, messageLen);
			if (ret != 0) {
				panic_code = __TEE_PanicOnEINVAL(ret,
					TEE_PANIC_BAD_INPUT_LENGTH);
				goto out;
			}
		}

		ret = mbedcrypto_hmac_final(ctx, mac);
		if (ret != 0) {
			panic_code = __TEE_PanicOnEINVAL(ret,
				TEE_PANIC_BAD_INPUT_LENGTH);
			goto out;
		}

		*macLen = mbedcrypto_hash_size(ctx->algo);
	} else if (ops->info.algorithm == TEE_ALG_POLY1305) {
		if (*macLen < MBEDCRYPTO_POLY1305_TAG_SIZE) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		if (messageLen > 0) {
			ret = mbedcrypto_poly1305_update(ops->ctx,
					message, messageLen);
			if (ret != 0) {
				panic_code = __TEE_PanicOnEINVAL(ret,
					TEE_PANIC_BAD_INPUT_LENGTH);
				goto out;
			}
		}

		ret = mbedcrypto_poly1305_final(ops->ctx, mac);
		if (ret != 0) {
			panic_code = __TEE_PanicOnEINVAL(ret,
				TEE_PANIC_BAD_INPUT_LENGTH);
			goto out;
		}

		*macLen = MBEDCRYPTO_POLY1305_TAG_SIZE;
	} else {
		/* Cipher-based MAC (CMAC, AES/DES CBC-MAC) */
		if (messageLen > 0) {
			ret = mbedcrypto_mac_update(ops->ctx, message, messageLen);
			if (ret != 0) {
				panic_code = __TEE_PanicOnEINVAL(ret,
					TEE_PANIC_BAD_INPUT_LENGTH);
				goto out;
			}
		}

		ret = mbedcrypto_mac_final(ops->ctx, mac, macLen);
		if (ret != 0) {
			panic_code = __TEE_PanicOnEINVAL(ret,
				TEE_PANIC_BAD_INPUT_LENGTH);
			goto out;
		}
	}

	ops->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
	ops->operationState = TEE_OPERATION_STATE_INITIAL;

	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret == TEE_SUCCESS || ret == TEE_ERROR_SHORT_BUFFER)
		return ret;
	return __TEE_PanicOrDie(ret, panic_code);
}

TEE_Result TEE_MACCompareFinal(TEE_OperationHandle operation,
	void *message, size_t messageLen, void *mac, size_t macLen)
{
	int ret = TEE_ERROR_GENERIC;
	unsigned char dst[64];
	size_t olen = sizeof(dst);

	ret = TEE_MACComputeFinal(operation, message, messageLen, dst, &olen);
	if (ret != TEE_SUCCESS) {
		/*
		 * TEE_MACComputeFinal may return TEE_PANIC_xxxx when panics
		 * are masked; propagate the code directly. It already panicked
		 * if panics were not masked, so we will not reach here in that
		 * case.
		 */
		return ret;
	}

	if ((olen != macLen) ||	mbedtee_memcmp(mac, dst, olen))
		return TEE_ERROR_MAC_INVALID;

	return TEE_SUCCESS;
}

TEE_Result TEE_AEInit(TEE_OperationHandle operation,
	void *nonce, size_t nonceLen, uint32_t tagLen,
	uint32_t AADLen, uint32_t payloadLen)
{
	int ret = TEE_ERROR_GENERIC;
	TEE_Result panic_code = 0;
	struct tee_operation *ops = NULL;
	struct tee_object *obj = NULL;
	struct mbedcrypto_aead_ctx *aead = NULL;
	int aead_id = 0;

	if (!nonce)
		TEE_Panic(EFAULT);

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_AE) ||
		!(ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET) ||
		(ops->info.handleState & TEE_HANDLE_FLAG_INITIALIZED)) {
		ret = -EINVAL;
		goto out;
	}

	obj = object_of(ops->key);
	if (!obj) {
		ret = -ENOSR;
		goto out;
	}
	LMSG("mode %d, payloadLen %d AADLen %d tagLen %d\n",
		ops->info.mode, payloadLen, AADLen, tagLen);

	aead_id = __TEE_Algo2AeadId(ops->info.algorithm);
	if (aead_id < 0) {
		ret = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	/* Validate tagLen per algorithm */
	switch (ops->info.algorithm) {
	case TEE_ALG_AES_GCM:
	case TEE_ALG_SM4_GCM:
		if ((tagLen < 96) || (tagLen > 128) || ((tagLen % 8) != 0)) {
			ret = TEE_ERROR_NOT_SUPPORTED;
			goto out;
		}
		if (nonceLen == 0) {
			ret = panic_code = TEE_PANIC_BAD_IV;
			goto out;
		}
		break;
	case TEE_ALG_AES_CCM:
	case TEE_ALG_SM4_CCM:
		if ((tagLen < 32) || (tagLen > 128) || ((tagLen % 16) != 0)) {
			ret = TEE_ERROR_NOT_SUPPORTED;
			goto out;
		}
		if (nonceLen < 7 || nonceLen > 13) {
			ret = panic_code = TEE_PANIC_BAD_IV;
			goto out;
		}
		break;
	case TEE_ALG_CHACHA20_POLY1305:
		if (tagLen != 128) {
			ret = TEE_ERROR_NOT_SUPPORTED;
			goto out;
		}
		if (nonceLen != 12) {
			ret = panic_code = TEE_PANIC_BAD_IV;
			goto out;
		}
		break;
	}

	aead = TEE_Malloc(sizeof(struct mbedcrypto_aead_ctx),
			  TEE_MALLOC_NO_FILL | TEE_MALLOC_NO_SHARE);
	if (!aead) {
		ret = -ENOMEM;
		goto out;
	}

	ret = mbedcrypto_aead_setkey(aead, aead_id,
				obj->attr[0].content.ref.buffer, ops->info.keySize);
	if (ret != 0) {
		panic_code = TEE_PANIC_CRYPTO_FAILURE;
		goto out;
	}

	ret = mbedcrypto_aead_start(aead,
				(ops->info.mode == TEE_MODE_DECRYPT) ?
				MBEDCRYPTO_AEAD_DECRYPT : MBEDCRYPTO_AEAD_ENCRYPT,
				nonce, nonceLen,
				__TEE_IsCCM(ops->info.algorithm) ? tagLen >> 3 : 0,
				__TEE_IsCCM(ops->info.algorithm) ? AADLen : 0,
				__TEE_IsCCM(ops->info.algorithm) ? payloadLen : 0);
	if (ret != 0) {
		panic_code = (ret == -EINVAL) ?
			TEE_PANIC_BAD_IV : TEE_PANIC_CRYPTO_FAILURE;
		goto out;
	}

	ops->ctx = aead;
	ops->tag_len = tagLen >> 3;
	ops->ae_payload_len = __TEE_IsCCM(ops->info.algorithm) ? payloadLen : 0;
	ops->ae_processed_len = 0;

	ops->info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
	ops->operationState = TEE_OPERATION_STATE_INITIAL;
	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret != TEE_SUCCESS) {
		if (aead)
			mbedcrypto_aead_cleanup(aead);
		TEE_Free(aead);
	}
	if (ret == TEE_SUCCESS || ret == TEE_ERROR_NOT_SUPPORTED)
		return ret;
	return __TEE_PanicOrDie(ret, panic_code);
}

static int __TEE_AEUpdateAAD(TEE_OperationHandle operation,
	void *AADdata, size_t AADdataLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;

	if (AADdataLen != 0 && (!AADdata))
		return EFAULT;

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	LMSG("algo %x AADdataLen %d\n", ops->info.algorithm, AADdataLen);

	if ((ops->info.operationClass != TEE_OPERATION_AE) ||
		!(ops->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
		(ops->operationState != TEE_OPERATION_STATE_INITIAL)) {
		ret = -EINVAL;
		goto out;
	}

	ret = mbedcrypto_aead_update_aad(ops->ctx, AADdata, AADdataLen);
	if (ret == -EINVAL)
		ret = -EMSGSIZE;
	if (ret != 0)
		goto out;

	if (AADdataLen != 0)
		ops->operationState = TEE_OPERATION_STATE_ACTIVE;

out:
	object_unlock();
	return ret;
}

void TEE_AEUpdateAAD(TEE_OperationHandle operation,
	void *AADdata, size_t AADdataLen)
{
	int ret = __TEE_AEUpdateAAD(operation, AADdata, AADdataLen);

	if (ret != 0)
		TEE_Panic(ret);
}

TEE_Result TEE_AEUpdateAAD_PS(TEE_OperationHandle operation,
	void *AADdata, size_t AADdataLen)
{
	int ret = __TEE_AEUpdateAAD(operation, AADdata, AADdataLen);

	if (ret != 0) {
		if (ret == -EMSGSIZE)
			return TEE_PANIC_BAD_AAD_LENGTH;
		/* EBADF/EINVAL/EFAULT: programmer error - always panic */
		if (ret == -EBADF || ret == -EINVAL || ret == -EFAULT)
			TEE_Panic(ret);
		/* Crypto/hardware failure: always return TEE_PANIC_xxxx (_PS) */
		return TEE_PANIC_CRYPTO_FAILURE;
	}

	return TEE_SUCCESS;
}

TEE_Result TEE_AEUpdate(TEE_OperationHandle operation, void *srcData,
	size_t srcLen, void *destData, size_t *destLen)
{
	int ret = TEE_ERROR_GENERIC;
	TEE_Result panic_code = 0; /* 0 = programmer error: always panic */
	struct tee_operation *ops = NULL;

	if (!destLen || (*destLen < srcLen))
		return TEE_ERROR_SHORT_BUFFER;

	if (((srcLen > 0) && (!srcData)) ||
		((*destLen > 0) && (!destData)))
		TEE_Panic(EINVAL);

	if (INVALID_BUFF(srcData, destData, srcLen))
		return __TEE_PanicOrReturn(TEE_PANIC_NOT_DISJOINT);

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_AE) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0)) {
		ret = -EINVAL;
		goto out;
	}

	LMSG("aeops->info.algorithm 0x%lx ilen %ld olen %ld\n",
		ops->info.algorithm, (long)srcLen, (long)*destLen);

	/* CCM: check if accumulated data exceeds declared payloadLen */
	if (__TEE_IsCCM(ops->info.algorithm) &&
		(ops->ae_processed_len + srcLen > ops->ae_payload_len)) {
		ret = panic_code = TEE_PANIC_BAD_AAD_LENGTH;
		goto out;
	}

	ret = mbedcrypto_aead_update(ops->ctx, srcData, srcLen,
				destData, destLen);
	if (ret != 0) {
		panic_code = __TEE_PanicOnEINVAL(ret, TEE_PANIC_BAD_AAD_LENGTH);
		goto out;
	}

	ops->ae_processed_len += srcLen;
	if (srcLen != 0)
		ops->operationState = TEE_OPERATION_STATE_ACTIVE;
	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret == TEE_SUCCESS || ret == TEE_ERROR_SHORT_BUFFER ||
		ret == TEE_ERROR_DATA_TO_WRITE)
		return ret;
	return __TEE_PanicOrDie(ret, panic_code);
}

TEE_Result TEE_AEEncryptFinal(TEE_OperationHandle operation,
	void *srcData, size_t srcLen, void *destData, size_t *destLen,
	void *tag, size_t *tagLen)
{
	int ret = TEE_ERROR_GENERIC;
	TEE_Result panic_code = 0; /* 0 = programmer error: always panic */
	struct tee_operation *ops = NULL;
	unsigned char dst[1024];
	size_t off = 0, olen = 0, ilen = 0;

	if (destData) {
		if (!destLen || (*destLen < srcLen))
			return TEE_ERROR_SHORT_BUFFER;
	}

	if ((srcLen > 0) && (!srcData))
		TEE_Panic(EINVAL);

	if (!tag || !tagLen)
		TEE_Panic(EFAULT);

	if (INVALID_BUFF(srcData, destData, srcLen))
		return __TEE_PanicOrReturn(TEE_PANIC_NOT_DISJOINT);

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_AE) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) ||
		(ops->info.mode != TEE_MODE_ENCRYPT)) {
		ret = -EINVAL;
		goto out;
	}

	LMSG("aeops->info.algorithm 0x%lx ilen %ld\n", ops->info.algorithm, (long)srcLen);

	if (*tagLen < ops->tag_len) {
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	/* CCM: check if total data matches declared payloadLen */
	if (__TEE_IsCCM(ops->info.algorithm) &&
		(ops->ae_processed_len + srcLen != ops->ae_payload_len)) {
		ret = panic_code = TEE_PANIC_BAD_AAD_LENGTH;
		goto out;
	}

	if (destData) {
		if (*destLen < srcLen) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		ret = mbedcrypto_aead_update(ops->ctx, srcData, srcLen,
						destData, destLen);
		if (ret != 0) {
			panic_code = __TEE_PanicOnEINVAL(ret, TEE_PANIC_BAD_AAD_LENGTH);
			goto out;
		}

		ret = mbedcrypto_aead_final(ops->ctx, tag, ops->tag_len);
		if (ret != 0) {
			panic_code = __TEE_PanicOnEINVAL(ret, TEE_PANIC_BAD_AAD_LENGTH);
			goto out;
		}
	} else {
		while (srcLen > 0) {
			ilen = min(srcLen, sizeof(dst));
			ret = mbedcrypto_aead_update(ops->ctx, srcData + off,
						ilen, dst, &olen);
			if (ret != 0) {
				panic_code = __TEE_PanicOnEINVAL(ret, TEE_PANIC_BAD_AAD_LENGTH);
				goto out;
			}

			srcLen -= ilen;
			off += ilen;
		}

		ret = mbedcrypto_aead_final(ops->ctx, tag, ops->tag_len);
		if (ret != 0) {
			panic_code = __TEE_PanicOnEINVAL(ret, TEE_PANIC_BAD_AAD_LENGTH);
			goto out;
		}
	}

	*tagLen = ops->tag_len;

	ops->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
	ops->operationState = TEE_OPERATION_STATE_INITIAL;
	if (ops->ctx && ops->info.operationClass == TEE_OPERATION_AE) {
		mbedcrypto_aead_cleanup(ops->ctx);
		TEE_Free(ops->ctx);
		ops->ctx = NULL;
	}
	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret == TEE_SUCCESS || ret == TEE_ERROR_SHORT_BUFFER ||
		ret == TEE_ERROR_DATA_TO_WRITE)
		return ret;
	return __TEE_PanicOrDie(ret, panic_code);
}

TEE_Result TEE_AEDecryptFinal(TEE_OperationHandle operation,
	void *srcData, size_t srcLen, void *destData, size_t *destLen,
	void *tag, size_t tagLen)
{
	int ret = TEE_ERROR_GENERIC;
	TEE_Result panic_code = 0; /* 0 = programmer error: always panic */
	struct tee_operation *ops = NULL;
	size_t off = 0, olen = 0, ilen = 0;
	unsigned char dst[1024];

	if (destData) {
		if (!destLen || (*destLen < srcLen))
			return TEE_ERROR_SHORT_BUFFER;
	}

	if ((srcLen > 0) && (!srcData))
		TEE_Panic(EINVAL);

	if (!tag || (tagLen == 0))
		TEE_Panic(EFAULT);

	if (INVALID_BUFF(srcData, destData, srcLen))
		return __TEE_PanicOrReturn(TEE_PANIC_NOT_DISJOINT);

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_AE) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) ||
		(ops->info.mode != TEE_MODE_DECRYPT)) {
		ret = -EINVAL;
		goto out;
	}

	LMSG("aeops->info.algorithm 0x%lx ilen %ld\n", ops->info.algorithm, (long)srcLen);

	if (tagLen != ops->tag_len) {
		ret = TEE_ERROR_MAC_INVALID;
		goto out;
	}

	/* CCM: check if total data matches declared payloadLen */
	if (__TEE_IsCCM(ops->info.algorithm) &&
		(ops->ae_processed_len + srcLen != ops->ae_payload_len)) {
		ret = panic_code = TEE_PANIC_BAD_AAD_LENGTH;
		goto out;
	}

	if (destData) {
		if (*destLen < srcLen) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		ret = mbedcrypto_aead_update(ops->ctx, srcData, srcLen,
						destData, destLen);
		if (ret != 0) {
			panic_code = __TEE_PanicOnEINVAL(ret, TEE_PANIC_BAD_AAD_LENGTH);
			goto out;
		}

		ret = mbedcrypto_aead_final(ops->ctx, dst, ops->tag_len);
		if (ret != 0) {
			panic_code = __TEE_PanicOnEINVAL(ret, TEE_PANIC_BAD_AAD_LENGTH);
			goto out;
		}
	} else {
		while (srcLen > 0) {
			ilen = min(srcLen, sizeof(dst));
			ret = mbedcrypto_aead_update(ops->ctx, srcData + off,
						ilen, dst, &olen);
			if (ret != 0) {
				panic_code = __TEE_PanicOnEINVAL(ret, TEE_PANIC_BAD_AAD_LENGTH);
				goto out;
			}

			srcLen -= ilen;
			off += ilen;
		}

		ret = mbedcrypto_aead_final(ops->ctx, dst, ops->tag_len);
		if (ret != 0) {
			panic_code = __TEE_PanicOnEINVAL(ret, TEE_PANIC_BAD_AAD_LENGTH);
			goto out;
		}
	}

	if (mbedtee_memcmp(tag, dst, ops->tag_len) != 0)
		ret = TEE_ERROR_MAC_INVALID;
	else
		ret = TEE_SUCCESS;

	ops->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
	ops->operationState = TEE_OPERATION_STATE_INITIAL;
	if (ops->ctx && ops->info.operationClass == TEE_OPERATION_AE) {
		mbedcrypto_aead_cleanup(ops->ctx);
		TEE_Free(ops->ctx);
		ops->ctx = NULL;
	}

out:
	object_unlock();
	if (ret == TEE_SUCCESS ||
		ret == TEE_ERROR_SHORT_BUFFER ||
		ret == TEE_ERROR_MAC_INVALID ||
		ret == TEE_ERROR_DATA_TO_WRITE)
		return ret;
	return __TEE_PanicOrDie(ret, panic_code);
}

static void __TEE_RsaEncPadding(uint32_t algorithm, int *pad, int *hashid)
{
	switch (algorithm) {
	case TEE_ALG_RSAES_PKCS1_V1_5:
		*pad = MBEDCRYPTO_RSA_PKCS1_V15;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
		*pad = MBEDCRYPTO_RSA_PKCS1_V21;
		*hashid = MBEDCRYPTO_HASH_SHA1;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
		*pad = MBEDCRYPTO_RSA_PKCS1_V21;
		*hashid = MBEDCRYPTO_HASH_SHA224;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
		*pad = MBEDCRYPTO_RSA_PKCS1_V21;
		*hashid = MBEDCRYPTO_HASH_SHA256;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
		*pad = MBEDCRYPTO_RSA_PKCS1_V21;
		*hashid = MBEDCRYPTO_HASH_SHA384;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		*pad = MBEDCRYPTO_RSA_PKCS1_V21;
		*hashid = MBEDCRYPTO_HASH_SHA512;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_224:
		*pad = MBEDCRYPTO_RSA_PKCS1_V21;
		*hashid = MBEDCRYPTO_HASH_SHA3_224;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_256:
		*pad = MBEDCRYPTO_RSA_PKCS1_V21;
		*hashid = MBEDCRYPTO_HASH_SHA3_256;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_384:
		*pad = MBEDCRYPTO_RSA_PKCS1_V21;
		*hashid = MBEDCRYPTO_HASH_SHA3_384;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA3_512:
		*pad = MBEDCRYPTO_RSA_PKCS1_V21;
		*hashid = MBEDCRYPTO_HASH_SHA3_512;
		break;
	case TEE_ALG_RSA_NOPAD:
	default:
		break;
	}
}

TEE_Result TEE_AsymmetricEncrypt(TEE_OperationHandle operation,
	TEE_Attribute *params, uint32_t paramCount, void *srcData,
	size_t srcLen, void *destData, size_t *destLen)
{
	int ret = TEE_ERROR_GENERIC;
	TEE_Result panic_code = 0; /* 0 = programmer error: always panic */
	struct tee_operation *ops = NULL;
	struct tee_object *obj = NULL;
	struct mbedcrypto_rsa_ctx ctx = {0};
	unsigned char *N = NULL, *E = NULL;
	size_t n_len = 0, e_len = 0, i = 0, olen = 0;
	int padding = 0, hash_id = MBEDCRYPTO_HASH_NONE;

	if (((paramCount > 0) && (!params)) ||
		((srcLen > 0) && (!srcData)))
		TEE_Panic(EINVAL);

	if (!destLen || ((*destLen > 0) && (!destData)))
		TEE_Panic(EINVAL);

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_ASYMMETRIC_CIPHER) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET) == 0) ||
		(ops->info.mode != TEE_MODE_ENCRYPT)) {
		ret = -EINVAL;
		goto out;
	}

	__TEE_RsaEncPadding(ops->info.algorithm, &padding, &hash_id);

	obj = object_of(ops->key);
	if (!obj) {
		ret = -ENOSR;
		goto out;
	}

	if (ops->info.algorithm == TEE_ALG_SM2_PKE) {
		struct mbedcrypto_sm2pke_ctx sm2pke = {0};

		mbedcrypto_sm2pke_init(&sm2pke);
		ret = mbedcrypto_sm2pke_load_group(&sm2pke);
		if (ret != 0)
			goto sm2_enc_out;

		for (i = 0; i < obj->attr_nr; i++) {
			if (obj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_X) {
				ret = mbedcrypto_bn_from_binary(&sm2pke.Q.X,
					obj->attr[i].content.ref.buffer,
					obj->attr[i].content.ref.length);
			} else if (obj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_Y) {
				ret = mbedcrypto_bn_from_binary(&sm2pke.Q.Y,
					obj->attr[i].content.ref.buffer,
					obj->attr[i].content.ref.length);
			}
			if (ret != 0) {
				ret = -ENOMEM;
				goto sm2_enc_out;
			}
		}
		ret = mbedcrypto_bn_set_word(&sm2pke.Q.Z, 1);
		if (ret != 0)
			goto sm2_enc_out;

		olen = 0;
		ret = mbedcrypto_sm2pke_encrypt(&sm2pke, srcData, srcLen,
				destData, &olen, tee_prng, NULL);
sm2_enc_out:
		mbedcrypto_sm2pke_cleanup(&sm2pke);
		if (ret != 0) {
			panic_code = TEE_PANIC_CRYPTO_FAILURE;
			goto out;
		}
		*destLen = olen;
		ret = TEE_SUCCESS;
		goto out;
	}

	for (i = 0 ; i < obj->attr_nr; i++) {
		if (obj->attr[i].attributeID == TEE_ATTR_RSA_MODULUS) {
			N = obj->attr[i].content.ref.buffer;
			n_len = obj->attr[i].content.ref.length;
		} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_PUBLIC_EXPONENT) {
			E = obj->attr[i].content.ref.buffer;
			e_len = obj->attr[i].content.ref.length;
		}
	}

	if ((!N) || (!E)) {
		ret = -ENOSR;
		goto out;
	}

	mbedcrypto_rsa_init(&ctx);
	mbedcrypto_rsa_configure(&ctx, padding, hash_id);

	/* Parse TEE_ATTR_RSA_OAEP_MGF_HASH for separate MGF1 hash */
	for (i = 0; i < paramCount; i++) {
		if (params[i].attributeID == TEE_ATTR_RSA_OAEP_MGF_HASH) {
			ctx.mgf_hash_id = __TEE_MbedDigestOf(
						params[i].content.value.a);
			if (ctx.mgf_hash_id == MBEDCRYPTO_HASH_NONE) {
				ret = TEE_ERROR_NOT_SUPPORTED;
				goto out;
			}
			break;
		}
	}

	if ((mbedcrypto_rsa_import_components(&ctx, N, n_len, NULL, 0, NULL, 0,
			NULL, 0, E, e_len)) != 0) {
		ret = panic_code = TEE_PANIC_BAD_PARAMETERS;
		goto out;
	}

	olen = mbedcrypto_rsa_len(&ctx);
	if (*destLen < olen) {
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	if (ops->info.algorithm != TEE_ALG_RSA_NOPAD) {
		ret = mbedcrypto_rsa_encrypt(&ctx, tee_prng, NULL,
			srcLen, srcData, destData);
	} else {
		/* RSA NOPAD: input must be padded with leading zeros to modulus length */
		if (srcLen > olen) {
			ret = panic_code = TEE_PANIC_BAD_INPUT_LENGTH;
			goto out;
		}
		if (srcLen < olen) {
			unsigned char *buf = TEE_Malloc(olen, TEE_MALLOC_FILL_ZERO);
			if (!buf) {
				ret = TEE_ERROR_OUT_OF_MEMORY;
				goto out;
			}
			memcpy(buf + olen - srcLen, srcData, srcLen);
			ret = mbedcrypto_rsa_raw_public(&ctx, buf, destData);
			TEE_MemFill(buf, 0, olen);
			TEE_Free(buf);
			if (ret != 0)
				panic_code = TEE_PANIC_CRYPTO_FAILURE;
		} else {
			ret = mbedcrypto_rsa_raw_public(&ctx, srcData, destData);
			if (ret != 0)
				panic_code = TEE_PANIC_CRYPTO_FAILURE;
		}
	}

	if (ret != 0) {
		if (ret == -EINVAL || ret == -EBADMSG)
			panic_code = TEE_PANIC_BAD_INPUT_LENGTH;
		else
			panic_code = TEE_PANIC_CRYPTO_FAILURE;
		goto out;
	}

	*destLen = olen;
	LMSG("asymops->info.algorithm 0x%lx\n", ops->info.algorithm);
	ret = TEE_SUCCESS;

out:
	object_unlock();
	mbedcrypto_rsa_cleanup(&ctx);
	if (ret == TEE_SUCCESS ||
		ret == TEE_ERROR_SHORT_BUFFER ||
		ret == TEE_ERROR_NOT_SUPPORTED)
		return ret;
	return __TEE_PanicOrDie(ret, panic_code);
}

TEE_Result TEE_AsymmetricDecrypt(TEE_OperationHandle operation,
	TEE_Attribute *params, uint32_t paramCount, void *srcData,
	size_t srcLen, void *destData, size_t *destLen)
{
	int ret = TEE_ERROR_GENERIC;
	TEE_Result panic_code = 0; /* 0 = programmer error: always panic */
	struct tee_operation *ops = NULL;
	struct tee_object *obj = NULL;
	struct mbedcrypto_rsa_ctx ctx = {0};
	unsigned char *N = NULL, *E = NULL, *D = NULL;
	unsigned char *P = NULL, *Q = NULL;
	unsigned char *DP = NULL, *DQ = NULL, *QP = NULL;
	size_t n_len = 0, e_len = 0, d_len = 0;
	size_t p_len = 0, q_len = 0;
	size_t dp_len = 0, dq_len = 0, qp_len = 0;
	size_t i = 0, olen = 0;
	int padding = 0, hash_id = MBEDCRYPTO_HASH_NONE;

	if (((paramCount > 0) && (!params)) ||
		((srcLen > 0) && (!srcData)))
		TEE_Panic(EINVAL);

	if (!destLen || ((*destLen > 0) && (!destData)))
		TEE_Panic(EINVAL);

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_ASYMMETRIC_CIPHER) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET) == 0) ||
		(ops->info.mode != TEE_MODE_DECRYPT)) {
		ret = -EINVAL;
		goto out;
	}

	__TEE_RsaEncPadding(ops->info.algorithm, &padding, &hash_id);

	obj = object_of(ops->key);
	if (!obj) {
		ret = -ENOSR;
		goto out;
	}

	if (ops->info.algorithm == TEE_ALG_SM2_PKE) {
		struct mbedcrypto_sm2pke_ctx sm2pke = {0};

		mbedcrypto_sm2pke_init(&sm2pke);
		ret = mbedcrypto_sm2pke_load_group(&sm2pke);
		if (ret != 0)
			goto sm2_dec_out;

		for (i = 0; i < obj->attr_nr; i++) {
			if (obj->attr[i].attributeID == TEE_ATTR_ECC_PRIVATE_VALUE) {
				ret = mbedcrypto_bn_from_binary(&sm2pke.d,
					obj->attr[i].content.ref.buffer,
					obj->attr[i].content.ref.length);
			} else if (obj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_X) {
				ret = mbedcrypto_bn_from_binary(&sm2pke.Q.X,
					obj->attr[i].content.ref.buffer,
					obj->attr[i].content.ref.length);
			} else if (obj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_Y) {
				ret = mbedcrypto_bn_from_binary(&sm2pke.Q.Y,
					obj->attr[i].content.ref.buffer,
					obj->attr[i].content.ref.length);
			}
			if (ret != 0) {
				ret = -ENOMEM;
				goto sm2_dec_out;
			}
		}
		ret = mbedcrypto_bn_set_word(&sm2pke.Q.Z, 1);
		if (ret != 0)
			goto sm2_dec_out;

		olen = 0;
		ret = mbedcrypto_sm2pke_decrypt(&sm2pke, srcData, srcLen,
				destData, &olen);
sm2_dec_out:
		mbedcrypto_sm2pke_cleanup(&sm2pke);
		if (ret != 0) {
			if (ret == (-EBADMSG))
				ret = TEE_ERROR_CIPHERTEXT_INVALID;
			else
				panic_code = TEE_PANIC_CRYPTO_FAILURE;
			goto out;
		}
		*destLen = olen;
		ret = TEE_SUCCESS;
		goto out;
	}

	for (i = 0 ; i < obj->attr_nr; i++) {
		if (obj->attr[i].attributeID == TEE_ATTR_RSA_MODULUS) {
			N = obj->attr[i].content.ref.buffer;
			n_len = obj->attr[i].content.ref.length;
		} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_PUBLIC_EXPONENT) {
			E = obj->attr[i].content.ref.buffer;
			e_len = obj->attr[i].content.ref.length;
		} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_PRIVATE_EXPONENT) {
			D = obj->attr[i].content.ref.buffer;
			d_len = obj->attr[i].content.ref.length;
		} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_PRIME1) {
			P = obj->attr[i].content.ref.buffer;
			p_len = obj->attr[i].content.ref.length;
		} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_PRIME2) {
			Q = obj->attr[i].content.ref.buffer;
			q_len = obj->attr[i].content.ref.length;
		} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_EXPONENT1) {
			DP = obj->attr[i].content.ref.buffer;
			dp_len = obj->attr[i].content.ref.length;
		} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_EXPONENT2) {
			DQ = obj->attr[i].content.ref.buffer;
			dq_len = obj->attr[i].content.ref.length;
		} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_COEFFICIENT) {
			QP = obj->attr[i].content.ref.buffer;
			qp_len = obj->attr[i].content.ref.length;
		}
	}

	if (!N || !D) {
		ret = -ENOSR;
		goto out;
	}

	mbedcrypto_rsa_init(&ctx);
	mbedcrypto_rsa_configure(&ctx, padding, hash_id);

	/* Parse TEE_ATTR_RSA_OAEP_MGF_HASH for separate MGF1 hash */
	for (i = 0; i < paramCount; i++) {
		if (params[i].attributeID == TEE_ATTR_RSA_OAEP_MGF_HASH) {
			ctx.mgf_hash_id = __TEE_MbedDigestOf(
						params[i].content.value.a);
			if (ctx.mgf_hash_id == MBEDCRYPTO_HASH_NONE) {
				ret = TEE_ERROR_NOT_SUPPORTED;
				goto out;
			}
			break;
		}
	}

	ret = mbedcrypto_rsa_import_components(&ctx, N, n_len,
			P, p_len, Q, q_len, D, d_len, E, e_len);
	if (ret != 0) {
		ret = panic_code = TEE_PANIC_BAD_PARAMETERS;
		goto out;
	}

	/* Reuse CRT params from the key object if available */
	if (DP && DQ && QP) {
		ret = mbedcrypto_bn_from_binary(&ctx.DP, DP, dp_len);
		if (ret != 0) {
			panic_code = TEE_PANIC_CRYPTO_FAILURE;
			goto out;
		}
		ret = mbedcrypto_bn_from_binary(&ctx.DQ, DQ, dq_len);
		if (ret != 0) {
			panic_code = TEE_PANIC_CRYPTO_FAILURE;
			goto out;
		}
		ret = mbedcrypto_bn_from_binary(&ctx.QP, QP, qp_len);
		if (ret != 0) {
			panic_code = TEE_PANIC_CRYPTO_FAILURE;
			goto out;
		}
	} else if (mbedcrypto_rsa_derive_crt(&ctx) != 0) {
		ret = panic_code = TEE_PANIC_BAD_PARAMETERS;
		goto out;
	}

	olen = mbedcrypto_rsa_len(&ctx);
	if (olen != srcLen) {
		ret = panic_code = TEE_PANIC_BAD_INPUT_LENGTH;
		goto out;
	}

	if (ops->info.algorithm != TEE_ALG_RSA_NOPAD) {
		ret = mbedcrypto_rsa_decrypt(&ctx, tee_prng, NULL,
			destLen, srcData, destData, *destLen);
		if (ret != 0) {
			if (ret == (-EBADMSG))
				ret = TEE_ERROR_CIPHERTEXT_INVALID;
			else if (ret == (-ERANGE))
				ret = TEE_ERROR_SHORT_BUFFER;
			else
				panic_code = TEE_PANIC_CRYPTO_FAILURE;
			goto out;
		}
	} else {
		/* TEE_ALG_RSA_NOPAD */
		unsigned char *buf = NULL;
		size_t offset = 0;

		buf = TEE_Malloc(olen, TEE_MALLOC_FILL_ZERO);
		if (!buf) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		if (mbedcrypto_rsa_raw_private(&ctx, tee_prng, NULL, srcData, buf) != 0) {
			panic_code = TEE_PANIC_CRYPTO_FAILURE;
			TEE_MemFill(buf, 0, olen);
			TEE_Free(buf);
			goto out;
		}

		/* Remove leading zeros (leave one zero if buf is all zeros) */
		while ((offset < olen - 1) && (buf[offset] == 0))
			offset++;

		if (*destLen < olen - offset) {
			*destLen = olen - offset;
			TEE_MemFill(buf, 0, olen);
			TEE_Free(buf);
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		*destLen = olen - offset;
		memcpy(destData, buf + offset, *destLen);
		TEE_MemFill(buf, 0, olen);
		TEE_Free(buf);
	}

	LMSG("asymops->info.algorithm 0x%lx\n", ops->info.algorithm);
	ret = TEE_SUCCESS;

out:
	object_unlock();
	mbedcrypto_rsa_cleanup(&ctx);
	if (ret == TEE_SUCCESS ||
		ret == TEE_ERROR_SHORT_BUFFER ||
		ret == TEE_ERROR_NOT_SUPPORTED ||
		ret == TEE_ERROR_CIPHERTEXT_INVALID)
		return ret;
	return __TEE_PanicOrDie(ret, panic_code);
}

static int __TEE_SignVerifyDigestInfo(uint32_t algo, int *pad, int *hashid)
{
	int padding = 0, hash_id = MBEDCRYPTO_HASH_NONE;

	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
		padding = MBEDCRYPTO_RSA_PKCS1_V15;
		hash_id = MBEDCRYPTO_HASH_MD5;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
		padding = MBEDCRYPTO_RSA_PKCS1_V15;
		hash_id = MBEDCRYPTO_HASH_SHA1;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
		padding = MBEDCRYPTO_RSA_PKCS1_V15;
		hash_id = MBEDCRYPTO_HASH_SHA224;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
		padding = MBEDCRYPTO_RSA_PKCS1_V15;
		hash_id = MBEDCRYPTO_HASH_SHA256;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
		padding = MBEDCRYPTO_RSA_PKCS1_V15;
		hash_id = MBEDCRYPTO_HASH_SHA384;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		padding = MBEDCRYPTO_RSA_PKCS1_V15;
		hash_id = MBEDCRYPTO_HASH_SHA512;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA3_224:
		padding = MBEDCRYPTO_RSA_PKCS1_V15;
		hash_id = MBEDCRYPTO_HASH_SHA3_224;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA3_256:
		padding = MBEDCRYPTO_RSA_PKCS1_V15;
		hash_id = MBEDCRYPTO_HASH_SHA3_256;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA3_384:
		padding = MBEDCRYPTO_RSA_PKCS1_V15;
		hash_id = MBEDCRYPTO_HASH_SHA3_384;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA3_512:
		padding = MBEDCRYPTO_RSA_PKCS1_V15;
		hash_id = MBEDCRYPTO_HASH_SHA3_512;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
		padding = MBEDCRYPTO_RSA_PKCS1_V21;
		hash_id = MBEDCRYPTO_HASH_SHA1;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		padding = MBEDCRYPTO_RSA_PKCS1_V21;
		hash_id = MBEDCRYPTO_HASH_SHA224;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
		padding = MBEDCRYPTO_RSA_PKCS1_V21;
		hash_id = MBEDCRYPTO_HASH_SHA256;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		padding = MBEDCRYPTO_RSA_PKCS1_V21;
		hash_id = MBEDCRYPTO_HASH_SHA384;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		padding = MBEDCRYPTO_RSA_PKCS1_V21;
		hash_id = MBEDCRYPTO_HASH_SHA512;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_224:
		padding = MBEDCRYPTO_RSA_PKCS1_V21;
		hash_id = MBEDCRYPTO_HASH_SHA3_224;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_256:
		padding = MBEDCRYPTO_RSA_PKCS1_V21;
		hash_id = MBEDCRYPTO_HASH_SHA3_256;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_384:
		padding = MBEDCRYPTO_RSA_PKCS1_V21;
		hash_id = MBEDCRYPTO_HASH_SHA3_384;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA3_512:
		padding = MBEDCRYPTO_RSA_PKCS1_V21;
		hash_id = MBEDCRYPTO_HASH_SHA3_512;
		break;
	case TEE_ALG_DSA_SHA1:
		hash_id = MBEDCRYPTO_HASH_SHA1;
		break;
	case TEE_ALG_DSA_SHA224:
		hash_id = MBEDCRYPTO_HASH_SHA224;
		break;
	case TEE_ALG_DSA_SHA256:
		hash_id = MBEDCRYPTO_HASH_SHA256;
		break;
	case TEE_ALG_DSA_SHA3_224:
		hash_id = MBEDCRYPTO_HASH_SHA3_224;
		break;
	case TEE_ALG_DSA_SHA3_256:
		hash_id = MBEDCRYPTO_HASH_SHA3_256;
		break;
	case TEE_ALG_DSA_SHA3_384:
		hash_id = MBEDCRYPTO_HASH_SHA3_384;
		break;
	case TEE_ALG_DSA_SHA3_512:
		hash_id = MBEDCRYPTO_HASH_SHA3_512;
		break;
	case TEE_ALG_ECDSA_SHA1:
		hash_id = MBEDCRYPTO_HASH_SHA1;
		break;
	case TEE_ALG_ECDSA_SHA224:
		hash_id = MBEDCRYPTO_HASH_SHA224;
		break;
	case TEE_ALG_ECDSA_SHA256:
		hash_id = MBEDCRYPTO_HASH_SHA256;
		break;
	case TEE_ALG_ECDSA_SHA384:
		hash_id = MBEDCRYPTO_HASH_SHA384;
		break;
	case TEE_ALG_ECDSA_SHA512:
		hash_id = MBEDCRYPTO_HASH_SHA512;
		break;
	case TEE_ALG_ECDSA_SHA3_224:
		hash_id = MBEDCRYPTO_HASH_SHA3_224;
		break;
	case TEE_ALG_ECDSA_SHA3_256:
		hash_id = MBEDCRYPTO_HASH_SHA3_256;
		break;
	case TEE_ALG_ECDSA_SHA3_384:
		hash_id = MBEDCRYPTO_HASH_SHA3_384;
		break;
	case TEE_ALG_ECDSA_SHA3_512:
		hash_id = MBEDCRYPTO_HASH_SHA3_512;
		break;
	case TEE_ALG_SM2_DSA_SM3:
		hash_id = MBEDCRYPTO_HASH_SM3;
		break;
	case TEE_ALG_ED25519:
	case TEE_ALG_ED448:
		*pad = 0;
		*hashid = MBEDCRYPTO_HASH_NONE;
		return 0;
	default:
		break;
	}

	if (hash_id == MBEDCRYPTO_HASH_NONE)
		return ENOTSUP;

	*pad = padding;
	*hashid = hash_id;
	return 0;
}

TEE_Result TEE_AsymmetricSignDigest(TEE_OperationHandle operation,
	TEE_Attribute *params, uint32_t paramCount, void *digest,
	size_t digestLen, void *signature, size_t *signatureLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;
	struct tee_object *obj = NULL;
	struct mbedcrypto_rsa_ctx rsa = {0};
	struct mbedcrypto_dsa_ctx dsa = {0};
	struct mbedcrypto_ecdsa_ctx ecdsa = {0};
	struct mbedcrypto_sm2dsa_ctx sm2dsa = {0};
	size_t i = 0, olen = 0;
	int padding = 0, hash_id = MBEDCRYPTO_HASH_NONE;

	if (((paramCount > 0) && (!params)) ||
		(!digest) || (!signature) || (!signatureLen))
		TEE_Panic(EINVAL);

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_ASYMMETRIC_SIGNATURE) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET) == 0) ||
		(ops->info.mode != TEE_MODE_SIGN)) {
		ret = -EINVAL;
		goto out;
	}

	ret = __TEE_SignVerifyDigestInfo(ops->info.algorithm,
			&padding, &hash_id);
	if (ret != 0) {
		ret = TEE_PANIC_INVALID_ALG;
		goto out;
	}

	if (hash_id != MBEDCRYPTO_HASH_NONE &&
		(mbedcrypto_hash_size(hash_id) == 0 ||
		 mbedcrypto_hash_size(hash_id) != digestLen)) {
		ret = TEE_PANIC_BAD_INPUT_LENGTH;
		goto out;
	}

	obj = object_of(ops->key);
	if (!obj) {
		ret = -ENOSR;
		goto out;
	}

	if (obj->info.objectType == TEE_TYPE_RSA_KEYPAIR) {
		unsigned char *N = NULL, *E = NULL, *D = NULL;
		unsigned char *P = NULL, *Q = NULL;
		unsigned char *DP = NULL, *DQ = NULL, *QP = NULL;
		size_t n_len = 0, e_len = 0, d_len = 0;
		size_t p_len = 0, q_len = 0;
		size_t dp_len = 0, dq_len = 0, qp_len = 0;

		for (i = 0 ; i < obj->attr_nr; i++) {
			if (obj->attr[i].attributeID == TEE_ATTR_RSA_MODULUS) {
				N = obj->attr[i].content.ref.buffer;
				n_len = obj->attr[i].content.ref.length;
			} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_PUBLIC_EXPONENT) {
				E = obj->attr[i].content.ref.buffer;
				e_len = obj->attr[i].content.ref.length;
			} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_PRIVATE_EXPONENT) {
				D = obj->attr[i].content.ref.buffer;
				d_len = obj->attr[i].content.ref.length;
			} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_PRIME1) {
				P = obj->attr[i].content.ref.buffer;
				p_len = obj->attr[i].content.ref.length;
			} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_PRIME2) {
				Q = obj->attr[i].content.ref.buffer;
				q_len = obj->attr[i].content.ref.length;
			} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_EXPONENT1) {
				DP = obj->attr[i].content.ref.buffer;
				dp_len = obj->attr[i].content.ref.length;
			} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_EXPONENT2) {
				DQ = obj->attr[i].content.ref.buffer;
				dq_len = obj->attr[i].content.ref.length;
			} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_COEFFICIENT) {
				QP = obj->attr[i].content.ref.buffer;
				qp_len = obj->attr[i].content.ref.length;
			}
		}

		mbedcrypto_rsa_init(&rsa);
		mbedcrypto_rsa_configure(&rsa, padding, hash_id);

		ret = mbedcrypto_rsa_import_components(&rsa, N, n_len,
				P, p_len, Q, q_len, D, d_len, E, e_len);
		if (ret != 0)
			goto out;

		/* Reuse CRT params from the key object if available */
		if (DP && DQ && QP) {
			ret = mbedcrypto_bn_from_binary(&rsa.DP, DP, dp_len);
			if (ret != 0)
				goto out;
			ret = mbedcrypto_bn_from_binary(&rsa.DQ, DQ, dq_len);
			if (ret != 0)
				goto out;
			ret = mbedcrypto_bn_from_binary(&rsa.QP, QP, qp_len);
			if (ret != 0)
				goto out;
		} else {
			ret = mbedcrypto_rsa_derive_crt(&rsa);
			if (ret != 0)
				goto out;
		}

		olen = mbedcrypto_rsa_len(&rsa);

		if (*signatureLen < olen) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		ret = mbedcrypto_rsa_sign(&rsa, tee_prng, NULL,
				hash_id, digestLen, digest, signature);
		if (ret != 0)
			goto out;
		*signatureLen = olen;
	} else if (obj->info.objectType == TEE_TYPE_ECDSA_KEYPAIR) {
		mbedcrypto_ecdsa_init(&ecdsa);
		for (i = 0; i < obj->attr_nr; i++) {
			if (obj->attr[i].attributeID == TEE_ATTR_ECC_PRIVATE_VALUE) {
				ret = mbedcrypto_bn_from_binary(&ecdsa.d,
					obj->attr[i].content.ref.buffer,
					obj->attr[i].content.ref.length);
				if (ret != 0) {
					ret = -ENOMEM;
					goto out;
				}
			} else if (obj->attr[i].attributeID == TEE_ATTR_ECC_CURVE) {
				ret = mbedcrypto_ecp_load_group(&ecdsa.grp,
						__TEE_MbedEccCurveOf(obj->attr[i].content.value.a));
				if (ret != 0)
					goto out;
			}
		}

		if (*signatureLen < MBEDCRYPTO_ECDSA_MAX_SIG_LEN(ops->info.keySize)) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		ret = mbedcrypto_ecdsa_sign(&ecdsa, hash_id, digest,
			digestLen, signature, *signatureLen, signatureLen, tee_prng, NULL);
		if (ret != 0) {
			if (ret == -ERANGE)
				ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}
	} else if (obj->info.objectType == TEE_TYPE_DSA_KEYPAIR) {
		unsigned char *P = NULL, *Q = NULL;
		unsigned char *G = NULL, *Y = NULL, *X = NULL;
		size_t p_len = 0, q_len = 0, g_len = 0, y_len = 0, x_len = 0;

		mbedcrypto_dsa_init(&dsa);
		for (i = 0 ; i < obj->attr_nr; i++) {
			if (obj->attr[i].attributeID == TEE_ATTR_DSA_PRIME) {
				P = obj->attr[i].content.ref.buffer;
				p_len = obj->attr[i].content.ref.length;
			} else if (obj->attr[i].attributeID == TEE_ATTR_DSA_SUBPRIME) {
				Q = obj->attr[i].content.ref.buffer;
				q_len = obj->attr[i].content.ref.length;
			} else if (obj->attr[i].attributeID == TEE_ATTR_DSA_BASE) {
				G = obj->attr[i].content.ref.buffer;
				g_len = obj->attr[i].content.ref.length;
			} else if (obj->attr[i].attributeID == TEE_ATTR_DSA_PRIVATE_VALUE) {
				X = obj->attr[i].content.ref.buffer;
				x_len = obj->attr[i].content.ref.length;
			} else if (obj->attr[i].attributeID == TEE_ATTR_DSA_PUBLIC_VALUE) {
				Y = obj->attr[i].content.ref.buffer;
				y_len = obj->attr[i].content.ref.length;
			}
		}

		ret = mbedcrypto_dsa_import_components(&dsa, P, p_len, Q, q_len,
				G, g_len, Y, y_len, X, x_len);
		if (ret != 0)
			goto out;

		if (*signatureLen < MBEDCRYPTO_DSA_MAX_SIG_LEN(q_len << 3)) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}
		ret = mbedcrypto_dsa_sign(&dsa, tee_prng, NULL,
				digestLen, digest, signature, signatureLen);
		if (ret != 0)
			goto out;
	} else if (obj->info.objectType == TEE_TYPE_ED25519_KEYPAIR) {
		uint8_t ed_priv[2 * MBEDCRYPTO_ED25519_KEY_SIZE];
		uint8_t *priv = NULL, *pub = NULL;

		for (i = 0; i < obj->attr_nr; i++) {
			if (obj->attr[i].attributeID == TEE_ATTR_ECC_PRIVATE_VALUE)
				priv = obj->attr[i].content.ref.buffer;
			else if (obj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_X)
				pub = obj->attr[i].content.ref.buffer;
		}
		if (!priv || !pub) {
			ret = -EINVAL;
			goto out;
		}
		if (*signatureLen < MBEDCRYPTO_ED25519_SIG_SIZE) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}
		memcpy(ed_priv, priv, MBEDCRYPTO_ED25519_KEY_SIZE);
		memcpy(ed_priv + MBEDCRYPTO_ED25519_KEY_SIZE, pub,
				MBEDCRYPTO_ED25519_KEY_SIZE);
		ret = mbedcrypto_ed25519_sign(signature, digest,
				digestLen, ed_priv);
		memset(ed_priv, 0, sizeof(ed_priv));
		if (ret != 0)
			goto out;
		*signatureLen = MBEDCRYPTO_ED25519_SIG_SIZE;
	} else if (obj->info.objectType == TEE_TYPE_ED448_KEYPAIR) {
		uint8_t ed_priv[2 * MBEDCRYPTO_ED448_KEY_SIZE];
		uint8_t *priv = NULL, *pub = NULL;

		for (i = 0; i < obj->attr_nr; i++) {
			if (obj->attr[i].attributeID == TEE_ATTR_ECC_PRIVATE_VALUE)
				priv = obj->attr[i].content.ref.buffer;
			else if (obj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_X)
				pub = obj->attr[i].content.ref.buffer;
		}
		if (!priv || !pub) {
			ret = -EINVAL;
			goto out;
		}
		if (*signatureLen < MBEDCRYPTO_ED448_SIG_SIZE) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}
		memcpy(ed_priv, priv, MBEDCRYPTO_ED448_KEY_SIZE);
		memcpy(ed_priv + MBEDCRYPTO_ED448_KEY_SIZE, pub,
				MBEDCRYPTO_ED448_KEY_SIZE);
		ret = mbedcrypto_ed448_sign(signature, digest,
				digestLen, ed_priv);
		memset(ed_priv, 0, sizeof(ed_priv));
		if (ret != 0)
			goto out;
		*signatureLen = MBEDCRYPTO_ED448_SIG_SIZE;
	} else if (obj->info.objectType == TEE_TYPE_SM2_DSA_KEYPAIR) {
		mbedcrypto_sm2dsa_init(&sm2dsa);
		for (i = 0; i < obj->attr_nr; i++) {
			if (obj->attr[i].attributeID == TEE_ATTR_ECC_PRIVATE_VALUE) {
				ret = mbedcrypto_bn_from_binary(&sm2dsa.d,
					obj->attr[i].content.ref.buffer,
					obj->attr[i].content.ref.length);
				if (ret != 0) {
					ret = -ENOMEM;
					goto out;
				}
			} else if (obj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_X) {
				ret = mbedcrypto_bn_from_binary(&sm2dsa.Q.X,
					obj->attr[i].content.ref.buffer,
					obj->attr[i].content.ref.length);
				if (ret != 0) {
					ret = -ENOMEM;
					goto out;
				}
			} else if (obj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_Y) {
				ret = mbedcrypto_bn_from_binary(&sm2dsa.Q.Y,
					obj->attr[i].content.ref.buffer,
					obj->attr[i].content.ref.length);
				if (ret != 0) {
					ret = -ENOMEM;
					goto out;
				}
			}
		}
		ret = mbedcrypto_sm2dsa_load_group(&sm2dsa);
		if (ret != 0)
			goto out;
		ret = mbedcrypto_bn_set_word(&sm2dsa.Q.Z, 1);
		if (ret != 0)
			goto out;

		if (*signatureLen < MBEDCRYPTO_SM2DSA_MAX_SIG_LEN) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}
		ret = mbedcrypto_sm2dsa_sign(&sm2dsa, digest,
			digestLen, signature, *signatureLen, signatureLen,
			tee_prng, NULL);
		if (ret != 0)
			goto out;
	} else {
		ret = -ENOTSUP;
		goto out;
	}

	LMSG("asymops->info.algorithm 0x%lx\n", ops->info.algorithm);
	ret = TEE_SUCCESS;

out:
	object_unlock();
	mbedcrypto_rsa_cleanup(&rsa);
	mbedcrypto_dsa_cleanup(&dsa);
	mbedcrypto_ecdsa_cleanup(&ecdsa);
	mbedcrypto_sm2dsa_cleanup(&sm2dsa);
	return __TEE_AsymRet(ret, TEE_ERROR_SHORT_BUFFER);
}

TEE_Result TEE_AsymmetricVerifyDigest(TEE_OperationHandle operation,
	TEE_Attribute *params, uint32_t paramCount, void *digest,
	size_t digestLen, void *signature, size_t signatureLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;
	struct tee_object *obj = NULL;
	struct mbedcrypto_rsa_ctx rsa = {0};
	struct mbedcrypto_dsa_ctx dsa = {0};
	struct mbedcrypto_ecdsa_ctx ecdsa = {0};
	struct mbedcrypto_sm2dsa_ctx sm2dsa = {0};
	size_t i = 0, olen = 0;
	int padding = 0, hash_id = MBEDCRYPTO_HASH_NONE;
	if (((paramCount > 0) && (!params)) ||
		(!digest) || (!signature))
		TEE_Panic(EINVAL);

	object_lock();
	ops = object_of(operation);
	if (!ops) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_ASYMMETRIC_SIGNATURE) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET) == 0) ||
		(ops->info.mode != TEE_MODE_VERIFY)) {
		ret = -EINVAL;
		goto out;
	}

	ret = __TEE_SignVerifyDigestInfo(ops->info.algorithm,
				&padding, &hash_id);
	if (ret != 0) {
		ret = TEE_PANIC_INVALID_ALG;
		goto out;
	}

	if (hash_id != MBEDCRYPTO_HASH_NONE &&
		(mbedcrypto_hash_size(hash_id) == 0 ||
		 mbedcrypto_hash_size(hash_id) != digestLen)) {
		ret = TEE_PANIC_BAD_INPUT_LENGTH;
		goto out;
	}

	obj = object_of(ops->key);
	if (!obj) {
		ret = -ENOSR;
		goto out;
	}

	if ((obj->info.objectType == TEE_TYPE_RSA_PUBLIC_KEY) ||
		(obj->info.objectType == TEE_TYPE_RSA_KEYPAIR)) {
		unsigned char *N = NULL, *E = NULL;
		size_t n_len = 0, e_len = 0;

		for (i = 0 ; i < obj->attr_nr; i++) {
			if (obj->attr[i].attributeID == TEE_ATTR_RSA_MODULUS) {
				N = obj->attr[i].content.ref.buffer;
				n_len = obj->attr[i].content.ref.length;
			} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_PUBLIC_EXPONENT) {
				E = obj->attr[i].content.ref.buffer;
				e_len = obj->attr[i].content.ref.length;
			}
		}

		mbedcrypto_rsa_init(&rsa);
		mbedcrypto_rsa_configure(&rsa, padding, hash_id);

		if ((mbedcrypto_rsa_import_components(&rsa, N, n_len, NULL, 0, NULL, 0,
				NULL, 0, E, e_len)) != 0)
			goto out;

		olen = mbedcrypto_rsa_len(&rsa);

		if (signatureLen != olen) {
			ret = TEE_ERROR_SIGNATURE_INVALID;
			goto out;
		}

		ret = mbedcrypto_rsa_verify(&rsa, hash_id, digestLen, digest, signature);
		if (ret != 0) {
			if (ret == (-EBADMSG))
				ret = TEE_ERROR_SIGNATURE_INVALID;
			goto out;
		}
	} else if ((obj->info.objectType == TEE_TYPE_ECDSA_PUBLIC_KEY) ||
			(obj->info.objectType == TEE_TYPE_ECDSA_KEYPAIR)) {
		mbedcrypto_ecdsa_init(&ecdsa);
		for (i = 0; i < obj->attr_nr; i++) {
			if (obj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_X) {
				ret = mbedcrypto_bn_from_binary(&ecdsa.Q.X,
					obj->attr[i].content.ref.buffer,
					obj->attr[i].content.ref.length);
				if (ret != 0) {
					ret = -ENOMEM;
					goto out;
				}
			} else if (obj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_Y) {
				ret = mbedcrypto_bn_from_binary(&ecdsa.Q.Y,
					obj->attr[i].content.ref.buffer,
					obj->attr[i].content.ref.length);
				if (ret != 0) {
					ret = -ENOMEM;
					goto out;
				}
			} else if (obj->attr[i].attributeID == TEE_ATTR_ECC_CURVE) {
				ret = mbedcrypto_ecp_load_group(&ecdsa.grp,
					__TEE_MbedEccCurveOf(obj->attr[i].content.value.a));
				if (ret != 0)
					goto out;
			}
		}

		ret = mbedcrypto_bn_set_word(&ecdsa.Q.Z, 1);
		if (ret != 0)
			goto out;

		ret = mbedcrypto_ecdsa_verify(&ecdsa, digest,
					digestLen, signature, signatureLen);
		if (ret != 0) {
			if (ret == (-EBADMSG) ||
				ret == (-EINVAL))
				ret = TEE_ERROR_SIGNATURE_INVALID;
			goto out;
		}
	} else if ((obj->info.objectType == TEE_TYPE_DSA_PUBLIC_KEY) ||
		(obj->info.objectType == TEE_TYPE_DSA_KEYPAIR)) {
		unsigned char *P = NULL, *Q = NULL;
		unsigned char *G = NULL, *Y = NULL;
		size_t p_len = 0, q_len = 0, g_len = 0, y_len = 0;

		mbedcrypto_dsa_init(&dsa);
		for (i = 0 ; i < obj->attr_nr; i++) {
			if (obj->attr[i].attributeID == TEE_ATTR_DSA_PRIME) {
				P = obj->attr[i].content.ref.buffer;
				p_len = obj->attr[i].content.ref.length;
			} else if (obj->attr[i].attributeID == TEE_ATTR_DSA_SUBPRIME) {
				Q = obj->attr[i].content.ref.buffer;
				q_len = obj->attr[i].content.ref.length;
			} else if (obj->attr[i].attributeID == TEE_ATTR_DSA_BASE) {
				G = obj->attr[i].content.ref.buffer;
				g_len = obj->attr[i].content.ref.length;
			} else if (obj->attr[i].attributeID == TEE_ATTR_DSA_PUBLIC_VALUE) {
				Y = obj->attr[i].content.ref.buffer;
				y_len = obj->attr[i].content.ref.length;
			}
		}

		ret = mbedcrypto_dsa_import_components(&dsa, P, p_len, Q, q_len,
				G, g_len, Y, y_len, NULL, 0);
		if (ret != 0)
			goto out;

		ret = mbedcrypto_dsa_verify(&dsa,
				digestLen, digest, signature, signatureLen);
		if (ret != 0) {
			if (ret == (-EBADMSG))
				ret = TEE_ERROR_SIGNATURE_INVALID;
			goto out;
		}
	} else if ((obj->info.objectType == TEE_TYPE_ED25519_PUBLIC_KEY) ||
		(obj->info.objectType == TEE_TYPE_ED25519_KEYPAIR)) {
		uint8_t *pub = NULL;

		for (i = 0; i < obj->attr_nr; i++) {
			if (obj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_X)
				pub = obj->attr[i].content.ref.buffer;
		}
		if (!pub) {
			ret = -EINVAL;
			goto out;
		}
		if (signatureLen != MBEDCRYPTO_ED25519_SIG_SIZE) {
			ret = TEE_ERROR_SIGNATURE_INVALID;
			goto out;
		}
		ret = mbedcrypto_ed25519_verify(signature, digest,
				digestLen, pub);
		if (ret != 0) {
			ret = TEE_ERROR_SIGNATURE_INVALID;
			goto out;
		}
	} else if ((obj->info.objectType == TEE_TYPE_ED448_PUBLIC_KEY) ||
		(obj->info.objectType == TEE_TYPE_ED448_KEYPAIR)) {
		uint8_t *pub = NULL;

		for (i = 0; i < obj->attr_nr; i++) {
			if (obj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_X)
				pub = obj->attr[i].content.ref.buffer;
		}
		if (!pub) {
			ret = -EINVAL;
			goto out;
		}
		if (signatureLen != MBEDCRYPTO_ED448_SIG_SIZE) {
			ret = TEE_ERROR_SIGNATURE_INVALID;
			goto out;
		}
		ret = mbedcrypto_ed448_verify(signature, digest,
				digestLen, pub);
		if (ret != 0) {
			ret = TEE_ERROR_SIGNATURE_INVALID;
			goto out;
		}
	} else if ((obj->info.objectType == TEE_TYPE_SM2_DSA_PUBLIC_KEY) ||
		(obj->info.objectType == TEE_TYPE_SM2_DSA_KEYPAIR)) {
		mbedcrypto_sm2dsa_init(&sm2dsa);
		for (i = 0; i < obj->attr_nr; i++) {
			if (obj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_X) {
				ret = mbedcrypto_bn_from_binary(&sm2dsa.Q.X,
					obj->attr[i].content.ref.buffer,
					obj->attr[i].content.ref.length);
				if (ret != 0) {
					ret = -ENOMEM;
					goto out;
				}
			} else if (obj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_Y) {
				ret = mbedcrypto_bn_from_binary(&sm2dsa.Q.Y,
					obj->attr[i].content.ref.buffer,
					obj->attr[i].content.ref.length);
				if (ret != 0) {
					ret = -ENOMEM;
					goto out;
				}
			}
		}
		ret = mbedcrypto_sm2dsa_load_group(&sm2dsa);
		if (ret != 0)
			goto out;
		ret = mbedcrypto_bn_set_word(&sm2dsa.Q.Z, 1);
		if (ret != 0)
			goto out;

		ret = mbedcrypto_sm2dsa_verify(&sm2dsa, digest,
				digestLen, signature, signatureLen);
		if (ret != 0) {
			if (ret == -EBADMSG || ret == -EINVAL)
				ret = TEE_ERROR_SIGNATURE_INVALID;
			goto out;
		}
	} else {
		ret = -ENOTSUP;
		goto out;
	}

	ret = TEE_SUCCESS;

out:
	object_unlock();
	mbedcrypto_rsa_cleanup(&rsa);
	mbedcrypto_dsa_cleanup(&dsa);
	mbedcrypto_ecdsa_cleanup(&ecdsa);
	mbedcrypto_sm2dsa_cleanup(&sm2dsa);
	return __TEE_AsymRet(ret, TEE_ERROR_SIGNATURE_INVALID);
}

static int __TEE_DeriveKeyCommon(TEE_OperationHandle operation,
		TEE_Attribute *params, uint32_t paramCount,
		TEE_ObjectHandle derivedKey)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;
	struct tee_object *obj = NULL;
	struct tee_object *kobj = NULL;
	struct mbedcrypto_dh_ctx dhm = {0};
	struct mbedcrypto_ecdh_ctx ecdh = {0};
	unsigned char *secret = NULL;
	size_t olen = 0, i = 0, dhm_len = 0;

	object_lock();
	ops = object_of(operation);
	obj = object_of(derivedKey);
	if ((!ops) || (!obj)) {
		ret = -EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_KEY_DERIVATION) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET) == 0) ||
		(ops->info.mode != TEE_MODE_DERIVE)) {
		ret = -EINVAL;
		goto out;
	}

	if ((paramCount == 0) || (!params)) {
		ret = TEE_PANIC_MISSING_PARAMETER;
		goto out;
	}

	kobj = object_of(ops->key);
	if (!kobj) {
		ret = -ENOSR;
		goto out;
	}

	if (ops->info.algorithm == TEE_ALG_DH_DERIVE_SHARED_SECRET) {
		mbedcrypto_dh_init(&dhm);
		for (i = 0; i < paramCount; i++) {
			if (params[i].attributeID == TEE_ATTR_DH_PUBLIC_VALUE) {
				if (mbedcrypto_bn_from_binary(&dhm.GY,
					params[i].content.ref.buffer,
					params[i].content.ref.length) != 0) {
					ret = -ENOMEM;
					goto out;
				}
				break;
			}
		}

		if (mbedcrypto_bn_byte_count(&dhm.GY) == 0) {
			ret = TEE_PANIC_MISSING_PARAMETER;
			goto out;
		}

		for (i = 0; i < kobj->attr_nr; i++) {
			if (kobj->attr[i].attributeID == TEE_ATTR_DH_PRIME) {
				if (mbedcrypto_bn_from_binary(&dhm.P,
					kobj->attr[i].content.ref.buffer,
					kobj->attr[i].content.ref.length) != 0) {
					ret = -ENOMEM;
					goto out;
				}
			} else if (kobj->attr[i].attributeID == TEE_ATTR_DH_BASE) {
				if (mbedcrypto_bn_from_binary(&dhm.G,
					kobj->attr[i].content.ref.buffer,
					kobj->attr[i].content.ref.length) != 0) {
					ret = -ENOMEM;
					goto out;
				}
			} else if (kobj->attr[i].attributeID == TEE_ATTR_DH_PRIVATE_VALUE) {
				if (mbedcrypto_bn_from_binary(&dhm.X,
					kobj->attr[i].content.ref.buffer,
					kobj->attr[i].content.ref.length) != 0) {
					ret = -ENOMEM;
					goto out;
				}
			} else if (kobj->attr[i].attributeID == TEE_ATTR_DH_PUBLIC_VALUE) {
				if (mbedcrypto_bn_from_binary(&dhm.GX,
					kobj->attr[i].content.ref.buffer,
					kobj->attr[i].content.ref.length) != 0) {
					ret = -ENOMEM;
					goto out;
				}
			}
		}

		dhm_len = mbedcrypto_dh_len(&dhm);
		if (obj->info.maxObjectSize < dhm_len * 8) {
			ret = -E2BIG;
			goto out;
		}

		secret = TEE_Malloc(obj->info.maxObjectSize / 8, TEE_MALLOC_FILL_ZERO);
		if (!secret) {
			ret = -ENOMEM;
			goto out;
		}

		ret = mbedcrypto_dh_derive_shared(&dhm, secret, dhm_len,
						&olen, tee_prng, NULL);
		if (ret != 0)
			goto out;
	} else if (ops->info.algorithm == TEE_ALG_ECDH_DERIVE_SHARED_SECRET) {
		mbedcrypto_ecdh_init(&ecdh);
		for (i = 0; i < paramCount; i++) {
			if (params[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_X) {
				if (mbedcrypto_bn_from_binary(&ecdh.Qp.X,
					params[i].content.ref.buffer,
					params[i].content.ref.length) != 0) {
					ret = -ENOMEM;
					goto out;
				}
			} else if (params[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_Y) {
				if (mbedcrypto_bn_from_binary(&ecdh.Qp.Y,
					params[i].content.ref.buffer,
					params[i].content.ref.length) != 0) {
					ret = -ENOMEM;
					goto out;
				}
			}
		}

		if ((mbedcrypto_bn_byte_count(&ecdh.Qp.X) == 0) ||
			(mbedcrypto_bn_byte_count(&ecdh.Qp.Y) == 0)) {
			ret = TEE_PANIC_MISSING_PARAMETER;
			goto out;
		}

		ret = mbedcrypto_bn_set_word(&ecdh.Qp.Z, 1);
		if (ret != 0)
			goto out;

		for (i = 0; i < kobj->attr_nr; i++) {
			if (kobj->attr[i].attributeID == TEE_ATTR_ECC_PRIVATE_VALUE) {
				if (mbedcrypto_bn_from_binary(&ecdh.d,
					kobj->attr[i].content.ref.buffer,
					kobj->attr[i].content.ref.length) != 0) {
					ret = -ENOMEM;
					goto out;
				}
			} else if (kobj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_X) {
				if (mbedcrypto_bn_from_binary(&ecdh.Q.X,
					kobj->attr[i].content.ref.buffer,
					kobj->attr[i].content.ref.length) != 0) {
					ret = -ENOMEM;
					goto out;
				}
			} else if (kobj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_Y) {
				if (mbedcrypto_bn_from_binary(&ecdh.Q.Y,
					kobj->attr[i].content.ref.buffer,
					kobj->attr[i].content.ref.length) != 0) {
					ret = -ENOMEM;
					goto out;
				}
			} else if (kobj->attr[i].attributeID == TEE_ATTR_ECC_CURVE) {
				ret = mbedcrypto_ecp_load_group(&ecdh.grp,
						__TEE_MbedEccCurveOf(kobj->attr[i].content.value.a));
				if (ret != 0)
					goto out;
			}
		}

		olen = roundup(obj->info.maxObjectSize, 8) / 8;
		secret = TEE_Malloc(olen, TEE_MALLOC_FILL_ZERO);
		if (!secret) {
			ret = -ENOMEM;
			goto out;
		}

		ret = mbedcrypto_ecdh_derive_shared(&ecdh, &olen, secret,
				olen, tee_prng, NULL);
		if (ret != 0)
			goto out;
	} else if (ops->info.algorithm == TEE_ALG_X25519) {
		uint8_t *priv = NULL, *peer_pub = NULL;

		/* Get peer's public key from params */
		for (i = 0; i < paramCount; i++) {
			if (params[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_X ||
			    params[i].attributeID == TEE_ATTR_X25519_PUBLIC_VALUE) {
				peer_pub = params[i].content.ref.buffer;
				break;
			}
		}
		if (!peer_pub) {
			ret = TEE_PANIC_MISSING_PARAMETER;
			goto out;
		}

		/* Get our private key */
		for (i = 0; i < kobj->attr_nr; i++) {
			if (kobj->attr[i].attributeID == TEE_ATTR_ECC_PRIVATE_VALUE) {
				priv = kobj->attr[i].content.ref.buffer;
				break;
			}
		}
		if (!priv) {
			ret = TEE_PANIC_MISSING_PARAMETER;
			goto out;
		}

		olen = MBEDCRYPTO_X25519_KEY_SIZE;
		secret = TEE_Malloc(olen, TEE_MALLOC_FILL_ZERO);
		if (!secret) {
			ret = -ENOMEM;
			goto out;
		}

		ret = mbedcrypto_x25519_calc_secret(secret, priv, peer_pub);
		if (ret != 0)
			goto out;
	} else if (ops->info.algorithm == TEE_ALG_X448) {
		uint8_t *priv = NULL, *peer_pub = NULL;

		/* Get peer's public key from params */
		for (i = 0; i < paramCount; i++) {
			if (params[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_X) {
				peer_pub = params[i].content.ref.buffer;
				break;
			}
		}
		if (!peer_pub) {
			ret = TEE_PANIC_MISSING_PARAMETER;
			goto out;
		}

		/* Get our private key */
		for (i = 0; i < kobj->attr_nr; i++) {
			if (kobj->attr[i].attributeID == TEE_ATTR_ECC_PRIVATE_VALUE) {
				priv = kobj->attr[i].content.ref.buffer;
				break;
			}
		}
		if (!priv) {
			ret = TEE_PANIC_MISSING_PARAMETER;
			goto out;
		}

		olen = MBEDCRYPTO_X448_KEY_SIZE;
		secret = TEE_Malloc(olen, TEE_MALLOC_FILL_ZERO);
		if (!secret) {
			ret = -ENOMEM;
			goto out;
		}

		ret = mbedcrypto_x448_calc_secret(secret, priv, peer_pub);
		if (ret != 0)
			goto out;
	} else if (ops->info.algorithm == TEE_ALG_HKDF) {
		uint8_t *ikm = NULL, *salt = NULL, *info = NULL;
		size_t ikm_len = 0, salt_len = 0, info_len = 0;
		int hash_id = MBEDCRYPTO_HASH_SHA256;

		/* Get IKM from key object */
		for (i = 0; i < kobj->attr_nr; i++) {
			if (kobj->attr[i].attributeID == TEE_ATTR_SECRET_VALUE) {
				ikm = kobj->attr[i].content.ref.buffer;
				ikm_len = kobj->attr[i].content.ref.length;
				break;
			}
		}
		if (!ikm) {
			ret = -EINVAL;
			goto out;
		}

		/* Get optional salt, info and hash algorithm from params */
		for (i = 0; i < paramCount; i++) {
			if (params[i].attributeID == TEE_ATTR_HKDF_SALT) {
				salt = params[i].content.ref.buffer;
				salt_len = params[i].content.ref.length;
			} else if (params[i].attributeID == TEE_ATTR_HKDF_INFO) {
				info = params[i].content.ref.buffer;
				info_len = params[i].content.ref.length;
			} else if (params[i].attributeID ==
				   TEE_ATTR_HKDF_HASH_ALGORITHM) {
				hash_id = __TEE_MbedDigestOf(
						params[i].content.value.a);
				if (hash_id == MBEDCRYPTO_HASH_NONE) {
					ret = -ENOTSUP;
					goto out;
				}
			}
		}

		olen = roundup(obj->info.maxObjectSize, 8) / 8;
		secret = TEE_Malloc(olen, TEE_MALLOC_FILL_ZERO);
		if (!secret) {
			ret = -ENOMEM;
			goto out;
		}

		ret = mbedcrypto_hkdf_derive_hash(hash_id, salt, salt_len,
				ikm, ikm_len, info, info_len, secret, olen);
		if (ret != 0)
			goto out;
	} else if (ops->info.algorithm == TEE_ALG_SM2_KEP) {
		struct mbedcrypto_ecp_keypair my_key, my_eph;
		struct mbedcrypto_ecp_point peer_key, peer_eph;
		struct mbedcrypto_sm2kep_parms kp;
		struct tee_object *kobj2 = NULL;
		const uint8_t *init_id = NULL, *resp_id = NULL;
		const uint8_t *conf_in_buf = NULL;
		size_t init_id_len = 0, resp_id_len = 0, conf_in_len = 0;
		int is_initiator = 0;
		size_t kdf_key_size = 0;
		uint8_t *conf_out_buf = NULL;
		size_t conf_out_len = 0;

		mbedcrypto_ecp_keypair_init(&my_key);
		mbedcrypto_ecp_keypair_init(&my_eph);
		mbedcrypto_ecp_point_init(&peer_key);
		mbedcrypto_ecp_point_init(&peer_eph);

		/* Load SM2 group */
		ret = mbedcrypto_ecp_load_group(&my_key.grp,
				__TEE_MbedEccCurveOf(TEE_ECC_CURVE_SM2));
		if (ret != 0)
			goto sm2kep_out;
		ret = mbedcrypto_ecp_load_group(&my_eph.grp,
				__TEE_MbedEccCurveOf(TEE_ECC_CURVE_SM2));
		if (ret != 0)
			goto sm2kep_out;

		/* Extract static key (key1) attributes */
		for (i = 0; i < kobj->attr_nr; i++) {
			if (kobj->attr[i].attributeID ==
			    TEE_ATTR_ECC_PRIVATE_VALUE)
				ret = mbedcrypto_bn_from_binary(&my_key.d,
					kobj->attr[i].content.ref.buffer,
					kobj->attr[i].content.ref.length);
			else if (kobj->attr[i].attributeID ==
				 TEE_ATTR_ECC_PUBLIC_VALUE_X)
				ret = mbedcrypto_bn_from_binary(&my_key.Q.X,
					kobj->attr[i].content.ref.buffer,
					kobj->attr[i].content.ref.length);
			else if (kobj->attr[i].attributeID ==
				 TEE_ATTR_ECC_PUBLIC_VALUE_Y)
				ret = mbedcrypto_bn_from_binary(&my_key.Q.Y,
					kobj->attr[i].content.ref.buffer,
					kobj->attr[i].content.ref.length);
			if (ret != 0)
				goto sm2kep_out;
		}
		mbedcrypto_bn_set_word(&my_key.Q.Z, 1);

		/* Extract ephemeral key (key2) attributes */
		kobj2 = object_of(ops->key2);
		if (!kobj2) {
			ret = TEE_ERROR_BAD_PARAMETERS;
			goto sm2kep_out;
		}
		for (i = 0; i < kobj2->attr_nr; i++) {
			if (kobj2->attr[i].attributeID ==
			    TEE_ATTR_ECC_PRIVATE_VALUE)
				ret = mbedcrypto_bn_from_binary(&my_eph.d,
					kobj2->attr[i].content.ref.buffer,
					kobj2->attr[i].content.ref.length);
			else if (kobj2->attr[i].attributeID ==
				 TEE_ATTR_ECC_PUBLIC_VALUE_X)
				ret = mbedcrypto_bn_from_binary(&my_eph.Q.X,
					kobj2->attr[i].content.ref.buffer,
					kobj2->attr[i].content.ref.length);
			else if (kobj2->attr[i].attributeID ==
				 TEE_ATTR_ECC_PUBLIC_VALUE_Y)
				ret = mbedcrypto_bn_from_binary(&my_eph.Q.Y,
					kobj2->attr[i].content.ref.buffer,
					kobj2->attr[i].content.ref.length);
			if (ret != 0)
				goto sm2kep_out;
		}
		mbedcrypto_bn_set_word(&my_eph.Q.Z, 1);

		/* Parse DeriveKey params */
		for (i = 0; i < paramCount; i++) {
			uint32_t aid = params[i].attributeID;

			if (aid == TEE_ATTR_ECC_PUBLIC_VALUE_X)
				ret = mbedcrypto_bn_from_binary(&peer_key.X,
					params[i].content.ref.buffer,
					params[i].content.ref.length);
			else if (aid == TEE_ATTR_ECC_PUBLIC_VALUE_Y)
				ret = mbedcrypto_bn_from_binary(&peer_key.Y,
					params[i].content.ref.buffer,
					params[i].content.ref.length);
			else if (aid ==
				 TEE_ATTR_ECC_EPHEMERAL_PUBLIC_VALUE_X)
				ret = mbedcrypto_bn_from_binary(&peer_eph.X,
					params[i].content.ref.buffer,
					params[i].content.ref.length);
			else if (aid ==
				 TEE_ATTR_ECC_EPHEMERAL_PUBLIC_VALUE_Y)
				ret = mbedcrypto_bn_from_binary(&peer_eph.Y,
					params[i].content.ref.buffer,
					params[i].content.ref.length);
			else if (aid == TEE_ATTR_SM2_ID_INITIATOR) {
				init_id = params[i].content.ref.buffer;
				init_id_len = params[i].content.ref.length;
			} else if (aid == TEE_ATTR_SM2_ID_RESPONDER) {
				resp_id = params[i].content.ref.buffer;
				resp_id_len = params[i].content.ref.length;
			} else if (aid == TEE_ATTR_SM2_KEP_USER)
				is_initiator =
					params[i].content.value.a ? 1 : 0;
			else if (aid == TEE_ATTR_SM2_KEP_CONFIRMATION_IN) {
				conf_in_buf = params[i].content.ref.buffer;
				conf_in_len = params[i].content.ref.length;
			} else if (aid == TEE_ATTR_KDF_KEY_SIZE)
				kdf_key_size = params[i].content.value.a;
			if (ret != 0)
				goto sm2kep_out;
		}
		mbedcrypto_bn_set_word(&peer_key.Z, 1);
		mbedcrypto_bn_set_word(&peer_eph.Z, 1);

		if (!init_id || !resp_id) {
			ret = TEE_PANIC_MISSING_PARAMETER;
			goto sm2kep_out;
		}

		/* kdf_key_size is in bits, convert to bytes */
		if (kdf_key_size)
			olen = roundup(kdf_key_size, 8) / 8;
		else
			olen = roundup(obj->info.maxObjectSize, 8) / 8;

		secret = TEE_Malloc(olen + 64, TEE_MALLOC_FILL_ZERO);
		if (!secret) {
			ret = -ENOMEM;
			goto sm2kep_out;
		}

		/* Allocate confirmation output buffer if requested */
		for (i = 0; i < paramCount; i++) {
			if (params[i].attributeID ==
			    TEE_ATTR_SM2_KEP_CONFIRMATION_OUT) {
				conf_out_buf = params[i].content.ref.buffer;
				conf_out_len = params[i].content.ref.length;
				break;
			}
		}

		memset(&kp, 0, sizeof(kp));
		kp.is_initiator = is_initiator;
		kp.initiator_id = init_id;
		kp.initiator_id_len = init_id_len;
		kp.responder_id = resp_id;
		kp.responder_id_len = resp_id_len;
		kp.out = secret;
		kp.out_len = olen;
		kp.conf_in = conf_in_buf;
		kp.conf_in_len = conf_in_len;
		kp.conf_out = conf_out_buf;
		kp.conf_out_len = conf_out_len;

		ret = mbedcrypto_sm2kep_derive(&my_key, &my_eph,
					       &peer_key, &peer_eph,
					       &kp);

sm2kep_out:
		mbedcrypto_ecp_keypair_cleanup(&my_key);
		mbedcrypto_ecp_keypair_cleanup(&my_eph);
		mbedcrypto_ecp_point_cleanup(&peer_key);
		mbedcrypto_ecp_point_cleanup(&peer_eph);
		if (ret != 0)
			goto out;
	} else {
		ret = -ENOTSUP;
		goto out;
	}

	TEE_InitRefAttribute(obj->attr, TEE_ATTR_SECRET_VALUE, secret, olen);
	obj->info.objectSize = olen * 8;
	obj->info.handleFlags = TEE_HANDLE_FLAG_INITIALIZED;
	ret = 0;

out:
	object_unlock();
	mbedcrypto_dh_cleanup(&dhm);
	mbedcrypto_ecdh_cleanup(&ecdh);
	if (ret != 0) {
		if (secret) {
			TEE_MemFill(secret, 0, olen);
			TEE_Free(secret);
		}
	}
	return ret;
}

void TEE_DeriveKey(TEE_OperationHandle operation, TEE_Attribute *params,
		uint32_t paramCount, TEE_ObjectHandle derivedKey)
{
	int ret = __TEE_DeriveKeyCommon(operation, params, paramCount, derivedKey);

	if (ret != 0)
		TEE_Panic(ret);
}

TEE_Result TEE_DeriveKey_PS(TEE_OperationHandle operation, TEE_Attribute *params,
		uint32_t paramCount, TEE_ObjectHandle derivedKey)
{
	int ret = __TEE_DeriveKeyCommon(operation, params, paramCount, derivedKey);

	if (ret != 0) {
		if (ret == TEE_PANIC_MISSING_PARAMETER ||
			ret == TEE_PANIC_BAD_PARAMETERS ||
			ret == TEE_PANIC_INVALID_ALG ||
			ret == TEE_PANIC_INVALID_ALG_2 ||
			ret == TEE_PANIC_INVALID_SIZE ||
			ret == TEE_PANIC_HARDWARE_FAILURE ||
			ret == TEE_PANIC_CRYPTO_FAILURE)
			return ret;
		if (ret == -ENOTSUP)
			return TEE_PANIC_INVALID_ALG;
		if (ret == -EBADF || ret == -EINVAL)
			TEE_Panic(ret);
		if (ret == -E2BIG)
			return TEE_PANIC_INVALID_SIZE;
		return TEE_PANIC_CRYPTO_FAILURE;
	}

	return TEE_SUCCESS;
}

TEE_Result TEE_EncapsulateKey(TEE_OperationHandle operation,
	uint32_t keySize, const TEE_Attribute *params,
	uint32_t paramCount, void *outputBuffer,
	size_t *bufferLen, TEE_ObjectHandle sessionKey)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TEE_DecapsulateKey(TEE_OperationHandle operation,
	uint32_t keySize, const TEE_Attribute *params,
	uint32_t paramCount, const void *encapsulatedKey,
	size_t bufferLen, TEE_ObjectHandle sessionKey)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

void TEE_GenerateRandom(void *randomBuffer, size_t randomBufferLen)
{
	int ret = -1;

	ret = tee_prng(NULL, randomBuffer, randomBufferLen);
	if (ret != 0)
		TEE_Panic(ret);
}

TEE_Result TEE_GenerateRandom_PS(void *randomBuffer, size_t randomBufferLen)
{
	int ret = tee_prng(NULL, randomBuffer, randomBufferLen);

	if (ret == 0)
		return TEE_SUCCESS;

	if (ret == -EAGAIN || ret == -ENODATA)
		return TEE_PANIC_INSUFFICIENT_ENTROPY;

	if (ret == -EIO)
		return TEE_PANIC_HARDWARE_FAILURE;

	/* Any other error is not representable by a _PS panic code here. */
	TEE_Panic(ret);
}
