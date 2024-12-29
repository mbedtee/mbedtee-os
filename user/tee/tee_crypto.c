// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * GlobalPlatform TEE Crypto Operation APIs
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syslimits.h>

#include <syscall.h>
#include <dirent.h>
#include <utrace.h>
#include <pthread.h>

#include <tee_internal_api.h>

#include "tee_api_priv.h"

int tee_prng(void *p_rng, unsigned char *output, size_t len)
{
#ifdef TEE_LIBC_PRNG
	int r = 0;

	while (len >= sizeof(r)) {
		r = rand();
		memcpy(output, &r, sizeof(r));
		len -= sizeof(r);
		output += sizeof(r);
	}

	if (len > 0) {
		r = rand();
		memcpy(output, &r, len);
	}
#else
	int fd = 0, ret = -1;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		EMSG("error opening /dev/urandom: %s\n", strerror(errno));
		return errno;
	}

	ret = read(fd, output, len);
	close(fd);
	if (ret < 0) {
		EMSG("error reading /dev/urandom: %s\n", strerror(errno));
		return errno;
	}
#endif

	return 0;
}

static inline int __TEE_Algo2Class(uint32_t algorithm)
{
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

static int __TEE_Algo2Type(uint32_t algo, uint32_t mode)
{
	int type = TEE_TYPE_ILLEGAL_VALUE;

	switch (algo) {
	case TEE_ALG_AES_XTS:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CTS:
	case TEE_ALG_AES_CTR:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CMAC:
	case TEE_ALG_AES_CCM:
	case TEE_ALG_AES_GCM:
		type = TEE_TYPE_AES;
		break;

	case TEE_ALG_DES_CBC_NOPAD:
	case TEE_ALG_DES_ECB_NOPAD:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
		type = TEE_TYPE_DES;
		break;

	case TEE_ALG_DES3_CBC_NOPAD:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		type = TEE_TYPE_DES3;
		break;

	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		if (mode == TEE_MODE_SIGN)
			type = TEE_TYPE_RSA_KEYPAIR;
		else if (mode == TEE_MODE_VERIFY)
			type = TEE_TYPE_RSA_PUBLIC_KEY;
		break;

	case TEE_ALG_RSAES_PKCS1_V1_5:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
	case TEE_ALG_RSA_NOPAD:
		if (mode == TEE_MODE_DECRYPT)
			type = TEE_TYPE_RSA_KEYPAIR;
		else if (mode == TEE_MODE_ENCRYPT)
			type = TEE_TYPE_RSA_PUBLIC_KEY;
		break;

	case TEE_ALG_DSA_SHA1:
	case TEE_ALG_DSA_SHA224:
	case TEE_ALG_DSA_SHA256:
		if (mode == TEE_MODE_SIGN)
			type = TEE_TYPE_DSA_KEYPAIR;
		else if (mode == TEE_MODE_VERIFY)
			type = TEE_TYPE_DSA_PUBLIC_KEY;
		break;

	case TEE_ALG_ECDSA_SHA1:
	case TEE_ALG_ECDSA_SHA224:
	case TEE_ALG_ECDSA_SHA256:
	case TEE_ALG_ECDSA_SHA384:
	case TEE_ALG_ECDSA_SHA512:
		if (mode == TEE_MODE_SIGN)
			type = TEE_TYPE_ECDSA_KEYPAIR;
		else if (mode == TEE_MODE_VERIFY)
			type = TEE_TYPE_ECDSA_PUBLIC_KEY;
		break;
	case TEE_ALG_ED25519:
		if (mode == TEE_MODE_SIGN)
			type = TEE_TYPE_ED25519_KEYPAIR;
		else if (mode == TEE_MODE_VERIFY)
			type = TEE_TYPE_ED25519_PUBLIC_KEY;
		break;

	case TEE_ALG_DH_DERIVE_SHARED_SECRET:
		if (mode == TEE_MODE_DERIVE)
			type = TEE_TYPE_DH_KEYPAIR;
		break;
	case TEE_ALG_ECDH_DERIVE_SHARED_SECRET:
		if (mode == TEE_MODE_DERIVE)
			type = TEE_TYPE_ECDH_KEYPAIR;
		break;
	case TEE_ALG_X25519:
		if (mode == TEE_MODE_DERIVE)
			type = TEE_TYPE_X25519_KEYPAIR;
		break;

	case TEE_ALG_MD5:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
	case TEE_ALG_SM3:
		if (mode == TEE_MODE_DIGEST)
			type = TEE_TYPE_DATA;
		break;

	case TEE_ALG_HMAC_MD5:
		type = TEE_TYPE_HMAC_MD5;
		break;
	case TEE_ALG_HMAC_SHA1:
		type = TEE_TYPE_HMAC_SHA1;
		break;
	case TEE_ALG_HMAC_SHA224:
		type = TEE_TYPE_HMAC_SHA224;
		break;
	case TEE_ALG_HMAC_SHA256:
		type = TEE_TYPE_HMAC_SHA256;
		break;
	case TEE_ALG_HMAC_SHA384:
		type = TEE_TYPE_HMAC_SHA384;
		break;
	case TEE_ALG_HMAC_SHA512:
		type = TEE_TYPE_HMAC_SHA512;
		break;
	case TEE_ALG_HMAC_SM3:
		type = TEE_TYPE_HMAC_SM3;
		break;

	default:
		break;
	}

	return type;
}

static int __TEE_MbedDigestOf(uint32_t algorithm)
{
	int type = MBEDTLS_MD_NONE;

	switch (algorithm) {
	case TEE_ALG_MD5:
		type = MBEDTLS_MD_MD5;
		break;
	case TEE_ALG_SHA1:
		type = MBEDTLS_MD_SHA1;
		break;
	case TEE_ALG_SHA224:
		type = MBEDTLS_MD_SHA224;
		break;
	case TEE_ALG_SHA256:
		type = MBEDTLS_MD_SHA256;
		break;
	case TEE_ALG_SHA384:
		type = MBEDTLS_MD_SHA384;
		break;
	case TEE_ALG_SHA512:
		type = MBEDTLS_MD_SHA512;
		break;
	case TEE_ALG_SM3:
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
	const mbedtls_md_info_t *md_info = NULL;

	/* re-start the digest state */
	if (ops->ctx != NULL)
		return mbedtls_md_starts(ops->ctx);

	ops->ctx = TEE_Malloc(sizeof(mbedtls_md_context_t), 1);
	if (ops->ctx == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	mbedtls_md_init(ops->ctx);

	md_info = mbedtls_md_info_from_type(md_type);
	if (md_info == NULL) {
		ret = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	ops->info.digestLength = mbedtls_md_get_size(md_info);

	ret = mbedtls_md_setup(ops->ctx, md_info, 0);
	if (ret != 0) {
		if (ret == MBEDTLS_ERR_MD_ALLOC_FAILED)
			ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	ret = mbedtls_md_starts(ops->ctx);
	if (ret != 0)
		goto out;

out:
	if (ret != 0) {
		TEE_Free(ops->ctx);
		ops->ctx = NULL;
	}
	return ret;
}

static int __TEE_DigestInit(struct tee_operation *ops)
{
	int ret = TEE_ERROR_GENERIC;
	int type = MBEDTLS_MD_NONE;

	type = __TEE_MbedDigestOf(ops->info.algorithm);
	if (type == MBEDTLS_MD_NONE) {
		ret = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	ret = __TEE_MbedDigestInit(ops, type);
	if (ret != 0)
		goto out;

	return 0;

out:
	free(ops->ctx);
	ops->ctx = NULL;
	return ret;
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
	if (t == NULL)
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
	if (ops != NULL) {
		ops->info.mode = mode;
		ops->info.algorithm = algorithm;
		ops->info.requiredKeyUsage = usage;
		ops->info.operationClass = opsclass;
		ops->info.maxKeySize = maxKeySize;
		ops->operationState = TEE_OPERATION_STATE_INITIAL;
		ops->objectType = type;

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

void TEE_FreeOperation(TEE_OperationHandle operation)
{
	struct tee_operation *ops = NULL;

	if (operation == TEE_HANDLE_NULL)
		return;

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		object_unlock();
		TEE_Panic(EBADF);
		return;
	}

	TEE_FreeTransientObject(ops->key);
	TEE_FreeTransientObject(ops->key2);
	TEE_Free(ops->ctx);
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
	if (ops == NULL) {
		object_unlock();
		TEE_Panic(EBADF);
		return;
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
		(operationInfoMultiple == NULL) ||
		(operationSize == NULL)) {
		ret = EINVAL;
		goto out;
	}

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
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
		if (obj != NULL) {
			operationInfoMultiple->keyInformation[0].keySize =
				obj->info.objectSize;
		}
		operationInfoMultiple->keyInformation[0].requiredKeyUsage =
				ops->info.requiredKeyUsage;

		if (expected > 1) {
			obj = object_of(ops->key2);
			if (obj != NULL) {
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

void TEE_ResetOperation(TEE_OperationHandle operation)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	if (!(ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		ret = EINVAL;
		goto out;
	}

	ops->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
	ops->operationState = TEE_OPERATION_STATE_INITIAL;

	if (ops->info.mode == TEE_MODE_DIGEST) {
		/* re-start the digest state */
		mbedtls_md_starts(ops->ctx);
		ops->info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
	}

	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

TEE_Result TEE_SetOperationKey(
	TEE_OperationHandle operation,
	TEE_ObjectHandle key)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_object *obj = NULL;
	struct tee_operation *ops = NULL;
	uint32_t usage = 0;

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	if ((ops->operationState != TEE_OPERATION_STATE_INITIAL) ||
		(ops->info.handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS) ||
		(ops->info.mode == TEE_MODE_DIGEST)) {
		ret = EINVAL;
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
	if (obj == NULL) {
		ret = ENOSR;
		goto out;
	}

	usage = ops->info.requiredKeyUsage;

	LMSG("maxKeySize %d objectSize %d\n",
		(int)ops->info.maxKeySize, (int)obj->info.objectSize);
	LMSG("requsage %x objectUsage %x\n",
		(int)usage, (int)obj->info.objectUsage);

	/* key/operation compatible */
	if ((ops->info.maxKeySize < obj->info.objectSize) ||
		((obj->info.objectUsage & usage) != usage) ||
		((obj->info.objectType | TEE_TYPE_PRIVATE_KEY_FLAG) !=
		(ops->objectType | TEE_TYPE_PRIVATE_KEY_FLAG))) {
		ret = EINVAL;
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
	if (ret != TEE_SUCCESS)
		goto out;

	ops->info.keySize = obj->info.objectSize;
	ops->info.handleState |= TEE_HANDLE_FLAG_KEY_SET;

out:
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_CORRUPT_OBJECT &&
		ret != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(ret);
	return ret;
}

TEE_Result TEE_SetOperationKey2(
	TEE_OperationHandle operation,
	TEE_ObjectHandle key1,
	TEE_ObjectHandle key2)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_object *obj1 = NULL, *obj2 = NULL;
	struct tee_operation *ops = NULL;
	uint32_t usage = 0;

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	if ((ops->operationState != TEE_OPERATION_STATE_INITIAL) ||
		!(ops->info.handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS)) {
		ret = EINVAL;
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
		ret = ENOSR;
		goto out;
	} else if (key1 == key2) {
		ret = TEE_ERROR_SECURITY;
		goto out;
	}

	obj1 = object_of(key1);
	obj2 = object_of(key2);
	if ((obj1 == NULL) || (obj2 == NULL)) {
		ret = ENOSR;
		goto out;
	}

	if (obj1->info.objectSize != obj2->info.objectSize) {
		ret = EINVAL;
		goto out;
	}

	if (obj1->info.objectType != obj2->info.objectType) {
		ret = EINVAL;
		goto out;
	}

	usage = ops->info.requiredKeyUsage;

	/* keys/operation compatible */
	if ((ops->info.maxKeySize < obj1->info.objectSize) ||
		((obj1->info.objectUsage & usage) != usage) ||
		((obj2->info.objectUsage & usage) != usage) ||
		(ops->objectType != obj1->info.objectType)) {
		ret = EINVAL;
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
	if (ret != TEE_SUCCESS)
		goto out;
	ret = TEE_CopyObjectAttributes1(ops->key2, key2);
	if (ret != TEE_SUCCESS)
		goto out;

	ops->info.handleState |= TEE_HANDLE_FLAG_KEY_SET;
	ops->info.keySize = obj1->info.objectSize;

out:
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_SECURITY &&
		ret != TEE_ERROR_CORRUPT_OBJECT &&
		ret != TEE_ERROR_CORRUPT_OBJECT_2 &&
		ret != TEE_ERROR_STORAGE_NOT_AVAILABLE &&
		ret != TEE_ERROR_STORAGE_NOT_AVAILABLE_2)
		TEE_Panic(ret);
	return ret;
}

void TEE_CopyOperation(
	TEE_OperationHandle dstOperation,
	TEE_OperationHandle srcOperation)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *sops = NULL;
	struct tee_operation *dops = NULL;

	object_lock();
	dops = object_of(dstOperation);
	sops = object_of(srcOperation);

	if ((sops == NULL) || (dops == NULL)) {
		ret = EBADF;
		goto out;
	}

	if ((sops->info.mode != dops->info.mode) ||
		(sops->info.algorithm != dops->info.algorithm)) {
		ret = EINVAL;
		goto out;
	}

	if (sops->info.keySize > dops->info.maxKeySize) {
		ret = E2BIG;
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
		ret = mbedtls_md_clone(dops->ctx, sops->ctx);
		if (ret != 0)
			goto out;
	}

	dops->info.handleState = sops->info.handleState;
	dops->operationState = sops->operationState;

	ret = 0;

out:
	object_unlock();
	if (ret != 0)
		TEE_Panic(ret);
}

static int __TEE_MbedEccCurveOf(int curve)
{
	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		return MBEDTLS_ECP_DP_SECP192R1;
	case TEE_ECC_CURVE_NIST_P224:
		return MBEDTLS_ECP_DP_SECP224R1;
	case TEE_ECC_CURVE_NIST_P256:
		return MBEDTLS_ECP_DP_SECP256R1;
	case TEE_ECC_CURVE_NIST_P384:
		return MBEDTLS_ECP_DP_SECP384R1;
	case TEE_ECC_CURVE_NIST_P521:
		return MBEDTLS_ECP_DP_SECP521R1;
	case TEE_ECC_CURVE_BSI_P256r1:
		return MBEDTLS_ECP_DP_BP256R1;
	case TEE_ECC_CURVE_BSI_P384r1:
		return MBEDTLS_ECP_DP_BP384R1;
	case TEE_ECC_CURVE_BSI_P512r1:
		return MBEDTLS_ECP_DP_BP512R1;
	case TEE_ECC_CURVE_25519:
		return MBEDTLS_ECP_DP_CURVE25519;
	default:
		return MBEDTLS_ECP_DP_NONE;
	}
}

TEE_Result TEE_IsAlgorithmSupported(
	uint32_t algId, uint32_t element)
{
	switch (algId) {
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
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
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_ECB_NOPAD:
	case TEE_ALG_DES3_CBC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
	case TEE_ALG_RSAES_PKCS1_V1_5:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
	case TEE_ALG_RSA_NOPAD:
	case TEE_ALG_DSA_SHA1:
	case TEE_ALG_DSA_SHA224:
	case TEE_ALG_DSA_SHA256:
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
		return TEE_SUCCESS;
	case TEE_ALG_ECDSA_SHA1:
	case TEE_ALG_ECDSA_SHA224:
	case TEE_ALG_ECDSA_SHA256:
	case TEE_ALG_ECDSA_SHA384:
	case TEE_ALG_ECDSA_SHA512:
	case TEE_ALG_ECDH_DERIVE_SHARED_SECRET:
		if (__TEE_MbedEccCurveOf(element) != MBEDTLS_ECP_DP_NONE)
			return TEE_SUCCESS;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

/* not supported algorithms
 * #define TEE_ALG_SM3                             0x50000007
	#define TEE_ALG_HMAC_SM3                        0x30000007
	#define TEE_ALG_SM2_DSA_SM3                     0x70006045
	#define TEE_ALG_SM2_KEP                         0x60000045
	#define TEE_ALG_SM2_PKE                         0x80000045
	#define TEE_ALG_SM4_ECB_NOPAD                   0x10000014
	#define TEE_ALG_SM4_CBC_NOPAD                   0x10000114
	#define TEE_ALG_SM4_CTR                         0x10000214
*/
}

TEE_Result TEE_GenerateKey(TEE_ObjectHandle object,
	uint32_t keySize, TEE_Attribute *params, uint32_t paramCount)
{
	uint32_t i = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct tee_object *obj = NULL;
	const struct object_attr *t = NULL;
	mbedtls_rsa_context rsa = {0};
	mbedtls_dhm_context dhm = {0};
	mbedtls_dsa_context dsa = {0};
	mbedtls_ecp_keypair ecp = {0};

	if ((paramCount > 0) && (params == NULL))
		return TEE_ERROR_BAD_PARAMETERS;

	object_lock();
	obj = object_of(object);
	if (obj == NULL) {
		ret = EBADF;
		goto out;
	}

	t = object_attr_of(obj->info.objectType);
	if (t == NULL) {
		ret = ENOTSUP;
		goto out;
	}

	if ((keySize < t->min_size) ||
		(keySize > obj->info.maxObjectSize)) {
		ret = ENOTSUP;
		goto out;
	}

	if ((obj->info.objectType == TEE_TYPE_DATA) ||
		(obj->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) ||
		(obj->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		ret = EINVAL;
		goto out;
	}

	if (t->attr_ids[0] == TEE_ATTR_SECRET_VALUE) {
		unsigned char *key = NULL;

		keySize >>= 3;
		key = TEE_Malloc(keySize, TEE_MALLOC_FILL_ZERO);
		if (key == NULL) {
			ret = ENOMEM;
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

		mbedtls_rsa_init(&rsa);

		for (i = 0; i < paramCount; i++) {
			if (params[i].attributeID == TEE_ATTR_RSA_PUBLIC_EXPONENT) {
				exponent = 0;
				e_len = params[i].content.ref.length;
				if (e_len > sizeof(int)) {
					ret = TEE_ERROR_BAD_PARAMETERS;
					goto out;
				}
				for (eidx = 0; eidx < e_len; eidx++) {
					exponent |= (int)(*(char *)(params[i].content.ref.buffer
							+ eidx)) << ((e_len - eidx - 1) * 8);
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

		ret = mbedtls_rsa_gen_key(&rsa, tee_prng,
					NULL, keySize, exponent);
		if (ret != 0) {
			if (ret == MBEDTLS_ERR_RSA_KEY_CHECK_FAILED)
				ret = TEE_ERROR_BAD_PARAMETERS;
			goto out;
		}

		n_len = rsa.len;
		e_len = mbedtls_mpi_size(&rsa.E);

		N = TEE_Malloc(n_len, TEE_MALLOC_FILL_ZERO);
		E = TEE_Malloc(e_len, TEE_MALLOC_FILL_ZERO);
		D = TEE_Malloc(n_len, TEE_MALLOC_FILL_ZERO);
		P = TEE_Malloc(n_len, TEE_MALLOC_FILL_ZERO);
		Q = TEE_Malloc(n_len, TEE_MALLOC_FILL_ZERO);
		DP = TEE_Malloc(n_len, TEE_MALLOC_FILL_ZERO);
		DQ = TEE_Malloc(n_len, TEE_MALLOC_FILL_ZERO);
		QP = TEE_Malloc(n_len, TEE_MALLOC_FILL_ZERO);
		if (!N || !E || !D || !P || !Q || !DP || !DQ || !QP) {
			ret = ENOMEM;
			TEE_Free(N); TEE_Free(E); TEE_Free(D); TEE_Free(P);
			TEE_Free(Q); TEE_Free(DP); TEE_Free(DQ); TEE_Free(QP);
			goto out;
		}

		mbedtls_mpi_write_binary(&rsa.N, N, n_len);
		mbedtls_mpi_write_binary(&rsa.E, E, e_len);
		mbedtls_mpi_write_binary(&rsa.D, D, n_len);
		mbedtls_mpi_write_binary(&rsa.P, P, n_len);
		mbedtls_mpi_write_binary(&rsa.Q, Q, n_len);
		mbedtls_mpi_write_binary(&rsa.DP, DP, n_len);
		mbedtls_mpi_write_binary(&rsa.DQ, DQ, n_len);
		mbedtls_mpi_write_binary(&rsa.QP, QP, n_len);

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

		mbedtls_dsa_init(&dsa);
		for (i = 0; i < paramCount; i++) {
			if (params[i].attributeID == TEE_ATTR_DSA_PRIME) {
				if (mbedtls_mpi_read_binary(&dsa.P,
					params[i].content.ref.buffer,
					params[i].content.ref.length) != 0) {
					ret = ENOMEM;
					goto out;
				}
			} else if (params[i].attributeID == TEE_ATTR_DSA_SUBPRIME) {
				if (mbedtls_mpi_read_binary(&dsa.Q,
					params[i].content.ref.buffer,
					params[i].content.ref.length) != 0) {
					ret = ENOMEM;
					goto out;
				}
			} else if (params[i].attributeID == TEE_ATTR_DSA_BASE) {
				if (mbedtls_mpi_read_binary(&dsa.G,
					params[i].content.ref.buffer,
					params[i].content.ref.length) != 0) {
					ret = ENOMEM;
					goto out;
				}
			}
		}

		ret = mbedtls_dsa_gen_key(&dsa, tee_prng, NULL);
		if (ret != 0)
			goto out;

		p_len = mbedtls_mpi_size(&dsa.P);
		q_len = mbedtls_mpi_size(&dsa.Q);
		g_len = mbedtls_mpi_size(&dsa.G);
		x_len = mbedtls_mpi_size(&dsa.X);
		y_len = mbedtls_mpi_size(&dsa.Y);

		P = TEE_Malloc(p_len, TEE_MALLOC_FILL_ZERO);
		Q = TEE_Malloc(q_len, TEE_MALLOC_FILL_ZERO);
		G = TEE_Malloc(g_len, TEE_MALLOC_FILL_ZERO);
		X = TEE_Malloc(x_len, TEE_MALLOC_FILL_ZERO);
		Y = TEE_Malloc(y_len, TEE_MALLOC_FILL_ZERO);
		if (!Y || !X || !G || !P || !Q) {
			ret = ENOMEM;
			TEE_Free(Y); TEE_Free(X); TEE_Free(G); TEE_Free(P); TEE_Free(Q);
			goto out;
		}

		mbedtls_mpi_write_binary(&dsa.P, P, p_len);
		mbedtls_mpi_write_binary(&dsa.Q, Q, q_len);
		mbedtls_mpi_write_binary(&dsa.G, G, g_len);
		mbedtls_mpi_write_binary(&dsa.X, X, x_len);
		mbedtls_mpi_write_binary(&dsa.Y, Y, y_len);

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

		mbedtls_dhm_init(&dhm);
		for (i = 0; i < paramCount; i++) {
			if (params[i].attributeID == TEE_ATTR_DH_PRIME) {
				if (mbedtls_mpi_read_binary(&dhm.P,
					params[i].content.ref.buffer,
					params[i].content.ref.length) != 0) {
					ret = ENOMEM;
					goto out;
				}
			} else if (params[i].attributeID == TEE_ATTR_DH_BASE) {
				if (mbedtls_mpi_read_binary(&dhm.G,
					params[i].content.ref.buffer,
					params[i].content.ref.length) != 0) {
					ret = ENOMEM;
					goto out;
				}
			} else if (params[i].attributeID == TEE_ATTR_DH_X_BITS) {
				xbits = params[i].content.value.a;
			}
		}

		p_len = mbedtls_mpi_size(&dhm.P);
		g_len = mbedtls_mpi_size(&dhm.G);

		if ((g_len == 0) || (p_len == 0)) {
			ret = EINVAL;
			goto out;
		}

		if (xbits == 0)
			xbits = p_len * 8;

		GX = TEE_Malloc(p_len, TEE_MALLOC_FILL_ZERO);
		if (GX == NULL) {
			ret = ENOMEM;
			goto out;
		}

		ret = mbedtls_dhm_make_public(&dhm, (xbits + 7) >> 3, GX, p_len, tee_prng, NULL);
		if (ret != 0) {
			TEE_Free(GX);
			goto out;
		}

		P = TEE_Malloc(p_len, TEE_MALLOC_FILL_ZERO);
		G = TEE_Malloc(g_len, TEE_MALLOC_FILL_ZERO);
		X = TEE_Malloc(p_len, TEE_MALLOC_FILL_ZERO);
		if (!P || !X || !G) {
			ret = ENOMEM;
			TEE_Free(GX); TEE_Free(X); TEE_Free(G); TEE_Free(P);
			goto out;
		}

		mbedtls_mpi_write_binary(&dhm.P, P, p_len);
		mbedtls_mpi_write_binary(&dhm.G, G, g_len);
		mbedtls_mpi_write_binary(&dhm.X, X, p_len);

		TEE_InitRefAttribute(&obj->attr[0], TEE_ATTR_DH_PRIME, P, p_len);
		TEE_InitRefAttribute(&obj->attr[1], TEE_ATTR_DH_BASE, G, g_len);
		TEE_InitRefAttribute(&obj->attr[2], TEE_ATTR_DH_PUBLIC_VALUE, GX, p_len);
		TEE_InitRefAttribute(&obj->attr[3], TEE_ATTR_DH_PRIVATE_VALUE, X, p_len);
		TEE_InitValueAttribute(&obj->attr[5], TEE_ATTR_DH_X_BITS,
						mbedtls_mpi_bitlen(&dhm.X), 0);
		break;
	}

	case TEE_TYPE_ECDSA_KEYPAIR:
	case TEE_TYPE_ECDH_KEYPAIR: {
		int curve = -1, mbedcurve = MBEDTLS_ECP_DP_NONE;
		unsigned char *D = NULL;
		unsigned char *X = NULL, *Y = NULL;
		size_t d_len = 0, x_len = 0, y_len = 0;

		mbedtls_ecp_keypair_init(&ecp);

		for (i = 0; i < paramCount; i++) {
			if (params[i].attributeID == TEE_ATTR_ECC_CURVE) {
				curve = params[i].content.value.a;
				mbedcurve = __TEE_MbedEccCurveOf(curve);
				break;
			}
		}

		ret = mbedtls_ecp_gen_key(mbedcurve, &ecp, tee_prng, NULL);
		if (ret != 0)
			goto out;

		d_len = mbedtls_mpi_size(&ecp.d);
		x_len = mbedtls_mpi_size(&ecp.Q.X);
		y_len = mbedtls_mpi_size(&ecp.Q.Y);

		D = TEE_Malloc(d_len, TEE_MALLOC_FILL_ZERO);
		X = TEE_Malloc(x_len, TEE_MALLOC_FILL_ZERO);
		Y = TEE_Malloc(y_len, TEE_MALLOC_FILL_ZERO);
		if (!D || !X || !Y) {
			ret = ENOMEM;
			TEE_Free(D); TEE_Free(X); TEE_Free(Y);
			goto out;
		}

		mbedtls_mpi_write_binary(&ecp.d, D, d_len);
		mbedtls_mpi_write_binary(&ecp.Q.X, X, x_len);
		mbedtls_mpi_write_binary(&ecp.Q.Y, Y, y_len);

		TEE_InitRefAttribute(&obj->attr[0], TEE_ATTR_ECC_PRIVATE_VALUE, D, d_len);
		TEE_InitRefAttribute(&obj->attr[1], TEE_ATTR_ECC_PUBLIC_VALUE_X, X, x_len);
		TEE_InitRefAttribute(&obj->attr[2], TEE_ATTR_ECC_PUBLIC_VALUE_Y, Y, y_len);
		TEE_InitValueAttribute(&obj->attr[3], TEE_ATTR_ECC_CURVE, curve, 0);
		break;
	}

	default:
		ret = ENOTSUP;
		goto out;
	}

	obj->info.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
	obj->info.objectSize = keySize;

out:
	object_unlock();
	mbedtls_rsa_free(&rsa);
	mbedtls_dhm_free(&dhm);
	mbedtls_dsa_free(&dsa);
	mbedtls_ecp_keypair_free(&ecp);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_BAD_PARAMETERS) {
		TEE_CloseObject(object);
		TEE_Panic(ret);
	}
	return ret;
}

void TEE_DigestUpdate(TEE_OperationHandle operation,
	void *chunk, size_t chunkSize)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	if ((ops->info.mode != TEE_MODE_DIGEST) ||
		((chunk == NULL) && chunkSize)) {
		ret = EINVAL;
		goto out;
	}

	ops->operationState = TEE_OPERATION_STATE_ACTIVE;

	ret = mbedtls_md_update(ops->ctx, chunk, chunkSize);

out:
	object_unlock();
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

TEE_Result TEE_DigestDoFinal(TEE_OperationHandle operation,
	void *chunk, size_t chunkLen, void *hash, size_t *hashLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	if ((ops->info.mode != TEE_MODE_DIGEST) ||
		((hash == NULL) || (hashLen == NULL)) ||
		((chunk == NULL) && chunkLen)) {
		ret = EINVAL;
		goto out;
	}

	if (*hashLen < ops->info.digestLength) {
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	ret = mbedtls_md_update(ops->ctx, chunk, chunkLen);
	if (ret != 0)
		goto out;

	ret = mbedtls_md_finish(ops->ctx, hash);
	if (ret != 0)
		goto out;

	*hashLen = ops->info.digestLength;

	/* re-start the digest state */
	mbedtls_md_starts(ops->ctx);
	ops->operationState = TEE_OPERATION_STATE_INITIAL;

	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(ret);
	return ret;
}

static int __TEE_MbedCipherOf(uint32_t algorithm, uint32_t key_size)
{
	int cipher = MBEDTLS_CIPHER_NONE;

	switch (algorithm) {
	case TEE_ALG_AES_ECB_NOPAD:
		if (key_size == 128)
			cipher = MBEDTLS_CIPHER_AES_128_ECB;
		else if (key_size == 192)
			cipher = MBEDTLS_CIPHER_AES_192_ECB;
		else if (key_size == 256)
			cipher = MBEDTLS_CIPHER_AES_256_ECB;
		break;

	case TEE_ALG_AES_CTR:
		if (key_size == 128)
			cipher = MBEDTLS_CIPHER_AES_128_CTR;
		else if (key_size == 192)
			cipher = MBEDTLS_CIPHER_AES_192_CTR;
		else if (key_size == 256)
			cipher = MBEDTLS_CIPHER_AES_256_CTR;
		break;

	case TEE_ALG_AES_CBC_NOPAD:
		if (key_size == 128)
			cipher = MBEDTLS_CIPHER_AES_128_CBC;
		else if (key_size == 192)
			cipher = MBEDTLS_CIPHER_AES_192_CBC;
		else if (key_size == 256)
			cipher = MBEDTLS_CIPHER_AES_256_CBC;
		break;

	case TEE_ALG_AES_CTS:
		if (key_size == 128)
			cipher = MBEDTLS_CIPHER_AES_128_CBC;
		else if (key_size == 192)
			cipher = MBEDTLS_CIPHER_AES_192_CBC;
		else if (key_size == 256)
			cipher = MBEDTLS_CIPHER_AES_256_CBC;
		break;

	case TEE_ALG_AES_XTS:
		if (key_size == 128)
			cipher = MBEDTLS_CIPHER_AES_128_XTS;
		else if (key_size == 256)
			cipher = MBEDTLS_CIPHER_AES_256_XTS;
		break;

	case TEE_ALG_DES_ECB_NOPAD:
		if (key_size == 64)
			cipher = MBEDTLS_CIPHER_DES_ECB;
		break;

	case TEE_ALG_DES_CBC_NOPAD:
		if (key_size == 64)
			cipher = MBEDTLS_CIPHER_DES_CBC;
		break;

	case TEE_ALG_DES3_ECB_NOPAD:
		if (key_size == 128)
			cipher = MBEDTLS_CIPHER_DES_EDE_ECB;
		else if (key_size == 192)
			cipher = MBEDTLS_CIPHER_DES_EDE3_ECB;
		break;

	case TEE_ALG_DES3_CBC_NOPAD:
		if (key_size == 128)
			cipher = MBEDTLS_CIPHER_DES_EDE_CBC;
		else if (key_size == 192)
			cipher = MBEDTLS_CIPHER_DES_EDE3_CBC;
		break;

	default:
		break;
	}

	return cipher;
}

static int __TEE_MbedCipherMacInit(
	struct tee_operation *ops, int cipher,
	void *IV, size_t IVLen, int nopad)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_object *obj = NULL;
	int key_size = 0;
	const mbedtls_cipher_info_t *cipher_info = NULL;
	unsigned char key_buffer[64] = {0};
	unsigned char iv[16] = {0};

	/* re-start the cbc-mac or cmac state */
	if (ops->ctx != NULL) {
		if (ops->info.algorithm != TEE_ALG_AES_CMAC) {
			TEE_MemFill(iv, 0, sizeof(iv));
			mbedtls_cipher_set_iv(ops->ctx, iv,
				mbedtls_cipher_get_iv_size(ops->ctx));
			mbedtls_cipher_reset(ops->ctx);
		} else {
			mbedtls_cipher_cmac_reset(ops->ctx);
		}
		ret = 0;
		goto out;
	}

	cipher_info = mbedtls_cipher_info_from_type(cipher);
	if (cipher_info == NULL) {
		ret = ENOTSUP;
		goto out;
	}

	ops->ctx = TEE_Malloc(sizeof(mbedtls_cipher_context_t), 1);
	if (ops->ctx == NULL) {
		ret = ENOMEM;
		goto out;
	}

	mbedtls_cipher_init(ops->ctx);

	ret = mbedtls_cipher_setup(ops->ctx, cipher_info);
	if (ret != 0)
		goto out;

	mbedtls_cipher_set_padding_mode(ops->ctx,
		nopad ? MBEDTLS_PADDING_NONE : MBEDTLS_PADDING_PKCS7);

	obj = object_of(ops->key);
	if (obj == NULL) {
		ret = ENOSR;
		goto out;
	}

	if (IVLen && (mbedtls_cipher_get_iv_size(ops->ctx) != IVLen)) {
		ret = EINVAL;
		goto out;
	}

	key_size = ops->info.keySize;

	memcpy(key_buffer, obj->attr[0].content.ref.buffer, key_size / 8);

	LMSG("ops->info.algorithm 0x%x\n", ops->info.algorithm);
	udump("key", key_buffer, key_size / 8);

	if (ops->info.algorithm != TEE_ALG_AES_CMAC) {
		ret = mbedtls_cipher_setkey(ops->ctx, key_buffer, key_size, MBEDTLS_ENCRYPT);
		if (ret != 0)
			goto out;
		TEE_MemFill(iv, 0, sizeof(iv));
		mbedtls_cipher_set_iv(ops->ctx, iv, mbedtls_cipher_get_iv_size(ops->ctx));
	} else {
		ret = mbedtls_cipher_cmac_starts(ops->ctx, key_buffer, key_size);
		if (ret != 0)
			goto out;
	}

out:
	if (ret != 0) {
		TEE_Free(ops->ctx);
		ops->ctx = NULL;
	}
	return ret;
}

static int __TEE_MbedCipherInit(
	struct tee_operation *ops, int cipher,
	void *IV, size_t IVLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_object *obj = NULL;
	int key_size = 0, mode = MBEDTLS_ENCRYPT;
	const mbedtls_cipher_info_t *cipher_info = NULL;
	unsigned char key_buffer[64] = {0};

	/* re-start the cipher state */
	if (ops->ctx != NULL) {
		if (mbedtls_cipher_get_iv_size(ops->ctx) != 0) {
			ret = mbedtls_cipher_set_iv(ops->ctx, IV, IVLen);
			if (ret != 0)
				goto out;
		}
		mbedtls_cipher_reset(ops->ctx);
		ret = 0;
		goto out;
	}

	cipher_info = mbedtls_cipher_info_from_type(cipher);
	if (cipher_info == NULL) {
		ret = ENOTSUP;
		goto out;
	}

	ops->ctx = TEE_Malloc(sizeof(mbedtls_cipher_context_t), 1);
	if (ops->ctx == NULL) {
		ret = ENOMEM;
		goto out;
	}

	mbedtls_cipher_init(ops->ctx);

	ret = mbedtls_cipher_setup(ops->ctx, cipher_info);
	if (ret != 0)
		goto out;

	mbedtls_cipher_set_padding_mode(ops->ctx, MBEDTLS_PADDING_NONE);

	if ((mbedtls_cipher_get_iv_size(ops->ctx) != 0) &&
		(mbedtls_cipher_get_iv_size(ops->ctx) != IVLen)) {
		ret = EINVAL;
		goto out;
	}

	obj = object_of(ops->key);
	if (obj == NULL) {
		ret = ENOSR;
		goto out;
	}

	key_size = ops->info.keySize;

	memcpy(key_buffer, obj->attr[0].content.ref.buffer, key_size / 8);

	udump("key1", key_buffer, key_size / 8);
	if (ops->info.handleState & TEE_HANDLE_FLAG_EXPECT_TWO_KEYS) {
		obj = object_of(ops->key2);
		if (obj == NULL) {
			ret = ENOSR;
			goto out;
		}
		memcpy(&key_buffer[key_size / 8], obj->attr[0].content.ref.buffer, key_size / 8);
		key_size *= 2;
		udump("key2", key_buffer, key_size / 8);
	}

	if (ops->info.mode == TEE_MODE_DECRYPT)
		mode = MBEDTLS_DECRYPT;

	ret = mbedtls_cipher_setkey(ops->ctx, key_buffer, key_size, mode);
	if (ret != 0)
		goto out;

	if (mbedtls_cipher_get_iv_size(ops->ctx) != 0) {
		udump("IV", IV, IVLen);
		if (ops->info.algorithm == TEE_ALG_AES_XTS) {
			mbedtls_cipher_context_t *cipher = ops->ctx;
			mbedtls_aes_xts_context *ctx = cipher->cipher_ctx;

			mbedtls_aes_crypt_ecb(&ctx->tweak, MBEDTLS_AES_ENCRYPT, IV, cipher->iv);
		} else {
			ret = mbedtls_cipher_set_iv(ops->ctx, IV, IVLen);
			if (ret != 0)
				goto out;
		}
	}

out:
	if (ret != 0) {
		TEE_Free(ops->ctx);
		ops->ctx = NULL;
	}
	return ret;
}

void TEE_CipherInit(TEE_OperationHandle operation, void *IV, size_t IVLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;
	int cipher = MBEDTLS_CIPHER_NONE;

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_CIPHER) ||
		!(ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		ret = EINVAL;
		goto out;
	}

	LMSG("algo:%x stat:%x %s ksz:%d iv:%p ivlen:%d\n", ops->info.algorithm,
		ops->info.handleState, ops->info.mode ? "decrypt" : "encrypt",
		ops->info.keySize, IV, IVLen);

	cipher = __TEE_MbedCipherOf(ops->info.algorithm, ops->info.keySize);
	if (cipher == MBEDTLS_CIPHER_NONE) {
		ret = ENOTSUP;
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
	if (ret != 0)
		TEE_Panic(ret);
}

TEE_Result TEE_CipherUpdate(TEE_OperationHandle operation,
	void *srcData, size_t srcLen, void *destData, size_t *destLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;

	if (!destLen || (*destLen < srcLen))
		return TEE_ERROR_SHORT_BUFFER;

	if (((srcLen > 0) && (srcData == NULL)) ||
		((*destLen > 0) && (destData == NULL))) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		TEE_Panic(EINVAL);
		return ret;
	}

	if (INVALID_BUFF(srcData, destData, srcLen)) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		TEE_Panic(EFAULT);
		return ret;
	}

	LMSG("ops %ld - src:%p ilen:%d dst:%p olen:%d\n", (uintptr_t)operation,
			srcData, srcLen, destData, *destLen);

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	LMSG("ccops->info.algorithm 0x%x\n", ops->info.algorithm);

	if ((ops->info.operationClass != TEE_OPERATION_CIPHER) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) ||
		(ops->operationState != TEE_OPERATION_STATE_ACTIVE)) {
		ret = EINVAL;
		goto out;
	}

	if (mbedtls_cipher_get_cipher_mode(ops->ctx) == MBEDTLS_MODE_ECB)
		ret = mbedtls_ecb_crypt(ops->ctx, srcData, srcLen, destData, destLen, false);
	else if (ops->info.algorithm == TEE_ALG_AES_CTS)
		ret = mbedtls_aes_cts(ops->ctx, srcData, srcLen, destData, destLen, false);
	else if (ops->info.algorithm == TEE_ALG_AES_XTS)
		ret = mbedtls_aes_xts(ops->ctx, srcData, srcLen, destData, destLen, false);
	else
		ret = mbedtls_cipher_update(ops->ctx, srcData, srcLen, destData, destLen);

	if (ret != 0)
		goto out;

	LMSG("ops %ld - src:%p ilen:%d dst:%p olen:%d\n", (uintptr_t)operation,
		srcData, srcLen, destData, *destLen);

	if (srcLen < 128) {
		udump("srcData", srcData, srcLen);
		udump("destData", destData, *destLen);
	}

out:
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(ret);
	return ret;
}

TEE_Result TEE_CipherDoFinal(TEE_OperationHandle operation,
	void *srcData, size_t srcLen, void *destData, size_t *destLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;
	size_t olen = 0;

	if (destData != NULL) {
		if (!destLen || (*destLen < srcLen))
			return TEE_ERROR_SHORT_BUFFER;
	}

	if ((srcLen > 0) && (srcData == NULL)) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		TEE_Panic(EINVAL);
		return ret;
	}

	if (INVALID_BUFF(srcData, destData, srcLen)) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		TEE_Panic(EFAULT);
		return ret;
	}

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	LMSG("ops %ld - src:%p ilen:%d dst:%p olen:%d\n", (uintptr_t)operation,
		srcData, srcLen, destData, destLen ? *destLen : 0);

	if ((ops->info.operationClass != TEE_OPERATION_CIPHER) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) ||
		(ops->operationState != TEE_OPERATION_STATE_ACTIVE)) {
		ret = EINVAL;
		goto out;
	}

	if ((destData != NULL) && srcLen) {
		if (mbedtls_cipher_get_cipher_mode(ops->ctx) == MBEDTLS_MODE_ECB) {
			ret = mbedtls_ecb_crypt(ops->ctx, srcData, srcLen, destData, destLen, true);
		} else if (ops->info.algorithm == TEE_ALG_AES_CTS) {
			ret = mbedtls_aes_cts(ops->ctx, srcData, srcLen, destData, destLen, true);
		} else if (ops->info.algorithm == TEE_ALG_AES_XTS) {
			ret = mbedtls_aes_xts(ops->ctx, srcData, srcLen, destData, destLen, true);
		} else {
			ret = mbedtls_cipher_update(ops->ctx, srcData, srcLen, destData, destLen);
			if (ret != 0)
				goto out;

			ret = mbedtls_cipher_finish(ops->ctx, destData + *destLen, &olen);
			if (ret != 0)
				goto out;

			*destLen += olen;
		}
	}
	if (ret != 0)
		goto out;

	LMSG("ops %ld - src:%p ilen:%d dst:%p olen:%d\n", (uintptr_t)operation,
			srcData, srcLen, destData, destLen ? *destLen : 0);

	if (destLen && (srcLen < 128)) {
		udump("srcData", srcData, srcLen);
		udump("destData", destData, *destLen);
	}

	ops->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
	ops->operationState = TEE_OPERATION_STATE_INITIAL;
	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(ret);
	return ret;
}

static int __TEE_MbedHMACInit(
	struct tee_operation *ops, int md_type)
{
	int ret = -1;
	const mbedtls_md_info_t *md_info = NULL;
	struct tee_object *obj = NULL;

	obj = object_of(ops->key);
	if (obj == NULL) {
		ret = ENOSR;
		goto out;
	}

	/* re-start the hmac state */
	if (ops->ctx != NULL) {
		ret = mbedtls_md_hmac_starts(ops->ctx,
			obj->attr[0].content.ref.buffer,
			ops->info.keySize / 8);
		goto out;
	}

	ops->ctx = TEE_Malloc(sizeof(mbedtls_md_context_t), 1);
	if (ops->ctx == NULL) {
		ret = ENOMEM;
		goto out;
	}

	mbedtls_md_init(ops->ctx);

	md_info = mbedtls_md_info_from_type(md_type);

	ops->info.digestLength = mbedtls_md_get_size(md_info);

	ret = mbedtls_md_setup(ops->ctx, md_info, 1);
	if (ret != 0)
		goto out;

	ret = mbedtls_md_hmac_starts(ops->ctx,
			obj->attr[0].content.ref.buffer,
			ops->info.keySize / 8);
	if (ret != 0)
		goto out;

out:
	if (ret != 0) {
		TEE_Free(ops->ctx);
		ops->ctx = NULL;
	}
	return ret;
}

static void __TEE_MbedMACTypeOf(struct tee_operation *ops,
	int *htype, int *ctype)
{
	int algo = 0, key_size = 0;

	key_size = ops->info.keySize;
	algo = ops->info.algorithm;

	switch (algo) {
	case TEE_ALG_HMAC_MD5:
		*htype = MBEDTLS_MD_MD5;
		break;
	case TEE_ALG_HMAC_SHA1:
		*htype = MBEDTLS_MD_SHA1;
		break;
	case TEE_ALG_HMAC_SHA224:
		*htype = MBEDTLS_MD_SHA224;
		break;
	case TEE_ALG_HMAC_SHA256:
		*htype = MBEDTLS_MD_SHA256;
		break;
	case TEE_ALG_HMAC_SHA384:
		*htype = MBEDTLS_MD_SHA384;
		break;
	case TEE_ALG_HMAC_SHA512:
		*htype = MBEDTLS_MD_SHA512;
		break;

	case TEE_ALG_AES_CMAC:
		if (key_size == 128)
			*ctype = MBEDTLS_CIPHER_AES_128_ECB;
		else if (key_size == 192)
			*ctype = MBEDTLS_CIPHER_AES_192_ECB;
		else if (key_size == 256)
			*ctype = MBEDTLS_CIPHER_AES_256_ECB;
		break;

	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
		if (key_size == 128)
			*ctype = MBEDTLS_CIPHER_AES_128_CBC;
		else if (key_size == 192)
			*ctype = MBEDTLS_CIPHER_AES_192_CBC;
		else if (key_size == 256)
			*ctype = MBEDTLS_CIPHER_AES_256_CBC;
		break;

	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
		if (key_size == 64)
			*ctype = MBEDTLS_CIPHER_DES_CBC;
		break;

	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		if (key_size == 128)
			*ctype = MBEDTLS_CIPHER_DES_EDE_CBC;
		else if (key_size == 192)
			*ctype = MBEDTLS_CIPHER_DES_EDE3_CBC;
		break;
	case TEE_ALG_HMAC_SM3:
		break;
	default:
		break;
	}
}

void TEE_MACInit(TEE_OperationHandle operation, void *IV, size_t IVLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;
	/* hash-mac or cipher-mac*/
	int htype = MBEDTLS_MD_NONE;
	int ctype = MBEDTLS_CIPHER_NONE;

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_MAC) ||
		!(ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET)) {
		ret = EINVAL;
		goto out;
	}

	__TEE_MbedMACTypeOf(ops, &htype, &ctype);

	ops->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
	ops->operationState = TEE_OPERATION_STATE_INITIAL;

	/* hash-mac or cipher-mac*/
	if (htype != MBEDTLS_MD_NONE) {
		ret = __TEE_MbedHMACInit(ops, htype);
		if (ret != 0)
			goto out;
	} else if (ctype != MBEDTLS_CIPHER_NONE) {
		ret = __TEE_MbedCipherMacInit(ops, ctype, IV, IVLen,
			(ops->info.algorithm == TEE_ALG_AES_CBC_MAC_NOPAD) ||
			(ops->info.algorithm == TEE_ALG_DES_CBC_MAC_NOPAD) ||
			(ops->info.algorithm == TEE_ALG_DES3_CBC_MAC_NOPAD));
		if (ret != 0)
			goto out;
	} else {
		ret = ENOTSUP;
		goto out;
	}

	ops->info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
	ops->operationState = TEE_OPERATION_STATE_ACTIVE;

out:
	object_unlock();
	if (ret != 0)
		TEE_Panic(ret);
}

void TEE_MACUpdate(TEE_OperationHandle operation, void *chunk, size_t chunkSize)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;
	/* hash-mac or cipher-mac*/
	int htype = MBEDTLS_MD_NONE;
	int ctype = MBEDTLS_CIPHER_NONE;

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_MAC) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) ||
		(ops->operationState != TEE_OPERATION_STATE_ACTIVE)) {
		ret = EINVAL;
		goto out;
	}

	if ((chunkSize > 0) && (chunk == NULL)) {
		ret = EINVAL;
		goto out;
	}

	if (INVALID_BUFF(chunk, chunk, chunkSize)) {
		ret = EFAULT;
		goto out;
	}

	LMSG("ops->info.algorithm 0x%x\n", ops->info.algorithm);
	udump("chunk", chunk, chunkSize);

	__TEE_MbedMACTypeOf(ops, &htype, &ctype);

	if (ops->info.algorithm == TEE_ALG_AES_CMAC) {
		ret = mbedtls_cipher_cmac_update(ops->ctx, chunk, chunkSize);
		if (ret != 0)
			goto out;
	} else if (htype != MBEDTLS_MD_NONE) {
		ret = mbedtls_md_hmac_update(ops->ctx, chunk, chunkSize);
		if (ret != 0)
			goto out;
	} else if (ctype != MBEDTLS_CIPHER_NONE) {
		unsigned char dst[512];
		size_t off = 0, olen = 0, ilen = 0;

		while ((ssize_t)chunkSize > 0) {
			ilen = min(chunkSize, sizeof(dst));
			ret = mbedtls_cipher_update(ops->ctx, chunk + off,
						ilen, dst, &olen);
			if (ret != 0)
				goto out;
			chunkSize -= ilen;
			off += ilen;
		}
	} else {
		ret = ENOTSUP;
		goto out;
	}

	ret = 0;

out:
	object_unlock();
	if (ret != 0)
		TEE_Panic(ret);
}

TEE_Result TEE_MACComputeFinal(TEE_OperationHandle operation,
	void *message, size_t messageLen, void *mac, size_t *macLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;
	/* hash-mac or cipher-mac*/
	int htype = MBEDTLS_MD_NONE;
	int ctype = MBEDTLS_CIPHER_NONE;

	object_lock();

	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_MAC) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) ||
		(ops->operationState != TEE_OPERATION_STATE_ACTIVE)) {
		ret = EINVAL;
		goto out;
	}

	if ((messageLen > 0) && (message == NULL)) {
		ret = EINVAL;
		goto out;
	}

	if (INVALID_BUFF(message, message, messageLen)) {
		ret = EFAULT;
		goto out;
	}

	LMSG("ops->info.algorithm 0x%x\n", ops->info.algorithm);
	udump("message", message, messageLen);

	__TEE_MbedMACTypeOf(ops, &htype, &ctype);

	if (ops->info.algorithm == TEE_ALG_AES_CMAC) {
		mbedtls_cipher_context_t *ctx = ops->ctx;

		if (*macLen < mbedtls_cipher_get_block_size(ctx)) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		if (messageLen > 0) {
			ret = mbedtls_cipher_cmac_update(ctx, message, messageLen);
			if (ret != 0)
				goto out;
		}

		ret = mbedtls_cipher_cmac_finish(ctx, mac);
		if (ret != 0)
			goto out;

		*macLen = mbedtls_cipher_get_block_size(ctx);
	} else if (htype != MBEDTLS_MD_NONE) {
		mbedtls_md_context_t *ctx = ops->ctx;

		if (*macLen < mbedtls_md_get_size(ctx->md_info)) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		if (messageLen > 0) {
			ret = mbedtls_md_hmac_update(ctx, message, messageLen);
			if (ret != 0)
				goto out;
		}

		ret = mbedtls_md_hmac_finish(ctx, mac);
		if (ret != 0)
			goto out;

		*macLen = mbedtls_md_get_size(ctx->md_info);
	} else if (ctype != MBEDTLS_CIPHER_NONE) {
		mbedtls_cipher_context_t *ctx = ops->ctx;
		unsigned char dst[512];
		size_t off = 0, olen = 0, ilen = 0, bsize = 0;

		bsize = mbedtls_cipher_get_block_size(ctx);

		if (*macLen < bsize) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		while ((ssize_t)messageLen > 0) {
			ilen = min(messageLen, sizeof(dst));
			ret = mbedtls_cipher_update(ctx, message + off,
						ilen, dst, &olen);
			if (ret != 0)
				goto out;
			messageLen -= ilen;
			off += ilen;
		}

		/* pkcs5 padding */
		ret = mbedtls_cipher_finish(ctx, mac, macLen);
		if (ret != 0)
			goto out;

		/* no padding, need to copy the last cipher block manually */
		if (ctx->add_padding == NULL) {
			memcpy(mac, dst + olen - bsize, bsize);
			*macLen = bsize;
		}
	} else {
		ret = ENOTSUP;
		goto out;
	}

	udump("mac", mac, *macLen);

	ops->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
	ops->operationState = TEE_OPERATION_STATE_INITIAL;

	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(ret);
	return ret;
}

TEE_Result TEE_MACCompareFinal(TEE_OperationHandle operation,
	void *message, size_t messageLen, void *mac, size_t macLen)
{
	int ret = TEE_ERROR_GENERIC;
	unsigned char dst[MBEDTLS_MD_MAX_SIZE];
	size_t olen = sizeof(dst);

	ret = TEE_MACComputeFinal(operation, message, messageLen, dst, &olen);
	if (ret != TEE_SUCCESS) {
		TEE_Panic(ret);
		return ret;
	}

	if ((olen != macLen) ||	memcmp(mac, dst, olen))
		return TEE_ERROR_MAC_INVALID;

	return TEE_SUCCESS;
}

TEE_Result TEE_AEInit(TEE_OperationHandle operation,
	void *nonce, size_t nonceLen, uint32_t tagLen,
	uint32_t AADLen, uint32_t payloadLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;
	struct tee_object *obj = NULL;
	mbedtls_gcm_context *gcm = NULL;
	mbedtls_ccm_context *ccm = NULL;

	if (nonce == NULL) {
		TEE_Panic(EFAULT);
		return ret;
	}

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_AE) ||
		!(ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET) ||
		(ops->operationState != TEE_OPERATION_STATE_INITIAL)) {
		ret = EINVAL;
		goto out;
	}

	obj = object_of(ops->key);
	if (obj == NULL) {
		ret = ENOSR;
		goto out;
	}
	LMSG("mode %d, payloadLen %d AADLen %d tagLen %d\n",
		ops->info.mode, payloadLen, AADLen, tagLen);

	if (ops->info.algorithm == TEE_ALG_AES_GCM) {
		if ((tagLen < 96) || (tagLen > 128) || ((tagLen % 8) != 0)) {
			ret = TEE_ERROR_NOT_SUPPORTED;
			goto out;
		}

		if (nonceLen == 0) {
			ret = EINVAL;
			goto out;
		}

		gcm = TEE_Malloc(sizeof(mbedtls_gcm_context), 1);
		if (gcm == NULL) {
			ret = ENOMEM;
			goto out;
		}

		mbedtls_gcm_init(gcm);

		ret = mbedtls_gcm_setkey(gcm, MBEDTLS_CIPHER_ID_AES,
				obj->attr[0].content.ref.buffer, ops->info.keySize);
		if (ret != 0)
			goto out;

		ret = mbedtls_gcm_starts(gcm, (ops->info.mode == TEE_MODE_DECRYPT) ?
						MBEDTLS_GCM_DECRYPT : MBEDTLS_GCM_ENCRYPT,
						nonce, nonceLen);
		if (ret != 0)
			goto out;
		ops->ctx = gcm;
		ops->tag_len = tagLen >> 3;
	} else if (ops->info.algorithm == TEE_ALG_AES_CCM) {
		if ((tagLen < 32) || (tagLen > 128) || ((tagLen % 16) != 0)) {
			ret = TEE_ERROR_NOT_SUPPORTED;
			goto out;
		}

		if (nonceLen < 7 || nonceLen > 13) {
			ret = EINVAL;
			goto out;
		}

		ccm = TEE_Malloc(sizeof(mbedtls_ccm_context), 1);
		if (ccm  == NULL) {
			ret = ENOMEM;
			goto out;
		}

		mbedtls_ccm_init(ccm);

		ret = mbedtls_ccm_setkey(ccm, MBEDTLS_CIPHER_ID_AES,
				obj->attr[0].content.ref.buffer, ops->info.keySize);
		if (ret != 0)
			goto out;

		ret = mbedtls_ccm_starts(ccm, (ops->info.mode == TEE_MODE_DECRYPT) ?
				MBEDTLS_CCM_DECRYPT : MBEDTLS_CCM_ENCRYPT, nonce, nonceLen);
		if (ret != 0)
			goto out;

		ret = mbedtls_ccm_set_lengths(ccm, AADLen, payloadLen, tagLen >> 3);
		if (ret != 0)
			goto out;
		ops->ctx = ccm;
	} else {
		ret = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	ops->info.handleState |= TEE_HANDLE_FLAG_INITIALIZED;
	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret != TEE_SUCCESS) {
		mbedtls_ccm_free(ccm);
		mbedtls_gcm_free(gcm);
	}
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_NOT_SUPPORTED)
		TEE_Panic(ret);
	return ret;
}

void TEE_AEUpdateAAD(TEE_OperationHandle operation,
	void *AADdata, size_t AADdataLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;

	if (AADdataLen && (AADdata == NULL)) {
		TEE_Panic(EFAULT);
		return;
	}

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	LMSG("algo %x AADdataLen %d\n", ops->info.algorithm, AADdataLen);

	if ((ops->info.operationClass != TEE_OPERATION_AE) ||
		!(ops->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
		(ops->operationState != TEE_OPERATION_STATE_INITIAL)) {
		ret = EINVAL;
		goto out;
	}

	if (ops->info.algorithm == TEE_ALG_AES_GCM) {
		ret = mbedtls_gcm_update_ad(ops->ctx, AADdata, AADdataLen);
		if (ret != 0)
			goto out;
	} else if (ops->info.algorithm == TEE_ALG_AES_CCM) {
		ret = mbedtls_ccm_update_ad(ops->ctx, AADdata, AADdataLen);
		if (ret != 0)
			goto out;
	}

	ops->operationState = TEE_OPERATION_STATE_ACTIVE;
	ret = 0;

out:
	object_unlock();
	if (ret != 0)
		TEE_Panic(ret);
}

TEE_Result TEE_AEUpdate(TEE_OperationHandle operation, void *srcData,
	size_t srcLen, void *destData, size_t *destLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;

	if (!destLen || (*destLen < srcLen))
		return TEE_ERROR_SHORT_BUFFER;

	if (((srcLen > 0) && (srcData == NULL)) ||
		((*destLen > 0) && (destData == NULL))) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		TEE_Panic(EINVAL);
		return ret;
	}

	if (INVALID_BUFF(srcData, destData, srcLen)) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		TEE_Panic(EFAULT);
		return ret;
	}

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_AE) ||
		(ops->operationState != TEE_OPERATION_STATE_ACTIVE)) {
		ret = EINVAL;
		goto out;
	}

	LMSG("aeops->info.algorithm 0x%lx ilen %ld olen %ld\n",
		ops->info.algorithm, (long)srcLen, (long)*destLen);

	if (ops->info.algorithm == TEE_ALG_AES_GCM) {
		ret = mbedtls_gcm_update(ops->ctx, srcData, srcLen,
					destData, *destLen, destLen);
		if (ret != 0)
			goto out;
	} else if (ops->info.algorithm == TEE_ALG_AES_CCM) {
		ret = mbedtls_ccm_update(ops->ctx, srcData, srcLen,
					destData, *destLen, destLen);
		if (ret != 0)
			goto out;
	}

	udump("destData", destData, *destLen);

	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(ret);
	return ret;
}

TEE_Result TEE_AEEncryptFinal(TEE_OperationHandle operation,
	void *srcData, size_t srcLen, void *destData, size_t *destLen,
	void *tag, size_t *tagLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;
	unsigned char dst[1024];
	size_t off = 0, olen = 0, ilen = 0;
	mbedtls_gcm_context *gcm = NULL;
	mbedtls_ccm_context *ccm = NULL;

	if (destData != NULL) {
		if (!destLen || (*destLen < srcLen))
			return TEE_ERROR_SHORT_BUFFER;
	}

	if ((srcLen > 0) && (srcData == NULL)) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		TEE_Panic(EINVAL);
		return ret;
	}

	if (INVALID_BUFF(srcData, destData, srcLen) ||
		(tag == NULL) || (tagLen == NULL)) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		TEE_Panic(EFAULT);
		return ret;
	}

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_AE) ||
		(ops->operationState != TEE_OPERATION_STATE_ACTIVE) ||
		(ops->info.mode != TEE_MODE_ENCRYPT)) {
		ret = EINVAL;
		goto out;
	}

	LMSG("aeops->info.algorithm 0x%lx ilen %ld\n", ops->info.algorithm, (long)srcLen);

	if (ops->info.algorithm == TEE_ALG_AES_GCM) {
		gcm = ops->ctx;
		if (*tagLen < ops->tag_len) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		if (destData != NULL) {
			if (*destLen < srcLen + ops->unprocessed_len) {
				ret = TEE_ERROR_SHORT_BUFFER;
				goto out;
			}

			ret = mbedtls_gcm_update(gcm, srcData, srcLen, destData,
							*destLen, destLen);
			if (ret != 0)
				goto out;

			ret = mbedtls_gcm_finish(gcm, NULL, 0, &olen, tag,
							ops->tag_len);
			if (ret != 0)
				goto out;
		} else {
			while ((ssize_t)srcLen > 0) {
				ilen = min(srcLen, sizeof(dst));
				ret = mbedtls_gcm_update(gcm, srcData + off, ilen,
							 dst, sizeof(dst), &olen);
				if (ret != 0)
					goto out;

				srcLen -= ilen;
				off += ilen;
			}

			ret = mbedtls_gcm_finish(gcm, NULL, 0, &olen,
							tag, ops->tag_len);
			if (ret != 0)
				goto out;
		}

		*tagLen = ops->tag_len;
	} else if (ops->info.algorithm == TEE_ALG_AES_CCM) {
		ccm = ops->ctx;
		if (*tagLen < ccm->tag_len) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		if (destData != NULL) {
			if (*destLen < srcLen + ops->unprocessed_len) {
				ret = TEE_ERROR_SHORT_BUFFER;
				goto out;
			}

			ret = mbedtls_ccm_update(ccm, srcData, srcLen, destData,
							*destLen, destLen);
			if (ret != 0)
				goto out;

			ret = mbedtls_ccm_finish(ccm, tag, ccm->tag_len);
			if (ret != 0)
				goto out;
		} else {
			while ((ssize_t)srcLen > 0) {
				ilen = min(srcLen, sizeof(dst));
				ret = mbedtls_ccm_update(ccm, srcData + off, ilen,
							dst, sizeof(dst), &olen);
				if (ret != 0)
					goto out;

				srcLen -= ilen;
				off += ilen;
			}

			ret = mbedtls_ccm_finish(ccm, tag, ccm->tag_len);
			if (ret != 0)
				goto out;
		}
		*tagLen = ccm->tag_len;
	}

	udump("destData", destData, *destLen);
	udump("tag", tag, *tagLen);

	ops->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
	ops->operationState = TEE_OPERATION_STATE_INITIAL;
	ret = TEE_SUCCESS;

out:
	if (ops) {
		mbedtls_gcm_free(gcm);
		mbedtls_ccm_free(ccm);
		TEE_Free(ops->ctx);
		ops->ctx = NULL;
	}
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(ret);
	return ret;
}

TEE_Result TEE_AEDecryptFinal(TEE_OperationHandle operation,
	void *srcData, size_t srcLen, void *destData, size_t *destLen,
	void *tag, size_t tagLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;
	size_t off = 0, olen = 0, ilen = 0;
	mbedtls_gcm_context *gcm = NULL;
	mbedtls_ccm_context *ccm = NULL;
	unsigned char dst[1024];

	if (destData != NULL) {
		if (!destLen || (*destLen < srcLen))
			return TEE_ERROR_SHORT_BUFFER;
	}

	if ((srcLen > 0) && (srcData == NULL)) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		TEE_Panic(EINVAL);
		return ret;
	}

	if (INVALID_BUFF(srcData, destData, srcLen) ||
		(tag == NULL) || (tagLen == 0)) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		TEE_Panic(EFAULT);
		return ret;
	}

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_AE) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_INITIALIZED) == 0) ||
		(ops->info.mode != TEE_MODE_DECRYPT)) {
		ret = EINVAL;
		goto out;
	}

	LMSG("aeops->info.algorithm 0x%lx ilen %ld\n", ops->info.algorithm, (long)srcLen);

	if (ops->info.algorithm == TEE_ALG_AES_GCM) {
		gcm = ops->ctx;
		if (tagLen != ops->tag_len) {
			ret = TEE_ERROR_MAC_INVALID;
			goto out;
		}

		if (destData != NULL) {
			if (*destLen < srcLen + ops->unprocessed_len) {
				ret = TEE_ERROR_SHORT_BUFFER;
				goto out;
			}

			ret = mbedtls_gcm_update(gcm, srcData, srcLen, destData,
							*destLen, destLen);
			if (ret != 0)
				goto out;

			ret = mbedtls_gcm_finish(gcm, NULL, 0, &olen, dst,
						ops->tag_len);
			if (ret != 0)
				goto out;
		} else {
			while ((ssize_t)srcLen > 0) {
				ilen = min(srcLen, sizeof(dst));
				ret = mbedtls_gcm_update(gcm, srcData + off, ilen,
							 dst, sizeof(dst), &olen);
				if (ret != 0)
					goto out;

				srcLen -= ilen;
				off += ilen;
			}

			ret = mbedtls_gcm_finish(gcm, NULL, 0, &olen,
							dst, ops->tag_len);
			if (ret != 0)
				goto out;
		}

		if (memcmp(tag, dst, ops->tag_len) != 0) {
			ret = TEE_ERROR_MAC_INVALID;
			goto out;
		}
	} else if (ops->info.algorithm == TEE_ALG_AES_CCM) {
		ccm = ops->ctx;
		if (tagLen != ccm->tag_len) {
			ret = TEE_ERROR_MAC_INVALID;
			goto out;
		}

		if (destData != NULL) {
			if (*destLen < srcLen + ops->unprocessed_len) {
				ret = TEE_ERROR_SHORT_BUFFER;
				goto out;
			}

			ret = mbedtls_ccm_update(ccm, srcData, srcLen, destData,
							*destLen, destLen);
			if (ret != 0)
				goto out;

			ret = mbedtls_ccm_finish(ccm, dst, ccm->tag_len);
			if (ret != 0)
				goto out;
		} else {
			while ((ssize_t)srcLen > 0) {
				ilen = min(srcLen, sizeof(dst));
				ret = mbedtls_ccm_update(ccm, srcData + off, ilen,
							dst, sizeof(dst), &olen);
				if (ret != 0)
					goto out;

				srcLen -= ilen;
				off += ilen;
			}

			ret = mbedtls_ccm_finish(ccm, dst, ccm->tag_len);
			if (ret != 0)
				goto out;
		}

		if (memcmp(tag, dst, ccm->tag_len) != 0) {
			ret = TEE_ERROR_MAC_INVALID;
			goto out;
		}
	}

	ops->info.handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
	ops->operationState = TEE_OPERATION_STATE_INITIAL;
	ret = TEE_SUCCESS;

out:
	if (ops) {
		mbedtls_gcm_free(gcm);
		mbedtls_ccm_free(ccm);
		TEE_Free(ops->ctx);
		ops->ctx = NULL;
	}
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_SHORT_BUFFER &&
		ret != TEE_ERROR_MAC_INVALID)
		TEE_Panic(ret);
	return ret;
}

TEE_Result TEE_AsymmetricEncrypt(TEE_OperationHandle operation,
	TEE_Attribute *params, uint32_t paramCount, void *srcData,
	size_t srcLen, void *destData, size_t *destLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;
	struct tee_object *obj = NULL;
	mbedtls_rsa_context ctx = {0};
	unsigned char *N = NULL, *E = NULL;
	size_t n_len = 0, e_len = 0, i = 0, olen = 0;
	int padding = 0, hash_id = MBEDTLS_MD_NONE;

	if (((paramCount > 0) && (params == NULL)) ||
		((srcLen > 0) && (srcData == NULL))) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		TEE_Panic(EINVAL);
		return ret;
	}

	if (!destLen || ((*destLen > 0) && (destData == NULL))) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		TEE_Panic(EINVAL);
		return ret;
	}

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_ASYMMETRIC_CIPHER) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET) == 0) ||
		(ops->info.mode != TEE_MODE_ENCRYPT)) {
		ret = EINVAL;
		goto out;
	}

	switch (ops->info.algorithm) {
	case TEE_ALG_RSAES_PKCS1_V1_5:
		padding = MBEDTLS_RSA_PKCS_V15;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
		padding = MBEDTLS_RSA_PKCS_V21;
		hash_id = MBEDTLS_MD_SHA1;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
		padding = MBEDTLS_RSA_PKCS_V21;
		hash_id = MBEDTLS_MD_SHA224;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
		padding = MBEDTLS_RSA_PKCS_V21;
		hash_id = MBEDTLS_MD_SHA256;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
		padding = MBEDTLS_RSA_PKCS_V21;
		hash_id = MBEDTLS_MD_SHA384;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		padding = MBEDTLS_RSA_PKCS_V21;
		hash_id = MBEDTLS_MD_SHA512;
		break;
	case TEE_ALG_RSA_NOPAD:
	default:
		break;
	}

	obj = object_of(ops->key);

	for (i = 0 ; i < obj->attr_nr; i++) {
		if (obj->attr[i].attributeID == TEE_ATTR_RSA_MODULUS) {
			N = obj->attr[i].content.ref.buffer;
			n_len = obj->attr[i].content.ref.length;
		} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_PUBLIC_EXPONENT) {
			E = obj->attr[i].content.ref.buffer;
			e_len = obj->attr[i].content.ref.length;
		}
	}

	if ((N == NULL) || (E == NULL)) {
		ret = ENOSR;
		goto out;
	}

	mbedtls_rsa_init(&ctx);
	mbedtls_rsa_set_padding(&ctx, padding, hash_id);

	if ((mbedtls_rsa_import_raw(&ctx, N, n_len, NULL, 0, NULL, 0,
			NULL, 0, E, e_len)) != 0) {
		ret = EINVAL;
		goto out;
	}

	olen = mbedtls_rsa_get_len(&ctx);
	if (*destLen < olen) {
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	if (ops->info.algorithm != TEE_ALG_RSA_NOPAD) {
		ret = mbedtls_rsa_pkcs1_encrypt(&ctx, tee_prng, NULL,
			srcLen, srcData, destData);
	} else {
		/* TEE_ALG_RSA_NOPAD */
		ret = mbedtls_rsa_public(&ctx, srcData, destData);
	}

	if (ret != 0) {
		if (ret == MBEDTLS_ERR_MPI_BAD_INPUT_DATA ||
			ret == MBEDTLS_ERR_RSA_BAD_INPUT_DATA)
			ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	*destLen = olen;
	LMSG("asymops->info.algorithm 0x%lx\n", ops->info.algorithm);
	udump("destData", destData, *destLen);
	ret = TEE_SUCCESS;

out:
	object_unlock();
	mbedtls_rsa_free(&ctx);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_SHORT_BUFFER &&
		ret != TEE_ERROR_BAD_PARAMETERS &&
		ret != TEE_ERROR_CIPHERTEXT_INVALID)
		TEE_Panic(ret);
	return ret;
}

TEE_Result TEE_AsymmetricDecrypt(TEE_OperationHandle operation,
	TEE_Attribute *params, uint32_t paramCount, void *srcData,
	size_t srcLen, void *destData, size_t *destLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;
	struct tee_object *obj = NULL;
	mbedtls_rsa_context ctx = {0};
	unsigned char *N = NULL, *E = NULL, *D = NULL;
	size_t n_len = 0, e_len = 0, i = 0, olen = 0, d_len = 0;
	int padding = 0, hash_id = MBEDTLS_MD_NONE;

	if (((paramCount > 0) && (params == NULL)) ||
		((srcLen > 0) && (srcData == NULL))) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		TEE_Panic(EINVAL);
		return ret;
	}

	if (!destLen || ((*destLen > 0) && (destData == NULL))) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		TEE_Panic(EINVAL);
		return ret;
	}

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_ASYMMETRIC_CIPHER) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET) == 0) ||
		(ops->info.mode != TEE_MODE_DECRYPT)) {
		ret = EINVAL;
		goto out;
	}

	switch (ops->info.algorithm) {
	case TEE_ALG_RSAES_PKCS1_V1_5:
		padding = MBEDTLS_RSA_PKCS_V15;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
		padding = MBEDTLS_RSA_PKCS_V21;
		hash_id = MBEDTLS_MD_SHA1;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
		padding = MBEDTLS_RSA_PKCS_V21;
		hash_id = MBEDTLS_MD_SHA224;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
		padding = MBEDTLS_RSA_PKCS_V21;
		hash_id = MBEDTLS_MD_SHA256;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
		padding = MBEDTLS_RSA_PKCS_V21;
		hash_id = MBEDTLS_MD_SHA384;
		break;
	case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		padding = MBEDTLS_RSA_PKCS_V21;
		hash_id = MBEDTLS_MD_SHA512;
		break;
	case TEE_ALG_RSA_NOPAD:
	default:
		break;
	}

	obj = object_of(ops->key);

	for (i = 0 ; i < obj->attr_nr; i++) {
		if (obj->attr[i].attributeID == TEE_ATTR_RSA_MODULUS) {
			N = obj->attr[i].content.ref.buffer;
			n_len = obj->attr[i].content.ref.length;
		} else if (obj->attr[i].attributeID  == TEE_ATTR_RSA_PUBLIC_EXPONENT) {
			E = obj->attr[i].content.ref.buffer;
			e_len = obj->attr[i].content.ref.length;
		} else if (obj->attr[i].attributeID == TEE_ATTR_RSA_PRIVATE_EXPONENT) {
			D = obj->attr[i].content.ref.buffer;
			d_len = obj->attr[i].content.ref.length;
		}
	}

	if ((N == NULL) || (D == NULL)) {
		ret = ENOSR;
		goto out;
	}

	mbedtls_rsa_init(&ctx);
	mbedtls_rsa_set_padding(&ctx, padding, hash_id);

	if ((mbedtls_rsa_import_raw(&ctx, N, n_len, NULL, 0,
			NULL, 0, D, d_len, E, e_len)) != 0) {
		ret = EINVAL;
		goto out;
	}

	if (mbedtls_rsa_complete(&ctx) != 0) {
		ret = EINVAL;
		goto out;
	}

	olen = mbedtls_rsa_get_len(&ctx);
	if (olen != srcLen) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (ops->info.algorithm != TEE_ALG_RSA_NOPAD) {
		ret = mbedtls_rsa_pkcs1_decrypt(&ctx, tee_prng, NULL,
			destLen, srcData, destData, *destLen);
		if (ret != 0) {
			if (ret == MBEDTLS_ERR_RSA_INVALID_PADDING)
				ret = TEE_ERROR_CIPHERTEXT_INVALID;
			if (ret == MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE)
				ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}
	} else {
		/* TEE_ALG_RSA_NOPAD */
		if (*destLen < olen) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}
		if (mbedtls_rsa_private(&ctx, tee_prng, NULL,
				srcData, destData) != 0)
			goto out;
		*destLen = olen;
	}

	LMSG("asymops->info.algorithm 0x%lx\n", ops->info.algorithm);
	udump("destData", destData, *destLen);
	ret = TEE_SUCCESS;

out:
	object_unlock();
	mbedtls_rsa_free(&ctx);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_SHORT_BUFFER &&
		ret != TEE_ERROR_BAD_PARAMETERS &&
		ret != TEE_ERROR_CIPHERTEXT_INVALID)
		TEE_Panic(ret);
	return ret;
}

static int __TEE_SignVerifyDigestInfo(uint32_t algo, int *pad, int *hashid)
{
	int padding = 0, hash_id = MBEDTLS_MD_NONE;

	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
		padding = MBEDTLS_RSA_PKCS_V15;
		hash_id = MBEDTLS_MD_MD5;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
		padding = MBEDTLS_RSA_PKCS_V15;
		hash_id = MBEDTLS_MD_SHA1;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
		padding = MBEDTLS_RSA_PKCS_V15;
		hash_id = MBEDTLS_MD_SHA224;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
		padding = MBEDTLS_RSA_PKCS_V15;
		hash_id = MBEDTLS_MD_SHA256;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
		padding = MBEDTLS_RSA_PKCS_V15;
		hash_id = MBEDTLS_MD_SHA384;
		break;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		padding = MBEDTLS_RSA_PKCS_V15;
		hash_id = MBEDTLS_MD_SHA512;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
		padding = MBEDTLS_RSA_PKCS_V21;
		hash_id = MBEDTLS_MD_SHA1;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		padding = MBEDTLS_RSA_PKCS_V21;
		hash_id = MBEDTLS_MD_SHA224;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
		padding = MBEDTLS_RSA_PKCS_V21;
		hash_id = MBEDTLS_MD_SHA256;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		padding = MBEDTLS_RSA_PKCS_V21;
		hash_id = MBEDTLS_MD_SHA384;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		padding = MBEDTLS_RSA_PKCS_V21;
		hash_id = MBEDTLS_MD_SHA512;
		break;
	case TEE_ALG_DSA_SHA1:
		hash_id = MBEDTLS_MD_SHA1;
		break;
	case TEE_ALG_DSA_SHA224:
		hash_id = MBEDTLS_MD_SHA224;
		break;
	case TEE_ALG_DSA_SHA256:
		hash_id = MBEDTLS_MD_SHA256;
		break;
	case TEE_ALG_ECDSA_SHA1:
		hash_id = MBEDTLS_MD_SHA1;
		break;
	case TEE_ALG_ECDSA_SHA224:
		hash_id = MBEDTLS_MD_SHA224;
		break;
	case TEE_ALG_ECDSA_SHA256:
		hash_id = MBEDTLS_MD_SHA256;
		break;
	case TEE_ALG_ECDSA_SHA384:
		hash_id = MBEDTLS_MD_SHA384;
		break;
	case TEE_ALG_ECDSA_SHA512:
		hash_id = MBEDTLS_MD_SHA512;
		break;
	default:
		break;
	}

	if (hash_id == MBEDTLS_MD_NONE)
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
	mbedtls_rsa_context rsa = {0};
	mbedtls_dsa_context dsa = {0};
	mbedtls_ecdsa_context ecdsa = {0};
	size_t i = 0, olen = 0;
	int padding = 0, hash_id = MBEDTLS_MD_NONE;
	const mbedtls_md_info_t *md_info = NULL;

	if (((paramCount > 0) && (params == NULL)) ||
		((digest == NULL) && (signature == NULL))) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		TEE_Panic(EINVAL);
		return ret;
	}

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_ASYMMETRIC_SIGNATURE) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET) == 0) ||
		(ops->info.mode != TEE_MODE_SIGN)) {
		ret = EINVAL;
		goto out;
	}

	ret = __TEE_SignVerifyDigestInfo(ops->info.algorithm,
			&padding, &hash_id);
	if (ret != 0)
		goto out;

	md_info = mbedtls_md_info_from_type(hash_id);
	if ((md_info == NULL) || (mbedtls_md_get_size(md_info) != digestLen)) {
		ret = EINVAL;
		goto out;
	}

	obj = object_of(ops->key);

	if (obj->info.objectType == TEE_TYPE_RSA_KEYPAIR) {
		unsigned char *N = NULL, *E = NULL, *D = NULL;
		size_t n_len = 0, e_len = 0, d_len = 0;

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
			}
		}

		mbedtls_rsa_init(&rsa);
		mbedtls_rsa_set_padding(&rsa, padding, hash_id);

		ret = mbedtls_rsa_import_raw(&rsa, N, n_len, NULL, 0,
				NULL, 0, D, d_len, E, e_len);
		if (ret != 0)
			goto out;

		ret = mbedtls_rsa_complete(&rsa);
		if (ret != 0)
			goto out;

		olen = mbedtls_rsa_get_len(&rsa);

		if (*signatureLen < olen) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		ret = mbedtls_rsa_pkcs1_sign(&rsa, tee_prng, NULL,
				hash_id, digestLen, digest, signature);
		if (ret != 0)
			goto out;
		*signatureLen = olen;
	} else if (obj->info.objectType == TEE_TYPE_ECDSA_KEYPAIR) {
		mbedtls_ecdsa_init(&ecdsa);
		for (i = 0; i < obj->attr_nr; i++) {
			if (obj->attr[i].attributeID == TEE_ATTR_ECC_PRIVATE_VALUE) {
				ret = mbedtls_mpi_read_binary(&ecdsa.d,
					obj->attr[i].content.ref.buffer,
					obj->attr[i].content.ref.length);
				if (ret != 0) {
					ret = ENOMEM;
					goto out;
				}
			} else if (obj->attr[i].attributeID == TEE_ATTR_ECC_CURVE) {
				ret = mbedtls_ecp_group_load(&ecdsa.grp,
						__TEE_MbedEccCurveOf(obj->attr[i].content.value.a));
				if (ret != 0)
					goto out;
			}
		}

		if (*signatureLen < MBEDTLS_ECDSA_MAX_SIG_LEN(ops->info.keySize)) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}

		ret = mbedtls_ecdsa_write_signature(&ecdsa, hash_id, digest,
			digestLen, signature, *signatureLen, signatureLen, tee_prng, NULL);
		if (ret != 0) {
			if (ret == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
				ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}
	} else if (obj->info.objectType == TEE_TYPE_DSA_KEYPAIR) {
		unsigned char *P = NULL, *Q = NULL;
		unsigned char *G = NULL, *Y = NULL, *X = NULL;
		size_t p_len = 0, q_len = 0, g_len = 0, y_len = 0, x_len = 0;

		mbedtls_dsa_init(&dsa);
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

		ret = mbedtls_dsa_import_raw(&dsa, P, p_len, Q, q_len,
				G, g_len, Y, y_len, X, x_len);
		if (ret != 0)
			goto out;

		if (*signatureLen < MBEDTLS_DSA_MAX_SIG_LEN(q_len << 3)) {
			ret = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}
		ret = mbedtls_dsa_sign(&dsa, tee_prng, NULL,
				digestLen, digest, signature, signatureLen);
		if (ret != 0)
			goto out;
	} else {
		ret = ENOTSUP;
		goto out;
	}

	LMSG("asymops->info.algorithm 0x%lx\n", ops->info.algorithm);
	udump("signature", signature, *signatureLen);
	ret = TEE_SUCCESS;

out:
	object_unlock();
	mbedtls_rsa_free(&rsa);
	mbedtls_dsa_free(&dsa);
	mbedtls_ecdsa_free(&ecdsa);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(ret);
	return ret;
}

TEE_Result TEE_AsymmetricVerifyDigest(TEE_OperationHandle operation,
	TEE_Attribute *params, uint32_t paramCount, void *digest,
	size_t digestLen, void *signature, size_t signatureLen)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;
	struct tee_object *obj = NULL;
	mbedtls_rsa_context rsa = {0};
	mbedtls_dsa_context dsa = {0};
	mbedtls_ecdsa_context ecdsa = {0};
	size_t i = 0, olen = 0;
	int padding = 0, hash_id = MBEDTLS_MD_NONE;
	const mbedtls_md_info_t *md_info = NULL;

	if (((paramCount > 0) && (params == NULL)) ||
		((digest == NULL) && (signature == NULL))) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		TEE_Panic(EINVAL);
		return ret;
	}

	object_lock();
	ops = object_of(operation);
	if (ops == NULL) {
		ret = EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_ASYMMETRIC_SIGNATURE) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET) == 0) ||
		(ops->info.mode != TEE_MODE_VERIFY)) {
		ret = EINVAL;
		goto out;
	}

	ret = __TEE_SignVerifyDigestInfo(ops->info.algorithm,
				&padding, &hash_id);
	if (ret != 0)
		goto out;

	md_info = mbedtls_md_info_from_type(hash_id);
	if ((md_info == NULL) || (mbedtls_md_get_size(md_info) != digestLen)) {
		ret = EINVAL;
		goto out;
	}

	obj = object_of(ops->key);

	if ((obj->info.objectType == TEE_TYPE_RSA_PUBLIC_KEY) ||
		(obj->info.objectType == TEE_TYPE_RSA_KEYPAIR)) {
		unsigned char *N = NULL, *E = NULL;
		size_t n_len = 0, e_len = 0;

		for (i = 0 ; i < obj->attr_nr; i++) {
			if (obj->attr[i].attributeID == TEE_ATTR_RSA_MODULUS) {
				N = obj->attr[i].content.ref.buffer;
				n_len = obj->attr[i].content.ref.length;
			} else if (obj->attr[i].attributeID  == TEE_ATTR_RSA_PUBLIC_EXPONENT) {
				E = obj->attr[i].content.ref.buffer;
				e_len = obj->attr[i].content.ref.length;
			}
		}

		mbedtls_rsa_init(&rsa);
		mbedtls_rsa_set_padding(&rsa, padding, hash_id);

		if ((mbedtls_rsa_import_raw(&rsa, N, n_len, NULL, 0, NULL, 0,
				NULL, 0, E, e_len)) != 0) {
			ret = EINVAL;
			goto out;
		}

		olen = mbedtls_rsa_get_len(&rsa);

		if (signatureLen != olen) {
			ret = TEE_ERROR_SIGNATURE_INVALID;
			goto out;
		}

		ret = mbedtls_rsa_pkcs1_verify(&rsa, hash_id, digestLen, digest, signature);
		if (ret != 0) {
			if (ret == MBEDTLS_ERR_RSA_VERIFY_FAILED)
				ret = TEE_ERROR_SIGNATURE_INVALID;
			goto out;
		}
	} else if ((obj->info.objectType == TEE_TYPE_ECDSA_PUBLIC_KEY) ||
			(obj->info.objectType == TEE_TYPE_ECDSA_KEYPAIR)) {
		mbedtls_ecdsa_init(&ecdsa);
		for (i = 0; i < obj->attr_nr; i++) {
			if (obj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_X) {
				ret = mbedtls_mpi_read_binary(&ecdsa.Q.X,
					obj->attr[i].content.ref.buffer,
					obj->attr[i].content.ref.length);
				if (ret != 0) {
					ret = ENOMEM;
					goto out;
				}
			} else if (obj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_Y) {
				ret = mbedtls_mpi_read_binary(&ecdsa.Q.Y,
					obj->attr[i].content.ref.buffer,
					obj->attr[i].content.ref.length);
				if (ret != 0) {
					ret = ENOMEM;
					goto out;
				}
			} else if (obj->attr[i].attributeID == TEE_ATTR_ECC_CURVE) {
				ret = mbedtls_ecp_group_load(&ecdsa.grp,
					__TEE_MbedEccCurveOf(obj->attr[i].content.value.a));
				if (ret != 0)
					goto out;
			}
		}

		ret = mbedtls_mpi_lset(&ecdsa.Q.Z, 1);
		if (ret != 0)
			goto out;

		ret = mbedtls_ecdsa_read_signature(&ecdsa, digest,
					digestLen, signature, signatureLen);
		if (ret != 0) {
			if (ret == MBEDTLS_ERR_ECP_VERIFY_FAILED ||
				ret == MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH)
				ret = TEE_ERROR_SIGNATURE_INVALID;
			goto out;
		}
	} else if ((obj->info.objectType == TEE_TYPE_DSA_PUBLIC_KEY) ||
		(obj->info.objectType == TEE_TYPE_DSA_KEYPAIR)) {
		unsigned char *P = NULL, *Q = NULL;
		unsigned char *G = NULL, *Y = NULL;
		size_t p_len = 0, q_len = 0, g_len = 0, y_len = 0;

		mbedtls_dsa_init(&dsa);
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

		ret = mbedtls_dsa_import_raw(&dsa, P, p_len, Q, q_len,
				G, g_len, Y, y_len, NULL, 0);
		if (ret != 0)
			goto out;

		ret = mbedtls_dsa_verify(&dsa, tee_prng, NULL,
				digestLen, digest, signature, signatureLen);
		if (ret != 0) {
			if (ret == MBEDTLS_ERR_DSA_VERIFY_FAILED)
				ret = TEE_ERROR_SIGNATURE_INVALID;
			goto out;
		}
	} else {
		ret = ENOTSUP;
		goto out;
	}

	ret = TEE_SUCCESS;

out:
	object_unlock();
	mbedtls_rsa_free(&rsa);
	mbedtls_dsa_free(&dsa);
	mbedtls_ecdsa_free(&ecdsa);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_SIGNATURE_INVALID)
		TEE_Panic(ret);
	return ret;
}

void TEE_DeriveKey(TEE_OperationHandle operation, TEE_Attribute *params,
		uint32_t paramCount, TEE_ObjectHandle derivedKey)
{
	int ret = TEE_ERROR_GENERIC;
	struct tee_operation *ops = NULL;
	struct tee_object *obj = NULL;
	struct tee_object *kobj = NULL;
	mbedtls_dhm_context dhm = {0};
	mbedtls_ecdh_context ecdh = {0};
	unsigned char *secret = NULL;
	size_t olen = 0, i = 0, dhm_len = 0;

	object_lock();
	ops = object_of(operation);
	obj = object_of(derivedKey);
	if ((ops == NULL) || (obj == NULL)) {
		ret = EBADF;
		goto out;
	}

	if ((ops->info.operationClass != TEE_OPERATION_KEY_DERIVATION) ||
		((ops->info.handleState & TEE_HANDLE_FLAG_KEY_SET) == 0) ||
		(ops->info.mode != TEE_MODE_DERIVE)) {
		ret = EINVAL;
		goto out;
	}

	if ((paramCount == 0) || (params == NULL)) {
		ret = EINVAL;
		goto out;
	}

	kobj = object_of(ops->key);
	if (kobj == NULL) {
		ret = ENOSR;
		goto out;
	}

	if (ops->info.algorithm == TEE_ALG_DH_DERIVE_SHARED_SECRET) {
		mbedtls_dhm_init(&dhm);
		for (i = 0; i < paramCount; i++) {
			if (params[i].attributeID == TEE_ATTR_DH_PUBLIC_VALUE) {
				if (mbedtls_mpi_read_binary(&dhm.GY,
					params[i].content.ref.buffer,
					params[i].content.ref.length) != 0) {
					ret = ENOMEM;
					goto out;
				}
				break;
			}
		}

		if (mbedtls_mpi_size(&dhm.GY) == 0) {
			ret = EINVAL;
			goto out;
		}

		for (i = 0; i < kobj->attr_nr; i++) {
			if (kobj->attr[i].attributeID == TEE_ATTR_DH_PRIME) {
				if (mbedtls_mpi_read_binary(&dhm.P,
					kobj->attr[i].content.ref.buffer,
					kobj->attr[i].content.ref.length) != 0) {
					ret = ENOMEM;
					goto out;
				}
			} else if (kobj->attr[i].attributeID == TEE_ATTR_DH_BASE) {
				if (mbedtls_mpi_read_binary(&dhm.G,
					kobj->attr[i].content.ref.buffer,
					kobj->attr[i].content.ref.length) != 0) {
					ret = ENOMEM;
					goto out;
				}
			} else if (kobj->attr[i].attributeID == TEE_ATTR_DH_PRIVATE_VALUE) {
				if (mbedtls_mpi_read_binary(&dhm.X,
					kobj->attr[i].content.ref.buffer,
					kobj->attr[i].content.ref.length) != 0) {
					ret = ENOMEM;
					goto out;
				}
			} else if (kobj->attr[i].attributeID == TEE_ATTR_DH_PUBLIC_VALUE) {
				if (mbedtls_mpi_read_binary(&dhm.GX,
					kobj->attr[i].content.ref.buffer,
					kobj->attr[i].content.ref.length) != 0) {
					ret = ENOMEM;
					goto out;
				}
			}
		}

		dhm_len = mbedtls_dhm_get_len(&dhm);
		if (obj->info.maxObjectSize < dhm_len) {
			ret = E2BIG;
			goto out;
		}

		secret = TEE_Malloc(obj->info.maxObjectSize / 8, TEE_MALLOC_FILL_ZERO);
		if (secret == NULL) {
			ret = ENOMEM;
			goto out;
		}

		ret = mbedtls_dhm_calc_secret(&dhm, secret, dhm_len,
						&olen, tee_prng, NULL);
		if (ret)
			goto out;
	} else if (ops->info.algorithm == TEE_ALG_ECDH_DERIVE_SHARED_SECRET) {
		mbedtls_ecdh_init(&ecdh);
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
	mbedtls_ecdh_context *ctx = &ecdh;
#else
	mbedtls_ecdh_context_mbed *ctx = &ecdh.ctx.mbed_ecdh;

	ecdh.var = MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0;
#endif
		for (i = 0; i < paramCount; i++) {
			if (params[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_X) {
				if (mbedtls_mpi_read_binary(&ctx->Qp.X,
					params[i].content.ref.buffer,
					params[i].content.ref.length) != 0) {
					ret = ENOMEM;
					goto out;
				}
			} else if (params[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_Y) {
				if (mbedtls_mpi_read_binary(&ctx->Qp.Y,
					params[i].content.ref.buffer,
					params[i].content.ref.length) != 0) {
					ret = ENOMEM;
					goto out;
				}
			}
		}

		if ((mbedtls_mpi_size(&ctx->Qp.X) == 0) ||
			(mbedtls_mpi_size(&ctx->Qp.Y) == 0)) {
			ret = EINVAL;
			goto out;
		}

		ret = mbedtls_mpi_lset(&ctx->Qp.Z, 1);
		if (ret != 0)
			goto out;

		for (i = 0; i < kobj->attr_nr; i++) {
			if (kobj->attr[i].attributeID == TEE_ATTR_ECC_PRIVATE_VALUE) {
				if (mbedtls_mpi_read_binary(&ctx->d,
					kobj->attr[i].content.ref.buffer,
					kobj->attr[i].content.ref.length) != 0) {
					ret = ENOMEM;
					goto out;
				}
			} else if (kobj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_X) {
				if (mbedtls_mpi_read_binary(&ctx->Q.X,
					kobj->attr[i].content.ref.buffer,
					kobj->attr[i].content.ref.length) != 0) {
					ret = ENOMEM;
					goto out;
				}
			} else if (kobj->attr[i].attributeID == TEE_ATTR_ECC_PUBLIC_VALUE_Y) {
				if (mbedtls_mpi_read_binary(&ctx->Q.Y,
					kobj->attr[i].content.ref.buffer,
					kobj->attr[i].content.ref.length) != 0) {
					ret = ENOMEM;
					goto out;
				}
			} else if (kobj->attr[i].attributeID == TEE_ATTR_ECC_CURVE) {
				ret = mbedtls_ecp_group_load(&ctx->grp,
						__TEE_MbedEccCurveOf(kobj->attr[i].content.value.a));
				if (ret != 0)
					goto out;
			}
		}

		olen = roundup(obj->info.maxObjectSize, 8) / 8;
		secret = TEE_Malloc(olen, TEE_MALLOC_FILL_ZERO);
		if (secret == NULL) {
			ret = ENOMEM;
			goto out;
		}

		ret = mbedtls_ecdh_calc_secret(&ecdh, &olen, secret,
				olen, tee_prng, NULL);
		if (ret)
			goto out;
	} else {
		ret = ENOTSUP;
		goto out;
	}

	TEE_InitRefAttribute(obj->attr, TEE_ATTR_SECRET_VALUE, secret, olen);
	obj->info.handleFlags = TEE_HANDLE_FLAG_INITIALIZED;
	ret = 0;

out:
	object_unlock();
	mbedtls_dhm_free(&dhm);
	mbedtls_ecdh_free(&ecdh);
	if (ret != 0) {
		TEE_CloseObject(derivedKey);
		TEE_Panic(ret);
	}
}

void TEE_GenerateRandom(void *randomBuffer, size_t randomBufferLen)
{
	int ret = -1;

	ret = tee_prng(NULL, randomBuffer, randomBufferLen);
	if (ret != 0)
		TEE_Panic(ret);
}
