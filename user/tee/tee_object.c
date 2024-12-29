// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * GlobalPlatform TEE Object/Storage APIs
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

#define INVALID_OBJECTID(n)   (strpbrk(n, "\\:*?\"<>|"))
#define INVALID_STORAGEID(n)  ((n) != TEE_STORAGE_PRIVATE)
#define PERSISTENT_OBJ_PATH "/ree/"

/* for persistent-object (storage) only */
static LIST_HEAD(storages);

static const uint32_t attr_secret_value_id[] = {
	TEE_ATTR_SECRET_VALUE
};

static const uint32_t attr_rsa_pub_id[2] = {
	TEE_ATTR_RSA_MODULUS, TEE_ATTR_RSA_PUBLIC_EXPONENT
};

static const uint32_t attr_rsa_keypair_id[8] = {
	TEE_ATTR_RSA_MODULUS, TEE_ATTR_RSA_PUBLIC_EXPONENT,
	TEE_ATTR_RSA_PRIVATE_EXPONENT, TEE_ATTR_RSA_PRIME1,
	TEE_ATTR_RSA_PRIME2, TEE_ATTR_RSA_EXPONENT1,
	TEE_ATTR_RSA_EXPONENT2, TEE_ATTR_RSA_COEFFICIENT
};

static const uint32_t attr_dsa_pub_id[4] = {
	TEE_ATTR_DSA_PRIME, TEE_ATTR_DSA_SUBPRIME,
	TEE_ATTR_DSA_BASE, TEE_ATTR_DSA_PUBLIC_VALUE
};

static const uint32_t attr_dsa_keypair_id[5] = {
	TEE_ATTR_DSA_PRIME, TEE_ATTR_DSA_SUBPRIME,
	TEE_ATTR_DSA_BASE, TEE_ATTR_DSA_PRIVATE_VALUE,
	TEE_ATTR_DSA_PUBLIC_VALUE
};

static const uint32_t attr_dh_keypair_id[6] = {
	TEE_ATTR_DH_PRIME, TEE_ATTR_DH_BASE,
	TEE_ATTR_DH_PUBLIC_VALUE, TEE_ATTR_DH_PRIVATE_VALUE,
	TEE_ATTR_DH_SUBPRIME, TEE_ATTR_DH_X_BITS
};

static const uint32_t attr_ecc_pub_id[3] = {
	TEE_ATTR_ECC_PUBLIC_VALUE_X, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
	TEE_ATTR_ECC_CURVE
};

static const uint32_t attr_ecc_keypair_id[4] = {
	TEE_ATTR_ECC_PRIVATE_VALUE, TEE_ATTR_ECC_PUBLIC_VALUE_X,
	TEE_ATTR_ECC_PUBLIC_VALUE_Y, TEE_ATTR_ECC_CURVE
};

static const struct object_attr obj_attrs[] = {
	{TEE_TYPE_DATA,               0,   0,    1,  0, 0, attr_secret_value_id}, /* dummy */
	{TEE_TYPE_AES,                128, 256,  64, 1, 1, attr_secret_value_id},
	{TEE_TYPE_DES,                64,  64,   64, 1, 1, attr_secret_value_id},
	{TEE_TYPE_DES3,               128, 192,  64, 1, 1, attr_secret_value_id},
	{TEE_TYPE_GENERIC_SECRET,	  8,   4096, 8,  3, 1, attr_secret_value_id},
	{TEE_TYPE_RSA_PUBLIC_KEY,	  256, 4096, 1,  2, 2, attr_rsa_pub_id},
	{TEE_TYPE_RSA_KEYPAIR,		  256, 4096, 1,  8, 3, attr_rsa_keypair_id},
	{TEE_TYPE_DSA_PUBLIC_KEY,	  512, 3072, 64, 4, 4, attr_dsa_pub_id},
	{TEE_TYPE_DSA_KEYPAIR,		  512, 3072, 64, 5, 5, attr_dsa_keypair_id},
	{TEE_TYPE_DH_KEYPAIR,		  256, 2048, 8,  6, 4, attr_dh_keypair_id},
	{TEE_TYPE_ECDSA_PUBLIC_KEY,   160, 521,  1,  3, 3, attr_ecc_pub_id},
	{TEE_TYPE_ECDSA_KEYPAIR,	  160, 521,  1,  4, 4, attr_ecc_keypair_id},
	{TEE_TYPE_ECDH_PUBLIC_KEY,    160, 521,  1,  3, 3, attr_ecc_pub_id},
	{TEE_TYPE_ECDH_KEYPAIR,       160, 521,  1,  4, 4, attr_ecc_keypair_id},
	{TEE_TYPE_HMAC_MD5,           64,  512,  8,  1, 1, attr_secret_value_id},
	{TEE_TYPE_HMAC_SHA1,		  80,  512,  8,  1, 1, attr_secret_value_id},
	{TEE_TYPE_HMAC_SHA224,		  112, 512,  8,  1, 1, attr_secret_value_id},
	{TEE_TYPE_HMAC_SHA256,		  192, 1024, 8,  1, 1, attr_secret_value_id},
	{TEE_TYPE_HMAC_SHA384,		  256, 1024, 8,  1, 1, attr_secret_value_id},
	{TEE_TYPE_HMAC_SHA512,		  256, 1024, 8,  1, 1, attr_secret_value_id},
	{TEE_TYPE_SM2_DSA_PUBLIC_KEY, 256, 256,  1,  3, 2, attr_ecc_pub_id},
	{TEE_TYPE_SM2_DSA_KEYPAIR,	  256, 256,  1,  4, 3, attr_ecc_keypair_id},
	{TEE_TYPE_SM2_KEP_PUBLIC_KEY, 256, 256,  1,  3, 2, attr_ecc_pub_id},
	{TEE_TYPE_SM2_KEP_KEYPAIR,	  256, 256,  1,  4, 3, attr_ecc_keypair_id},
	{TEE_TYPE_SM2_PKE_PUBLIC_KEY, 256, 256,  1,  3, 2, attr_ecc_pub_id},
	{TEE_TYPE_SM2_PKE_KEYPAIR,	  256, 256,  1,  4, 3, attr_ecc_keypair_id},
	{TEE_TYPE_SM4,				  128, 128,  1,  1, 1, attr_secret_value_id},
	{TEE_TYPE_HMAC_SM3,           80,  1024, 8,  1, 1, attr_secret_value_id},
};

static pthread_mutex_t object_mutex = PTHREAD_MUTEX_INITIALIZER;

void object_lock(void)
{
	pthread_mutexattr_t mattr;
	static pthread_spinlock_t obj_mutex_init_lock;

	if (object_mutex == PTHREAD_MUTEX_INITIALIZER) {
		pthread_spin_lock(&obj_mutex_init_lock);
		if (object_mutex == PTHREAD_MUTEX_INITIALIZER) {
			pthread_mutexattr_init(&mattr);
			pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);
			pthread_mutex_init(&object_mutex, &mattr);
		}
		pthread_spin_unlock(&obj_mutex_init_lock);
	}
	pthread_mutex_lock(&object_mutex);
}

void object_unlock(void)
{
	pthread_mutex_unlock(&object_mutex);
}

static struct tee_object *object_find(void *id, size_t id_len)
{
	struct tee_object *obj = NULL, *ret = NULL;

	list_for_each_entry(obj, &storages, node) {
		if ((memcmp(obj->name, id, id_len) == 0) &&
			(strlen(obj->name) == id_len)) {
			ret = obj;
			break;
		}
	}

	return ret;
}

static TEE_Result object_access_check(void *id,
	size_t ilen, uint32_t nflags)
{
	uint32_t oflags = 0;
	struct tee_object *obj = NULL;
	uint32_t rflag = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ;
	uint32_t wflag = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_SHARE_WRITE;
	uint32_t mflag_r = rflag | TEE_DATA_FLAG_SHARE_WRITE;
	uint32_t mflag_w = wflag | TEE_DATA_FLAG_SHARE_READ;
	uint32_t mflag_rw = rflag | mflag_w;

	obj = object_find(id, ilen);
	if (obj == NULL)
		return TEE_SUCCESS;

	oflags = obj->info.handleFlags & 0xFFFF;

	if (((oflags == rflag) && (nflags == rflag)) ||
		((oflags == wflag) && (nflags == wflag)))
		return TEE_SUCCESS;

	if ((oflags == mflag_r || oflags == mflag_w || oflags == mflag_rw) &&
		(nflags == mflag_r || nflags == mflag_w || nflags == mflag_rw))
		return TEE_SUCCESS;

	return TEE_ERROR_ACCESS_CONFLICT;
}

static int object_populate_attr(TEE_Attribute *dst,
					   TEE_Attribute *src)
{
	if (!(src->attributeID & TEE_ATTR_FLAG_VALUE)) {
		TEE_Free(dst->content.ref.buffer);
		dst->content.ref.buffer =
			TEE_Malloc(src->content.ref.length, 0);
		if (dst->content.ref.buffer == NULL)
			return TEE_ERROR_OUT_OF_MEMORY;

		memcpy(dst->content.ref.buffer,	src->content.ref.buffer,
				src->content.ref.length);
		dst->content.ref.length = src->content.ref.length;
	} else {
		dst->content.value.a = src->content.value.a;
		dst->content.value.b = src->content.value.b;
	}

	dst->attributeID = src->attributeID;
	return 0;
}

const struct object_attr *object_attr_of(uint32_t objectType)
{
	uint32_t i = 0;
	const struct object_attr *t = NULL;

	for (i = 0; i < ARRAY_SIZE(obj_attrs); i++) {
		if (obj_attrs[i].type == objectType) {
			t = &obj_attrs[i];
			break;
		}
	}

	return t;
}

void TEE_GetObjectInfo(
	TEE_ObjectHandle object,
	TEE_ObjectInfo *objectInfo)
{
	TEE_GetObjectInfo1(object, objectInfo);
}

TEE_Result TEE_GetObjectInfo1(
	TEE_ObjectHandle object,
	TEE_ObjectInfo *objectInfo)
{
	uint32_t flags = 0;
	struct tee_object *obj = NULL;
	TEE_Result ret = TEE_ERROR_GENERIC;
/*
 * TEE_SUCCESS: In case of success.
 TEE_ERROR_CORRUPT_OBJECT: If the persistent object is corrupt. The object handle is closed.
 TEE_ERROR_STORAGE_NOT_AVAILABLE: If the persistent object is stored in a storage area which is
		currently inaccessible.
 */
	if (object == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (objectInfo == NULL) {
		TEE_CloseObject(object);
		TEE_Panic(EFAULT);
		goto out;
	}

	object_lock();

	obj = object_of(object);
	if (obj == NULL) {
		TEE_Panic(EBADF);
		goto out;
	}

	flags = obj->info.handleFlags;

	memcpy(objectInfo, &obj->info, sizeof(TEE_ObjectInfo));

	if ((flags & TEE_HANDLE_FLAG_INITIALIZED) == false)
		objectInfo->objectSize = 0;

	if ((flags & TEE_HANDLE_FLAG_PERSISTENT) == false) {
		objectInfo->dataSize = 0;
		objectInfo->dataPosition = 0;
	} else {
		objectInfo->maxObjectSize = objectInfo->objectSize;
	}

	ret = TEE_SUCCESS;

out:
	object_unlock();
	return ret;
}

void TEE_RestrictObjectUsage(
	TEE_ObjectHandle object,
	uint32_t objectUsage)
{
	TEE_RestrictObjectUsage1(object, objectUsage);
}

TEE_Result TEE_RestrictObjectUsage1(
	TEE_ObjectHandle object,
	uint32_t objectUsage)
{
	struct tee_object *obj = NULL;
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
/*
 * TEE_SUCCESS: In case of success.
 TEE_ERROR_CORRUPT_OBJECT: If the persistent object is corrupt. The object handle is closed.
 TEE_ERROR_STORAGE_NOT_AVAILABLE: If the persistent object is stored in a storage area which is
		currently inaccessible.
 */

	if (object == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	object_lock();

	obj = object_of(object);
	if (obj == NULL) {
		TEE_Panic(EBADF);
		goto out;
	}

	obj->info.objectUsage &= objectUsage;

	ret = TEE_SUCCESS;

out:
	object_unlock();
	return ret;
}

TEE_Result TEE_GetObjectBufferAttribute(
	TEE_ObjectHandle object, uint32_t attributeID,
	void *buffer, size_t *size)
{
	uint32_t i = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct tee_object *obj = NULL;

/*
 * TEE_SUCCESS: In case of success.
 TEE_ERROR_ITEM_NOT_FOUND: If the attribute is not found on this object
 TEE_ERROR_SHORT_BUFFER: If buffer is NULL or too small to contain the key part
 TEE_ERROR_CORRUPT_OBJECT: If the persistent object is corrupt. The object handle is closed.
 TEE_ERROR_STORAGE_NOT_AVAILABLE: If the persistent object is stored in a storage area which is
		currently inaccessible.
 */

	if (buffer == TEE_HANDLE_NULL)
		return TEE_ERROR_SHORT_BUFFER;

	if (object == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	object_lock();

	obj = object_of(object);
	if (obj == NULL) {
		ret = EBADF;
		goto out;
	}

	if (size == NULL) {
		ret = EINVAL;
		goto out;
	}

	if (!(obj->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		EMSG("Object isn't initialized\n");
		ret = EINVAL;
		goto out;
	}

	if (attributeID & TEE_ATTR_FLAG_VALUE) {
		EMSG("not a buffer attributeID\n");
		ret = EINVAL;
		goto out;
	}

	/* search from the attributes */
	for (i = 0; i < obj->attr_nr; i++) {
		if (obj->attr[i].attributeID == attributeID)
			break;
	}

	if (i == obj->attr_nr) {
		EMSG("attributeID 0x%x not found\n", attributeID);
		ret = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}

	if (!(obj->attr[i].attributeID & TEE_ATTR_FLAG_PUBLIC)) {
		if (!(obj->info.objectUsage & TEE_USAGE_EXTRACTABLE)) {
			EMSG("objectUsage isn't extractable!\n");
			ret = EACCES;
			goto out;
		}
	}

	if (*size < obj->attr[i].content.ref.length) {
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	*size = obj->attr[i].content.ref.length;

	memcpy(buffer, obj->attr[i].content.ref.buffer, *size);

	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_SHORT_BUFFER &&
		ret != TEE_ERROR_ITEM_NOT_FOUND &&
		ret != TEE_ERROR_CORRUPT_OBJECT &&
		ret != TEE_ERROR_STORAGE_NOT_AVAILABLE) {
		TEE_CloseObject(object);
		TEE_Panic(ret);
	}
	return ret;
}

TEE_Result TEE_GetObjectValueAttribute(
	TEE_ObjectHandle object, uint32_t attributeID,
	uint32_t *a, uint32_t *b)
{
	uint32_t i = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct tee_object *obj = NULL;

/*
 * TEE_SUCCESS: In case of success.
 TEE_ERROR_ITEM_NOT_FOUND: If the attribute is not found on this object
 TEE_ERROR_ACCESS_DENIED: Deprecated: Handled by a panic
 TEE_ERROR_CORRUPT_OBJECT: If the persistent object is corrupt. The object handle is closed.
 TEE_ERROR_STORAGE_NOT_AVAILABLE: If the persistent object is stored in a storage area which is
		currently inaccessible.
 */

	if (object == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	object_lock();

	obj = object_of(object);
	if (obj == NULL) {
		ret = EBADF;
		goto out;
	}

	if (!(obj->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		EMSG("Object isn't initialized\n");
		ret = EINVAL;
		goto out;
	}

	if ((attributeID & TEE_ATTR_FLAG_VALUE) == false) {
		EMSG("not a value attributeID\n");
		ret = EINVAL;
		goto out;
	}

	/* search from the attributes */
	for (i = 0; i < obj->attr_nr; i++) {
		if (obj->attr[i].attributeID == attributeID)
			break;
	}

	if (i == obj->attr_nr) {
		EMSG("attributeID 0x%x not found\n", attributeID);
		ret = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}

	if (!(obj->attr[i].attributeID & TEE_ATTR_FLAG_PUBLIC)) {
		if (!(obj->info.objectUsage & TEE_USAGE_EXTRACTABLE)) {
			EMSG("objectUsage isn't extractable!\n");
			ret = EACCES;
			goto out;
		}
	}

	if (a)
		*a = obj->attr[i].content.value.a;
	if (b)
		*b = obj->attr[i].content.value.b;

	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_ITEM_NOT_FOUND &&
		ret != TEE_ERROR_CORRUPT_OBJECT &&
		ret != TEE_ERROR_STORAGE_NOT_AVAILABLE) {
		TEE_CloseObject(object);
		TEE_Panic(ret);
	}
	return ret;
}

static void __TEE_CloseObject(struct tee_object *obj)
{
	uint32_t i = 0;

	if (obj == NULL)
		return;

	if (obj->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) {
		list_del(&obj->node);
		close(obj->fd);
	}

	for (i = 0; i < obj->attr_nr; i++) {
		if (obj->attr[i].attributeID & TEE_ATTR_FLAG_VALUE)
			continue;
		TEE_Free(obj->attr[i].content.ref.buffer);
	}

	TEE_Free(obj->attr);
	object_free(obj);
}

void TEE_CloseObject(TEE_ObjectHandle object)
{
	struct tee_object *obj = NULL;

	if (object == TEE_HANDLE_NULL)
		return;

	object_lock();

	obj = object_of(object);
	if (obj != NULL) {
		__TEE_CloseObject(obj);
		object_unlock();
	} else {
		object_unlock();
		TEE_Panic(EBADF);
	}
}

TEE_Result TEE_AllocateTransientObject(
	uint32_t objectType, uint32_t maxObjectSize,
	TEE_ObjectHandle *object)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	TEE_Attribute *attr = NULL;
	struct tee_object *obj = NULL;
	const struct object_attr *t = NULL;

/*
 * TEE_SUCCESS: On success.
 TEE_ERROR_OUT_OF_MEMORY: If not enough resources are available to allocate the object handle
 TEE_ERROR_NOT_SUPPORTED: If the key size is not supported or the object type is not supported.
 */

	if (object == NULL) {
		TEE_Panic(EINVAL);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	t = object_attr_of(objectType);
	if (t == NULL)
		return TEE_ERROR_NOT_SUPPORTED;

	if ((maxObjectSize < t->min_size) ||
		(maxObjectSize > t->max_size) ||
		(maxObjectSize % t->quantum))
		return TEE_ERROR_NOT_SUPPORTED;

	if (t->max_attr) {
		attr = TEE_Malloc(sizeof(TEE_Attribute) * t->max_attr,
						TEE_MALLOC_FILL_ZERO);
		if (attr == NULL) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
	}

	object_lock();
	obj = object_alloc(sizeof(struct tee_object));
	if (obj != NULL) {
		obj->info.objectType = objectType;
		obj->info.maxObjectSize = maxObjectSize;
		obj->info.objectUsage = 0xFFFFFFFF;

		obj->fd = -1;
		obj->attr = attr;
		obj->attr_nr = t->max_attr;
		*object = (TEE_ObjectHandle)obj->tag.idx;
		object_unlock();
		return TEE_SUCCESS;
	}

	ret = TEE_ERROR_OUT_OF_MEMORY;
	object_unlock();

out:
	TEE_Free(attr);
	return ret;
}

void TEE_FreeTransientObject(TEE_ObjectHandle object)
{
	TEE_CloseObject(object);
}

static void __TEE_ResetTransientObject(struct tee_object *obj)
{
	uint32_t i = 0;

	if (obj == NULL)
		return;

	for (i = 0; i < obj->attr_nr; i++) {
		if (!(obj->attr[i].attributeID & TEE_ATTR_FLAG_VALUE))
			TEE_Free(obj->attr[i].content.ref.buffer);
		obj->attr[i].content.value.a = 0;
		obj->attr[i].content.value.b = 0;
	}

	obj->info.objectUsage = 0xFFFFFFFF;
	obj->info.handleFlags = 0x0;
}

void TEE_ResetTransientObject(TEE_ObjectHandle object)
{
	struct tee_object *obj = NULL;

	if (object == TEE_HANDLE_NULL)
		return;

	object_lock();
	obj = object_of(object);
	if (obj != NULL) {
		__TEE_ResetTransientObject(obj);
		object_unlock();
	} else {
		object_unlock();
		TEE_Panic(EBADF);
	}
}

static inline int __TEE_Type2Usage(uint32_t objectType)
{
	int ret = 0;

	switch (objectType) {
	case TEE_TYPE_AES:
	case TEE_TYPE_DES:
	case TEE_TYPE_DES3:
		ret = TEE_USAGE_MAC | TEE_USAGE_ENCRYPT | TEE_USAGE_DECRYPT;
		break;
	case TEE_TYPE_SM2_PKE_PUBLIC_KEY:
		ret = TEE_USAGE_ENCRYPT | TEE_USAGE_DECRYPT;
		break;

	case TEE_TYPE_HMAC_MD5:
	case TEE_TYPE_HMAC_SHA1:
	case TEE_TYPE_HMAC_SHA224:
	case TEE_TYPE_HMAC_SHA256:
	case TEE_TYPE_HMAC_SHA384:
	case TEE_TYPE_HMAC_SHA512:
	case TEE_TYPE_HMAC_SM3:
		ret = TEE_USAGE_MAC;
		break;

	case TEE_TYPE_RSA_KEYPAIR:
	case TEE_TYPE_DSA_KEYPAIR:
	case TEE_TYPE_ECDSA_KEYPAIR:
	case TEE_TYPE_ED25519_KEYPAIR:
		ret = TEE_USAGE_SIGN | TEE_USAGE_DECRYPT;
		/*
		 * TEE_USAGE_ENCRYPT and TEE_USAGE_VERIFY are
		 * only for the public part of this keypair
		 */
		ret |= TEE_USAGE_ENCRYPT | TEE_USAGE_VERIFY;
		break;

	case TEE_TYPE_RSA_PUBLIC_KEY:
		ret = TEE_USAGE_ENCRYPT | TEE_USAGE_VERIFY;
		break;

	case TEE_TYPE_DSA_PUBLIC_KEY:
	case TEE_TYPE_ECDSA_PUBLIC_KEY:
	case TEE_TYPE_SM2_DSA_PUBLIC_KEY:
	case TEE_TYPE_ED25519_PUBLIC_KEY:
		ret = TEE_USAGE_VERIFY;
		break;

	case TEE_TYPE_DH_KEYPAIR:
	case TEE_TYPE_ECDH_KEYPAIR:
	case TEE_TYPE_X25519_KEYPAIR:
	case TEE_TYPE_SM2_KEP_KEYPAIR:
	case TEE_TYPE_ECDH_PUBLIC_KEY:
	case TEE_TYPE_SM2_KEP_PUBLIC_KEY:
	case TEE_TYPE_X25519_PUBLIC_KEY:
		ret = TEE_USAGE_DERIVE;
		break;

	default:
		break;
	}

	return ret | TEE_USAGE_EXTRACTABLE;
}

TEE_Result TEE_PopulateTransientObject(
	TEE_ObjectHandle object, TEE_Attribute *attrs,
	uint32_t attrCount)
{
	uint32_t i = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint32_t src = 0, objsize = 0, populated = 0;
	const struct object_attr *t = NULL;
	struct tee_object *obj = NULL;

/*
 * TEE_SUCCESS: In case of success. In this case, the content of the object SHALL be initialized.
 TEE_ERROR_BAD_PARAMETERS: If an incorrect or inconsistent attribute value is detected. In this case,
	the content of the object SHALL remain uninitialized.
 */

	if (object == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (attrs == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	object_lock();

	obj = object_of(object);
	if (obj == NULL) {
		ret = EBADF;
		goto out;
	}

	if (obj->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) {
		ret = EFTYPE;
		goto out;
	}

	if (obj->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) {
		ret = EEXIST;
		goto out;
	}

	t = object_attr_of(obj->info.objectType);
	if (t == NULL) {
		ret = ENOTSUP;
		goto out;
	}

	objsize = roundup(obj->info.maxObjectSize, 8);

	for (src = 0 ; src < attrCount; src++) {
		for (i = 0; i < t->max_attr; i++) {
			if (t->attr_ids[i] == attrs[src].attributeID) {
				if (!(attrs[src].attributeID & TEE_ATTR_FLAG_VALUE)) {
					if (objsize < attrs[src].content.ref.length * 8) {
						EMSG("attr-objSize %d exceed maxObjectSize %d\n",
							attrs[src].content.ref.length * 8, objsize);
						ret = E2BIG;
						goto out;
					}
				} else {
					if (!attrs[src].content.value.a && !attrs[src].content.value.b) {
						EMSG("value all zero\n");
						ret = ENOMSG;
						goto out;
					}
				}

				if (object_populate_attr(&obj->attr[i], &attrs[src])) {
					ret = ENOMEM;
					goto out;
				}
				populated++;
				break;
			}
		}

		/* not found */
		if (i == t->max_attr) {
			ret = ESRCH;
			goto out;
		}
	}

	if (populated < t->min_attr) {
		ret = ENOSR;
		EMSG("lack of necessary attr\n");
		goto out;
	}

	if (obj->info.objectType == TEE_TYPE_RSA_KEYPAIR) {
		if ((populated != t->min_attr) && (populated != t->max_attr)) {
			ret = ENOSR;
			EMSG("lack of necessary rsa attr\n");
			goto out;
		}
	}

	obj->info.objectUsage &= __TEE_Type2Usage(obj->info.objectType);

	obj->info.objectSize = min((size_t)obj->info.maxObjectSize,
				obj->attr[0].content.ref.length * 8);
	obj->info.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;

	object_unlock();
	return TEE_SUCCESS;

out:
	__TEE_CloseObject(obj);
	object_unlock();
	TEE_Panic(ret);
	return ret;
}

void TEE_InitRefAttribute(TEE_Attribute *attr,
	uint32_t attributeID, void *buffer, size_t length)
{
	if ((attr == NULL) || (attributeID & TEE_ATTR_FLAG_VALUE)
		|| (buffer == NULL) || (length == 0)) {
		TEE_Panic(EINVAL);
		return;
	}

	attr->attributeID = attributeID;
	attr->content.ref.buffer = buffer;
	attr->content.ref.length = length;
}

void TEE_InitValueAttribute(TEE_Attribute *attr,
	uint32_t attributeID, uint32_t a, uint32_t b)
{
	if ((attr == NULL) || !(attributeID & TEE_ATTR_FLAG_VALUE)) {
		TEE_Panic(EINVAL);
		return;
	}

	attr->attributeID = attributeID;
	attr->content.value.a = a;
	attr->content.value.b = b;
}

void TEE_CopyObjectAttributes(
	TEE_ObjectHandle destObject,
	TEE_ObjectHandle srcObject)
{
	TEE_CopyObjectAttributes1(destObject, srcObject);
}

TEE_Result TEE_CopyObjectAttributes1(
	TEE_ObjectHandle destObject,
	TEE_ObjectHandle srcObject)
{
	uint32_t i = 0, j = 0, populated = 0;
	int ret = TEE_ERROR_GENERIC;
	const struct object_attr *t = NULL;
	struct tee_object *sobj = NULL;
	struct tee_object *dobj = NULL;

/*
 * TEE_SUCCESS: In case of success.
 TEE_ERROR_CORRUPT_OBJECT: If the persistent object is corrupt. The object handle is closed.
 TEE_ERROR_STORAGE_NOT_AVAILABLE: If the persistent object is stored in a storage area which is
		currently inaccessible.
 */

	if (srcObject == TEE_HANDLE_NULL ||
		destObject == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	object_lock();

	sobj = object_of(srcObject);
	if (sobj == NULL) {
		ret = EBADF;
		goto err;
	}

	dobj = object_of(destObject);
	if (dobj == NULL) {
		ret = EBADF;
		goto err;
	}

	if (!(sobj->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
		ret = EINVAL;
		goto err;
	}

	if (dobj->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) {
		ret = EEXIST;
		goto err;
	}

	if (dobj->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) {
		ret = EFTYPE;
		goto err;
	}

	t = object_attr_of(dobj->info.objectType);
	if (t == NULL) {
		ret = ENOTSUP;
		goto err;
	}

	if (dobj->info.maxObjectSize < sobj->info.objectSize) {
		ret = E2BIG;
		goto err;
	}

	dobj->info.objectUsage &= sobj->info.objectUsage;

	if (dobj->info.objectType == sobj->info.objectType) {
		for (i = 0; i < sobj->attr_nr; i++) {
			if (object_populate_attr(&dobj->attr[i], &sobj->attr[i])) {
				ret = ENOMEM;
				goto err;
			}
		}
		dobj->attr_nr = sobj->attr_nr;
		goto out;
	}

	if (t->attr_ids[0] == TEE_ATTR_SECRET_VALUE) {
		ret = ENOTSUP;
		goto err;
	}

	for (j = 0; j < t->max_attr; j++) {
		for (i = 0; i < sobj->attr_nr; i++) {
			if (t->attr_ids[j] == sobj->attr[i].attributeID) {
				if (object_populate_attr(&dobj->attr[j], &sobj->attr[i])) {
					ret = ENOMEM;
					goto err;
				}
				populated++;
				break;
			}
		}

		if (i == sobj->attr_nr) {
			ret = ENOSR;
			goto err;
		}
	}

	if (populated < t->min_attr) {
		ret = ENOSR;
		goto err;
	}

out:
	dobj->info.objectUsage &= __TEE_Type2Usage(dobj->info.objectType);
	dobj->info.objectSize = sobj->info.objectSize;
	dobj->info.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
	object_unlock();
	return TEE_SUCCESS;

err:
	__TEE_CloseObject(sobj);
	__TEE_CloseObject(dobj);
	object_unlock();
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
	return ret;
}

static inline void object_prepare_path(char *path,
	void *objectID, size_t objectIDLen)
{
	int len = strlen(PERSISTENT_OBJ_PATH);

	memcpy(path, PERSISTENT_OBJ_PATH, len);
	memcpy(path + len, objectID, objectIDLen);
	path[objectIDLen + len] = 0;
}

TEE_Result TEE_OpenPersistentObject(
	uint32_t storageID, void *objectID, size_t objectIDLen,
	uint32_t flags, TEE_ObjectHandle *object)
{
	int fd = -1;
	TEE_Result ret = TEE_ERROR_GENERIC;
	char objpath[NAME_MAX];
	struct tee_object *obj = NULL;
	struct stat s;

/*
 * TEE_SUCCESS: In case of success.
 TEE_ERROR_ITEM_NOT_FOUND: If the storage denoted by storageID does not exist or if the object
		identifier cannot be found in the storage
 TEE_ERROR_ACCESS_CONFLICT: If an access right conflict (see section 5.7.3) was detected while
		opening the object
 TEE_ERROR_OUT_OF_MEMORY: If there is not enough memory to complete the operation
 TEE_ERROR_CORRUPT_OBJECT: If the storage or object is corrupt
 TEE_ERROR_STORAGE_NOT_AVAILABLE: If the persistent object is stored in a storage area which is
		currently inaccessible. It may be associated with the device but unplugged, busy, or inaccessible for
		some other reason.
 */
	if (objectIDLen > TEE_OBJECT_ID_MAX_LEN) {
		TEE_Panic(ENAMETOOLONG);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!objectID || INVALID_STORAGEID(storageID))
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (INVALID_FLAG(flags)) {
		TEE_Panic(EINVAL);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (object == NULL) {
		TEE_Panic(EFAULT);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	object_lock();

	ret = object_access_check(objectID, objectIDLen, flags);
	if (ret != TEE_SUCCESS) {
		EMSG("access %s conflict\n", objpath);
		goto out;
	}

	object_prepare_path(objpath, objectID, objectIDLen);

	ret = TEE_ERROR_GENERIC;

	fd = open(objpath, O_FLAG(flags));
	if (fd < 0) {
		ret = TEE_ERROR_ITEM_NOT_FOUND;
		EMSG("open %s failed errno %d\n", objpath, errno);
		goto out;
	}

	obj = object_alloc(sizeof(struct tee_object));
	if (obj == NULL) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	obj->fd = fd;
	INIT_LIST_HEAD(&obj->node);
	memcpy(obj->name, objectID, objectIDLen);
	obj->name[objectIDLen] = 0;

	fstat(fd, &s);
	obj->info.dataSize = s.st_size;

	obj->info.handleFlags = (TEE_HANDLE_FLAG_PERSISTENT |
							TEE_HANDLE_FLAG_INITIALIZED | flags);
	list_add_tail(&obj->node, &storages);
	*object = (TEE_ObjectHandle)obj->tag.idx;

	object_unlock();
	return TEE_SUCCESS;

out:
	close(fd);
	object_unlock();
	return ret;
}

TEE_Result TEE_CreatePersistentObject(
	uint32_t storageID, void *objectID,
	size_t objectIDLen, uint32_t flags,
	TEE_ObjectHandle attributes, void *initialData,
	size_t initialDataLen, TEE_ObjectHandle *object)
{
	int fd = -1, wr_bytes = 0, i = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;
	char objpath[NAME_MAX];
	struct tee_object *obj = NULL;
	struct tee_object *attr_obj = NULL;

/*
 * TEE_SUCCESS: In case of success.
 TEE_ERROR_ITEM_NOT_FOUND: If the storage denoted by storageID does not exist
 TEE_ERROR_ACCESS_CONFLICT: If an access right conflict (see section 5.7.3) was detected while
		opening the object
 TEE_ERROR_OUT_OF_MEMORY: If there is not enough memory to complete the operation
 TEE_ERROR_STORAGE_NO_SPACE: If insufficient space is available to create the persistent object
 TEE_ERROR_CORRUPT_OBJECT: If the storage is corrupt
 TEE_ERROR_STORAGE_NOT_AVAILABLE: If the persistent object is stored in a storage area which is
		currently inaccessible. It may be associated with the device but unplugged, busy, or inaccessible for
		some other reason.
 */
	if (objectIDLen > TEE_OBJECT_ID_MAX_LEN) {
		TEE_Panic(ENAMETOOLONG);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!objectID || INVALID_STORAGEID(storageID))
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (INVALID_FLAG(flags)) {
		TEE_Panic(EINVAL);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (object == NULL) {
		TEE_Panic(EFAULT);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	object_lock();

	object_prepare_path(objpath, objectID, objectIDLen);

	if (object_find(objectID, objectIDLen) != NULL) {
		ret = TEE_ERROR_ACCESS_CONFLICT;
		EMSG("%s exist\n", objpath);
		goto out;
	}

	if (INVALID_OBJECTID(objpath)) {
		ret = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}

	fd = open(objpath, O_FLAG(flags) | O_CREAT | O_EXCL);
	if (fd < 0) {
		ret = (errno == EEXIST) ? TEE_ERROR_ACCESS_CONFLICT : errno;
		EMSG("create %s failed (%d)\n", objpath, errno);
		goto out;
	}

	obj = object_alloc(sizeof(struct tee_object));
	if (obj == NULL) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	obj->fd = fd;
	INIT_LIST_HEAD(&obj->node);
	memcpy(obj->name, objectID, objectIDLen);
	obj->name[objectIDLen] = 0;

	if (attributes != NULL) {
		attr_obj = object_of(attributes);
		if (attr_obj == NULL) {
			ret = EBADF;
			goto out;
		}
		if (!(attr_obj->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED)) {
			ret = EINVAL;
			goto out;
		}

		obj->attr = TEE_Malloc(sizeof(TEE_Attribute) *
					   attr_obj->attr_nr, TEE_MALLOC_FILL_ZERO);
		if (obj->attr == NULL) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}

		obj->attr_nr = attr_obj->attr_nr;
		for (i = 0; i < obj->attr_nr; i++) {
			if (object_populate_attr(&obj->attr[i], &attr_obj->attr[i])) {
				ret = TEE_ERROR_OUT_OF_MEMORY;
				goto out;
			}
		}

		obj->info.objectType = attr_obj->info.objectType;
		obj->info.objectUsage = attr_obj->info.objectUsage;
		obj->info.objectSize = attr_obj->info.objectSize;
		obj->info.maxObjectSize = attr_obj->info.maxObjectSize;
	} else {
		obj->info.objectType = TEE_TYPE_DATA;
	}

	if ((initialData != NULL) && (initialDataLen > 0)) {
		wr_bytes = write(fd, initialData, initialDataLen);
		if (wr_bytes != initialDataLen) {
			ret = wr_bytes > 0 ? TEE_ERROR_STORAGE_NO_SPACE : errno;
			goto out;
		}
		obj->info.dataSize = wr_bytes;
		lseek(fd, 0, SEEK_SET);
	}

	obj->info.handleFlags = (TEE_HANDLE_FLAG_PERSISTENT |
							TEE_HANDLE_FLAG_INITIALIZED | flags);

	*object = (TEE_ObjectHandle)obj->tag.idx;
	list_add_tail(&obj->node, &storages);
	object_unlock();
	return TEE_SUCCESS;

out:
	if (fd > 0) {
		close(fd);
		remove(objpath);
	}
	__TEE_CloseObject(obj);
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_ITEM_NOT_FOUND &&
		ret != TEE_ERROR_OUT_OF_MEMORY &&
		ret != TEE_ERROR_ACCESS_CONFLICT &&
		ret != TEE_ERROR_STORAGE_NO_SPACE &&
		ret != TEE_ERROR_CORRUPT_OBJECT &&
		ret != TEE_ERROR_STORAGE_NOT_AVAILABLE)
		TEE_Panic(ret);
	return ret;
}

void TEE_CloseAndDeletePersistentObject(
	TEE_ObjectHandle object)
{
	TEE_CloseAndDeletePersistentObject1(object);
}

TEE_Result TEE_CloseAndDeletePersistentObject1(
	TEE_ObjectHandle object)
{
	char objpath[NAME_MAX];
	struct tee_object *obj = NULL;
	TEE_Result ret = TEE_ERROR_GENERIC;
/*
 * If object is TEE_HANDLE_NULL, the function does nothing.

 TEE_SUCCESS: In case of success.
 TEE_ERROR_STORAGE_NOT_AVAILABLE: If the persistent object is stored in a storage area which is
		currently inaccessible
 */

	if (object == TEE_HANDLE_NULL)
		return TEE_SUCCESS;

	object_lock();

	obj = object_of(object);
	if (obj == NULL) {
		ret = EBADF;
		goto out;
	}

	if (!(obj->info.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META)) {
		ret = EACCES;
		goto out;
	}

	object_prepare_path(objpath, obj->name, strlen(obj->name));

	__TEE_CloseObject(obj);

	if (remove(objpath) != 0) {
		EMSG("remove %s failed %d\n", objpath, errno);
		ret = errno;
		goto out;
	}

	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_STORAGE_NOT_AVAILABLE) {
		TEE_CloseObject(object);
		TEE_Panic(ret);
	}
	return ret;
}

TEE_Result TEE_RenamePersistentObject(
	TEE_ObjectHandle object, void *newObjectID,
	size_t newObjectIDLen)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	char oldpath[NAME_MAX];
	char newpath[NAME_MAX];
	struct tee_object *obj = NULL;

/*
 * TEE_SUCCESS: In case of success.
 TEE_ERROR_ACCESS_CONFLICT: If an object with the same identifier already exists
 TEE_ERROR_CORRUPT_OBJECT: If the object is corrupt. The object handle is closed.
 TEE_ERROR_STORAGE_NOT_AVAILABLE: If the persistent object is stored in a storage area which is
		currently inaccessible.
 */

	if (object == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (newObjectID == NULL) {
		TEE_Panic(EINVAL);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (newObjectIDLen > TEE_OBJECT_ID_MAX_LEN) {
		TEE_Panic(ENAMETOOLONG);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	object_lock();

	obj = object_of(object);
	if (obj == NULL) {
		ret = EBADF;
		goto out;
	}

	if (!(obj->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		ret = EFTYPE;
		goto out;
	}

	if (!(obj->info.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE_META)) {
		ret = EACCES;
		goto out;
	}

	object_prepare_path(oldpath, obj->name, strlen(obj->name));
	object_prepare_path(newpath, newObjectID, newObjectIDLen);

	if (INVALID_OBJECTID(newpath)) {
		ret = EINVAL;
		goto out;
	}

	ret = rename(oldpath, newpath);
	if (ret != 0) {
		EMSG("rename %s -> %s failed errno %d\n",
			oldpath, newpath, errno);
		ret = TEE_ERROR_ACCESS_CONFLICT;
		goto out;
	}

	memcpy(obj->name, newObjectID, newObjectIDLen);
	obj->name[newObjectIDLen] = 0;

	ret = TEE_SUCCESS;

out:
	object_unlock();

	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_ACCESS_CONFLICT &&
		ret != TEE_ERROR_STORAGE_NOT_AVAILABLE &&
		ret != TEE_ERROR_CORRUPT_OBJECT) {
		TEE_CloseObject(object);
		TEE_Panic(ret);
	}
	return ret;
}

static void __TEE_ResetPersistentObjectEnumerator(
	struct object_enumerator *p)
{
	if (p != NULL) {
		closedir(p->dir);
		p->dir = NULL;
	}
}

TEE_Result TEE_AllocatePersistentObjectEnumerator(
	TEE_ObjectEnumHandle *objectEnumerator)
{
	struct object_enumerator *p = NULL;

	p = object_alloc(sizeof(struct object_enumerator));
	if (p == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	__TEE_ResetPersistentObjectEnumerator(p);

	*objectEnumerator = (TEE_ObjectEnumHandle)p->tag.idx;

	return TEE_SUCCESS;
}

void TEE_ResetPersistentObjectEnumerator(
	TEE_ObjectEnumHandle objectEnumerator)
{
	struct object_enumerator *p = NULL;

	if (objectEnumerator == NULL)
		TEE_Panic(EINVAL);

	object_lock();

	p = object_of(objectEnumerator);
	__TEE_ResetPersistentObjectEnumerator(p);
	object_unlock();

	if (p == NULL)
		TEE_Panic(EBADF);
}

void TEE_FreePersistentObjectEnumerator(
	TEE_ObjectEnumHandle objectEnumerator)
{
	struct object_enumerator *p = NULL;

	if (objectEnumerator == TEE_HANDLE_NULL)
		return;

	object_lock();

	p = object_of(objectEnumerator);
	if (p) {
		__TEE_ResetPersistentObjectEnumerator(p);
		object_free(p);
	}
	object_unlock();

	if (p == NULL)
		TEE_Panic(EBADF);
}

TEE_Result TEE_StartPersistentObjectEnumerator(
	TEE_ObjectEnumHandle objectEnumerator, uint32_t storageID)
{
	DIR *dir = NULL;
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct dirent *dent = NULL;
	struct object_enumerator *p = NULL;

	if (INVALID_STORAGEID(storageID))
		return TEE_ERROR_ITEM_NOT_FOUND;

	object_lock();

	p = object_of(objectEnumerator);
	if (p == NULL) {
		ret = EBADF;
		goto out;
	}

	if (p->dir) {
		ret = EEXIST;
		goto out;
	}

	dir = opendir(PERSISTENT_OBJ_PATH);
	if (dir == NULL) {
		ret = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}

	dent = readdir(dir);
	if (dent == NULL) {
		ret = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}

	rewinddir(dir);

	p->dir = dir;
	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_ITEM_NOT_FOUND &&
		ret != TEE_ERROR_STORAGE_NOT_AVAILABLE) {
		TEE_FreePersistentObjectEnumerator(objectEnumerator);
		TEE_Panic(ret);
	}
	return ret;
}

TEE_Result TEE_GetNextPersistentObject(
	TEE_ObjectEnumHandle objectEnumerator,
	TEE_ObjectInfo *objectInfo, void *objectID,
	size_t *objectIDLen)
{
	struct dirent *dent = NULL;
	struct tee_object *obj = NULL;
	struct object_enumerator *p = NULL;
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct stat s;

	object_lock();

	if ((objectIDLen == NULL) || (objectID == NULL)) {
		ret = EFAULT;
		goto out;
	}

	p = object_of(objectEnumerator);
	if (p == NULL) {
		ret = EBADF;
		goto out;
	}

	if (p->dir == NULL) {
		ret = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}

	dent = readdir(p->dir);
	if (dent != NULL) {
		*objectIDLen = strlen(dent->d_name);
		memcpy(objectID, dent->d_name, *objectIDLen);

		IMSG("filename is %s\n", dent->d_name);
		if (objectInfo != NULL) {
			obj = object_find(objectID, *objectIDLen);
			if (obj == NULL) {
				IMSG("object isn't open\n");
				char objpath[NAME_MAX];

				object_prepare_path(objpath, dent->d_name, *objectIDLen);
				stat(objpath, &s);
				objectInfo->dataSize = s.st_size;
			} else
				memcpy(objectInfo, &obj->info, sizeof(TEE_ObjectInfo));
		}
	} else {
		ret = TEE_ERROR_ITEM_NOT_FOUND;
		goto out;
	}

	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_ITEM_NOT_FOUND) {
		TEE_FreePersistentObjectEnumerator(objectEnumerator);
		TEE_Panic(ret);
	}
	return ret;
}

TEE_Result TEE_ReadObjectData(TEE_ObjectHandle object,
	void *buffer, size_t size, uint32_t *count)
{
	ssize_t rd_bytes = 0;
	struct tee_object *obj = NULL;
	TEE_Result ret = TEE_ERROR_GENERIC;
/*
 * TEE_SUCCESS: In case of success.
 TEE_ERROR_CORRUPT_OBJECT: If the object is corrupt. The object handle is closed.
 TEE_ERROR_STORAGE_NOT_AVAILABLE: If the persistent object is stored in a storage area which is
		currently inaccessible.
 */
	if (object == TEE_HANDLE_NULL)
		return ret;

	object_lock();

	obj = object_of(object);
	if (obj == NULL) {
		ret = EBADF;
		goto out;
	}

	if ((buffer == NULL) || (count == NULL)) {
		ret = EFAULT;
		goto out;
	}

	if (!(obj->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		ret = EFTYPE;
		goto out;
	}

	if (!(obj->info.handleFlags & TEE_DATA_FLAG_ACCESS_READ)) {
		ret = EACCES;
		goto out;
	}

	if (size <= 0)
		*count = 0;
	else {
		rd_bytes = read(obj->fd, buffer, size);
		if (rd_bytes < 0) {
			ret = errno;
			*count = 0;
			goto out;
		}
		rd_bytes = (rd_bytes < 0) ? 0 : rd_bytes;
		*count = rd_bytes;
		obj->info.dataPosition += rd_bytes;
	}

	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_CORRUPT_OBJECT &&
		ret != TEE_ERROR_STORAGE_NOT_AVAILABLE) {
		TEE_CloseObject(object);
		TEE_Panic(ret);
	}
	return ret;
}

TEE_Result TEE_WriteObjectData(TEE_ObjectHandle object,
	void *buffer, size_t size)
{
	ssize_t wr_bytes = 0;
	struct tee_object *obj = NULL;
	TEE_Result ret = TEE_ERROR_GENERIC;

/*
 * TEE_SUCCESS: In case of success.
 TEE_ERROR_STORAGE_NO_SPACE: If insufficient storage space is available
 TEE_ERROR_OVERFLOW: If the value of the data position indicator resulting from this operation would
		be greater than TEE_DATA_MAX_POSITION
 TEE_ERROR_CORRUPT_OBJECT: If the object is corrupt. The object handle is closed.
 TEE_ERROR_STORAGE_NOT_AVAILABLE: If the persistent object is stored in a storage area which is
		currently inaccessible
 */

	if (object == TEE_HANDLE_NULL)
		return ret;

	if (buffer == NULL) {
		TEE_Panic(EFAULT);
		return ret;
	}

	object_lock();

	obj = object_of(object);
	if (obj == NULL) {
		ret = EBADF;
		goto out;
	}

	if (!(obj->info.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE)) {
		ret = EACCES;
		goto out;
	}

	if (!(obj->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		ret = EFTYPE;
		goto out;
	}

	if ((uint64_t)obj->info.dataPosition + size >
		 TEE_DATA_MAX_POSITION) {
		ret = TEE_ERROR_OVERFLOW;
		goto out;
	}

	wr_bytes = write(obj->fd, buffer, size);
	if (wr_bytes != size) {
		ret = errno;
		goto out;
	}

	obj->info.dataPosition += wr_bytes;
	if (obj->info.dataPosition > obj->info.dataSize)
		obj->info.dataSize = obj->info.dataPosition;

	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_STORAGE_NO_SPACE &&
		ret != TEE_ERROR_OVERFLOW &&
		ret != TEE_ERROR_CORRUPT_OBJECT &&
		ret != TEE_ERROR_STORAGE_NOT_AVAILABLE) {
		TEE_CloseObject(object);
		TEE_Panic(ret);
	}
	return ret;
}

TEE_Result TEE_TruncateObjectData(
	TEE_ObjectHandle object, size_t size)
{
	struct tee_object *obj = NULL;
	TEE_Result ret = TEE_ERROR_GENERIC;
/*
 * TEE_SUCCESS: In case of success.
 TEE_ERROR_STORAGE_NO_SPACE: If insufficient storage space is available to perform the operation
 TEE_ERROR_CORRUPT_OBJECT: If the object is corrupt. The object handle is closed.
 TEE_ERROR_STORAGE_NOT_AVAILABLE: If the persistent object is stored in a storage area which is
		currently inaccessible.
 */
	if (object == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	object_lock();

	obj = object_of(object);
	if (obj == NULL) {
		ret = EBADF;
		goto out;
	}

	if (!(obj->info.handleFlags & TEE_DATA_FLAG_ACCESS_WRITE)) {
		ret = EACCES;
		goto out;
	}

	if (!(obj->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		ret = EFTYPE;
		goto out;
	}

	ret = ftruncate(obj->fd, size);
	if (ret != 0) {
		ret = errno;
		goto out;
	}

	obj->info.dataSize = size;
	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_STORAGE_NO_SPACE &&
		ret != TEE_ERROR_CORRUPT_OBJECT &&
		ret != TEE_ERROR_STORAGE_NOT_AVAILABLE) {
		TEE_CloseObject(object);
		TEE_Panic(ret);
	}
	return ret;
}

TEE_Result TEE_SeekObjectData(TEE_ObjectHandle object,
	size_t offset, TEE_Whence whence)
{
	size_t pos = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct tee_object *obj = NULL;

/*
 * TEE_SUCCESS: In case of success.
 TEE_ERROR_OVERFLOW: If the value of the data position indicator resulting from this operation would
		be greater than TEE_DATA_MAX_POSITION
 TEE_ERROR_CORRUPT_OBJECT: If the object is corrupt. The object handle is closed.
 TEE_ERROR_STORAGE_NOT_AVAILABLE: If the persistent object is stored in a storage area which is
		currently inaccessible.
 */

	if (object == TEE_HANDLE_NULL)
		return ret;

	object_lock();

	obj = object_of(object);
	if (obj == NULL) {
		ret = EBADF;
		goto out;
	}

	if (!(obj->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		ret = EFTYPE;
		goto out;
	}

	pos = obj->info.dataPosition;

	switch (whence) {
	case TEE_DATA_SEEK_SET:
		if ((ssize_t)offset < 0)
			offset = 0;
		obj->info.dataPosition = offset;
		whence = SEEK_SET;
		break;
	case TEE_DATA_SEEK_CUR:
		if ((uint64_t)obj->info.dataPosition + offset >
			 TEE_DATA_MAX_POSITION) {
			ret = TEE_ERROR_OVERFLOW;
			goto out;
		}
		obj->info.dataPosition += offset;
		whence = SEEK_CUR;
		break;
	case TEE_DATA_SEEK_END:
		if ((uint64_t)obj->info.dataSize + offset >
			 TEE_DATA_MAX_POSITION) {
			ret = TEE_ERROR_OVERFLOW;
			goto out;
		}
		obj->info.dataPosition = obj->info.dataSize + offset;
		whence = SEEK_END;
		break;
	default:
		goto out;
	}

	ret = lseek(obj->fd, offset, whence);
	if (ret < 0) {
		obj->info.dataPosition = pos;
		ret = errno;
		goto out;
	}

	ret = TEE_SUCCESS;

out:
	object_unlock();
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_OVERFLOW &&
		ret != TEE_ERROR_CORRUPT_OBJECT &&
		ret != TEE_ERROR_STORAGE_NOT_AVAILABLE) {
		TEE_CloseObject(object);
		TEE_Panic(ret);
	}
	return ret;
}
