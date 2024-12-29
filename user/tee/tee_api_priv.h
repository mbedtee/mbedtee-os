/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * GlobalPlatform API private defines
 */

#include <list.h>
#include <syscall.h>
#include <dirent.h>
#include <utrace.h>

#include <pthread.h>
#include <pthread_object.h>

#include <tee_api_defines.h>
#include <tee_api_types.h>

#include <mbedtls.h>

#define TEE_LIBC_PRNG 1

#define TEE_TYPE_PRIVATE_KEY_FLAG (1 << 24)

#define O_FLAG(x) (((x) & (TEE_DATA_FLAG_ACCESS_WRITE |	\
	TEE_DATA_FLAG_ACCESS_WRITE_META)) ? O_RDWR : O_RDONLY)

#define INVALID_FLAG(x) ((x) & ~(TEE_DATA_FLAG_ACCESS_WRITE | \
	TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_ACCESS_READ | \
	TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_SHARE_WRITE | \
	TEE_DATA_FLAG_OVERWRITE))

#define INVALID_BUFF(src, dst, l) ({			\
	unsigned long s = (unsigned long)src;		\
	unsigned long d = (unsigned long)dst;		\
	(s > s + l) || (d > d + l) ||				\
	((d > s) && (d < s + l)) ||					\
	(s > d && (s < d + l));						})

struct object_tag {
	long idx; /* index in pthread_object */
	long magic; /* magic of current pthread_object */
};

struct tee_object {
	struct object_tag tag;
	char name[TEE_OBJECT_ID_MAX_LEN + 1];
	uint16_t attr_nr;
	int fd;
	TEE_Attribute *attr;
	TEE_ObjectInfo info;
	struct list_head node;
};

struct object_enumerator {
	struct object_tag tag;
	DIR *dir;
};

struct tee_operation {
	struct object_tag tag;
	TEE_OperationInfo info;
	TEE_ObjectHandle key;
	TEE_ObjectHandle key2;
	uint32_t operationState;
	uint32_t objectType; /* assumed */

	/* mbedtls ctx */
	void *ctx;
	/** Buffer for input that has not been processed yet. */
	unsigned char unprocessed_data[16];
	/** Number of Bytes that have not been processed yet. */
	size_t unprocessed_len;
	size_t tag_len;
};

struct object_attr {
	uint32_t type;
	uint16_t min_size; /* min size in bit */
	uint16_t max_size; /* max size in bit */
	uint16_t quantum;  /* multiple of this quantum */
	uint8_t max_attr;  /* Max number of the attr */
	uint8_t min_attr;  /* Min number of the attr (mandatory count) */
	const uint32_t *attr_ids;
};

const struct object_attr *object_attr_of(uint32_t objectType);

int tee_prng(void *p_rng, unsigned char *output, size_t len);

void object_lock(void);
void object_unlock(void);

#define object_alloc(_s)		  ({						\
	extern intptr_t __stack_chk_guard;						\
	struct tee_object *__obj = NULL;						\
	int __i = __pthread_object_alloc((size_t)(_s));			\
	__obj = __pthread_object_of(__i);						\
	if (__obj != NULL) {									\
		__obj->tag.magic = __stack_chk_guard;				\
		__obj->tag.idx = __i;								\
	}														\
	(void *)__obj;											})

#define object_free(_o)										\
	do {													\
		if (_o)												\
			__pthread_object_free((_o)->tag.idx);			\
	} while (0)

#define object_of(_x)			  ({						\
	int __x = (intptr_t)(_x);								\
	extern intptr_t __stack_chk_guard;						\
	struct tee_object *__o = NULL, *__r = NULL;				\
	__o = __pthread_object_of(__x);							\
	if (__o == NULL)										\
		EMSG("invalid objectHandle 0x%x\n", __x);			\
	__r = __o && __o->tag.idx == __x &&						\
	__o->tag.magic == __stack_chk_guard ? __o : NULL;		\
	if (__x && __o && __r == NULL)							\
		EMSG("attack objectHandle 0x%x\n", __x);			\
	(void *)__r;											})
