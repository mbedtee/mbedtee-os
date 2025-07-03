/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * GlobalPlatform API private defines
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <list.h>
#include <syscall.h>
#include <dirent.h>
#include <utrace.h>

#include <pthread.h>
#include <pthread_object.h>

#include <tee_api_defines.h>
#include <tee_api_types.h>

#include <mbedcrypto.h>

#define TEE_TYPE_PRIVATE_KEY_FLAG (1 << 24)

#define O_FLAG(x) (((x) & (TEE_DATA_FLAG_ACCESS_WRITE |	\
	TEE_DATA_FLAG_ACCESS_WRITE_META)) ? O_RDWR : O_RDONLY)

#define INVALID_FLAG(x) ((x) & ~(TEE_DATA_FLAG_ACCESS_WRITE | \
	TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_ACCESS_READ | \
	TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_SHARE_WRITE | \
	TEE_DATA_FLAG_OVERWRITE))

#define INVALID_BUFF(src, dst, l) ({			\
	unsigned long s = (unsigned long)(src);		\
	unsigned long d = (unsigned long)(dst);		\
	unsigned long len = (unsigned long)(l);		\
	((len > 0) && ((s == 0) || (d == 0))) ||	\
	(s > s + len) || (d > d + len) ||			\
	((d > s) && (d < s + len)) ||				\
	((s > d) && (s < d + len));					})

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

	/* crypto ctx */
	void *ctx;
	uint8_t digest_extract_buf[64];
	size_t digest_extract_len;
	size_t digest_extract_offs;
	size_t tag_len;
	/** AE: expected payload length (for CCM) */
	size_t ae_payload_len;
	/** AE: accumulated payload bytes processed */
	size_t ae_processed_len;
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

bool __TEE_ArePanicsMasked(void);

/*
 * For non-_PS TEE_Result functions: when a condition maps to a
 * TEE_PANIC_xxxx code (GP v1.4 Sec. 5.3), return panic_code if panics are
 * currently masked; otherwise panic unconditionally.
 *
 * _PS functions must NOT use this helper -- they always return TEE_PANIC_xxxx
 * regardless of mask state (both columns in the spec table are identical).
 */
TEE_Result __TEE_PanicOrReturnImpl(TEE_Result panic_code,
	const char *func, int line);

#define __TEE_PanicOrReturn(_panic_code) \
	__TEE_PanicOrReturnImpl((_panic_code), __func__, __LINE__)

/*
 * Helper for non-_PS APIs that carry both programmer-error errno and
 * optional TEE_PANIC_xxxx mapping in local state.
 */
TEE_Result __TEE_PanicOrDieImpl(TEE_Result ret, TEE_Result panic_code,
	const char *func, int line);

#define __TEE_PanicOrDie(_ret, _panic_code) \
	__TEE_PanicOrDieImpl((_ret), (_panic_code), __func__, __LINE__)

void object_lock(void);
void object_unlock(void);

#define object_alloc(_s)		  ({						\
	extern intptr_t __stack_chk_guard;						\
	struct tee_object *__obj = NULL;						\
	int __i = __pthread_object_alloc((_s));					\
	__obj = __pthread_object_of(__i);						\
	if (__obj) {											\
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
	if (!__o)												\
		EMSG("invalid objectHandle 0x%x\n", __x);			\
	__r = __o && __o->tag.idx == __x &&						\
	__o->tag.magic == __stack_chk_guard ? __o : NULL;		\
	if (__x != 0 && __o && !__r)							\
		EMSG("attack objectHandle 0x%x\n", __x);			\
	(void *)__r;											})

#ifdef __cplusplus
}
#endif
