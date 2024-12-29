// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * objects management for pthread internal implementation only.
 * e.g. for the pthread_cond_t and pthread_mutex_t internal structures.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

#include <defs.h>
#include <__pthread.h>
#include "pthread_mutexdep.h"

DECLARE_RECURSIVE_PTHREAD_MUTEX(__objects_lock);

/* id starts from 1 ~ OBJECT_ID_END, 0 reserved */
#define OBJECT_ID_START (1)
#define OBJECT_ID_END (ARRAY_SIZE(((struct __process *)(0))->pobjs))
#define OBJECT_INVALID_ID(x) (((unsigned int)(x) >= OBJECT_ID_END) || !(x))

static int last_oid = OBJECT_ID_START;
static void **__objects;

static int __pthread_object_alloc_id(int start)
{
	int id = 0, ret = -1;

	if (!__objects)
		__objects = __pthread_self->proc->pobjs;

	if (start == OBJECT_ID_END)
		start = OBJECT_ID_START;

	for (id = start; id < OBJECT_ID_END; id++) {
		if (__objects[id] == NULL) {
			ret = id;
			break;
		}
	}

	return ret;
}

/*
 * alloc size of the memory, return the associated object ID
 */
int __pthread_object_alloc(size_t size)
{
	int id = 0;
	void *object = NULL;

	__pthread_mutex_lock(&__objects_lock);

	id = __pthread_object_alloc_id(last_oid);
	if (OBJECT_INVALID_ID(id))
		id = __pthread_object_alloc_id(OBJECT_ID_START);

	if (!OBJECT_INVALID_ID(id)) {
		last_oid = id + 1;
		object = calloc(1, size);

		if (object == NULL)
			id = -ENOMEM;
		else
			__objects[id] = object;
	} else {
		id = -EAGAIN;
	}

	__pthread_mutex_unlock(&__objects_lock);

	return id;
}

/*
 * free the object ID and the associated memory
 */
int __pthread_object_free(int id)
{
	if (OBJECT_INVALID_ID(id) || !__objects)
		return EINVAL;

	void *object = __objects[id];

	/*
	 * strex/sc for __exchange_n(), str/sw for __store_n()
	 *
	 * __ATOMIC_ACQUIRE add memory barrier after strex/sc/str/sw
	 * __ATOMIC_RELEASE add memory barrier before strex/sc/str/sw
	 * __ATOMIC_SEQ_CST add memory barrier before/after strex/sc/str/sw both.
	 */
	__atomic_store_n((long *)&__objects[id],
		0L, __ATOMIC_SEQ_CST);

	free(object);

	return 0;
}

/*
 * Get the associated memory address of
 * the specified object ID
 */
void *__pthread_object_of(int id)
{
	if (OBJECT_INVALID_ID(id) || !__objects)
		return NULL;

	return __objects[id];
}
