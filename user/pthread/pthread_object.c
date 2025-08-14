// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * objects management for pthread internal implementation only.
 * e.g. for the pthread_cond_t and pthread_mutex_t internal structures.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <defs.h>
#include <__pthread.h>
#include "pthread_mutexdep.h"

static DECLARE_RECURSIVE_PTHREAD_MUTEX(__objects_lock);

/*
 * Dynamically allocated object slots,
 * initial capacity 64, grows as needed.
 */
#define POBJS_INIT_MAX 64

/* id starts from 1 ~ pobjs_max, 0 reserved */
#define OBJECT_ID_START (1)

static int pobjs_max;
static int last_oid = OBJECT_ID_START;
static void **__objects;

static inline bool object_id_invalid(int x)
{
	return (unsigned int)x >= pobjs_max || x == 0;
}

static int __pthread_objects_grow(void)
{
	int new_max = pobjs_max != 0 ? pobjs_max * 2 : POBJS_INIT_MAX;
	void **new_objs = calloc(new_max, sizeof(void *));

	if (!new_objs)
		return -ENOMEM;

	if (__objects)
		memcpy(new_objs, __objects, pobjs_max * sizeof(void *));

	/*
	 * Publish new array first, then update pobjs_max.
	 * Lock-free readers acquire pobjs_max, so seeing
	 * the new max guarantees seeing the new array.
	 * Old array is not freed - lock-free readers
	 * in __pthread_object_of() may still reference it.
	 */
	__objects = new_objs;
	__atomic_store_n(&pobjs_max, new_max, __ATOMIC_RELEASE);
	return 0;
}

static int __pthread_object_alloc_id(int start)
{
	int id = 0, ret = -1;

	if (!__objects) {
		if (__pthread_objects_grow() != 0)
			return -1;
	}

	if (start >= pobjs_max)
		start = OBJECT_ID_START;

	for (id = start; id < pobjs_max; id++) {
		if (!__objects[id]) {
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
	if (object_id_invalid(id))
		id = __pthread_object_alloc_id(OBJECT_ID_START);

	/* all slots full, try to grow */
	if (object_id_invalid(id)) {
		int old_max = pobjs_max;

		if (__pthread_objects_grow() == 0)
			id = __pthread_object_alloc_id(old_max);
	}

	if (!object_id_invalid(id)) {
		last_oid = id + 1;
		object = calloc(1, size);

		if (!object)
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
 * Free the object ID and the associated memory.
 *
 * Must hold __objects_lock - lock-free _free() would
 * race with _grow()'s memcpy, leaving a dangling
 * pointer in the new array.
 */
int __pthread_object_free(int id)
{
	void *object = NULL;

	__pthread_mutex_lock(&__objects_lock);

	if (object_id_invalid(id) || !__objects) {
		__pthread_mutex_unlock(&__objects_lock);
		return EINVAL;
	}

	object = __objects[id];
	__objects[id] = NULL;

	__pthread_mutex_unlock(&__objects_lock);

	free(object);

	return 0;
}

/*
 * Get the associated memory address of
 * the specified object ID.
 *
 * Lock-free: acquire pobjs_max guarantees seeing
 * the __objects that was published before it.
 */
void *__pthread_object_of(int id)
{
	int max = __atomic_load_n(&pobjs_max, __ATOMIC_ACQUIRE);

	if ((unsigned int)id >= max || id == 0 || !__objects)
		return NULL;

	return __objects[id];
}
