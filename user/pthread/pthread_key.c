// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * pthread independent (thread-specific data visible to all threads
 * in the process)
 */

#include <stdbool.h>
#include <errno.h>

#include "pthread_key.h"

#define PTHREAD_KEY_MAX (64U)
#define PTHREAD_KEY_UNUSED ((void *)0)
#define PTHREAD_KEY_INUSE ((void *)1)
#define PTHREAD_DESTRUCTOR_ITERATIONS 4

#define PTHREAD_KEY_INVALID(key) ((unsigned int)(key) >= PTHREAD_KEY_MAX)

struct __pthread_key {
	void (*destructor)(void *data);
};

struct __pthread_key __pthread_keys[PTHREAD_KEY_MAX] = {{NULL}};

#define PTHREAD_KEY_INACTIVE(key) \
	(__atomic_load_n(&__pthread_keys[key].destructor, \
		__ATOMIC_ACQUIRE) == PTHREAD_KEY_UNUSED)

struct __pthread_key_data {
	struct list_head node;
	pthread_key_t id;
	const void *data;
};

static int __pthread_key_create(pthread_key_t id,
	pthread_key_t *key,	void (*destructor)(void *))
{
	void *d = PTHREAD_KEY_UNUSED;
	void *destr = destructor ? destructor : PTHREAD_KEY_INUSE;
	struct __pthread_key *k = &__pthread_keys[id];

	if (__atomic_compare_exchange_n(&k->destructor, &d,
		destr, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
		*key = id;
		return 0;
	}

	return EAGAIN;
}

/*
 * The pthread_key_create() function creates a
 * thread-specific data key visible to all threads
 * in the process.
 */
int	pthread_key_create(pthread_key_t *key,
	void (*destructor)(void *))
{
	pthread_key_t id = 0;

	for (id = 0; id < PTHREAD_KEY_MAX; id++) {
		if (__pthread_key_create(id, key, destructor) == 0)
			return 0;
	}

	return EAGAIN;
}

int	pthread_key_delete(pthread_key_t key)
{
	struct __pthread_key_data *d = NULL;
	struct __pthread_aux *aux = pthread_aux(__pthread_self);

	if (PTHREAD_KEY_INVALID(key))
		return EINVAL;

	list_for_each_entry(d, &aux->keys, node) {
		if (d->id == key) {
			d->data = NULL;
			list_del(&d->node);
			free(d);
			break;
		}
	}

	/*
	 * strex/sc for __exchange_n(), str/sw for __store_n()
	 *
	 * __ATOMIC_ACQUIRE add memory barrier after strex/sc/str/sw
	 * __ATOMIC_RELEASE add memory barrier before strex/sc/str/sw
	 * __ATOMIC_SEQ_CST add memory barrier before/after strex/sc/str/sw both.
	 */
	__atomic_store_n(&__pthread_keys[key].destructor,
		PTHREAD_KEY_UNUSED, __ATOMIC_SEQ_CST);

	return 0;
}

int	pthread_setspecific(pthread_key_t key, const void *value)
{
	struct __pthread_key_data *d = NULL;
	struct __pthread_aux *aux = pthread_aux(__pthread_self);

	if (PTHREAD_KEY_INVALID(key))
		return EINVAL;

	if (PTHREAD_KEY_INACTIVE(key))
		return EINVAL;

	list_for_each_entry(d, &aux->keys, node) {
		if (d->id == key) {
			d->data = value;
			return 0;
		}
	}

	if (!value)
		return 0;

	d = malloc(sizeof(struct __pthread_key_data));
	if (!d)
		return ENOMEM;

	d->data = value;
	d->id = key;
	list_add_tail(&d->node, &aux->keys);
	return 0;
}

void *pthread_getspecific(pthread_key_t key)
{
	struct __pthread_key_data *d = NULL;
	struct __pthread_aux *aux = pthread_aux(__pthread_self);

	if (PTHREAD_KEY_INVALID(key))
		return NULL;

	if (PTHREAD_KEY_INACTIVE(key))
		return NULL;

	list_for_each_entry(d, &aux->keys, node) {
		if (d->id == key)
			return (void *)d->data;
	}

	return NULL;
}

static bool __pthread_exec_destructor(struct __pthread_key_data *d)
{
	struct __pthread_key *k = &__pthread_keys[d->id];
	void (*destr)(void *) = NULL;
	void *data = (void *)d->data;

	list_del(&d->node);

	if (data) {
		destr = __atomic_load_n(&k->destructor, __ATOMIC_ACQUIRE);
		if ((destr != PTHREAD_KEY_UNUSED) && (destr != PTHREAD_KEY_INUSE)) {
			d->data = NULL;
			free(d);
			destr(data);
			return true;
		}
	}

	free(d);
	return false;
}

void __pthread_key_destructor(struct __pthread *t)
{
	struct __pthread_aux *aux = pthread_aux(t);
	struct __pthread_key_data *d = NULL, *n = NULL;
	int iter = 0;
	bool called = false;

	for (iter = 0; iter < PTHREAD_DESTRUCTOR_ITERATIONS; iter++) {
		called = false;
		list_for_each_entry_safe(d, n, &aux->keys, node) {
			if (__pthread_exec_destructor(d))
				called = true;
		}

		if (!called || list_empty(&aux->keys))
			break;
	}

	list_for_each_entry_safe(d, n, &aux->keys, node) {
		list_del(&d->node);
		free(d);
	}

	INIT_LIST_HEAD(&aux->keys);
}
