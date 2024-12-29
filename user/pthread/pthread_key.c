// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread independent (thread-specific data visible to all threads
 * in the process)
 */

#include <stdbool.h>
#include <errno.h>

#include "pthread_key.h"

struct __pthread_key __pthread_keys[PTHREAD_KEY_MAX] = {{NULL}};

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
	static pthread_key_t last;
	pthread_key_t id = 0;

	for (id = last + 1; id < PTHREAD_KEY_MAX; id++) {
		if (__pthread_key_create(id, key, destructor) == 0) {
			last = id;
			return 0;
		}
	}

	for (id = 0; id < PTHREAD_KEY_MAX; id++) {
		if (__pthread_key_create(id, key, destructor) == 0) {
			last = id;
			return 0;
		}
	}

	return EAGAIN;
}

int	pthread_key_delete(pthread_key_t key)
{
	if (PTHREAD_KEY_INVALID(key))
		return EINVAL;

	/*
	 * strex/sc for __exchange_n(), str/sw for __store_n()
	 *
	 * __ATOMIC_ACQUIRE add memory barrier after strex/sc/str/sw
	 * __ATOMIC_RELEASE add memory barrier before strex/sc/str/sw
	 * __ATOMIC_SEQ_CST add memory barrier before/after strex/sc/str/sw both.
	 */
	__atomic_store_n((long *)&__pthread_keys[key].destructor,
		(long)PTHREAD_KEY_UNUSED, __ATOMIC_SEQ_CST);

	return 0;
}

int	pthread_setspecific(pthread_key_t key, const void *value)
{
	struct __pthread_key_data *d = NULL;
	struct __pthread_aux *aux = aux_of(__pthread_self);

	if (PTHREAD_KEY_INVALID(key))
		return EINVAL;

	if (PTHREAD_KEY_INACTIVE(key))
		return EINVAL;

	if (value == NULL)
		return 0;

	list_for_each_entry(d, &aux->keys, node) {
		if (d->id == key) {
			d->data = (void *)value;
			return 0;
		}
	}

	d = malloc(sizeof(struct __pthread_key_data));
	if (!d)
		return ENOMEM;

	d->data = (void *)value;
	d->id = key;
	list_add_tail(&d->node, &aux->keys);
	return 0;
}

void *pthread_getspecific(pthread_key_t key)
{
	struct __pthread_key_data *d = NULL;
	struct __pthread_aux *aux = aux_of(__pthread_self);

	if (PTHREAD_KEY_INVALID(key))
		return NULL;

	if (PTHREAD_KEY_INACTIVE(key))
		return NULL;

	list_for_each_entry(d, &aux->keys, node) {
		if (d->id == key)
			return d->data;
	}

	return NULL;
}
