/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread independent (thread-specific data visible to all threads
 * in the process)
 */

#ifndef _PTHREAD_KEY_H
#define _PTHREAD_KEY_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <list.h>

#include "pthread_auxiliary.h"

#define PTHREAD_KEY_UNUSED ((void *)0)
#define PTHREAD_KEY_INUSE ((void *)1)
#define PTHREAD_KEY_MAX (256U)

#define PTHREAD_KEY_INVALID(key) ((unsigned int)(key) >= PTHREAD_KEY_MAX)

struct __pthread_key {
	void (*destructor)(void *data);
};

extern struct __pthread_key __pthread_keys[PTHREAD_KEY_MAX];

#define PTHREAD_KEY_INACTIVE(key) \
	(__pthread_keys[key].destructor == PTHREAD_KEY_UNUSED)

struct __pthread_key_data {
	struct list_head node;
	pthread_key_t id;
	void *data;
};

static inline void __pthread_key_destructor
(
	struct __pthread *t
)
{
	struct __pthread_aux *aux = aux_of(t);
	struct __pthread_key_data *d = NULL, *n = NULL;
	struct __pthread_key *k = NULL;

	list_for_each_entry_safe(d, n, &aux->keys, node) {
		k = &__pthread_keys[d->id];
		if ((k->destructor != PTHREAD_KEY_UNUSED) &&
			(k->destructor != PTHREAD_KEY_INUSE) &&
			d->data)
			k->destructor(d->data);
		free(d);
	}
}

#endif
