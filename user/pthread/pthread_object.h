/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * objects management for pthread internal implementation only.
 * e.g. for the pthread_cond_t and pthread_mutex_t internal structures.
 */

#ifndef _PTHREAD_OBJECT_H
#define	_PTHREAD_OBJECT_H

/*
 * alloc size of the memory, return the associated object ID
 */
int __pthread_object_alloc(size_t size);

/*
 * free the object ID and the associated memory
 */
int __pthread_object_free(int id);

/*
 * Get the associated memory address of
 * the specified object ID
 */
void *__pthread_object_of(int id);

#endif
