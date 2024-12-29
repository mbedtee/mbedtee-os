/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread cleanup
 */

#ifndef _PTHREAD_CLEANUP_H
#define	_PTHREAD_CLEANUP_H

#include "pthread_auxiliary.h"

static inline void __pthread_cleanup_exec(struct __pthread *t)
{
	struct __pthread_aux *aux = aux_of(t);
	struct __pthread_cleanup *cleaner = aux->cleanups;

	/* LIFO: last in first out */
	while (cleaner) {
		cleaner->routine(cleaner->arg);
		cleaner = cleaner->next;
	}
}

#endif
