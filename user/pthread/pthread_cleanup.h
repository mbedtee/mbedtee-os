/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * pthread cleanup
 */

#ifndef _PTHREAD_CLEANUP_H
#define	_PTHREAD_CLEANUP_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pthread_auxiliary.h"

static inline void __pthread_cleanup_exec(struct __pthread *t)
{
	struct __pthread_aux *aux = pthread_aux(t);
	struct __pthread_cleanup *cleaner = NULL;

	/* LIFO: last in first out */
	while ((cleaner = aux->cleanups) != NULL) {
		aux->cleanups = cleaner->next;
		cleaner->routine(cleaner->arg);
	}

	aux->cleanups = NULL;
}

#ifdef __cplusplus
}
#endif

#endif
