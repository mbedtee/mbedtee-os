// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * pthread cleanup stack for push/pop
 */

#include "pthread_auxiliary.h"

struct __pthread_cleanup **__pthread_get_cleanup_stack(void)
{
	return &aux_of(__pthread_self)->cleanups;
}
