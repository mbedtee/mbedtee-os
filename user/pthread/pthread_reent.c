// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * reentrant struct for each pthread
 */

#include "pthread_reent.h"

struct _reent *__getreent(void)
{
	return reent_of(__pthread_self);
}
