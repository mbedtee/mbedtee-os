/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Kernel assert_func
 */

#ifndef _ASSERT_H
#define _ASSERT_H

void assert_func(int line, const char *func, const char *expr);

#undef assert
#define assert(condition)  \
	do { \
		if (!(condition)) \
			assert_func(__LINE__, __func__, #condition); \
	} while (0)

#endif
