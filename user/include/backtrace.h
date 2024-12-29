/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Call Stack Backtrace (user unwind)
 */

#ifndef _UBACKTRACE_H
#define _UBACKTRACE_H

#include <generated/autoconf.h>

#ifdef CONFIG_USER_BACKTRACE
void backtrace(void);
void unwind_init(void);
void __register_frame(void *framehdr);
#else
static inline void backtrace(void) {}
static inline void unwind_init(void) {}
#endif

#endif
