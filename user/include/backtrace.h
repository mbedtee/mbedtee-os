/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Call Stack Backtrace (user unwind)
 */

#ifndef _UBACKTRACE_H
#define _UBACKTRACE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <generated/autoconf.h>

#if defined(CONFIG_USER_BACKTRACE)
void backtrace(void);
void backtrace_exit(void);
void __register_frame(void *framehdr);
void __process_unwind_init(void);
#else
static inline void backtrace(void) {}
static inline void backtrace_exit(void) {}
static inline void __process_unwind_init(void) {}
#endif

#ifdef __cplusplus
}
#endif

#endif
