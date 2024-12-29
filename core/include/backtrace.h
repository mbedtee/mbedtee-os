/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Call Stack Backtrace (kernel unwind)
 */

#ifndef _BACKTRACE_H
#define _BACKTRACE_H

#include <generated/autoconf.h>

#define BACKTRACE_STACK_SIZE (8192)

#ifdef CONFIG_BACKTRACE
void backtrace(void);
const char *ksymname_of(unsigned long addr, unsigned long *offset);
extern void __register_frame(void *framehdr);
extern __weak_symbol const unsigned int ksymnum; /* number of total symbols */
extern __weak_symbol const char ksymname[]; /* symbols name array */
extern __weak_symbol const unsigned long ksymaddr[]; /* symbol run-address */
extern __weak_symbol const unsigned int ksymoffset[]; /* symbol name offset within the 'ksymname' */
#else
static inline void backtrace(void) {}
static inline const char *ksymname_of(
	unsigned long addr, unsigned long *offset)
{
	return "null";
}
#endif

#endif
