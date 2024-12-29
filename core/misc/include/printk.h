/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Kernel printf
 */

#ifndef _PRINTK_H
#define _PRINTK_H

#include <stdarg.h>
#include <stddef.h>

#include <file.h>
#include <generated/autoconf.h>

#ifdef CONFIG_PRINTK
/*
 * formatted-print to uart or redirected-file
 * fmt: format
 * ...: __VA_ARGS__
 */
__printf(1, 2) void printk(const char *fmt, ...);

/*
 * raw-string-print to uart or redirected-file
 * str: string
 * size: print length
 */
void printk_raw(const char *str, size_t size);

void printk_setfd(struct file_desc *d);

#else
static inline void printk(const char *fmt, ...) {}
static inline void printk_raw(const char *str, size_t size) {}
static inline void printk_setfd(struct file_desc *d) {}
#endif
#endif
