/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Kernel Log Trace
 */

#ifndef _TRACE_H
#define _TRACE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <panic.h>
#include <printk.h>

#define TRACE_LEVEL_IGNORE 0
#define TRACE_LEVEL_ERROR  1
#define TRACE_LEVEL_WARN   2
#define TRACE_LEVEL_INFO   3
#define TRACE_LEVEL_DEBUG  4
#define TRACE_LEVEL_LOG    5
#define TRACE_LEVEL_FS     6

#if defined(CONFIG_TRACE_LEVEL)
#define DEFAULT_TRACE_LEVEL CONFIG_TRACE_LEVEL
#else
#define DEFAULT_TRACE_LEVEL TRACE_LEVEL_IGNORE
#endif

#ifdef CONFIG_PRINTK
__printf(4, 5) void trace_kern(
	const char *func, int line, int level,
	const char *fmt, ...);
#else
static inline void trace_kern(
	const char *func, int line, int level,
	const char *fmt, ...) {}
#endif

#define trace_level(l, ...) ({ \
	if ((l) <= DEFAULT_TRACE_LEVEL) \
		trace_kern(__func__, __LINE__, (l), __VA_ARGS__); })

#define EMSG(...) trace_level(TRACE_LEVEL_ERROR, __VA_ARGS__)
#define WMSG(...) trace_level(TRACE_LEVEL_WARN, __VA_ARGS__)
#define IMSG(...) trace_level(TRACE_LEVEL_INFO, __VA_ARGS__)
#define DMSG(...) trace_level(TRACE_LEVEL_DEBUG, __VA_ARGS__)
#define LMSG(...) trace_level(TRACE_LEVEL_LOG, __VA_ARGS__)
#define FMSG(...) trace_level(TRACE_LEVEL_FS, __VA_ARGS__)

#define kdump(data, len, unit) \
	do { \
		int __i, __l = (len), __u = (unit); \
		printk("Kernel: In %s %s line: %d:\n", __func__, \
			__FILE__, __LINE__); \
		for (__i = 0; __i < __l; __i += __u) { \
			if (__u == 1) \
				printk("0x%02X,", *(unsigned char *)((long)(data) + __i)); \
			if (__u == 4) \
				printk("0x%08X,", *(unsigned int *)((long)(data) + __i)); \
			if (__u == 8) \
				printk("0x%016llX,", *(unsigned long long *)((long)(data) + __i)); \
			if ((__i/__u + 1) % (16/__u) == 0) \
				printk("\n"); \
		} \
		if ((__l/__u) % (16/__u)) \
			printk("\n"); \
	} while (0)

#endif
