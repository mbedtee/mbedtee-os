/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * User Log Trace
 */

#ifndef _UTRACE_H
#define _UTRACE_H

#define TRACE_LEVEL_IGNORE 0
#define TRACE_LEVEL_ERROR  1
#define TRACE_LEVEL_WARN   2
#define TRACE_LEVEL_INFO   3
#define TRACE_LEVEL_DEBUG  4
#define TRACE_LEVEL_LOG    5

#define DEFAULT_TRACE_LEVEL TRACE_LEVEL_INFO

void utrace(const char *func, int line, int level, const char *fmt, ...);

#define utrace_level(level, ...) do { \
		if ((level) <= DEFAULT_TRACE_LEVEL) \
			utrace(__func__, __LINE__, (level), __VA_ARGS__); \
	} while (0)

#define EMSG(...) utrace_level(TRACE_LEVEL_ERROR, __VA_ARGS__)
#define WMSG(...) utrace_level(TRACE_LEVEL_WARN, __VA_ARGS__)
#define IMSG(...) utrace_level(TRACE_LEVEL_INFO, __VA_ARGS__)
#define DMSG(...) utrace_level(TRACE_LEVEL_DEBUG, __VA_ARGS__)
#define LMSG(...) utrace_level(TRACE_LEVEL_LOG, __VA_ARGS__)

#define udump(pre, data, len) do { \
	if (DEFAULT_TRACE_LEVEL > TRACE_LEVEL_INFO) { \
		int __i, __l = (len); \
		printf("App: In %s() line: %d -- %s\n", __func__, \
			__LINE__, pre); \
		for (__i = 0; __i < __l; __i++) { \
			printf("0x%02X,", *(unsigned char *)((long)(data) + __i)); \
			if ((__i + 1) % 16 == 0) \
				printf("\n"); \
		} \
		if (__l % 16)  \
			printf("\n"); \
	} \
} while (0)

#endif
