/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Extended string operations
 */

#include <ctype.h>
#include <string.h>

#ifndef _STRMISC_H
#define	_STRMISC_H

_BEGIN_STD_C

#if !defined(basename)
char *basename(const char *path);
#endif

#if !defined(strchrnul)
char *strchrnul(const char *s, int c);
#endif

/*
 * copy max. n bytes from 's' to 'd' and
 * trim the leading / trailing space and tab
 * including the terminal null '\0'.
 */
void strncpy_trim(char *d, const char *s, size_t n);

/*
 * in-place operation
 * trim the duplicated '/' and '\'
 */
void strtrim_unused(char *s);

/*
 * check if 's2' is substring of 's1' with delimiter
 */
int strstr_delimiter(const char *s1, const char *s2, int delimiter);

_END_STD_C

#endif
