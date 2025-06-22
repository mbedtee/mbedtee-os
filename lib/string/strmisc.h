/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Extended string operations
 */

#ifndef _STRMISC_H
#define	_STRMISC_H

#include <ctype.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(basename)
char *basename(char *path);
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
 * check if 's2' is a token of 's1' with delimiter
 * strict match, no suffix/prefix matching allowed.
 */
int strstr_token(const char *s1, const char *s2, int delimiter);

#ifdef __cplusplus
}
#endif

#endif
