// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Extended string operations
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

#include <printk.h>
#include <strmisc.h>

char *basename(const char *path)
{
	char *p = (char *)path;

	if (path == NULL || *path == 0)
		return NULL;

	while (*p)
		p++;

	while ((p >= path) && (*p != '/'))
		p--;

	p = ((p < path) || (*p == '/')) ? p + 1 : p;

	return *p ? p : "/";
}

/*
 * copy max. n bytes from 's' to 'd'
 * including the terminal null '\0'.
 *
 * trim the duplicated '/' and '\'
 * trim the leading / trailing space and tab
 */
void strncpy_trim(char *d, const char *s, size_t n)
{
	const char *p1 = s;
	char *p2 = d, c = 0;

	while (*p1 == ' ' || *p1 == '\t')
		p1++;

	while (((c = *p1) != '\0') && (p2 - d  < n)) {
		if (c == '\\')
			c = '/';
		if (c == '/' && (*(p1 + 1) == '/' ||
			*(p1 + 1) == '\\'))
			p1++;
		else {
			*p2++ = *p1++;
		}
	}

	*p2-- = '\0';

	while (*p2 == ' ' || *p2 == '\t')
		*p2-- = '\0';
}

/*
 * in-place operation
 * trim the duplicated '/' and '\'
 * trim the leading / trailing space and tab
 */
void strtrim_unused(char *s)
{
	char *p1 = s, *p2 = s, c = 0;

	while (*p1 == ' ' || *p1 == '\t')
		p1++;

	while ((c = *p1) != '\0') {
		if (c == '\\')
			c = '/';
		if (c == '/' && (*(p1 + 1) == '/' ||
			*(p1 + 1) == '\\'))
			p1++;
		else {
			*p2++ = *p1++;
		}
	}

	*p2-- = '\0';

	while (*p2 == ' ' || *p2 == '\t')
		*p2-- = '\0';
}

/*
 * check if 's2' is substring of 's1' with delimiter
 */
int strstr_delimiter(const char *s1, const char *s2,
	int delimiter)
{
	size_t l1 = 0, l2 = 0;

	if (!s1 || !s2)
		return false;

	l2 = strlen(s2);
	l1 = strlen(s1);

	while (l1 >= l2) {
		l1--;
		if (!memcmp(s1, s2, l2) && ((s1[l2] == 0) ||
			(s1[l2] == delimiter)))
			return true;
		s1++;
	}
	return false;
}
