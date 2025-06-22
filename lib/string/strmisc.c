// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
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

char *basename(char *path)
{
	char *p = path;
	char *end = NULL;
	char *base = NULL;

	if (!path || *path == 0)
		return "/";

	while (*p)
		p++;

	end = p;

	/* Skip trailing slashes */
	while (end > path && *(end - 1) == '/')
		end--;

	/* All slashes -> root */
	if (end == path)
		return "/";

	/* NUL-terminate to strip trailing slashes */
	*end = '\0';

	/* Walk back to find start of basename */
	base = end;
	while (base > path && *(base - 1) != '/')
		base--;

	return base;
}

/*
 * copy max. n bytes from 's' to 'd'
 * including the terminal null '\0'.
 *
 * trim the duplicated '/' and '\'
 * trim the leading and trailing space and tab
 */
void strncpy_trim(char *d, const char *s, size_t n)
{
	const char *p1 = s;
	char *p2 = d, c = 0;

	if (!d || !s)
		return;

	while (*p1 == ' ' || *p1 == '\t')
		p1++;

	while (((c = *p1) != '\0') && ((size_t)(p2 - d) < n)) {
		if (c == '\\')
			c = '/';

		if (c == '/' && (*(p1 + 1) == '/' ||
			*(p1 + 1) == '\\')) {
			p1++;
		} else {
			*p2++ = c;
			p1++;
		}
	}

	*p2 = '\0';

	while (p2 > d && (*(p2 - 1) == ' ' || *(p2 - 1) == '\t'))
		*--p2 = '\0';
}

/*
 * in-place operation
 * trim the duplicated '/' and '\'
 * trim the leading / trailing space and tab
 */
void strtrim_unused(char *s)
{
	char *p1 = s, *p2 = s, c = 0;

	if (!s || *s == '\0')
		return;

	while (*p1 == ' ' || *p1 == '\t')
		p1++;

	while ((c = *p1) != '\0') {
		if (c == '\\')
			c = '/';

		if (c == '/' && (*(p1 + 1) == '/' ||
			*(p1 + 1) == '\\')) {
			p1++;
		} else {
			*p2++ = c;
			p1++;
		}
	}

	*p2 = '\0';

	/* Trim trailing spaces safely */
	while (p2 > s && (*(p2 - 1) == ' ' || *(p2 - 1) == '\t'))
		*--p2 = '\0';
}

/*
 * check if 's2' is a token of 's1' with delimiter
 * strict match, no suffix/prefix matching allowed.
 */
int strstr_token(const char *s1, const char *s2,
	int delimiter)
{
	size_t len = 0;
	const char *start = s1;

	if (!s1 || !s2)
		return false;

	len = strlen(s2);

	while ((s1 = strstr(s1, s2)) != NULL) {
		/* check start boundary */
		if (s1 == start || s1[-1] == delimiter) {
			/* check end boundary */
			if (s1[len] == delimiter || s1[len] == '\0')
				return true;
		}
		s1 += len;
	}

	return false;
}

