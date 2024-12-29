// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * String functions
 */

#include <cpu.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <kmath.h>

int strcmp(const char *s1, const char *s2)
{
	char c = 0;

	while (((c = *s1) != 0) && (c == *s2)) {
		s1++;
		s2++;
	}

	return c - *s2;
}

int strncmp(const char *s1, const char *s2, size_t n)
{
	char c = 0;

	if (n == 0)
		return 0;

	while (n-- && ((c = *s1) == *s2)) {
		if (n == 0 || c == 0)
			return 0;
		s1++;
		s2++;
	}

	return c - *s2;
}

/*
 * length is excluding the terminating null byte ('\0').
 */
size_t strlen(const char *s)
{
	const char *sc = NULL;

	for (sc = s; *sc; ++sc)
		;

	return sc - s;
}

/*
 * length is excluding the terminating null byte ('\0').
 */
size_t strnlen(const char *s, size_t n)
{
	const char *str = NULL;

	for (str = s; ((*str) && (n--)); ++str)
		;

	return str - s;
}

char *strcpy(char *dst, const char *src)
{
	char *tmp = dst;

	while ((*dst++ = *src++))
		;

	return tmp;
}

char *stpcpy(char *dst, const char *src)
{
	while ((*dst++ = *src++))
		;

	return --dst;
}

/*
 * length is excluding the terminating null byte ('\0').
 */
size_t strlcpy(char *dst, const char *src, size_t n)
{
	char *d = dst;
	const char *s = src;

	if (n) {
		while (--n && (*d++ = *s++))
			;
		if (n == 0)
			*d = 0;
	}

	if (n == 0) {
		while (*s++)
			;
	}

	return s - src - 1;
}

char *strncpy(char *dst, const char *src, size_t n)
{
	char *d = dst;
	const char *s = src;

	while (n) {
		n--;
		*d = *s++;
		if (*d++ == 0)
			break;
	}

	while (n-- > 0)
		*d++ = 0;

	return dst;
}

int strcasecmp(const char *s1, const char *s2)
{
	int c = 0;
	int c1 = 0;
	int c2 = 0;

	for (;;) {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);

		c = c1 - c2;
		if ((c != 0) || (c2 == 0))
			break;
	}

	return c;
}

int strncasecmp(const char *s1, const char *s2, size_t n)
{
	int c = 0;
	int c1 = 0;
	int c2 = 0;

	for ( ; n != 0; n--) {
		c1 = tolower(*s1++);
		c2 = tolower(*s2++);

		c = c1 - c2;
		if ((c != 0) || (c2 == 0))
			break;
	}

	return c;
}

char *strcat(char *dst, const char *src)
{
	char *d = dst;

	for (; *dst; ++dst)
		;

	while ((*dst++ = *src++))
		;

	return d;
}

/*
 * length is excluding the terminating null byte ('\0').
 */
size_t strlcat(char *dst, const char *src, size_t cnt)
{
	char *d = dst;
	const char *s = src;
	size_t n = cnt, oridlen = 0, left = 0;

	while (n && *d) {
		n--;
		d++;
	}

	oridlen = cnt - n;
	left = cnt - oridlen;
	if (left == 0) {
		while (*s) {
			s++;
			oridlen++;
		}
		return oridlen;
	}

	while (--left && ((*d++ = *s++)))
		;

	if (left == 0) {
		while (*s)
			s++;
	}

	*d = 0;

	return oridlen + s - src;
}

char *strncat(char *dst, const char *src, size_t n)
{
	char *d = dst;
	const char *s = src;

	if (n) {
		while (*d)
			d++;
		do {
			*d = *s++;
			if (*d == 0)
				break;
			d++;
		} while (--n != 0);

		*d = 0;
	}

	return dst;
}

char *strpbrk(const char *s1, const char *s2)
{
	char *ptr1 = NULL, *ptr2 = NULL;

	if (*s2 == 0)
		return NULL;

	ptr1 = (char *)s1;

	while (*ptr1 != 0) {
		ptr2 = (char *)s2;

		while (*ptr2 != 0) {
			if (*ptr1 == *ptr2)
				return ptr1;

			ptr2++;
		}
		ptr1++;
	}

	return NULL;
}

char *strchr(const char *s, int c)
{
	char *ptr = (char *)s;

	while (*ptr != (char)c) {
		if (*ptr == 0)
			return NULL;

		ptr++;
	}

	return ptr;
}

char *strchrnul(const char *s, int c)
{
	char *ptr = (char *)s;

	while (*ptr != (char)c) {
		if (*ptr == 0)
			return ptr;

		ptr++;
	}

	return ptr;
}

char *strrchr(const char *s, int c)
{
	char *ls = (char *)s;

	if (!c)
		return NULL;

	while (*ls)
		ls++;

	while ((ls != s) && ((char)c != *ls))
		ls--;

	if ((char)c == *ls)
		return ls;

	return NULL;
}

const char _ctype_[1 + 256] = {
	0,
	_C, _C, _C, _C, _C, _C, _C, _C, _C, _C|_S, _C|_S, _C|_S, _C|_S, _C|_S, _C, _C,
	_C, _C, _C, _C, _C, _C, _C, _C, _C, _C, _C, _C, _C, _C, _C, _C,
	_S|_B, _P, _P,	_P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P, _P,
	_N, _N, _N, _N, _N, _N, _N, _N, _N, _N, _P, _P, _P, _P, _P, _P,
	_P, _U|_X, _U|_X, _U|_X, _U|_X, _U|_X, _U|_X, _U, _U, _U, _U, _U, _U, _U, _U, _U,
	_U, _U, _U, _U, _U, _U, _U, _U, _U, _U, _U, _P, _P, _P, _P, _P,
	_P, _L|_X, _L|_X, _L|_X, _L|_X, _L|_X, _L|_X, _L, _L, _L, _L, _L, _L, _L, _L, _L,
	_L, _L, _L, _L, _L, _L, _L, _L, _L, _L, _L, _P, _P, _P, _P, _C,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static int number_x(char **str, char *end,
	int minimum, va_list *args, bool is_64bit, bool is_upper)
{
	uint64_t number = 0;
	int i = 0, len = 0;
	int digits_max = sizeof(uint32_t) * 2;
	int bits = digits_max * 4;
	int byte = 0;
	bool nonzero = false;
	char *dst = *str;

	if (!is_64bit) {
		number = va_arg(*args, uint32_t);
	} else {
		number = va_arg(*args, uint64_t);
		digits_max *= 2;
		bits *= 2;
	}

	for (i = 0; i < digits_max; i++) {
		byte = number >> (bits - ((i + 1) * 4));
		byte = byte & 0xF;

		if (byte != 0)
			nonzero = true;

		if (nonzero || (i >= (digits_max - minimum))) {
			if ((byte >= 0) && (byte <= 9)) {
				byte = byte + '0';
			} else if ((byte >= 0xA) && (byte <= 0xF)) {
				byte = 'a' + (byte - 0xA);
				if (is_upper)
					byte = toupper(byte);
			}
			if (dst < end)
				*dst++ = byte;
			len++;
		}
	}


	*str = dst;
	return len;
}

static int number_d(char **str, char *end,
	int minimum, va_list *args, bool is_64bit, bool is_unsigned)
{
	uint64_t num = 0;
	int64_t num_s = 0;
	int i = 0, val = 0, len = 0;
	int digits_max = 20;
	uint64_t divisor = 0;
	char *dst = *str;
	bool nonzero = false;

	if (!is_unsigned) {
		if (is_64bit)
			num_s = va_arg(*args, int64_t);
		else
			num_s = va_arg(*args, int32_t);

		if (num_s < 0) {
			if (dst < end)
				*dst++ = '-';
			len++;
			num_s = -(num_s);
		}
		num = num_s;
	} else {
		if (is_64bit)
			num = va_arg(*args, uint64_t);
		else
			num = va_arg(*args, uint32_t);
	}

	for (i = 0; i < digits_max; i++) {
		divisor = pow_of(10, digits_max - 1 - i);

		while (num >= divisor) {
			num -= divisor;
			val++;
		}

		if (val != 0)
			nonzero = true;

		if (nonzero || (i >= (digits_max - minimum))) {
			if (dst < end)
				*dst++ = val + '0';
			len++;
		}
		val = 0;
	}

	*str = dst;
	return len;
}

static int number_o(char **str, char *end,
	int minimum, va_list *args, bool is_64bit)
{
	uint64_t number = 0;
	int i = 0, len = 0;
	int digits_max = 11;
	int bits = digits_max * 3;
	int byte = 0;
	bool nonzero = false;
	char *dst = *str;

	if (!is_64bit) {
		number = va_arg(*args, uint32_t);
	} else {
		number = va_arg(*args, uint64_t);
		digits_max *= 2;
		bits *= 2;
	}

	for (i = 0; i < digits_max; i++) {
		byte = number >> (bits - ((i + 1) * 3));
		byte = byte & 0x7;

		if (byte != 0)
			nonzero = true;

		if (nonzero || (i >= (digits_max - minimum))) {
			if (dst < end)
				*dst++ = byte + '0';
			len++;
		}
	}

	*str = dst;
	return len;
}

/*
 * string is always null terminated ('\0')
 * the return value does not include the terminating null byte
 */
int vsnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
	int len = 0;
	char *str = NULL, *end = NULL;

	if (size > (0UL - (long)buf))
		return 0;

	str = buf;
	end = buf + size - 1;

	for (; *fmt ; ++fmt) {
		if (*fmt != '%') {
			if (str < end)
				*str++ = *fmt;
			len++;
			continue;
		} else {
			++fmt;
			int width = 0;
			int minimum = 1;
			bool is_unsigned = false;
			bool is_64bit = false;
			bool is_upper = false;

			while ((*fmt >= '0') && (*fmt <= '9')) {
				fmt++;
				width++;
				minimum = 0;
			}

			while (width) {
				minimum += pow_of(10, width - 1) *
						(*(fmt - width) - '0');
				width--;
			}

			if (*fmt == 'l') {
				++fmt;
				if (BYTES_PER_LONG != BYTES_PER_INT)
					is_64bit = true;
				if (*fmt == 'l') {
					is_64bit = true;
					++fmt;
				}
			}

			switch (*fmt) {
			case 'X':
				is_upper = true;
			case 'p':
				if (BYTES_PER_LONG != BYTES_PER_INT)
					is_64bit = true;
				if (str < end - 1) {
					*str++ = '0';
					*str++ = 'x';
					len += 2;
				}
			case 'x':
				len += number_x(&str, end, minimum, &args, is_64bit, is_upper);
				break;
			case 'u':
				is_unsigned = true;
			case 'i':
			case 'd':
				len += number_d(&str, end, minimum, &args, is_64bit, is_unsigned);
				break;
			case 'o':
				len += number_o(&str, end, minimum, &args, is_64bit);
				break;

			case 's': {
				char c = 0;
				char *argstr = va_arg(args, char *);

				if (argstr == NULL)
					argstr = "null";
				while ((c = *argstr++) != 0) {
					if (str < end)
						*str++ = c;
					len++;
				}
				break;
			}

			case 'c': {
				char byte = (char)va_arg(args, int);

				if (str < end)
					*str++ = byte;
				len++;
				break;
			}

			default:
				if (str < end)
					*str++ = *fmt;
				len++;
				break;
			}
		}
	}

	if (str <= end)
		*str = 0;

	return len;
}

/*
 * string is always null terminated ('\0')
 * the return value does not include the terminating null byte
 */
int snprintf(char *buf, size_t size, const char *fmt, ...)
{
	int i = 0;
	va_list args;

	va_start(args, fmt);
	i = vsnprintf(buf, size, fmt, args);
	va_end(args);

	return i;
}

int sprintf(char *buf, const char *fmt, ...)
{
	int i = 0;
	va_list args;

	va_start(args, fmt);
	i = vsnprintf(buf, 0UL - (long)buf, fmt, args);
	va_end(args);

	return i;
}

char *strstr(const char *s1, const char *s2)
{
	size_t l1 = 0, l2 = 0;

	l2 = strlen(s2);
	if (!l2)
		return (char *)s1;

	l1 = strlen(s1);

	while (l1 >= l2) {
		l1--;
		if (!memcmp(s1, s2, l2))
			return (char *)s1;
		s1++;
	}

	return NULL;
}

char *strcasestr(const char *s1,	const char *s2)
{
	size_t l1 = 0, l2 = 0;

	l2 = strlen(s2);
	if (!l2)
		return (char *)s1;

	l1 = strlen(s1);

	while (l1 >= l2) {
		l1--;
		if (!strncasecmp(s1, s2, l2))
			return (char *)s1;
		s1++;
	}

	return NULL;
}

char *strtok_r(char *s, const char *delim, char **lasts)
{
	char *spanp = NULL;
	int c = 0, sc = 0;
	char *tok = NULL;

	if ((!lasts) || (!delim))
		return NULL;

	if ((!s) && (!(*lasts)))
		return NULL;

	if (!s)
		s = *lasts;

cont:
	c = *s++;
	for (spanp = (char *)delim; (sc = *spanp++) != 0;) {
		if (c == sc)
			goto cont;
	}

	if (c == 0) {
		*lasts = NULL;
		return NULL;
	}
	tok = s - 1;

	for (;;) {
		c = *s++;
		spanp = (char *)delim;
		do {
			sc = *spanp++;
			if (sc == c) {
				if (c == 0)
					s = NULL;
				else
					s[-1] = 0;
				*lasts = s;
				return tok;
			}
		} while (sc != 0);
	}
}

unsigned long strtoul(const char *s, char **endp, int base)
{
	char c = 0;
	unsigned long result = 0, value = 0;

	if (!s)
		return result;

	c = *s;
	while (!isxdigit(c)) {
		s++;
		c = *s;
	}

	if (!base) {
		base = 10;
		if (*s == '0') {
			base = 8;
			s++;
			c = s[1];
			if ((tolower(*s) == 'x') && (isxdigit(c))) {
				s++;
				base = 16;
			}
		}
	} else if (base == 16) {
		if ((s[0] == '0') && (tolower(s[1]) == 'x'))
			s += 2;
	}

	c = *s;
	while (isxdigit(c) && ((value = (isdigit(c) ?
			c - '0' : tolower(c) - 'a' + 10)) < base)) {
		result = result * base + value;
		s++;
		c = *s;
	}

	if (endp)
		*endp = (char *)s;

	return result;
}

unsigned long long strtoull(const char *s, char **endp, int base)
{
	char c = 0;
	unsigned long long result = 0, value = 0;

	if (!s)
		return result;

	c = *s;
	while (!isxdigit(c)) {
		s++;
		c = *s;
	}

	if (!base) {
		base = 10;
		if (*s == '0') {
			base = 8;
			s++;
			c = s[1];
			if ((tolower(*s) == 'x') && (isxdigit(c))) {
				s++;
				base = 16;
			}
		}
	} else if (base == 16) {
		if ((s[0] == '0') && (tolower(s[1]) == 'x'))
			s += 2;
	}

	c = *s;
	while ((isxdigit(c)) && ((value = (isdigit(c) ?
			c - '0' : tolower(c) - 'a' + 10)) < base)) {
		result = result * base + value;
		s++;
		c = *s;
	}

	if (endp)
		*endp = (char *)s;

	return result;
}

void *memchr(const void *src, int c, size_t count)
{
	unsigned char ch = c;

	while (count--) {
		if (*(unsigned char *)src == ch)
			return (void *)src;

		src++;
	}

	return NULL;
}

void *memrchr(const void *src, int c, size_t count)
{
	unsigned char ch = c;
	unsigned char *s = (void *)src + count - 1;

	while (count--) {
		if (*s == ch)
			return (void *)s;

		s--;
	}

	return NULL;
}

void *memccpy(void *dst, const void *src, int c, size_t count)
{
	char endchar = c;

	while (count--) {
		*(char *)dst = *(char *)src++;
		if (*(char *)dst++ == endchar)
			return dst;
	}

	return NULL;
}
