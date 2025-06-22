// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
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

/*
 * strcmp() - Compare two NUL-terminated strings.
 *
 * Return: <0, 0, >0 depending on lexical order.
 * Corner cases/constraints:
 * - Inputs must be valid pointers to NUL-terminated strings.
 * - Comparison is performed byte-wise as unsigned char.
 */
int strcmp(const char *s1, const char *s2)
{
	unsigned char c = 0;

	while (((c = *s1) != 0) && (c == (unsigned char)*s2)) {
		s1++;
		s2++;
	}

	return c - (unsigned char)*s2;
}

/*
 * strncmp() - Compare at most n bytes of two strings.
 *
 * Return: <0, 0, >0.
 * Corner cases/constraints:
 * - If n == 0, returns 0.
 * - Stops early at NUL in either string.
 * - Inputs must be valid pointers; behavior is undefined for non-accessible memory.
 */
int strncmp(const char *s1, const char *s2, size_t n)
{
	unsigned char c = 0;

	if (n == 0)
		return 0;

	while (n-- && ((c = *s1) == (unsigned char)*s2)) {
		if (n == 0 || c == 0)
			return 0;
		s1++;
		s2++;
	}

	return c - (unsigned char)*s2;
}

/*
 * strlen() - Compute string length.
 *
 * Return: number of bytes before the first '\0' (excluding terminator).
 * Corner cases/constraints:
 * - Input must be a valid pointer to a NUL-terminated string.
 */
size_t strlen(const char *s)
{
	const char *sc = NULL;

	for (sc = s; *sc; ++sc)
		;

	return sc - s;
}

/*
 * strnlen() - Compute string length, bounded by n.
 *
 * Return: min(strlen(s), n).
 * Corner cases/constraints:
 * - Safe for non-terminated buffers only up to n bytes.
 * - Input must be a valid pointer to at least n readable bytes.
 */
size_t strnlen(const char *s, size_t n)
{
	const char *str = NULL;

	for (str = s; ((*str) && (n--)); ++str)
		;

	return str - s;
}

/*
 * strcpy() - Copy a NUL-terminated string.
 *
 * Return: dst.
 * Corner cases/constraints:
 * - dst must have enough space for src including the trailing '\0'.
 * - src must be NUL-terminated.
 * - Overlapping src/dst is undefined; use memmove() for overlap.
 */
char *strcpy(char *dst, const char *src)
{
	char *tmp = dst;

	while ((*dst++ = *src++))
		;

	return tmp;
}

/*
 * stpcpy() - Copy string and return pointer to the final '\0'.
 *
 * Return: pointer to the terminating '\0' in dst.
 * Corner cases/constraints: same as strcpy().
 */
char *stpcpy(char *dst, const char *src)
{
	while ((*dst++ = *src++))
		;

	return --dst;
}

/*
 * strlcpy() - Bounded string copy.
 *
 * Return: strlen(src) (excluding '\0'), regardless of truncation.
 * Corner cases/constraints:
 * - If n > 0, dst is always NUL-terminated.
 * - If n == 0, no bytes are written to dst.
 * - Overlapping src/dst is undefined.
 */
size_t strlcpy(char *dst, const char *src, size_t n)
{
	char *d = dst;
	const char *s = src;

	if (n != 0) {
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

/*
 * strncpy() - Copy up to n bytes from src to dst.
 *
 * Return: dst.
 * Corner cases/constraints:
 * - If src is shorter than n, the remainder is padded with '\0'.
 * - If src length >= n, dst will NOT be NUL-terminated.
 * - Overlapping src/dst is undefined.
 */
char *strncpy(char *dst, const char *src, size_t n)
{
	char *d = dst;
	const char *s = src;

	while (n != 0) {
		n--;
		*d = *s++;
		if (*d++ == 0)
			break;
	}

	while (n-- > 0)
		*d++ = 0;

	return dst;
}

/*
 * strcasecmp() - Case-insensitive string compare (ASCII).
 *
 * Return: <0, 0, >0.
 * Corner cases/constraints:
 * - Uses tolower() on unsigned char values.
 * - Locale-specific rules are not supported; ASCII semantics only.
 */
int strcasecmp(const char *s1, const char *s2)
{
	int c = 0;
	int c1 = 0;
	int c2 = 0;

	for (;;) {
		c1 = tolower((unsigned char)*s1++);
		c2 = tolower((unsigned char)*s2++);

		c = c1 - c2;
		if ((c != 0) || (c2 == 0))
			break;
	}

	return c;
}

/*
 * strncasecmp() - Case-insensitive bounded compare (ASCII).
 *
 * Return: <0, 0, >0.
 * Corner cases/constraints:
 * - Compares up to n bytes or until NUL.
 * - Locale-specific rules are not supported.
 */
int strncasecmp(const char *s1, const char *s2, size_t n)
{
	int c = 0;
	int c1 = 0;
	int c2 = 0;

	for ( ; n != 0; n--) {
		c1 = tolower((unsigned char)*s1++);
		c2 = tolower((unsigned char)*s2++);

		c = c1 - c2;
		if ((c != 0) || (c2 == 0))
			break;
	}

	return c;
}

/*
 * strcat() - Append src to dst.
 *
 * Return: dst.
 * Corner cases/constraints:
 * - dst must be NUL-terminated and have enough capacity for the result.
 * - Overlapping src/dst is undefined.
 */
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
 * strlcat() - Bounded string append.
 *
 * Return: initial strlen(dst) + strlen(src) (excluding '\0').
 * Corner cases/constraints:
 * - If cnt == 0, no writes occur and return is strlen(src) + cnt (per implementation).
 * - If dst is not NUL-terminated within cnt, no bytes are appended.
 * - If cnt > 0, ensures dst is NUL-terminated.
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

	while (--left && *s)
		*d++ = *s++;

	if (left == 0) {
		while (*s)
			s++;
	}

	*d = 0;

	return oridlen + (s - src);
}

/*
 * strncat() - Append at most n bytes of src to dst.
 *
 * Return: dst.
 * Corner cases/constraints:
 * - Always writes a terminating '\0' (if dst is writable).
 * - dst must be NUL-terminated and have enough space.
 * - Overlapping src/dst is undefined.
 */
char *strncat(char *dst, const char *src, size_t n)
{
	char *d = dst;
	const char *s = src;

	if (n != 0) {
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

/*
 * strpbrk() - Find first char in s1 that is present in s2.
 *
 * Return: pointer into s1, or NULL if not found.
 * Corner cases/constraints:
 * - If s2 is empty, returns NULL.
 * - Inputs must be NUL-terminated.
 */
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

/*
 * strchr() - Locate the first occurrence of c in s (including '\0').
 *
 * Return: pointer to the match, or NULL if not found.
 * Corner cases/constraints:
 * - If c == '\0', returns pointer to string terminator.
 */
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

/*
 * strchrnul() - Locate c in s; if not found, return pointer to terminating '\0'.
 *
 * Return: pointer to match or to NUL terminator.
 */
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

/*
 * strrchr() - Locate the last occurrence of c in s.
 *
 * Return: pointer to the last match, or NULL if not found.
 * Corner cases/constraints:
 * - If c == '\0', returns pointer to string terminator.
 */
char *strrchr(const char *s, int c)
{
	char *ls = (char *)s;

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

/*
 * number_x() - Print an integer argument in hexadecimal.
 *
 * Corner cases/constraints:
 * - Supports 32-bit, 64-bit, and unsigned long based on modifiers.
 * - 'minimum' controls the minimum digit count by suppressing leading zeros
 *   until the last minimum digits.
 * - Output is truncated if dst >= end; length is still counted.
 */
static int number_x(char **str, char *end,
	int minimum, va_list *args, bool is_64bit, bool is_long, bool is_upper)
{
	uint64_t number = 0;
	int i = 0, len = 0;
	int digits_max = sizeof(uint32_t) * 2;
	int bits = digits_max * 4;
	int byte = 0;
	bool nonzero = false;
	char *dst = *str;

	if (is_long) {
		number = va_arg(*args, unsigned long);
		if (sizeof(unsigned long) > sizeof(uint32_t)) {
			digits_max *= 2;
			bits *= 2;
		}
	} else if (!is_64bit) {
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
			if ((byte >= 0) && (byte <= 9))
				byte = byte + '0';
			else if ((byte >= 0xA) && (byte <= 0xF)) {
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

/*
 * number_x_val() - Print a uintptr_t-sized value in hexadecimal.
 *
 * Corner cases/constraints:
 * - 'minimum' controls a minimum digit count (zero-padded by skipping leading zeros).
 * - Output is truncated if dst >= end; length is still counted.
 */
static int number_x_val(char **str, char *end,
	int minimum, uint64_t number, bool is_upper)
{
	int i = 0, len = 0;
	int digits_max = sizeof(uintptr_t) * 2;
	int bits = digits_max * 4;
	int byte = 0;
	bool nonzero = false;
	char *dst = *str;

	for (i = 0; i < digits_max; i++) {
		byte = number >> (bits - ((i + 1) * 4));
		byte = byte & 0xF;

		if (byte != 0)
			nonzero = true;

		if (nonzero || (i >= (digits_max - minimum))) {
			if ((byte >= 0) && (byte <= 9))
				byte = byte + '0';
			else if ((byte >= 0xA) && (byte <= 0xF)) {
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

/*
 * number_d() - Print signed/unsigned decimal integer with optional width.
 *
 * Corner cases/constraints:
 * - 'minimum' is the minimum digit count (leading zeros not emitted, but leading
 *   digits are suppressed until minimum is reached).
 * - digits_max is fixed at 20 (covers 64-bit unsigned max in decimal).
 * - Output is truncated if dst >= end; length is still counted.
 */
static int number_d(char **str, char *end,
	int minimum, va_list *args, bool is_64bit, bool is_long, bool is_unsigned)
{
	uint64_t num = 0;
	int64_t num_s = 0;
	int i = 0, val = 0, len = 0;
	int digits_max = 20;
	uint64_t divisor = 0;
	char *dst = *str;
	bool nonzero = false;

	if (!is_unsigned) {
		if (is_long)
			num_s = va_arg(*args, long);
		else if (is_64bit)
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
		if (is_long)
			num = va_arg(*args, unsigned long);
		else if (is_64bit)
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

/*
 * number_o() - Print an integer in octal.
 *
 * Corner cases/constraints:
 * - digits_max is fixed (11 for 32-bit, doubled for 64-bit).
 * - Output is truncated if dst >= end; length is still counted.
 */
static int number_o(char **str, char *end,
	int minimum, va_list *args, bool is_64bit, bool is_long)
{
	uint64_t number = 0;
	int i = 0, len = 0;
	int digits_max = 11;
	int bits = digits_max * 3;
	int byte = 0;
	bool nonzero = false;
	char *dst = *str;

	if (is_long) {
		number = va_arg(*args, unsigned long);
		if (sizeof(unsigned long) > sizeof(uint32_t)) {
			digits_max *= 2;
			bits *= 2;
		}
	} else if (!is_64bit) {
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
 * vsnprintf() - Format a string into a fixed-size buffer.
 *
 * Return: number of characters that would have been written (excluding '\0').
 * Corner cases/constraints:
 * - If size == 0, no bytes are written; return length is still computed.
 * - If size > 0, the output buffer is NUL-terminated.
 * - Supported format subset: %d/%i/%u/%o/%x/%X/%p/%c/%s plus optional width
 *   (digits only) and length modifiers: 'l', 'll', and a limited 'z'.
 * - Precision, flags (0,+,-,#,space), and floating-point are not supported.
 * - This implementation does not set errno.
 */
int vsnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
	int len = 0;
	char *str = NULL, *end = NULL;

	if (size > (0UL - (long)buf))
		return 0;

	str = buf;
	/* Handle size=0: end < str so no writes will happen */
	end = (size > 0) ? (buf + size - 1) : buf;

	for (; *fmt ; ++fmt) {
		if (*fmt != '%') {
			if (str < end)
				*str++ = *fmt;
			len++;
			continue;
		} else {
			int width = 0;
			int minimum = 1;
			int precision = -1;
			bool is_unsigned = false;
			bool is_64bit = false;
			bool is_long = false;
			bool is_upper = false;

			++fmt;

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

			if (*fmt == '.') {
				++fmt;
				if (*fmt == '*') {
					precision = va_arg(args, int);
					++fmt;
				} else {
					precision = 0;
					while ((*fmt >= '0') && (*fmt <= '9')) {
						precision = (precision * 10) + (*fmt - '0');
						++fmt;
					}
				}

				if (precision < 0)
					precision = -1;
			}

			if (*fmt == 'l') {
				++fmt;
				is_long = true;
				if (*fmt == 'l') {
					is_long = false;
					is_64bit = true;
					++fmt;
				} else if (sizeof(unsigned long) == sizeof(uint64_t)) {
					is_64bit = true;
				}
			} else if (*fmt == 'z') {
				/* %z modifier for size_t/ssize_t */
				++fmt;
				if (sizeof(size_t) == sizeof(long long))
					is_64bit = true;
			}

			switch (*fmt) {
			case 'X':
				is_upper = true;
				len += number_x(&str, end, minimum, &args, is_64bit, is_long, is_upper);
				break;
			case 'p':
				if (str < end)
					*str++ = '0';
				if (str < end)
					*str++ = 'x';
				/* Always count 0x prefix in return length */
				len += 2;
				len += number_x_val(&str, end, minimum,
					(uintptr_t)va_arg(args, void *), false);
				break;
			case 'x':
				len += number_x(&str, end, minimum, &args, is_64bit, is_long, is_upper);
				break;
			case 'u':
				is_unsigned = true;
				/* fallthrough */
			case 'i':
			case 'd':
				len += number_d(&str, end, minimum, &args, is_64bit, is_long, is_unsigned);
				break;
			case 'o':
				len += number_o(&str, end, minimum, &args, is_64bit, is_long);
				break;

			case 's': {
				char c = 0;
				char *argstr = va_arg(args, char *);
				int rem = precision;

				if (!argstr)
					argstr = "null";
				while ((c = *argstr++) != 0) {
					if ((precision >= 0) && (rem <= 0))
						break;
					if (str < end)
						*str++ = c;
					len++;
					if (precision >= 0)
						rem--;
				}
				break;
			}

			case 'c': {
				char byte = va_arg(args, int);

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

	if (size > 0 && str <= end)
		*str = 0;

	return len;
}

/*
 * snprintf() - Variadic wrapper around vsnprintf().
 *
 * Corner cases/constraints: see vsnprintf().
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

/*
 * sprintf() - Unbounded formatting into buf.
 *
 * Corner cases/constraints:
 * - There is no size limit; caller must ensure buf is large enough.
 * - Uses a very large size derived from buf address; this is not a substitute
 *   for proper bounds checking.
 */
int sprintf(char *buf, const char *fmt, ...)
{
	int i = 0;
	va_list args;

	va_start(args, fmt);
	i = vsnprintf(buf, 0UL - (long)buf, fmt, args);
	va_end(args);

	return i;
}

/*
 * strstr() - Find the first occurrence of s2 in s1.
 *
 * Return: pointer to the first match, or NULL if not found.
 * Corner cases/constraints:
 * - If s2 is empty, returns (char *)s1.
 */
char *strstr(const char *s1, const char *s2)
{
	size_t l1 = 0, l2 = 0;

	l2 = strlen(s2);
	if (l2 == 0)
		return (char *)s1;

	l1 = strlen(s1);

	while (l1 >= l2) {
		l1--;
		if (memcmp(s1, s2, l2) == 0)
			return (char *)s1;
		s1++;
	}

	return NULL;
}

/*
 * strcasestr() - Case-insensitive substring search (ASCII).
 *
 * Return: pointer to the first match, or NULL.
 * Corner cases/constraints:
 * - If s2 is empty, returns (char *)s1.
 * - Locale-specific case folding is not supported.
 */
char *strcasestr(const char *s1, const char *s2)
{
	size_t l1 = 0, l2 = 0;

	l2 = strlen(s2);
	if (l2 == 0)
		return (char *)s1;

	l1 = strlen(s1);

	while (l1 >= l2) {
		l1--;
		if (strncasecmp(s1, s2, l2) == 0)
			return (char *)s1;
		s1++;
	}

	return NULL;
}

/*
 * strtok_r() - Reentrant string tokenizer.
 *
 * Return: next token pointer, or NULL when finished.
 * Corner cases/constraints:
 * - Modifies the input string by writing '\0' terminators.
 * - 'delim' must be a NUL-terminated delimiter set.
 * - 'lasts' must be a valid pointer; state is stored in *lasts.
 */
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

/*
 * strtoul() - Convert a string to unsigned long.
 *
 * Return: converted value; on overflow saturates to ULONG_MAX.
 * Corner cases/constraints:
 * - Optional leading whitespace and sign are supported.
 * - base==0 enables 0/0x prefix detection.
 * - On negative input, the value is negated in unsigned arithmetic.
 * - Does not set errno; caller should detect overflow via result==ULONG_MAX
 *   and remaining characters as needed.
 */
unsigned long strtoul(const char *s, char **endp, int base)
{
	unsigned char c = 0;
	unsigned long result = 0, value = 0;
	unsigned long cutoff = 0;
	int cutlim = 0;
	int neg = 0;
	int overflow = 0;

	if (!s)
		return result;

	c = *s;
	while (isspace(c)) {
		s++;
		c = *s;
	}

	/* Handle optional sign */
	if (c == '-') {
		neg = 1;
		s++;
		c = *s;
	} else if (c == '+') {
		s++;
		c = *s;
	}

	if (base == 0) {
		base = 10;
		if (*s == '0') {
			base = 8;
			s++;
			if (tolower(*s) == 'x') {
				c = s[1];
				if (isxdigit(c)) {
					s++;
					base = 16;
				}
			}
		}
	} else if (base == 16) {
		if (s[0] == '0' && tolower(s[1]) == 'x')
			s += 2;
	}

	/* Compute cutoff values for overflow detection */
	cutoff = ULONG_MAX / base;
	cutlim = ULONG_MAX % base;

	c = *s;
	while (isxdigit(c) && ((value = (isdigit(c) ?
			c - '0' : tolower(c) - 'a' + 10)) < base)) {
		if (result > cutoff || (result == cutoff && value > cutlim))
			overflow = 1;
		else
			result = result * base + value;
		s++;
		c = *s;
	}

	if (overflow)
		result = ULONG_MAX;
	else if (neg)
		result = -result;

	if (endp)
		*endp = (char *)s;

	return result;
}

/*
 * strtol() - Convert a string to signed long.
 *
 * Return: converted value; on overflow saturates to LONG_MIN/LONG_MAX.
 * Corner cases/constraints:
 * - Delegates parsing to strtoul() after stripping sign.
 * - If no conversion is performed, returns 0 and restores *endp to the
 *   original input pointer.
 * - Does not set errno.
 */
long strtol(const char *s, char **endp, int base)
{
	unsigned long result;
	int neg = 0;
	const char *orig_s = s;

	if (!s) {
		if (endp)
			*endp = (char *)s;
		return 0;
	}

	/* Skip whitespace */
	while (isspace((unsigned char)*s))
		s++;

	/* Handle sign */
	if (*s == '-') {
		neg = 1;
		s++;
	} else if (*s == '+') {
		s++;
	}

	/* Use strtoul for conversion */
	result = strtoul(s, endp, base);

	/* Check if any conversion was performed */
	if (endp && *endp == s) {
		/* No conversion, restore original pointer */
		*endp = (char *)orig_s;
		return 0;
	}

	/* Apply sign and check overflow */
	if (neg) {
		if (result > (unsigned long)LONG_MAX + 1)
			return LONG_MIN;
		return -(long)result;
	} else {
		if (result > (unsigned long)LONG_MAX)
			return LONG_MAX;
		return (long)result;
	}
}

/*
 * strtoull() - Convert a string to unsigned long long.
 *
 * Return: converted value; on overflow saturates to ULLONG_MAX.
 * Corner cases/constraints:
 * - Optional leading whitespace and sign are supported.
 * - base==0 enables 0/0x prefix detection.
 * - On negative input, the value is negated in unsigned arithmetic.
 * - Does not set errno.
 */

unsigned long long strtoull(const char *s, char **endp, int base)
{
	unsigned char c = 0;
	unsigned long long result = 0, value = 0;
	unsigned long long cutoff = 0;
	int cutlim = 0;
	int neg = 0;
	int overflow = 0;

	if (!s)
		return result;

	c = *s;
	while (isspace(c)) {
		s++;
		c = *s;
	}

	/* Handle optional sign */
	if (c == '-') {
		neg = 1;
		s++;
		c = *s;
	} else if (c == '+') {
		s++;
		c = *s;
	}

	if (base == 0) {
		base = 10;
		if (*s == '0') {
			base = 8;
			s++;
			if (tolower(*s) == 'x') {
				c = s[1];
				if (isxdigit(c)) {
					s++;
					base = 16;
				}
			}
		}
	} else if (base == 16) {
		if (s[0] == '0' && tolower(s[1]) == 'x')
			s += 2;
	}

	/* Compute cutoff values for overflow detection */
	cutoff = ULLONG_MAX / base;
	cutlim = ULLONG_MAX % base;

	c = *s;
	while (isxdigit(c) && ((value = (isdigit(c) ?
			c - '0' : tolower(c) - 'a' + 10)) < base)) {
		if (result > cutoff || (result == cutoff && value > cutlim))
			overflow = 1;
		else
			result = result * base + value;
		s++;
		c = *s;
	}

	if (overflow)
		result = ULLONG_MAX;
	else if (neg)
		result = -result;

	if (endp)
		*endp = (char *)s;

	return result;
}

/*
 * strtoll() - Convert a string to signed long long.
 *
 * Return: converted value; on overflow saturates to LLONG_MIN/LLONG_MAX.
 * Corner cases/constraints: similar to strtol().
 */
long long strtoll(const char *s, char **endp, int base)
{
	unsigned long long result;
	int neg = 0;
	const char *orig_s = s;

	if (!s) {
		if (endp)
			*endp = (char *)s;
		return 0;
	}

	/* Skip whitespace */
	while (isspace((unsigned char)*s))
		s++;

	/* Handle sign */
	if (*s == '-') {
		neg = 1;
		s++;
	} else if (*s == '+') {
		s++;
	}

	/* Use strtoull for conversion */
	result = strtoull(s, endp, base);

	/* Check if any conversion was performed */
	if (endp && *endp == s) {
		/* No conversion, restore original pointer */
		*endp = (char *)orig_s;
		return 0;
	}

	/* Apply sign and check overflow */
	if (neg) {
		if (result > (unsigned long long)LLONG_MAX + 1)
			return LLONG_MIN;
		return -(long long)result;
	} else {
		if (result > (unsigned long long)LLONG_MAX)
			return LLONG_MAX;
		return (long long)result;
	}
}

/*
 * memchr() - Find the first occurrence of byte c within count bytes.
 *
 * Return: pointer to the match, or NULL.
 * Corner cases/constraints:
 * - Operates on raw bytes; does not stop at '\0'.
 */
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

/*
 * memrchr() - Find the last occurrence of byte c within count bytes.
 *
 * Return: pointer to the match, or NULL.
 */
void *memrchr(const void *src, int c, size_t count)
{
	unsigned char ch = c;
	unsigned char *s = NULL;

	if (count == 0)
		return NULL;

	s = (unsigned char *)src + count - 1;

	while (count--) {
		if (*s == ch)
			return (void *)s;

		s--;
	}

	return NULL;
}

/*
 * memccpy() - Copy bytes until byte c is copied or count bytes are copied.
 *
 * Return: pointer to the next byte in dst after c, or NULL if c not found.
 * Corner cases/constraints:
 * - Overlap between src and dst is undefined.
 */
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

/*
 * atoi() - Convert string to int (base 10).
 *
 * Corner cases/constraints:
 * - Delegates to strtol(); overflow behavior follows strtol then cast.
 * - Does not set errno.
 */
int atoi(const char *s)
{
	return strtol(s, NULL, 10);
}

/*
 * atol() - Convert string to long (base 10).
 *
 * Corner cases/constraints: does not set errno.
 */
long atol(const char *s)
{
	return strtol(s, NULL, 10);
}

/*
 * atoll() - Convert string to long long (base 10).
 *
 * Corner cases/constraints: does not set errno.
 */
long long atoll(const char *s)
{
	return strtoll(s, NULL, 10);
}

/*
 * itoa() - Convert integer to string.
 *
 * Return: str.
 * Corner cases/constraints:
 * - Supported bases: 2..36. For invalid base, writes empty string.
 * - Negative sign is only emitted for base 10.
 * - Caller must provide a buffer large enough for sign + digits + '\0'.
 */
char *itoa(int value, char *str, int base)
{
	char *ptr = str;
	char *ptr1 = str;
	char tmp_char;
	int tmp_value;
	unsigned int uvalue;

	/* Check for valid base */
	if (base < 2 || base > 36) {
		*str = '\0';
		return str;
	}

	/* Handle negative numbers for base 10 */
	if (value < 0 && base == 10) {
		*ptr++ = '-';
		ptr1++;
		/* Avoid signed overflow for INT_MIN */
		uvalue = (unsigned int)0 - (unsigned int)value;
	} else {
		uvalue = (unsigned int)value;
	}

	/* Convert to string (reversed) */
	do {
		tmp_value = uvalue % base;
		*ptr++ = "0123456789abcdefghijklmnopqrstuvwxyz"[tmp_value];
		uvalue /= base;
	} while (uvalue);

	*ptr-- = '\0';

	/* Reverse the string */
	while (ptr1 < ptr) {
		tmp_char = *ptr;
		*ptr-- = *ptr1;
		*ptr1++ = tmp_char;
	}

	return str;
}
