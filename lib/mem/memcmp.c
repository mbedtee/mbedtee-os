// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * time-constant memory comparation
 */

#include <errno.h>
#include <string.h>

/*
 * time-constant memcmp()
 */
int memcmp(const void *s, const void *d, size_t l)
{
	int ret = -EINVAL;
	size_t i = 0, j = 0;
	/*
	 * record the bad/good count
	 */
	size_t cnt[2] = {0};
	/*
	 * record the last bad/good index
	 */
	size_t idx[2] = {0};
	unsigned char *src = (unsigned char *)s;
	unsigned char *dst = (unsigned char *)d;

	if (l == 0)
		return 0;

	if (!s || !d)
		return ret;

	for (i = 0, j = l - 1; ((i < l) && (j >= 0)); i++, j--) {
		if (src[i] != dst[i])
			cnt[0]++;
		else
			cnt[1]++;

		if (src[j] != dst[j]) {
			cnt[0]++;
			idx[0] = j;
		} else {
			cnt[1]++;
			idx[1] = j;
		}
	}

	ret = src[idx[0]] - dst[idx[0]];

	if ((cnt[1] == (2 * l)) &&
		(cnt[0] == 0) &&
		(idx[1] == 0) &&
		(idx[0] == 0))
		return ret;

	if (src[idx[0]] == dst[idx[0]])
		return -1;

	return ret;
}
