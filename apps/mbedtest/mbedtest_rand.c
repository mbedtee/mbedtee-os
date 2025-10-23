// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * mbedtest_rand.c -- Random / entropy helpers and tests.
 */

#include "mbedtest.h"
#include "mbedtest_internal.h"

int test_rand(void)
{
	return rand();
}

int test_rng(void *ctx, uint8_t *out, size_t len)
{
	size_t i = 0;

	for (i = 0; i < len; i++)
		out[i] = rand();

	return 0;
}

/*
 * urandom_test: Test /dev/urandom random device.
 * Basic read operations + statistical distribution sanity.
 * SKIPs gracefully if /dev/urandom cannot be opened.
 */
void urandom_test(void)
{
	unsigned char big[4096];
	unsigned char small[1] = {0};
	unsigned char med[256] = {0};
	int rngfd = -1, ret = 0;
	size_t j;
	unsigned long bits_set = 0;
	size_t total_bits;
	double ratio;

	TEST_START("urandom");

	rngfd = open("/dev/urandom", O_RDONLY);
	CHECK(rngfd >= 0, errno);

	/* Basic reads: 1 byte, 256 bytes, 4096 bytes */
	ret = read(rngfd, small, sizeof(small));
	CHECK(ret == 1, errno, "read 1 byte ret=%d", ret);

	ret = read(rngfd, med, sizeof(med));
	CHECK(ret == 256, errno, "read 256 byte ret=%d", ret);

	ret = read(rngfd, big, sizeof(big));
	CHECK(ret == sizeof(big), errno, "read 4096 byte ret=%d", ret);

	/*
	 * Distribution: count set bits, expect ~50% in [0.47, 0.53].
	 * For 32768 trials, 99.99% confidence interval is ~0.50 + 0.025.
	 */
	for (j = 0; j < sizeof(big); j++) {
		unsigned char b = big[j];

		while (b) {
			bits_set += b & 1u;
			b >>= 1;
		}
	}
	total_bits = sizeof(big) * 8u;
	ratio = (double)bits_set / (double)total_bits;
	CHECK(ratio >= 0.47 && ratio <= 0.53, ERANGE,
		"distribution out of band ratio=%d/1000",
		(int)(ratio * 1000));

	/* Sequential reads must differ (extremely high probability). */
	CHECK(memcmp(big, med, sizeof(med)) != 0, EBADMSG,
		"two reads collided");

out:
	test_close_fd(&rngfd);
	TEST_END();
}
