// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 */

#include <string.h>
#include <trace.h>
#include <otp_huk.h>

/*
 * Weak default implementation that fails safely.
 * This forces the platform to provide a real implementation.
 */
__attribute__((weak)) int otp_get_huk(uint8_t *key, size_t size)
{
	/* Test Key for development only */
	static const uint8_t test_key[] = {
		0x9a, 0x4f, 0x2c, 0x8d, 0x1e, 0x5b, 0x73, 0x6a,
		0x0f, 0xe2, 0x91, 0x3c, 0x4d, 0x88, 0x76, 0x54,
		0x2b, 0x1a, 0x09, 0xf8, 0xe7, 0xd6, 0xc5, 0xb4,
		0xa3, 0x92, 0x81, 0x70, 0x6f, 0x5e, 0x4d, 0x3c
	};

	WMSG("WARNING: Using Test HUK!\n");

	if (size > sizeof(test_key))
		size = sizeof(test_key);

	memcpy(key, test_key, size);
	return 0;
}
