/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 */

#ifndef _OTP_HUK_H
#define _OTP_HUK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*
 * Get Hardware Unique Key (HUK) from OTP
 *
 * @key: buffer to store the key
 * @size: size of the buffer
 * @return: 0 on success, negative error code on failure
 */
int otp_get_huk(uint8_t *key, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* _OTP_HUK_H */
