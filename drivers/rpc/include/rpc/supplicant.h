/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Define the supplicant types
 */

#ifndef _RPC_SUPPLICANT_H
#define _RPC_SUPPLICANT_H

#include <errno.h>

#include <tee_api_defines.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * supplicant types
 */
#define MBEDTEE_SUPP_REEFS		 1
#define MBEDTEE_SUPP_RPMB		 2
#define MBEDTEE_SUPP_MAX		 10

/*
 * Common supplicant command header embedded as the first member of both
 * reefs_cmd and rpmb_cmd.  This guarantees ret and op are always at a
 * well-known offset regardless of the full payload layout.
 */
struct supp_cmd_hdr {
	int ret;
	int op;
};

/*
 * Supplicant payload fields preserve non-negative success values but encode GP
 * failures in the same signed int slot. Decode only the GP failures back to
 * local errno values expected by the TEE-side REEFS/RPMB wrappers.
 */
static inline int mbedtee_rpc_gp_to_errno(int ret)
{
	if (ret >= 0)
		return ret;

	switch ((uint32_t)ret) {
	case TEE_ERROR_ACCESS_DENIED:
		return -EACCES;
	case TEE_ERROR_CANCEL:
		return -ECANCELED;
	case TEE_ERROR_ACCESS_CONFLICT:
		return -EEXIST;
	case TEE_ERROR_EXCESS_DATA:
		return -E2BIG;
	case TEE_ERROR_BAD_FORMAT:
		return -EBADMSG;
	case TEE_ERROR_BAD_PARAMETERS:
		return -EINVAL;
	case TEE_ERROR_ITEM_NOT_FOUND:
		return -ENOENT;
	case TEE_ERROR_NOT_IMPLEMENTED:
	case TEE_ERROR_NOT_SUPPORTED:
		return -EOPNOTSUPP;
	case TEE_ERROR_NO_DATA:
		return -ENODATA;
	case TEE_ERROR_OUT_OF_MEMORY:
		return -ENOMEM;
	case TEE_ERROR_BUSY:
		return -EBUSY;
	case TEE_ERROR_COMMUNICATION:
		return -EIO;
	case TEE_ERROR_SHORT_BUFFER:
		return -EMSGSIZE;
	case TEE_ERROR_STORAGE_NO_SPACE:
		return -ENOSPC;
	case TEE_ERROR_TARGET_DEAD:
		return -ESRCH;
	default:
		return -EIO;
	}
}

#ifdef __cplusplus
}
#endif

#endif
