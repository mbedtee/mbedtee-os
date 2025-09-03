/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Define the structures and macros for RPMB rpc
 */

#ifndef _RPC_RPMB_H
#define _RPC_RPMB_H

#include <rpc/supplicant.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RPMB functions
 */
#define RPMB_EXEC         1
#define RPMB_GET_DEV_INFO 2

/* RPMB Request/Response Types */
#define RPMB_REQ_KEY		0x0001
#define RPMB_REQ_WCOUNTER	0x0002
#define RPMB_REQ_WRITE		0x0003
#define RPMB_REQ_READ		0x0004
#define RPMB_REQ_STATUS		0x0005
#define RPMB_RESP_KEY		0x0100
#define RPMB_RESP_WCOUNTER	0x0200
#define RPMB_RESP_WRITE		0x0300
#define RPMB_RESP_READ		0x0400

/*
 * RPMB Frame Definition (512 bytes)
 */
struct rpmb_frame {
	unsigned char stuff[196];
	unsigned char key_mac[32];
	unsigned char data[256];
	unsigned char nonce[16];
	unsigned int write_counter;
	unsigned short addr;
	unsigned short block_count;
	unsigned short result;
	unsigned short req_resp;
} __attribute__((packed));

/*
 * RPMB Device Information
 * Queried from hardware via sysfs (eMMC) or device capabilities
 * Note: write_counter field is NOT populated by supplicant as it
 * requires RPMB key authentication. Use rpmb_get_counter() instead.
 */
struct rpmb_dev_info {
	unsigned int total_blocks;     /* Total RPMB blocks (256 bytes each) */
	unsigned int rel_wr_sec_c;     /* Reliable Write Sector Count (in 256B frames) */
	unsigned int rpmb_size_mult;   /* RPMB size multiplier (128KB units) */
	unsigned int max_wr_blkcnt;    /* Max blocks per write command */
	unsigned int max_rd_blkcnt;    /* Max blocks per read command */
	unsigned char flags;           /* Capability flags (reserved) */
	unsigned char reserved[3];     /* Padding for alignment */
};

/*
 * RPMB Command Structure
 * For RPMB_EXEC: followed by struct rpmb_frame frames[nframes]
 * For RPMB_GET_DEV_INFO: followed by struct rpmb_dev_info (nframes=0)
 */
struct rpmb_cmd {
	struct supp_cmd_hdr hdr;
	unsigned int nframes;

	/* Variable-length payload */
	struct rpmb_frame frames[];
};

#ifdef __cplusplus
}
#endif

#endif
