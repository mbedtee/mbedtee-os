/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * REEFS Anti-Rollback Protection via RPMB
 *
 * Design: Each REEFS file's header is mirrored to RPMB.
 *
 * On file open: compare REE header version with RPMB version
 * On file write: update both REE and RPMB headers
 * On file delete: remove RPMB mirror
 *
 * This provides hardware-backed anti-rollback protection:
 * - RPMB writes are protected by hardware write counter
 * - Attacker cannot replace REE file with older version
 *   because RPMB still has the newer version recorded
 *
 * Recovery: If REE header is corrupted, RPMB header can be
 * used to recover the file's encryption key/iv.
 */

#ifndef _REEFS_RPMB_H
#define _REEFS_RPMB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/*
 * REEFS file header structure
 * Shared between reefs.c and reefs_rpmb.c
 */
struct reefs_hdr {
	/* total-payloads-len */
	uint64_t length;
	/* current file version for anti-rollback */
	uint64_t version;

	uint64_t atime; /* time of last access */
	uint64_t mtime; /* time of last modification */
	uint64_t ctime; /* time of last status change */

	/* GCM aad (APP uuid) */
	unsigned char aad[16];

	/* GCM tag of key-iv */
	unsigned char tag[16];
	/* key for payload */
	unsigned char key[16];
	/* iv for payload */
	unsigned char iv[16];
};

#if defined(CONFIG_REEFS_ANTIROLLBACK_RPMB)

/*
 * Initialize RPMB protection
 * Called during REEFS mount
 */
int reefs_rpmb_init(void);

/*
 * Store header to RPMB after successful write
 * Called after reefs_update_hdr()
 */
int reefs_rpmb_store_hdr(const char *path, const struct reefs_hdr *hdr);

/*
 * Load header from RPMB (for recovery)
 * Returns 0 on success, -ENOENT if no RPMB record exists
 */
int reefs_rpmb_load_hdr(const char *path, struct reefs_hdr *hdr);

/*
 * Verify REE header against RPMB mirror
 * Returns 0 if OK, -EBADMSG if rollback detected
 * Called after reefs_read_hdr()
 */
int reefs_rpmb_verify_hdr(const char *path, const struct reefs_hdr *hdr);

/*
 * Unlink RPMB mirror on file deletion
 * Called on unlink
 */
int reefs_rpmb_unlink(const char *path);

/*
 * Rename RPMB mirror
 * Called on rename
 */
int reefs_rpmb_rename(const char *oldpath, const char *newpath);

#else /* !CONFIG_REEFS_ANTIROLLBACK_RPMB */

static inline int reefs_rpmb_init(void) { return 0; }
static inline int reefs_rpmb_store_hdr(const char *p, const struct reefs_hdr *h)
{ return 0; }
static inline int reefs_rpmb_load_hdr(const char *p, struct reefs_hdr *h)
{ return -ENOENT; }
static inline int reefs_rpmb_verify_hdr(const char *p, const struct reefs_hdr *h)
{ return 0; }
static inline int reefs_rpmb_unlink(const char *p) { return 0; }
static inline int reefs_rpmb_rename(const char *o, const char *n) { return 0; }
#endif /* CONFIG_REEFS_ANTIROLLBACK_RPMB */

#ifdef __cplusplus
}
#endif
#endif /* _REEFS_RPMB_H */
