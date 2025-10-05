// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * RPMB Secure File System
 */

#include <fs.h>
#include <init.h>
#include <trace.h>
#include <errno.h>
#include <fcntl.h>
#include <mutex.h>
#include <kmalloc.h>
#include <string.h>
#include <thread.h>
#include <prng.h>
#include <uaccess.h>
#include <bitops.h>
#include <defs.h>
#include <ktime.h>

#include <mbedtee_memcmp.h>
#include <mbedcrypto/hkdf.h>
#include <mbedcrypto/gcm.h>

#include <rpc/rpmb.h>
#include <rpc.h>
#include <otp_huk.h>

/* #define RPMB_FS_DEBUG_INTEGRITY */

/* RPMB Response Results */
#define RPMB_RES_OK					0x0000
#define RPMB_RES_GENERAL_FAILURE	0x0001
#define RPMB_RES_AUTH_FAILURE		0x0002
#define RPMB_RES_COUNTER_FAILURE	0x0003
#define RPMB_RES_ADDR_FAILURE		0x0004
#define RPMB_RES_WRITE_FAILURE		0x0005
#define RPMB_RES_READ_FAILURE		0x0006
#define RPMB_RES_NO_KEY				0x0007

/* FS Constants */
#define RPMB_BLOCK_SIZE		256
#define RPMB_BLOCK_PAYLOAD	240  /* 256 - 16 bytes GCM tag */
#define RPMB_BLOCK_TAG		16
#define RPMB_MAX_FILENAME	176
#define RPMB_FAT_START		0

#ifndef CONFIG_RPMB_FS_MAX_FILES
#define CONFIG_RPMB_FS_MAX_FILES 128
#endif

#ifndef CONFIG_RPMB_FS_CACHE_ENTRIES
#define CONFIG_RPMB_FS_CACHE_ENTRIES 128
#endif

/*
 * RPMB Read/Write Batch Sizes:
 * - CONFIG_RPMB_FS_READ_BATCH: Max blocks per read (1-32)
 * - CONFIG_RPMB_FS_WRITE_BATCH: Max blocks per write (1-32)
 *
 * Now correctly implements RPMB batch MAC verification:
 * - Read: Frames 0..(N-2) have MAC=0, frame N-1 has MAC covering all frames
 * - Write: MAC calculated over all frames, placed in last frame
 */
#if !defined(CONFIG_RPMB_FS_READ_BATCH)
#define CONFIG_RPMB_FS_READ_BATCH 32 /* Default: 8KB batches */
#endif

#if !defined(CONFIG_RPMB_FS_WRITE_BATCH)
#define CONFIG_RPMB_FS_WRITE_BATCH 32 /* Default: 8KB batches */
#endif

#define RPMB_FAT_ENTRIES		CONFIG_RPMB_FS_MAX_FILES
#define RPMB_READ_BATCH			CONFIG_RPMB_FS_READ_BATCH
#define RPMB_WRITE_BATCH		CONFIG_RPMB_FS_WRITE_BATCH
#define RPMB_FAT_CACHED			CONFIG_RPMB_FS_CACHE_ENTRIES

#define RPMB_MAX_BLOCKS			65536 /* 16MB Limit (eMMC 5.0/5.1) */

#define RPMB_ENT_EMPTY			0
#define RPMB_ENT_FILE			1
#define RPMB_ENT_DIR			2

/* IOCTL Commands -- never exported */
#define RPMB_IOC_PROGRAM_KEY	0x1001

#define RPMB_ROOT_IDX (-1)
#define IS_ROOT_DIR(name) ((name)[0] == 0)
#define IS_ROOT_IDX(idx) ((idx) == RPMB_ROOT_IDX)

/*
 * RPMB Key (Derived from HUK)
 */
static unsigned char rpmb_key[32];

/*
 * FAT Encryption Key and IV (Derived from HUK)
 */
static unsigned char rpmb_fat_key[16];
static unsigned char rpmb_fat_iv[16];

static int rpmb_rpc_call(struct rpmb_cmd *cmd, size_t size)
{
	int ret = -1;

	ret = rpc_call_sync(MBEDTEE_RPC_RPMB, cmd, size);
	if (ret != 0)
		return ret;

	return mbedtee_rpc_gp_to_errno(cmd->hdr.ret);
}

/* On-disk FAT Entry (256 bytes) */
struct rpmb_fat_entry {
	char filename[RPMB_MAX_FILENAME]; /* 176 bytes */
	uint8_t fek[16];     /* 16 bytes, File Encryption Key (AES-128) */
	uint8_t iv[16];      /* 16 bytes, Base IV for file */
	uint32_t unique_id;  /* 4 bytes, Generation ID */
	uint32_t version;    /* 4 bytes, Version for FAT modifications */
	uint32_t start_addr; /* 4 bytes, Block index */
	uint32_t size;       /* 4 bytes, File size */
	uint32_t flags;      /* 4 bytes, 1 = Valid */
	uint8_t tag[16];     /* 16 bytes, GCM tag for FAT entry */
	uint8_t reserved[12]; /* 12 bytes, Padding to 256 bytes */
} __attribute__((packed));

/* In-memory FS State */
struct rpmb_fs {
	struct mutex mlock;
	/*
	 * FAT Cache: Significant performance improvement
	 * Cache size determined by RPMB_FAT_CACHED compile-time constant
	 */
	struct rpmb_fat_entry *fat_cache;

	uint32_t write_counter;
	uint32_t unique_id_gen;
	unsigned long *bitmap;

	/* Total RPMB Size (block count) - Default: 4096 (1MB) */
	uint32_t total_blkcnt;
	/* RPMB Reliable Write Block Count - Default: 1 */
	uint32_t rel_wr_blkcnt;
	/* Idle (free) block count for fs_getsize */
	uint32_t idle_blkcnt;

	struct list_head open_files;

	/* Cached FAT GCM context */
	struct mbedcrypto_aes_gcm_ctx fat_ctx;
};

/* File Handle */
struct rpmb_file {
	struct list_head node;
	int refc;

	int type;
	int fat_idx;
	int deleted;  /* Set when unlinked but still open (POSIX semantics) */
	time_t open_time; /* File open time (RPMB FAT doesn't store timestamps) */

	/*
	 * Zero-copy pointer to fat_cache[fat_idx] when cache enabled.
	 * Falls back to entry_local when cache disabled or unavailable.
	 */
	struct rpmb_fat_entry *entry;
	struct rpmb_fat_entry entry_local;  /* Fallback when cache disabled */

	/* Cached File GCM context */
	struct mbedcrypto_aes_gcm_ctx gcm_ctx;
};

/*
 * On-disk data block structure
 */
struct rpmb_data_block {
	uint8_t payload[RPMB_BLOCK_PAYLOAD]; /* 240 bytes */
	uint8_t tag[RPMB_BLOCK_TAG];         /* 16 bytes */
} __attribute__((packed));

/* Checkpoint helpers for write rollback */
struct rpmb_write_checkpoint {
	uint32_t start_addr;
	uint32_t size;
	uint32_t version;
	off_t pos;
};

/*
 * FAT Entry Iterator - eliminates repeated two-phase (cache + RPMB) traversal
 *
 * Callback return values:
 *   > 0: Stop iteration and return this value (found/success)
 *   = 0: Continue to next entry
 *   < 0: Stop iteration and return this error code
 */
struct fat_iter_ctx {
	const char *name;                    /* name to match */
	size_t len;                          /* name length (for prefix match) */
	int skip_idx;                        /* index to skip (-1 = none) */
	struct rpmb_fat_entry *out;          /* output entry */
	uint32_t counter;                    /* generic counter */
};

typedef int (*fat_entry_callback)(struct rpmb_fs *fs, int idx,
				  const struct rpmb_fat_entry *entry,
				  struct fat_iter_ctx *ctx);

static inline struct rpmb_fs *file2rpmb(struct file *f)
{
	return f->fs->priv;
}

static inline void rpmb_save_checkpoint(
	struct rpmb_write_checkpoint *cp,
	struct rpmb_fat_entry *entry, off_t file_pos)
{
	cp->start_addr = entry->start_addr;
	cp->size = entry->size;
	cp->version = entry->version;
	cp->pos = file_pos;
}

static inline void rpmb_restore_checkpoint(
	const struct rpmb_write_checkpoint *cp,
	struct rpmb_fat_entry *entry, off_t *file_pos)
{
	entry->start_addr = cp->start_addr;
	entry->size = cp->size;
	entry->version = cp->version;

	if (file_pos)
		*file_pos = cp->pos;
}

/* Calculate blocks needed for file size (FAT size is uint32_t) */
static inline uint32_t rpmb_blocks_for_size(uint32_t size)
{
	return (size + RPMB_BLOCK_PAYLOAD - 1) / RPMB_BLOCK_PAYLOAD;
}

/* Build GCM IV from base IV and block address (XOR block position) */
static void rpmb_build_iv(unsigned char *iv,
	const unsigned char *base_iv, uint32_t block_addr)
{
	int i = 0;

	memcpy(iv, base_iv, 16);

	/* XOR block address into first 4 bytes */
	for (i = 0; i < 4; i++)
		iv[i] ^= (block_addr >> (i * 8)) & 0xFF;

	/* No version in IV - each block is independently encrypted */
}

static int rpmb_generate_keys(void)
{
	int ret = 0;
	uint8_t huk[32];

	/*
	 * Use a fixed salt to avoid NULL salt weakness in HKDF.
	 * Ideally this should be a device-specific random value
	 * persisted in OTP or similar.
	 */
	const unsigned char salt[] = "mbedtee-rpmb-salt";

	/* Get Hardware Unique Key */
	ret = otp_get_huk(huk, sizeof(huk));
	if (ret != 0) {
		EMSG("Failed to get HUK from OTP! (ret=%d)\n", ret);
		return ret;
	}

	/* Derive RPMB Key using HKDF */
	ret = mbedcrypto_hkdf_derive(salt, sizeof(salt), huk, sizeof(huk),
			(const unsigned char *)"RPMB", 4, rpmb_key, 32);
	if (ret != 0) {
		EMSG("Failed to derive RPMB key (ret=%d)\n", ret);
		memset(huk, 0, sizeof(huk));  /* Clear HUK on error */
		return -EPERM;
	}

	/* Derive FAT Key using HKDF */
	ret = mbedcrypto_hkdf_derive(salt, sizeof(salt), huk, sizeof(huk),
			(const unsigned char *)"Secure Storage", 14, rpmb_fat_key, 16);
	if (ret != 0) {
		EMSG("Failed to derive FAT key (ret=%d)\n", ret);
		memset(huk, 0, sizeof(huk));
		return -EPERM;
	}

	/* Derive FAT IV using HKDF */
	ret = mbedcrypto_hkdf_derive(salt, sizeof(salt), huk, sizeof(huk),
			(const unsigned char *)"FAT IV", 6, rpmb_fat_iv, 16);

	/* Always clear HUK after use */
	memset(huk, 0, sizeof(huk));

	if (ret != 0) {
		EMSG("Failed to derive FAT IV (ret=%d)\n", ret);
		return -EPERM;
	}

	return 0;
}

/* AES-GCM encrypt FAT entry in-place */
static int rpmb_fat_encrypt(struct rpmb_fs *fs, uint32_t idx,
	struct rpmb_fat_entry *entry)
{
	unsigned char iv[16] = {0};
	unsigned char aad[4] = {0};
	size_t tag_offset = offsetof(struct rpmb_fat_entry, tag);
	int ret = 0;

	/* Build IV: base IV XOR entry index */
	rpmb_build_iv(iv, rpmb_fat_iv, idx);

	/* AAD = entry index */
	aad[0] = (idx >> 0) & 0xFF;
	aad[1] = (idx >> 8) & 0xFF;
	aad[2] = (idx >> 16) & 0xFF;
	aad[3] = (idx >> 24) & 0xFF;

	/* Encrypt everything except the tag field */
	ret = mbedcrypto_aes_gcm_encrypt(&fs->fat_ctx,
			iv, 16, aad, sizeof(aad),
			(unsigned char *)entry, tag_offset,
			(unsigned char *)entry,
			entry->tag, RPMB_BLOCK_TAG);

	return (ret == 0) ? 0 : -EIO;
}

/* AES-GCM decrypt FAT entry with tag verification */
static int rpmb_fat_decrypt(struct rpmb_fs *fs, uint32_t idx,
	const struct rpmb_fat_entry *encrypted_entry,
	struct rpmb_fat_entry *decrypted_entry)
{
	unsigned char iv[16] = {0};
	unsigned char aad[4] = {0};
	size_t tag_offset = offsetof(struct rpmb_fat_entry, tag);
	int ret = 0;

	/* Build IV: base IV XOR entry index */
	rpmb_build_iv(iv, rpmb_fat_iv, idx);

	/* AAD = entry index */
	aad[0] = (idx >> 0) & 0xFF;
	aad[1] = (idx >> 8) & 0xFF;
	aad[2] = (idx >> 16) & 0xFF;
	aad[3] = (idx >> 24) & 0xFF;

	ret = mbedcrypto_aes_gcm_decrypt(&fs->fat_ctx,
			iv, 16, aad, sizeof(aad),
			(const unsigned char *)encrypted_entry, tag_offset,
			(unsigned char *)decrypted_entry,
			encrypted_entry->tag, RPMB_BLOCK_TAG);

	return (ret == 0) ? 0 : -EBADMSG;
}

/*
 * AES-GCM Encryption for file data block
 */
static int rpmb_file_encrypt_block(struct rpmb_file *rf,
	uint32_t block_addr, const uint8_t *plaintext,
	size_t len, struct rpmb_data_block *out)
{
	unsigned char iv[16] = {0};
	unsigned char *aad = NULL;
	int ret = 0, aadsz = 0;

	if (len > RPMB_BLOCK_PAYLOAD)
		return -EINVAL;

	/* Build IV from file's base IV and block address (no version) */
	rpmb_build_iv(iv, rf->entry->iv, block_addr);
	LMSG("ENCRYPT: addr=%d actual_iv=%02x%02x%02x%02x...%02x%02x%02x%02x\n",
		(int)block_addr, iv[0], iv[1], iv[2], iv[3], iv[8], iv[9], iv[10], iv[11]);

	/* AAD = unique_id */
	aad = (unsigned char *)&rf->entry->unique_id;
	aadsz = sizeof(rf->entry->unique_id);
	LMSG("ENCRYPT AAD: %02x%02x%02x%02x%02x%02x%02x%02x\n",
	     aad[0], aad[1], aad[2], aad[3], aad[4], aad[5], aad[6], aad[7]);

	/* Clear output block */
	memset(out, 0, sizeof(*out));

	/* Encrypt */
	ret = mbedcrypto_aes_gcm_encrypt(&rf->gcm_ctx,
			iv, 16, aad, aadsz,
			plaintext, len,
			out->payload,
			out->tag, RPMB_BLOCK_TAG);

	return (ret == 0) ? 0 : -EIO;
}

/*
 * AES-GCM Decryption for file data block
 */
static int rpmb_file_decrypt_block(struct rpmb_file *rf,
	uint32_t block_addr, const struct rpmb_data_block *in,
	uint8_t *plaintext, size_t len)
{
	unsigned char iv[16] = {0};
	unsigned char *aad = NULL;
	int ret = 0, aadsz = 0;

	if (len > RPMB_BLOCK_PAYLOAD)
		return -EINVAL;

	/* Build IV from file's base IV and block address (no version) */
	rpmb_build_iv(iv, rf->entry->iv, block_addr);
	LMSG("DECRYPT: addr=%d actual_iv=%02x%02x%02x%02x...%02x%02x%02x%02x\n",
		(int)block_addr, iv[0], iv[1], iv[2], iv[3], iv[8], iv[9], iv[10], iv[11]);

	/* AAD = unique_id */
	aad = (unsigned char *)&rf->entry->unique_id;
	aadsz = sizeof(rf->entry->unique_id);
	LMSG("DECRYPT AAD: %02x%02x%02x%02x%02x%02x%02x%02x\n",
	     aad[0], aad[1], aad[2], aad[3], aad[4], aad[5], aad[6], aad[7]);

	ret = mbedcrypto_aes_gcm_decrypt(&rf->gcm_ctx,
			iv, 16, aad, aadsz,
			in->payload, len,
			plaintext,
			in->tag, RPMB_BLOCK_TAG);
	if (ret != 0)
		DMSG("GCM auth failed: mbedcrypto ret=%d\n", ret);

	return (ret == 0) ? 0 : -EBADMSG;
}

/* Calculate HMAC-SHA256 for RPMB frame */
static int rpmb_calc_mac(const unsigned char *key, struct rpmb_frame *frame)
{
	int ret = -1;
	unsigned char computed_mac[32] = {0};

	/*
	 * HMAC over data(256) + nonce(16) + counter(4) + addr(2) +
	 * block_count(2) + result(2) + req_resp(2)
	 */
	ret = mbedcrypto_hmac_sha256(key, 32, frame->data, 284, computed_mac);
	if (ret != 0)
		return -EACCES;

	memcpy(frame->key_mac, computed_mac, 32);
	return 0;
}

/* Get RPMB device info from hardware */
static int rpmb_get_dev_info(struct rpmb_dev_info *info)
{
	union {
		struct rpmb_cmd cmd;
		uint8_t raw[sizeof(struct rpmb_cmd) + sizeof(struct rpmb_dev_info)];
	} u = {0};
	struct rpmb_cmd *cmd = &u.cmd;
	size_t size = sizeof(u);
	int ret = -1;

	if (!info)
		return -EINVAL;

	cmd->hdr.op = RPMB_GET_DEV_INFO;
	cmd->nframes = 0;

	ret = rpmb_rpc_call(cmd, size);
	if (ret != 0)
		return ret;

	memcpy(info, cmd->frames, sizeof(*info));
	DMSG("RPMB: blocks=%u, rel_wr_sec_c=%u\n",
		info->total_blocks, info->rel_wr_sec_c);

	return ret;
}

/*
 * Get current RPMB write counter from hardware (via supplicant)
 * Verifies MAC and Nonce to ensure integrity.
 */
static int rpmb_get_counter(uint32_t *counter)
{
	struct {
		union {
			struct rpmb_cmd cmd;
			uint8_t raw[sizeof(struct rpmb_cmd) + sizeof(struct rpmb_frame)];
		} u;
		unsigned char mac[32];
		unsigned char nonce[16];
	} *cctx;
	struct rpmb_cmd *cmd = NULL;
	struct rpmb_frame *frame = NULL;
	size_t size = sizeof(struct rpmb_cmd) + sizeof(struct rpmb_frame);
	int ret = -1;

	cctx = kzalloc(sizeof(*cctx));
	if (!cctx)
		return -ENOMEM;

	cmd = &cctx->u.cmd;
	frame = cmd->frames;

	cmd->hdr.op = RPMB_EXEC;
	cmd->nframes = 1;

	frame->req_resp = cpu_to_be16(RPMB_REQ_WCOUNTER);
	prng(cctx->nonce, sizeof(cctx->nonce));
	memcpy(frame->nonce, cctx->nonce, sizeof(cctx->nonce));

	ret = rpmb_rpc_call(cmd, size);

	if (ret != 0)
		goto out;

	if (be16_to_cpu(frame->result) != RPMB_RES_OK) {
		ret = -EIO;
		goto out;
	}

	/* Verify MAC */
	memcpy(cctx->mac, frame->key_mac, 32);
	ret = rpmb_calc_mac(rpmb_key, frame);
	if (ret != 0)
		goto out;

	if (mbedtee_memcmp(cctx->mac, frame->key_mac, 32) != 0) {
		EMSG("MAC verification failed\n");
		ret = -EBADMSG;
		goto out;
	}

	/* Verify Nonce to prevent replay attacks */
	if (mbedtee_memcmp(cctx->nonce, frame->nonce, 16) != 0) {
		ret = -EBADMSG;
		goto out;
	}

	*counter = be32_to_cpu(frame->write_counter);
	ret = 0;

out:
	kfree(cctx);
	return ret;
}

/*
 * Calculate MAC for batch-read (only the last
 * frame has valid MAC according to RPMB spec)
 */
static int rpmb_verify_batch_mac(const unsigned char *key,
	struct rpmb_frame *frames, size_t nframes,
	const unsigned char *nonce)
{
	struct {
		struct mbedcrypto_hmac_sha256_ctx ctx;
		unsigned char computed_mac[32];
	} *mctx;
	int ret = 0;
	size_t i = 0;

	if (!key || !frames || nframes == 0)
		return -EINVAL;

	mctx = kzalloc(sizeof(*mctx));
	if (!mctx)
		return -ENOMEM;

	ret = mbedcrypto_hmac_sha256_init(&mctx->ctx, key, 32);
	if (ret != 0)
		goto cleanup;

	/* Accumulate data from all frames (284 bytes each) */
	for (i = 0; i < nframes; i++) {
		/*
		 * RPMB_MAC_PROTECT_DATA_SIZE = 284 bytes:
		 * data(256) + nonce(16) + counter(4) + addr(2) +
		 * block_count(2) + result(2) + req_resp(2)
		 */
		ret = mbedcrypto_hmac_sha256_update(&mctx->ctx,
			frames[i].data, 284);
		if (ret != 0)
			goto cleanup;
	}

	ret = mbedcrypto_hmac_sha256_final(&mctx->ctx, mctx->computed_mac);
	if (ret != 0)
		goto cleanup;

	/* Compare with MAC from last frame */
	if (mbedtee_memcmp(mctx->computed_mac,
			frames[nframes - 1].key_mac, 32) != 0) {
		EMSG("Batch MAC verification failed for %zu blocks\n", nframes);
		ret = -EBADMSG;
		goto cleanup;
	}

	/* Verify nonce matches (only in last frame) */
	if (mbedtee_memcmp(nonce, frames[nframes - 1].nonce, 16) != 0) {
		EMSG("Nonce verification failed\n");
		ret = -EBADMSG;
		goto cleanup;
	}

	ret = 0;

cleanup:
	mbedcrypto_hmac_sha256_cleanup(&mctx->ctx);
	kfree(mctx);
	return ret;
}

/*
 * Read RPMB frames into a secure buffer with batch processing and TOCTOU protection.
 *
 * SECURITY: This function copies frames from RPC shm to secure memory before
 * MAC verification to prevent TOCTOU attacks. REE cannot modify data during
 * or after MAC verification.
 *
 * OPTIMIZATION: Caller allocates rpmb_frame buffer, we copy directly to it,
 * eliminating the need to extract data field separately.
 *
 * @addr:   Starting block address
 */
static int rpmb_read_frames(unsigned int addr,
	struct rpmb_frame *frames, size_t count)
{
	int ret = -1;
	struct rpmb_cmd *cmd = NULL;
	unsigned char nonce[16] = {0};
	size_t batch = 0, processed = 0;
	size_t cmd_size = 0, i = 0;

	if (!frames || count == 0)
		return -EINVAL;

	/* Process in batches (limited by RPMB_READ_BATCH from Kconfig) */
	while (processed < count) {
		batch = min(count - processed, (size_t)RPMB_READ_BATCH);

		/* Allocate RPC shared memory for this batch */
		cmd_size = sizeof(struct rpmb_cmd) + batch * sizeof(struct rpmb_frame);
		cmd = rpc_shm_alloc(cmd_size);
		if (!cmd)
			return -ENOMEM;

		memset(cmd, 0, cmd_size);
		prng(nonce, sizeof(nonce));

		cmd->hdr.op = RPMB_EXEC;
		cmd->nframes = batch;

		/* Setup read request in first frame */
		cmd->frames[0].req_resp = cpu_to_be16(RPMB_REQ_READ);
		cmd->frames[0].addr = cpu_to_be16(addr + processed);
		cmd->frames[0].block_count = cpu_to_be16(batch);
		memcpy(cmd->frames[0].nonce, nonce, sizeof(nonce));

		/* Execute RPC call */
		ret = rpmb_rpc_call(cmd, cmd_size);

		if (ret != 0) {
			rpc_shm_free(cmd);
			return ret;
		}

		/* Check result code in last frame */
		if (be16_to_cpu(cmd->frames[batch - 1].result) != RPMB_RES_OK) {
			rpc_shm_free(cmd);
			return -EIO;
		}

		/* Copy frames to secure buffer before MAC verification (TOCTOU prevention) */
		for (i = 0; i < batch; i++)
			memcpy(&frames[processed + i], &cmd->frames[i], sizeof(struct rpmb_frame));

		/* Done with RPC shm, free immediately */
		rpc_shm_free(cmd);

		/* Verify batch MAC using frames in caller's secure buffer */
		ret = rpmb_verify_batch_mac(rpmb_key, &frames[processed], batch, nonce);
		if (ret != 0)
			return ret;

		processed += batch;
	}

	return 0;
}

/*
 * Calculate MAC for batch write following RPMB spec.
 * For N-block write, MAC is calculated over all frames' protected data,
 * and placed in the last frame's key_mac field.
 */
static int rpmb_calc_batch_write_mac(const unsigned char *key,
	struct rpmb_frame *frames, size_t nframes)
{
	struct {
		struct mbedcrypto_hmac_sha256_ctx ctx;
		unsigned char computed_mac[32];
	} *mctx;
	int ret = 0;
	size_t i = 0;

	if (!key || !frames || nframes == 0)
		return -EINVAL;

	mctx = kzalloc(sizeof(*mctx));
	if (!mctx)
		return -ENOMEM;

	ret = mbedcrypto_hmac_sha256_init(&mctx->ctx, key, 32);
	if (ret != 0)
		goto cleanup;

	/* Accumulate data from all frames */
	for (i = 0; i < nframes; i++) {
		/*
		 * RPMB_MAC_PROTECT_DATA_SIZE = 284 bytes:
		 * data(256) + nonce(16) + counter(4) + addr(2) +
		 * block_count(2) + result(2) + req_resp(2)
		 */
		ret = mbedcrypto_hmac_sha256_update(&mctx->ctx,
			frames[i].data, 284);
		if (ret != 0)
			goto cleanup;
	}

	ret = mbedcrypto_hmac_sha256_final(&mctx->ctx, mctx->computed_mac);
	if (ret != 0)
		goto cleanup;

	/* Store MAC in last frame */
	memcpy(frames[nframes - 1].key_mac, mctx->computed_mac, 32);

	DMSG("RPMB batch MAC: nframes=%zu, mac=%02x%02x%02x%02x...%02x%02x%02x%02x\n",
	     nframes,
	     mctx->computed_mac[0], mctx->computed_mac[1],
	     mctx->computed_mac[2], mctx->computed_mac[3],
	     mctx->computed_mac[28], mctx->computed_mac[29],
	     mctx->computed_mac[30], mctx->computed_mac[31]);

	ret = 0;

cleanup:
	mbedcrypto_hmac_sha256_cleanup(&mctx->ctx);
	kfree(mctx);
	return ret;
}

static int rpmb_write_data(unsigned int addr, const void *data,
	size_t count, uint32_t *counter)
{
	int ret = -1;
	int cret = 0;
	struct rpmb_cmd *cmd = NULL;
	unsigned char mac[32] = {0};
	size_t i = 0, batch = 0;
	size_t processed = 0, cmd_size = 0;
	bool retry = false;

	while (processed < count) {
		/* Batch size controlled by CONFIG_RPMB_FS_WRITE_BATCH (Kconfig) */
		batch = count - processed;
		if (batch > RPMB_WRITE_BATCH)
			batch = RPMB_WRITE_BATCH;

		cmd_size = sizeof(struct rpmb_cmd) + batch * sizeof(struct rpmb_frame);
		cmd = rpc_shm_alloc(cmd_size);
		if (!cmd)
			return -ENOMEM;

retry_batch:
		memset(cmd, 0, cmd_size);
		cmd->hdr.op = RPMB_EXEC;
		cmd->nframes = batch;

		/* Fill all frames with data and metadata */
		for (i = 0; i < batch; i++) {
			cmd->frames[i].req_resp = cpu_to_be16(RPMB_REQ_WRITE);
			cmd->frames[i].addr = cpu_to_be16(addr + processed + i);
			cmd->frames[i].block_count = cpu_to_be16(batch);
			cmd->frames[i].write_counter = cpu_to_be32(*counter);
			memcpy(cmd->frames[i].data,
				(uint8_t *)data + (processed + i) * RPMB_BLOCK_SIZE,
				RPMB_BLOCK_SIZE);
		}

		/* Calculate batch MAC covering all frames */
		ret = rpmb_calc_batch_write_mac(rpmb_key, cmd->frames, batch);
		if (ret != 0) {
			rpc_shm_free(cmd);
			goto out;
		}

		ret = rpmb_rpc_call(cmd, cmd_size);

		if (ret != 0) {
			rpc_shm_free(cmd);
			goto out;
		}

		/* Check the last frame for status (since it's a multi-block write) */
		if (be16_to_cpu(cmd->frames[0].result) != RPMB_RES_OK) {
			EMSG("RPMB Write failed: result=0x%04x counter=%d\n",
				be16_to_cpu(cmd->frames[0].result),
				(int)be32_to_cpu(cmd->frames[0].write_counter));
			if (be16_to_cpu(cmd->frames[0].result) == RPMB_RES_COUNTER_FAILURE ||
				be16_to_cpu(cmd->frames[0].result) == RPMB_RES_WRITE_FAILURE) {
				if (!retry) {
					WMSG("RPMB Write Counter Mismatch, resyncing...\n");
					cret = rpmb_get_counter(counter);
					if (cret != 0) {
						ret = cret;
						rpc_shm_free(cmd);
						goto out;
					}
					retry = true;
					goto retry_batch;
				}
			}
			ret = -EIO;
			rpc_shm_free(cmd);
			goto out;
		}

		/* Verify Response MAC (single frame response) */
		memcpy(mac, cmd->frames[0].key_mac, 32);
		ret = rpmb_calc_mac(rpmb_key, &cmd->frames[0]);
		if (ret != 0) {
			rpc_shm_free(cmd);
			goto out;
		}

		if (mbedtee_memcmp(mac, cmd->frames[0].key_mac, 32) != 0) {
			ret = -EBADMSG;
			rpc_shm_free(cmd);
			goto out;
		}

		if (be32_to_cpu(cmd->frames[0].write_counter) != *counter + 1) {
			EMSG("Counter mismatch: expected %d+1, got %d\n",
				(int)*counter, (int)be32_to_cpu(cmd->frames[0].write_counter));
			ret = -EBADMSG;
			rpc_shm_free(cmd);
			goto out;
		}

		*counter = be32_to_cpu(cmd->frames[0].write_counter);
		rpc_shm_free(cmd);
		processed += batch;
		retry = false;
	}

	ret = 0;

out:
	return ret;
}

/* Flush pending batch write and reset batch_count */
static inline int rpmb_flush_batch(uint32_t start_addr,
	struct rpmb_data_block *batch, uint32_t *batch_count,
	uint32_t *write_counter)
{
	int ret = 0;

	if (*batch_count > 0) {
		ret = rpmb_write_data(start_addr, batch, *batch_count, write_counter);
		if (ret == 0)
			*batch_count = 0;
		if (ret != 0)
			EMSG("RPMB Write ret %d...\n", ret);
	}

	return ret;
}

/* Fill hole region in a block with zeros (RMW or direct zero encryption) */
static int rpmb_fill_hole_in_block(struct rpmb_file *rf,
	uint32_t block_addr, size_t hole_start,
	size_t hole_end, uint32_t *write_counter,
	struct rpmb_data_block *output_buffer)
{
	struct rpmb_frame *frame = NULL;
	uint8_t plaintext[RPMB_BLOCK_PAYLOAD];
	struct rpmb_data_block *encrypted = NULL;
	int ret = 0;

	if (hole_start >= hole_end || hole_end > RPMB_BLOCK_PAYLOAD)
		return 0;

	frame = kmalloc(sizeof(*frame));
	if (!frame)
		return -ENOMEM;

	memset(plaintext, 0, sizeof(plaintext));

	if (hole_start == 0 && hole_end == RPMB_BLOCK_PAYLOAD) {
		/* Entire block is hole - encrypt zeros */
		ret = rpmb_file_encrypt_block(rf, block_addr, plaintext,
				RPMB_BLOCK_PAYLOAD, output_buffer ? output_buffer :
				(struct rpmb_data_block *)frame->data);
		if (ret != 0)
			goto out;
	} else {
		/* Partial hole - RMW */
		ret = rpmb_read_frames(block_addr, frame, 1);
		if (ret != 0)
			goto out;

		encrypted = (struct rpmb_data_block *)frame->data;
		ret = rpmb_file_decrypt_block(rf, block_addr, encrypted,
					      plaintext, RPMB_BLOCK_PAYLOAD);
		if (ret != 0)
			goto out;

		memset(plaintext + hole_start, 0, hole_end - hole_start);

		ret = rpmb_file_encrypt_block(rf, block_addr, plaintext,
				RPMB_BLOCK_PAYLOAD, output_buffer ? output_buffer :
				(struct rpmb_data_block *)frame->data);
		if (ret != 0)
			goto out;
	}

	/* Write back if no output buffer provided */
	if (!output_buffer) {
		encrypted = (struct rpmb_data_block *)frame->data;
		ret = rpmb_write_data(block_addr, encrypted, 1, write_counter);
	}

out:
	kfree(frame);
	return ret;
}

/*
 * Fill multiple consecutive hole blocks with zeros in batch
 * (POSIX sparse file support)
 */
static int rpmb_fill_holes_batch(struct rpmb_file *rf,
	uint32_t start_block, uint32_t count, uint32_t *write_counter)
{
	unsigned char zeros[RPMB_BLOCK_PAYLOAD];
	struct rpmb_data_block *batch = NULL;
	uint32_t max_batch = RPMB_WRITE_BATCH, batch_count = 0, i = 0;
	int ret = 0;

	if (count == 0)
		return 0;

	memset(zeros, 0, sizeof(zeros));

	if (count < max_batch)
		max_batch = count;

	batch = kmalloc(max_batch * sizeof(struct rpmb_data_block));
	if (!batch && max_batch > 1) {
		max_batch = 1;
		batch = kmalloc(sizeof(struct rpmb_data_block));
	}
	if (!batch)
		return -ENOMEM;

	for (i = 0; i < count; i++) {
		ret = rpmb_file_encrypt_block(rf, start_block + i, zeros,
						RPMB_BLOCK_PAYLOAD, &batch[batch_count]);
		if (ret != 0)
			goto out;

		batch_count++;

		/* Flush when batch full or last block */
		if (batch_count >= max_batch || i == count - 1) {
			ret = rpmb_flush_batch(start_block + i - batch_count + 1,
					       batch, &batch_count, write_counter);
			if (ret != 0)
				goto out;
		}
	}

out:
	kfree(batch);
	return ret;
}

/*
 * Fill hole range [old_size, new_size) with zeros
 * (partial tail + complete blocks)
 */
static int rpmb_fill_hole_range(struct rpmb_file *rf,
	uint32_t base_addr, uint32_t old_size, uint32_t new_size,
	uint32_t *write_counter)
{
	/*
	 * Fill the logical gap [old_size, new_size) with zeros.
	 *
	 * IMPORTANT:
	 * - There can be a hole that stays within the last existing block
	 *   (e.g. lseek beyond EOF then write in same block).
	 * - For security and to keep future extensions deterministic, we
	 *   zero the entire tail of the last existing block from old EOF to
	 *   end-of-block.
	 * - Any blocks beyond the old EOF block are newly allocated and can
	 *   be initialized by writing encrypted-zero blocks directly.
	 */
	uint32_t old_blocks = 0, eof_tail_off = 0;
	uint32_t first_new_block = 0, last_full_new_block = 0;
	uint32_t full_new_blocks = 0, last_partial_new_block = 0;
	bool has_partial_new_block = false;
	int ret = 0;

	DMSG("FILL_HOLE: base_addr=%d old_size=%d new_size=%d\n",
		(int)base_addr, (int)old_size, (int)new_size);

	if (new_size <= old_size)
		return 0;

	old_blocks = rpmb_blocks_for_size(old_size);
	eof_tail_off = old_size % RPMB_BLOCK_PAYLOAD;

	/* Step 1: Zero tail in the last existing block (covers same-block holes too). */
	if (old_blocks > 0 && eof_tail_off != 0) {
		uint32_t last_old_block = old_blocks - 1;

		ret = rpmb_fill_hole_in_block(rf, base_addr + last_old_block,
					      eof_tail_off, RPMB_BLOCK_PAYLOAD,
					      write_counter, NULL);
		if (ret != 0)
			return ret;
	}

	/* Step 2: Initialize new blocks beyond old EOF with encrypted zeros. */
	first_new_block = old_blocks;
	if (new_size % RPMB_BLOCK_PAYLOAD) {
		has_partial_new_block = true;
		last_partial_new_block = new_size / RPMB_BLOCK_PAYLOAD;
		/* Blocks [first_new_block, last_partial_new_block) are full new blocks. */
		last_full_new_block = last_partial_new_block;
	} else {
		has_partial_new_block = false;
		/* new_size ends on boundary, blocks [first_new_block, new_size/blk) are full. */
		last_full_new_block = new_size / RPMB_BLOCK_PAYLOAD;
	}

	if (last_full_new_block > first_new_block) {
		full_new_blocks = last_full_new_block - first_new_block;
		ret = rpmb_fill_holes_batch(rf, base_addr + first_new_block,
					    full_new_blocks, write_counter);
		if (ret != 0)
			return ret;
	}

	/* Step 3: If new_size ends inside a new block, initialize that block too. */
	if (has_partial_new_block && last_partial_new_block >= first_new_block) {
		ret = rpmb_fill_holes_batch(rf, base_addr + last_partial_new_block,
					    1, write_counter);
	}

	return ret;
}

/* Program RPMB authentication key */
static int rpmb_program_key(void)
{
	int ret = -1;
	size_t size = sizeof(struct rpmb_cmd) + sizeof(struct rpmb_frame);
	union {
		struct rpmb_cmd cmd;
		uint8_t raw[sizeof(struct rpmb_cmd) + sizeof(struct rpmb_frame)];
	} u;
	struct rpmb_cmd *cmd = &u.cmd;
	struct rpmb_frame *frame = cmd->frames;

	memset(&u, 0, sizeof(u));
	cmd->hdr.op = RPMB_EXEC;
	cmd->nframes = 1;

	frame->req_resp = cpu_to_be16(RPMB_REQ_KEY);
	memcpy(frame->key_mac, rpmb_key, sizeof(rpmb_key));

	ret = rpmb_rpc_call(cmd, size);

	if (ret != 0)
		goto out;

	if (be16_to_cpu(frame->result) != RPMB_RES_OK)
		ret = -EPERM;
	else
		ret = 0;

out:
	return ret;
}

static int rpmb_fs_write_fat_entry(struct rpmb_fs *fs,
	int idx, struct rpmb_fat_entry *entry)
{
	struct rpmb_fat_entry block;
	int ret = 0;

	if (idx < 0 || idx >= RPMB_FAT_ENTRIES)
		return -EINVAL;

	/* Copy entry and encrypt */
	memcpy(&block, entry, sizeof(block));

	ret = rpmb_fat_encrypt(fs, idx, &block);
	if (ret != 0)
		return ret;

	ret = rpmb_write_data(RPMB_FAT_START + idx,
			&block, 1, &fs->write_counter);

	/* Always update FAT cache on successful write (write-through cache) */
	if (ret == 0 && fs->fat_cache && idx < RPMB_FAT_CACHED)
		memcpy(&fs->fat_cache[idx], entry, sizeof(*entry));

	return ret;
}

static int rpmb_fs_init_bitmap(struct rpmb_fs *fs)
{
	int ret = 0;
	struct rpmb_dev_info dev_info = {0};

	if (fs->bitmap)
		return 0;

	/* Get device info including total blocks and reliable write sector count */
	ret = rpmb_get_dev_info(&dev_info);
	if (ret != 0) {
		WMSG("Failed to get RPMB device info - ret %d\n", ret);
		return ret;
	}

	if (dev_info.total_blocks < RPMB_FAT_ENTRIES) {
		EMSG("RPMB size too small (%d blocks), min %d required\n",
			(int)dev_info.total_blocks, RPMB_FAT_ENTRIES);
		return -ENOSPC;
	}

	/* Sanity check: limit to 16MB (RPMB_MAX_BLOCKS) to prevent memory DoS */
	if (dev_info.total_blocks > RPMB_MAX_BLOCKS) {
		WMSG("RPMB size too large (%d blocks), clamping to 16MB\n",
			(int)dev_info.total_blocks);
		dev_info.total_blocks = RPMB_MAX_BLOCKS;
	}

	fs->bitmap = bitmap_zalloc(dev_info.total_blocks);
	if (!fs->bitmap)
		return -ENOMEM;

	/* Reserve FAT blocks (0 ~ RPMB_FAT_ENTRIES - 1) */
	bitmap_set(fs->bitmap, RPMB_FAT_START, RPMB_FAT_ENTRIES);

	/* Save device capabilities to fs struct */
	fs->total_blkcnt = dev_info.total_blocks;
	fs->rel_wr_blkcnt = dev_info.rel_wr_sec_c;
	/* Initialize idle_blkcnt (total - FAT reserved blocks) */
	fs->idle_blkcnt = fs->total_blkcnt - RPMB_FAT_ENTRIES;

	return 0;
}

/* Check if write is atomic (within reliable write block count) */
static bool rpmb_write_is_atomic(struct rpmb_fs *fs,
	size_t pos, size_t len)
{
	uint32_t first_blk = pos / RPMB_BLOCK_PAYLOAD;
	uint32_t last_blk = (pos + len - 1) / RPMB_BLOCK_PAYLOAD;

	/* RPMB hardware guarantees atomic completion if within reliable count */
	return (last_blk - first_blk + 1 <= fs->rel_wr_blkcnt);
}

/* Allocate contiguous blocks from bitmap */
static int rpmb_fs_alloc_blocks(struct rpmb_fs *fs, uint32_t count,
	uint32_t start_hint, uint32_t *out_start)
{
	unsigned int start = 0;

	if (start_hint >= fs->total_blkcnt)
		start_hint = RPMB_FAT_ENTRIES;

	start = bitmap_next_zero_area(fs->bitmap, fs->total_blkcnt,
		start_hint, count);

	if (start >= fs->total_blkcnt)
		return -ENOSPC;

	bitmap_set(fs->bitmap, start, count);
	fs->idle_blkcnt -= count;
	*out_start = start;
	return 0;
}

static void rpmb_fs_free_blocks(struct rpmb_fs *fs,
	uint32_t start, uint32_t count)
{
	if (count == 0)
		return;
	if (start < RPMB_FAT_ENTRIES)
		return;
	if (start >= fs->total_blkcnt)
		return;
	if (start + count < start)
		return;
	if (start + count > fs->total_blkcnt)
		return;

	bitmap_clear(fs->bitmap, start, count);
	fs->idle_blkcnt += count;
}

/*
 * Relocate file blocks to a new location (common for write and truncate)
 */
static int rpmb_relocate_file_blocks(struct rpmb_file *rf,
	struct rpmb_fs *fs, uint32_t old_start, uint32_t new_start,
	uint32_t old_blocks, struct rpmb_data_block *batch_blocks,
	uint32_t max_batch_blocks)
{
	uint8_t decrypted[RPMB_BLOCK_PAYLOAD];
	int ret = 0;
	struct rpmb_frame *old_frames = NULL;
	struct rpmb_data_block *wrbatch = NULL;
	struct rpmb_data_block *heap_batch = NULL;
	struct rpmb_data_block *encrypted_block = NULL, *out_block = NULL;
	uint32_t read_batch_max = 0, write_batch_max = 0;
	uint32_t remaining = old_blocks, batch_count = 0;
	uint32_t i = 0, batch_start_addr = 0;
	bool use_inline = false;
	bool is_last = false;

	read_batch_max = min(old_blocks, (uint32_t)RPMB_READ_BATCH);
	old_frames = kmalloc(read_batch_max * sizeof(struct rpmb_frame));
	if (!old_frames && read_batch_max > 1) {
		read_batch_max = 1;
		old_frames = kmalloc(sizeof(struct rpmb_frame));
		use_inline = true;
	}
	if (!old_frames)
		return -ENOMEM;

	write_batch_max = min(old_blocks, (uint32_t)RPMB_WRITE_BATCH);
	if (batch_blocks && max_batch_blocks > 0) {
		wrbatch = batch_blocks;
		write_batch_max = min(write_batch_max, max_batch_blocks);
	} else {
		heap_batch = kmalloc(write_batch_max * sizeof(*heap_batch));
		wrbatch = heap_batch;
	}
	if (!wrbatch) {
		write_batch_max = 1;
		use_inline = true;
	}

	/* read + relocate all existing blocks */
	while (remaining) {
		uint32_t read_batch = min(remaining, read_batch_max);

		ret = rpmb_read_frames(old_start, old_frames, read_batch);
		if (ret != 0) {
			EMSG("RPMB Relocation: Batch read failed %d\n", ret);
			goto out;
		}

		for (i = 0; i < read_batch; i++) {
			is_last = (remaining == read_batch) && (i == read_batch - 1);

			encrypted_block = (struct rpmb_data_block *)old_frames[i].data;

			/* Decrypt from old address */
			ret = rpmb_file_decrypt_block(rf, old_start + i, encrypted_block,
					      decrypted, RPMB_BLOCK_PAYLOAD);
			if (ret != 0)
				goto out;

			if (use_inline) {
				out_block = (struct rpmb_data_block *)old_frames[i].data;
				ret = rpmb_file_encrypt_block(rf, new_start + i, decrypted,
					      RPMB_BLOCK_PAYLOAD, out_block);
				if (ret != 0)
					goto out;
				ret = rpmb_write_data(new_start + i, out_block, 1, &fs->write_counter);
				if (ret != 0)
					goto out;
			} else {
				/* Re-encrypt for new address */
				ret = rpmb_file_encrypt_block(rf, new_start + i, decrypted,
					      RPMB_BLOCK_PAYLOAD, &wrbatch[batch_count]);
				if (ret != 0)
					goto out;

				if (batch_count == 0)
					batch_start_addr = new_start + i;
				batch_count++;

				/* Flush batch if full or last block */
				if (batch_count >= write_batch_max || is_last) {
					ret = rpmb_flush_batch(batch_start_addr, wrbatch,
							       &batch_count, &fs->write_counter);
					if (ret != 0)
						goto out;
				}
			}
		}

		remaining -= read_batch;
		old_start += read_batch;
		new_start += read_batch;
	}

out:
	kfree(heap_batch);
	kfree(old_frames);
	memset(decrypted, 0, sizeof(decrypted));
	return ret;
}

/*
 * Block allocation helper - handles new/extend/relocate scenarios
 *
 * @rf: File handle (for relocation)
 * @fs: Filesystem context
 * @new_blocks: Target block count
 * @force_relocate: Force CoW relocation (e.g., non-atomic overwrite)
 * @batch_buf: Optional batch buffer for relocation (can be NULL)
 * @batch_size: Size of batch buffer
 * @out_alloc_start: [out] Start address of newly allocated blocks
 * @out_alloc_count: [out] Number of newly allocated blocks
 * @out_old_start: [out] Old start address if relocated (0 if not)
 *
 * Returns 0 on success, negative error on failure.
 * Caller must free old blocks after FAT commit if out_old_start != 0.
 */
static int rpmb_alloc_or_extend(struct rpmb_file *rf, struct rpmb_fs *fs,
	uint32_t new_blocks, bool force_relocate,
	struct rpmb_data_block *batch_buf, uint32_t batch_size,
	uint32_t *out_alloc_start, uint32_t *out_alloc_count, uint32_t *out_old_start)
{
	struct rpmb_fat_entry *entry = rf->entry;
	uint32_t old_blocks = rpmb_blocks_for_size(entry->size);
	uint32_t start = 0, new_start = 0, free_start = 0;
	uint32_t needed = 0, next_start = 0;
	int ret = 0;

	*out_alloc_start = 0;
	*out_alloc_count = 0;
	*out_old_start = 0;

	if (new_blocks == 0)
		return 0;

	if (old_blocks == 0) {
		/* New file: allocate initial extent */
		ret = rpmb_fs_alloc_blocks(fs, new_blocks, 0, &start);
		if (ret != 0)
			return ret;
		entry->start_addr = start;
		*out_alloc_start = start;
		*out_alloc_count = new_blocks;
		return 0;
	}

	/* Try in-place contiguous extension (only if not forcing relocation) */
	if (!force_relocate && new_blocks > old_blocks) {
		needed = new_blocks - old_blocks;
		next_start = entry->start_addr + old_blocks;
		ret = rpmb_fs_alloc_blocks(fs, needed, next_start, &free_start);
		if (ret == 0 && free_start == next_start) {
			/* Extended in-place */
			*out_alloc_start = next_start;
			*out_alloc_count = needed;
			return 0;
		}
		/* Allocation succeeded but not contiguous - free and try relocate */
		if (ret == 0)
			rpmb_fs_free_blocks(fs, free_start, needed);
	}

	/* Relocate: alloc new extent, copy old data, update entry */
	if (force_relocate || new_blocks > old_blocks) {
		uint32_t orig_start = entry->start_addr;

		ret = rpmb_fs_alloc_blocks(fs, new_blocks, 0, &new_start);
		if (ret != 0)
			return ret;

		ret = rpmb_relocate_file_blocks(rf, fs, orig_start, new_start,
						old_blocks, batch_buf, batch_size);
		if (ret != 0) {
			rpmb_fs_free_blocks(fs, new_start, new_blocks);
			return ret;
		}

		entry->start_addr = new_start;
		*out_alloc_start = new_start;
		*out_alloc_count = new_blocks;
		*out_old_start = orig_start;  /* Caller frees after FAT commit */
	}

	return 0;
}

static int rpmb_for_each_fat_entry(struct rpmb_fs *fs, int start_idx,
				   fat_entry_callback callback,
				   struct fat_iter_ctx *ctx)
{
	struct rpmb_fat_entry entry;
	struct rpmb_frame *frames = NULL;
	const struct rpmb_fat_entry *enc;
	int i, j, max_batch, ret = 0;
	int batch = 0;

	/* Phase 1: cached entries */
	if (fs->fat_cache && start_idx < RPMB_FAT_CACHED) {
		for (i = start_idx; i < RPMB_FAT_CACHED; i++) {
			ret = callback(fs, i, &fs->fat_cache[i], ctx);
			if (ret != 0)
				return ret;
		}
		start_idx = RPMB_FAT_CACHED;
	}

	if (start_idx >= RPMB_FAT_ENTRIES)
		return 0;

	/* Phase 2: uncached entries with batch read */
	max_batch = RPMB_READ_BATCH;
	frames = kmalloc(max_batch * sizeof(*frames));
	if (!frames && max_batch > 1) {
		max_batch = 1;
		frames = kmalloc(sizeof(*frames));
	}
	if (!frames)
		return -ENOMEM;

	for (i = start_idx; i < RPMB_FAT_ENTRIES; i += max_batch) {
		batch = min(max_batch, RPMB_FAT_ENTRIES - i);

		ret = rpmb_read_frames(RPMB_FAT_START + i, frames, batch);
		if (ret != 0)
			goto out;

		for (j = 0; j < batch; j++) {
			enc = (const struct rpmb_fat_entry *)frames[j].data;
			ret = rpmb_fat_decrypt(fs, i + j, enc, &entry);
			if (ret != 0)
				continue;  /* skip corrupted entries */

			ret = callback(fs, i + j, &entry, ctx);
			if (ret != 0)
				goto out;
		}
	}

	ret = 0;
out:
	kfree(frames);
	return ret;
}

/* FAT iteration callbacks using unified fat_iter_ctx */
static int dir_empty_cb(struct rpmb_fs *fs, int idx,
			const struct rpmb_fat_entry *entry,
			struct fat_iter_ctx *ctx)
{
	if (idx == ctx->skip_idx || entry->flags == RPMB_ENT_EMPTY)
		return 0;
	if (strncmp(entry->filename, ctx->name, ctx->len) == 0 &&
	    entry->filename[ctx->len] == '/')
		return -ENOTEMPTY;
	return 0;
}

static int rpmb_fs_is_dir_empty(struct rpmb_fs *fs,
	const char *dirname, int skip_idx)
{
	struct fat_iter_ctx ctx = {
		.name = dirname, .len = strlen(dirname), .skip_idx = skip_idx
	};
	return rpmb_for_each_fat_entry(fs, 0, dir_empty_cb, &ctx);
}

/*
 * Rename all files/subdirectories within a directory
 * Used when renaming a directory to update all child paths
 * Returns 0 on success, negative error code otherwise
 */
static int rpmb_fs_rename_dir_children(struct rpmb_fs *fs,
	const char *oldname, const char *newname)
{
	struct rpmb_fat_entry entry;
	char new_path[RPMB_MAX_FILENAME];
	struct rpmb_frame *frames = NULL;
	const struct rpmb_fat_entry *enc;
	struct rpmb_file *rf;
	size_t old_len = strlen(oldname);
	const char *fname = NULL;
	int i, j, max_batch, start_idx, ret = 0, slen;

	/* Phase 1: update cached entries */
	start_idx = 0;
	if (fs->fat_cache) {
		for (i = 0; i < RPMB_FAT_CACHED; i++) {
			if (fs->fat_cache[i].flags == RPMB_ENT_EMPTY)
				continue;

			fname = fs->fat_cache[i].filename;
			if (strncmp(fname, oldname, old_len) == 0 && fname[old_len] == '/') {
				/* Build new path */
				slen = snprintf(new_path, sizeof(new_path), "%s%s",
					 newname, &fs->fat_cache[i].filename[old_len]);

				if (slen < 0 || (size_t)slen >= RPMB_MAX_FILENAME) {
					ret = -ENAMETOOLONG;
					goto out;
				}

				/* Update entry */
				strlcpy(fs->fat_cache[i].filename, new_path, RPMB_MAX_FILENAME);
				ret = rpmb_fs_write_fat_entry(fs, i, &fs->fat_cache[i]);
				if (ret != 0)
					goto out;
			}
		}
		start_idx = RPMB_FAT_CACHED;
	}

	/* Phase 2: update uncached entries */
	if (start_idx >= RPMB_FAT_ENTRIES) {
		ret = 0;
		goto out;
	}

	max_batch = RPMB_READ_BATCH;
	frames = kmalloc(max_batch * sizeof(struct rpmb_frame));
	if (!frames && max_batch > 1) {
		max_batch = 1;
		frames = kmalloc(sizeof(struct rpmb_frame));
	}
	if (!frames) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = start_idx; i < RPMB_FAT_ENTRIES; i += max_batch) {
		max_batch = min(max_batch, RPMB_FAT_ENTRIES - i);

		ret = rpmb_read_frames(RPMB_FAT_START + i, frames, max_batch);
		if (ret != 0)
			goto out;

		for (j = 0; j < max_batch; j++) {
			enc = (const struct rpmb_fat_entry *)frames[j].data;
			ret = rpmb_fat_decrypt(fs, i + j, enc, &entry);
			if (ret != 0)
				continue;

			if (entry.flags == RPMB_ENT_EMPTY)
				continue;

			if (strncmp(entry.filename, oldname, old_len) == 0 &&
			    entry.filename[old_len] == '/') {
				/* Build new path */
				slen = snprintf(new_path, sizeof(new_path), "%s%s",
					 newname, &entry.filename[old_len]);

				if (slen < 0 || (size_t)slen >= RPMB_MAX_FILENAME) {
					ret = -ENAMETOOLONG;
					goto out;
				}

				/* Update entry */
				strlcpy(entry.filename, new_path, RPMB_MAX_FILENAME);
				ret = rpmb_fs_write_fat_entry(fs, i + j, &entry);
				if (ret != 0)
					goto out;

				/* Update open file if outside cache (cache auto-updated) */
				list_for_each_entry(rf, &fs->open_files, node) {
					if (rf->fat_idx == i + j) {
						strlcpy(rf->entry->filename, new_path, RPMB_MAX_FILENAME);
						break;
					}
				}
			}
		}
	}

	ret = 0;
out:
	kfree(frames);
	return ret;
}

/* Initialize RPMB partition on first use (counter = 0) */
static int rpmb_fs_init_partition(struct rpmb_fs *fs)
{
	int ret = 0, i = 0, batch_start = 0;
	struct rpmb_fat_entry *batch = NULL, inline_batch[1];
	struct rpmb_fat_entry empty_entry;
	size_t batch_count = 0, max_batch = RPMB_WRITE_BATCH;

	IMSG("Initializing RPMB partition with empty FAT\n");

	/* Allocate batch buffer (fallback to inline if allocation fails) */
	batch = kmalloc(max_batch * sizeof(struct rpmb_fat_entry));
	if (!batch) {
		batch = inline_batch;
		max_batch = 1;
	}

	/* Write empty FAT entries in batches */
	for (i = 0; i < RPMB_FAT_ENTRIES; i++) {
		/* Prepare empty FAT entry template */
		memset(&empty_entry, 0, sizeof(empty_entry));
		empty_entry.flags = RPMB_ENT_EMPTY;

		ret = rpmb_fat_encrypt(fs, i, &empty_entry);
		if (ret != 0)
			goto out;
		memcpy(&batch[batch_count], &empty_entry, sizeof(struct rpmb_fat_entry));

		if (batch_count == 0)
			batch_start = i;

		batch_count++;

		/* Flush when batch full or last entry */
		if (batch_count >= max_batch || i == RPMB_FAT_ENTRIES - 1) {
			ret = rpmb_write_data(RPMB_FAT_START + batch_start,
					      batch, batch_count, &fs->write_counter);
			if (ret != 0) {
				EMSG("Failed to write FAT batch at %d: %d\n", batch_start, ret);
				goto out;
			}

			batch_count = 0;
		}
	}

	IMSG("RPMB partition initialized (counter=%d)\n", (int)fs->write_counter);

out:
	if (batch != inline_batch)
		kfree(batch);
	return ret;
}

static int rpmb_fs_scan(struct rpmb_fs *fs)
{
	struct rpmb_frame *frames = NULL;
	struct rpmb_fat_entry entry;
	int i, j, max_batch, ret = 0;
	uint32_t num_blocks = 0;
	const struct rpmb_fat_entry *enc = NULL;
	int idx = 0;
	unsigned long next_set = 0;

	ret = rpmb_fs_init_bitmap(fs);
	if (ret != 0)
		return ret;

	/* Allocate FAT cache (significant performance improvement) */
	if (!fs->fat_cache && RPMB_FAT_CACHED) {
		fs->fat_cache = kzalloc(RPMB_FAT_CACHED * sizeof(struct rpmb_fat_entry));
		if (!fs->fat_cache) {
			EMSG("Failed to allocate FAT cache (%zu bytes)\n",
			     RPMB_FAT_CACHED * sizeof(struct rpmb_fat_entry));
			return -ENOMEM;
		}
	}

	/* Allocate batch buffer for scanning FAT */
	frames = kmalloc(RPMB_READ_BATCH * sizeof(struct rpmb_frame));
	if (!frames) {
		ret = -ENOMEM;
		goto out;
	}

	/* Scan FAT in batches to build bitmap and cache */
	for (i = 0; i < RPMB_FAT_ENTRIES; i += RPMB_READ_BATCH) {
		max_batch = min(RPMB_FAT_ENTRIES - i, RPMB_READ_BATCH);

		ret = rpmb_read_frames(RPMB_FAT_START + i, frames, max_batch);
		if (ret != 0)
			goto out;

		for (j = 0; j < max_batch; j++) {
			enc = (const struct rpmb_fat_entry *)frames[j].data;
			idx = i + j;

			ret = rpmb_fat_decrypt(fs, idx, enc, &entry);
			if (ret != 0)
				continue;

			/* Track highest unique_id */
			if (entry.unique_id > fs->unique_id_gen)
				fs->unique_id_gen = entry.unique_id;

			/* Mark file blocks in bitmap */
			if (entry.flags == RPMB_ENT_FILE) {
				num_blocks = rpmb_blocks_for_size(entry.size);
				if (num_blocks > 0) {
					if (entry.start_addr >= RPMB_FAT_ENTRIES &&
					    entry.start_addr + num_blocks <= fs->total_blkcnt) {
						/* Check for overlap */
						next_set = bitmap_next_one(fs->bitmap,
							entry.start_addr + num_blocks, entry.start_addr);
						if (next_set < entry.start_addr + num_blocks) {
							EMSG("RPMB FS Corrupted: Overlapping blocks @ %s\n",
							     entry.filename);
						}
						bitmap_set(fs->bitmap, entry.start_addr, num_blocks);
						fs->idle_blkcnt -= num_blocks;
					} else {
						EMSG("RPMB FS Corrupted: File %s out of bounds\n",
						     entry.filename);
					}
				}
			}

			/* Copy to FAT cache */
			if (fs->fat_cache && idx < RPMB_FAT_CACHED)
				memcpy(&fs->fat_cache[idx], &entry, sizeof(entry));
		}
	}

	DMSG("RPMB init: total_blkcnt=%d, rel_wr_blkcnt=%d, idle_blkcnt=%d\n",
	     (int)fs->total_blkcnt, (int)fs->rel_wr_blkcnt, (int)fs->idle_blkcnt);

	ret = 0;  /* Success */

out:
	kfree(frames);

	if (ret == 0 && fs->fat_cache)
		IMSG("FAT cache initialized: %d entries (%zu bytes)\n",
			(int)RPMB_FAT_CACHED, RPMB_FAT_CACHED * sizeof(struct rpmb_fat_entry));

	return ret;
}
static int find_file_cb(struct rpmb_fs *fs, int idx,
			const struct rpmb_fat_entry *entry,
			struct fat_iter_ctx *ctx)
{
	if (entry->flags != RPMB_ENT_EMPTY &&
	    strncmp(entry->filename, ctx->name, RPMB_MAX_FILENAME) == 0) {
		if (ctx->out)
			memcpy(ctx->out, entry, sizeof(*ctx->out));
		return idx + 1;  /* Return idx+1 to distinguish from 0 */
	}
	return 0;
}

static int rpmb_fs_find_file(struct rpmb_fs *fs, const char *name,
			struct rpmb_fat_entry *out_entry)
{
	struct fat_iter_ctx ctx = { .name = name, .out = out_entry };
	int ret = rpmb_for_each_fat_entry(fs, 0, find_file_cb, &ctx);

	return ret > 0 ? ret - 1 : (ret < 0 ? ret : -ENOENT);
}

static int alloc_file_cb(struct rpmb_fs *fs, int idx,
			 const struct rpmb_fat_entry *entry,
			 struct fat_iter_ctx *ctx)
{
	return entry->flags == RPMB_ENT_EMPTY ? idx + 1 : 0;
}

static int rpmb_fs_alloc_file(struct rpmb_fs *fs)
{
	int ret = rpmb_for_each_fat_entry(fs, 0, alloc_file_cb, NULL);

	return ret > 0 ? ret - 1 : (ret < 0 ? ret : -ENOSPC);
}

/*
 * Check single FAT entry integrity (helper for rpmb_fs_integrity_check)
 */
static inline int rpmb_check_entry_integrity(
	struct rpmb_fs *fs, size_t idx,
	struct rpmb_fat_entry *entry, uint32_t *used_blocks)
{
#if defined(RPMB_FS_DEBUG_INTEGRITY)
	struct rpmb_frame *frames = NULL;
	struct rpmb_data_block *encrypted;
	uint8_t plaintext[RPMB_BLOCK_PAYLOAD];
	uint32_t blk = 0, num_blocks = 0;
	int ret = 0, error_count = 0;
	struct rpmb_file rf_temp = {0};
	struct rpmb_fat_entry entry_copy;

	if (entry->flags == RPMB_ENT_EMPTY)
		return 0;

	/* Basic validation */
	if (entry->flags != RPMB_ENT_FILE && entry->flags != RPMB_ENT_DIR) {
		EMSG("[%zu] Invalid flags: %d (name=%s)\n",
			idx, (int)entry->flags, entry->filename);
		return 1;
	}

	if (entry->flags == RPMB_ENT_DIR && \
		strlen(entry->filename) == 0) {
		EMSG("[%zu] Invalid dir name\n", idx);
		return 1;
	}

	/* Only files have blocks */
	if (entry->flags != RPMB_ENT_FILE)
		return 0;

	num_blocks = rpmb_blocks_for_size(entry->size);
	*used_blocks += num_blocks;

	if (num_blocks == 0)
		return 0;

	/* Check start_addr valid */
	if (entry->start_addr < RPMB_FAT_ENTRIES) {
		EMSG("[%zu] Invalid start_addr=%d (name=%s size=%d)\n",
		     idx, (int)entry->start_addr, entry->filename, (int)entry->size);
		return 1;
	}

	/* Check bitmap consistency */
	for (blk = 0; blk < num_blocks; blk++) {
		if (!bitmap_bit_isset(fs->bitmap, entry->start_addr + blk)) {
			EMSG("[%zu] Block %d not in bitmap (name=%s)\n",
			     idx, (int)(entry->start_addr + blk), entry->filename);
			error_count++;
			break;
		}
	}

	/* Read and verify GCM for all blocks */
	frames = kmalloc(num_blocks * sizeof(struct rpmb_frame));
	if (!frames) {
		EMSG("[%zu] Cannot alloc frames for integrity check\n", idx);
		return error_count > 0 ? error_count : 0;
	}

	ret = rpmb_read_frames(entry->start_addr, frames, num_blocks);
	if (ret != 0) {
		EMSG("[%zu] Read frames failed: %d (name=%s)\n",
			idx, ret, entry->filename);
		kfree(frames);
		return error_count + 1;
	}

	/* Try to decrypt each block (validates GCM auth) */
	for (blk = 0; blk < num_blocks; blk++) {
		encrypted = (struct rpmb_data_block *)frames[blk].data;

		/* Build minimal rpmb_file for decrypt */
		memset(&rf_temp, 0, sizeof(rf_temp));
		memcpy(&entry_copy, entry, sizeof(entry_copy));
		rf_temp.entry = &entry_copy;

		ret = mbedcrypto_aes_gcm_setkey(&rf_temp.gcm_ctx,
					 entry->fek, 128);
		if (ret != 0) {
			EMSG("[%zu] GCM setkey failed: %d (name=%s)\n",
				idx, ret, entry->filename);
			error_count++;
			mbedcrypto_aes_gcm_cleanup(&rf_temp.gcm_ctx);
			break;
		}

		ret = rpmb_file_decrypt_block(&rf_temp, entry->start_addr + blk,
					      encrypted, plaintext, RPMB_BLOCK_PAYLOAD);
		mbedcrypto_aes_gcm_cleanup(&rf_temp.gcm_ctx);

		if (ret != 0) {
			EMSG("[%zu] GCM auth FAILED at block %d (name=%s addr=%d version=%d)\n",
			     idx, (int)blk, entry->filename,
			     (int)(entry->start_addr + blk), (int)entry->version);
			EMSG("     fek=%02x%02x... iv=%02x%02x... uid=%08x\n",
			     entry->fek[0], entry->fek[1], entry->iv[0], entry->iv[1],
			     (unsigned int)entry->unique_id);
			error_count++;
			break;
		}
	}

	kfree(frames);
	memset(plaintext, 0, sizeof(plaintext));
	return error_count;
#else
	return 0;
#endif
}

/*
 * RPMB Filesystem Integrity Check (Debug/Diagnostic)
 */
#if defined(RPMB_FS_DEBUG_INTEGRITY)
static int integrity_cb(struct rpmb_fs *fs, int idx,
			const struct rpmb_fat_entry *entry,
			struct fat_iter_ctx *ctx)
{
	/* counter = error_count, skip_idx reused as used_blocks accumulator */
	ctx->counter += rpmb_check_entry_integrity(fs, idx,
		(struct rpmb_fat_entry *)entry, (uint32_t *)&ctx->skip_idx);
	return 0;
}
#endif

static void rpmb_fs_integrity_check(struct rpmb_fs *fs, const char *caller)
{
#if defined(RPMB_FS_DEBUG_INTEGRITY)
	struct fat_iter_ctx ctx = {0};  /* counter=errors, skip_idx=used_blocks */

	IMSG("=== RPMB Integrity Check: %s ===\n", caller);
	rpmb_for_each_fat_entry(fs, 0, integrity_cb, &ctx);

	if (ctx.counter > 0)
		EMSG("=== Integrity Check FAILED: %d errors (used_blocks=%d) ===\n",
			(int)ctx.counter, ctx.skip_idx);
	else
		IMSG("=== Integrity Check PASSED (used_blocks=%d) ===\n", ctx.skip_idx);
#endif
}

/* Truncate file to size 0 and free old blocks */
static int rpmb_truncate_file(struct rpmb_fs *fs,
	int fat_idx, struct rpmb_fat_entry *entry)
{
	int ret = 0;
	uint32_t num_blocks = 0;
	struct rpmb_write_checkpoint cp;
	num_blocks = rpmb_blocks_for_size(entry->size);

	rpmb_save_checkpoint(&cp, entry, 0);

	/* O_TRUNC: discard old data without CoW */
	entry->size = 0;
	entry->start_addr = 0;
	entry->version++;

	/*
	 * Write to RPMB and fat_cache atomically
	 * (rf->entry auto-synced via write-through)
	 */
	ret = rpmb_fs_write_fat_entry(fs, fat_idx, entry);
	if (ret != 0) {
		/* FAT update failed - restore in-memory state */
		rpmb_restore_checkpoint(&cp, entry, NULL);
		return ret;
	}

	/* Success: free old blocks */
	rpmb_fs_free_blocks(fs, cp.start_addr, num_blocks);
	return 0;
}

/*
 * Helper: Normalize path name for RPMBFS lookup
 * - Strips leading '/'
 * - Strips trailing '/' (unless root)
 */
static int rpmb_normalize_path(const char *path, char *buf, size_t bufsize)
{
	size_t i = 0, j = 0;

	/* 1. Skip all leading slashes */
	while (path[i] == '/')
		i++;

	/* 2. Copy and collapse slashes */
	while (path[i] != '\0' && j < bufsize - 1) {
		buf[j++] = path[i++];

		if (path[i-1] == '/') {
			while (path[i] == '/')
				i++;
		}
	}

	if (j >= bufsize - 1 && path[i] != '\0') {
		buf[0] = '\0';
		return -ENAMETOOLONG;
	}

	/* 3. Strip trailing slash (if strictly directory) */
	if (j > 0 && buf[j - 1] == '/')
		j--;

	buf[j] = '\0';
	return 0;
}

/*
 * Helper: Allocate/Initialize a rpmb_file structure
 * FAT: Uses cache pointer when available, falls back to entry_local otherwise.
 */
static struct rpmb_file *rpmb_file_init(struct rpmb_fs *fs,
	int fat_idx, struct rpmb_fat_entry *entry, int type)
{
	struct rpmb_file *rf = kzalloc(sizeof(*rf));

	if (!rf)
		return NULL;

	rf->refc = 1;
	rf->type = type;
	rf->fat_idx = fat_idx;

	/* Record open time for fstat (RPMB FAT doesn't store timestamps) */
	get_systime(&rf->open_time, NULL);

	/*
	 * Use zero-copy pointer to cache when available.
	 * Fall back to entry_local when cache disabled or file outside cache range.
	 */
	if (fs->fat_cache && fat_idx >= 0 && fat_idx < RPMB_FAT_CACHED) {
		/* Entry is in the cache, just point to it */
		rf->entry = &fs->fat_cache[fat_idx];
	} else {
		/* Fallback: copy to entry_local and point to it */
		if (entry)
			memcpy(&rf->entry_local, entry, sizeof(rf->entry_local));
		rf->entry = &rf->entry_local;
	}

	INIT_LIST_HEAD(&rf->node);
	return rf;
}

/*
 * Helper to process and format a RPMB FAT entry into dirent
 * Handles directory path filtering and calls fs_format_dirent
 *
 * Returns: Number of bytes written (>0) on success
 *          0 if entry should be skipped
 *          -ENOSPC if buffer is full
 */
static inline ssize_t rpmb_fill_dirent(
	const struct rpmb_fat_entry *entry,
	const char *dir_name, size_t dir_len,
	struct dirent **d_ptr, size_t *buflen,
	uint64_t off)
{
	const char *sub_name;
	uint8_t type = 0;

	if (entry->flags == RPMB_ENT_EMPTY ||
		entry->filename[0] == 0)
		return 0;

	/* Filter entries based on directory path */
	if (dir_len > 0) {
		if (strncmp(entry->filename, dir_name, dir_len) != 0 ||
			entry->filename[dir_len] != '/')
			return 0;
		sub_name = entry->filename + dir_len + 1;
	} else {
		sub_name = entry->filename;
	}

	/* Skip entry if it equals the directory name */
	if (*sub_name == 0)
		return 0;

	/* Skip subdirectories */
	if (strchr(sub_name, '/'))
		return 0;

	type = (entry->flags == RPMB_ENT_DIR) ? DT_DIR : DT_REG;
	return fs_format_dirent(d_ptr, buflen, sub_name, type, off);
}

static int rpmb_opendir(struct rpmb_fs *fs, struct file *f, const char *name)
{
	int idx = 0;
	struct rpmb_file *rf = NULL;
	struct rpmb_fat_entry entry;

	if ((f->flags & O_ACCMODE) != O_RDONLY)
		return -EISDIR;
	if (f->flags & (O_CREAT | O_TRUNC | O_APPEND))
		return -EISDIR;

	if (IS_ROOT_DIR(name)) {
		/* Root has no FAT entry (fat_idx = RPMB_ROOT_IDX) */
		rf = rpmb_file_init(fs, RPMB_ROOT_IDX, NULL, DT_DIR);
		if (!rf)
			return -ENOMEM;
		f->priv = rf;
		return 0;
	}

	/* Check if file is already open */
	list_for_each_entry(rf, &fs->open_files, node) {
		if (strncmp(rf->entry->filename, name, RPMB_MAX_FILENAME) == 0) {
			if (rf->type != DT_DIR)
				return -ENOTDIR;
			rf->refc++;
			f->priv = rf;
			return 0;
		}
	}

	idx = rpmb_fs_find_file(fs, name, &entry);
	if (idx < 0)
		return -ENOENT;

	if (entry.flags != RPMB_ENT_DIR)
		return -ENOTDIR;

	rf = rpmb_file_init(fs, idx, &entry, DT_DIR);
	if (!rf)
		return -ENOMEM;

	/* Track open objects (used for path reuse and deferred deletion semantics) */
	list_add(&rf->node, &fs->open_files);

	f->priv = rf;
	return 0;
}

static int rpmb_openfile(struct rpmb_fs *fs, struct file *f, const char *name)
{
	struct rpmb_file *rf = NULL;
	int ret = 0, idx = -1, allocatedidx = -1;
	struct rpmb_fat_entry entry;

	if (IS_ROOT_DIR(name))
		return -EISDIR;

	/* Check if file is already open */
	list_for_each_entry(rf, &fs->open_files, node) {
		if (strncmp(rf->entry->filename, name, RPMB_MAX_FILENAME) == 0) {
			if (rf->type == DT_DIR)
				return -EISDIR;

			if ((f->flags & O_CREAT) && (f->flags & O_EXCL))
				return -EEXIST;

			if (f->flags & O_TRUNC) {
				/* Perform truncation on already-open file */
				ret = rpmb_truncate_file(fs, rf->fat_idx, rf->entry);
				if (ret != 0)
					return ret;
			}
			rf->refc++;
			f->priv = rf;
			return 0;
		}
	}

	idx = rpmb_fs_find_file(fs, name, &entry);
	if (idx < 0) {
		if (!(f->flags & O_CREAT))
			return -ENOENT;

		allocatedidx = rpmb_fs_alloc_file(fs);
		if (allocatedidx < 0)
			return allocatedidx;

		idx = allocatedidx;
		memset(&entry, 0, sizeof(struct rpmb_fat_entry));
		strlcpy(entry.filename, name, RPMB_MAX_FILENAME);
		entry.flags = RPMB_ENT_FILE;
		/* Generate per-file FEK and IV */
		prng(entry.fek, sizeof(entry.fek));
		prng(entry.iv, sizeof(entry.iv));
		entry.unique_id = ++fs->unique_id_gen;
	} else {
		if (f->flags & O_EXCL)
			return -EEXIST;

		if (entry.flags == RPMB_ENT_DIR)
			return -EISDIR;

		if (f->flags & O_TRUNC) {
			ret = rpmb_truncate_file(fs, idx, &entry);
			if (ret != 0)
				return ret;
		}
	}

	rf = rpmb_file_init(fs, idx, &entry, DT_REG);
	if (!rf)
		return -ENOMEM;

	/* Initialize GCM context with file's encryption key */
	ret = mbedcrypto_aes_gcm_setkey(&rf->gcm_ctx, entry.fek, 128);
	if (ret != 0) {
		mbedcrypto_aes_gcm_cleanup(&rf->gcm_ctx);
		kfree(rf);
		return ret;
	}
	if (allocatedidx >= 0) {
		ret = rpmb_fs_write_fat_entry(fs, allocatedidx, &entry);
		if (ret != 0) {
			mbedcrypto_aes_gcm_cleanup(&rf->gcm_ctx);
			kfree(rf);
			return ret;
		}
		rpmb_fs_integrity_check(fs, "rpmb_open(create)");
	}

	/* Track open objects (used for path reuse and deferred deletion semantics) */
	list_add(&rf->node, &fs->open_files);

	f->priv = rf;
	return 0;
}

static int rpmb_open(struct file *f, mode_t mode, void *arg)
{
	struct rpmb_fs *fs = file2rpmb(f);
	char name[RPMB_MAX_FILENAME];
	int ret = 0;

	/* Normalize path: strip leading and trailing slashes */
	ret = rpmb_normalize_path(f->path, name, RPMB_MAX_FILENAME);
	if (ret != 0)
		return ret;

	DMSG("opening %s flags %x\n", name, f->flags);

	ret = mutex_lock_interruptible(&fs->mlock);
	if (ret != 0)
		return ret;

	if ((f->flags & O_DIRECTORY) || fspath_isdir(f->path))
		ret = rpmb_opendir(fs, f, name);
	else {
		ret = rpmb_openfile(fs, f, name);
		if (ret == -EISDIR)
			ret = rpmb_opendir(fs, f, name);
	}

	mutex_unlock(&fs->mlock);
	return ret;
}

static int rpmb_close(struct file *f)
{
	struct rpmb_fs *fs = file2rpmb(f);
	struct rpmb_file *rf = f->priv;
	uint32_t num_blocks = 0;
	uint32_t start_addr = 0;

	if (rf) {
		if (mutex_lock_interruptible(&fs->mlock) != 0)
			return -EINTR;

		if (--rf->refc == 0) {
			list_del(&rf->node);
			if (rf->type == DT_REG)
				mbedcrypto_aes_gcm_cleanup(&rf->gcm_ctx);

			/* POSIX deferred deletion: mark EMPTY (+ free blocks for files) */
			if (rf->deleted && rf->fat_idx >= 0) {
				struct rpmb_fat_entry empty_entry = {0};

				empty_entry.flags = RPMB_ENT_EMPTY;

				start_addr = rf->entry->start_addr;
				num_blocks = rpmb_blocks_for_size(rf->entry->size);
				if (rpmb_fs_write_fat_entry(fs, rf->fat_idx,
						&empty_entry) == 0) {
					if (rf->type == DT_REG)
						rpmb_fs_free_blocks(fs,
							start_addr, num_blocks);
					rpmb_fs_integrity_check(fs,
						"rpmb_close(deferred_delete)");
				}
			}

			/* Securely clear key material */
			memset(rf, 0, sizeof(*rf));
			kfree(rf);
		}

		mutex_unlock(&fs->mlock);
	}

	return 0;
}

static ssize_t rpmb_read(struct file *f, void *buf, size_t cnt)
{
	struct rpmb_fs *fs = file2rpmb(f);
	struct rpmb_file *rf = f->priv;
	struct rpmb_fat_entry *entry = NULL;
	struct rpmb_frame *frames = NULL;
	struct rpmb_data_block *encrypted_block = NULL;
	uint8_t plaintext[RPMB_BLOCK_PAYLOAD];
	uint32_t blk_idx = 0, start_blk = 0, end_blk = 0;
	size_t i = 0, read_sz = 0;
	size_t byte_off = 0, copy_sz = 0;
	size_t total_blocks = 0, max_batch = 0, cur_batch = 0;
	int ret = 0;

	ret = mutex_lock_interruptible(&fs->mlock);
	if (ret != 0)
		return ret;

	entry = rf->entry;

	DMSG("READ: pos=%d rdbytes=%zu filesz=%d version=%d\n",
		(int)f->pos, cnt, (int)entry->size, (int)entry->version);

	if (entry->flags != RPMB_ENT_FILE) {
		mutex_unlock(&fs->mlock);
		return -EBADF;
	}

	if (f->pos + cnt < f->pos) {
		mutex_unlock(&fs->mlock);
		return -EINVAL;
	}

	if (f->pos >= entry->size) {
		mutex_unlock(&fs->mlock);
		return 0;
	}

	if (cnt > entry->size - f->pos)
		cnt = entry->size - f->pos;

	/*
	 * Optimize: Batch read RPMB frames to reduce RPC calls
	 * Allocate rpmb_frame buffer (larger but eliminates extra copy)
	 */
	start_blk = f->pos / RPMB_BLOCK_PAYLOAD;
	end_blk = (f->pos + cnt - 1) / RPMB_BLOCK_PAYLOAD;
	total_blocks = end_blk - start_blk + 1;

	/* Allocate buffer for batched RPMB frames (includes encrypted data + MAC info) */
	max_batch = min(total_blocks, (size_t)RPMB_READ_BATCH);
	frames = kmalloc(max_batch * sizeof(struct rpmb_frame));
	if (!frames && max_batch > 1) {
		max_batch = 1;
		frames = kmalloc(sizeof(struct rpmb_frame));
	}
	if (!frames) {
		mutex_unlock(&fs->mlock);
		return -ENOMEM;
	}

	while (read_sz < cnt) {
		cur_batch = min((size_t)(end_blk - start_blk + 1), max_batch);

		/* Batch read all frames (handles TOCTOU internally, no extra copy) */
		ret = rpmb_read_frames(entry->start_addr + start_blk, frames, cur_batch);
		if (ret != 0) {
			EMSG("READ: batch read failed ret=%d\n", ret);
			goto out;
		}

		/* Decrypt and copy each block */
		for (i = 0; i < cur_batch && read_sz < cnt; i++) {
			blk_idx = start_blk + i;

			/* Calculate offset and copy size for this block */
			byte_off = (f->pos + read_sz) % RPMB_BLOCK_PAYLOAD;
			copy_sz = RPMB_BLOCK_PAYLOAD - byte_off;
			if (copy_sz > cnt - read_sz)
				copy_sz = cnt - read_sz;

			/* Point to encrypted data in frame (frame.data contains rpmb_data_block) */
			encrypted_block = (struct rpmb_data_block *)frames[i].data;
			ret = rpmb_file_decrypt_block(rf, entry->start_addr + blk_idx,
						  encrypted_block, plaintext, RPMB_BLOCK_PAYLOAD);
			if (ret != 0) {
				EMSG("READ: decrypt failed ret=%d\n", ret);
				goto out;
			}

			/* Copy decrypted data to user buffer */
			memcpy(buf + read_sz, plaintext + byte_off, copy_sz);
			read_sz += copy_sz;
		}

		start_blk += cur_batch;
	}

	f->pos += read_sz;
	DMSG("READ: returned %zu bytes, new pos=%d\n", read_sz, (int)f->pos);
	ret = read_sz;

out:
	kfree(frames);
	memset(plaintext, 0, sizeof(plaintext));
	mutex_unlock(&fs->mlock);
	return (ret < 0 && read_sz > 0) ? (ssize_t)read_sz : ret;
}

static ssize_t rpmb_write(struct file *f, const void *buf, size_t cnt)
{
	struct rpmb_fs *fs = file2rpmb(f);
	struct rpmb_file *rf = f->priv;
	struct rpmb_fat_entry *entry = NULL;
	struct rpmb_data_block *encrypted_block = NULL;
	uint32_t blk_idx = 0, batch_start_idx = 0;
	uint32_t new_size = 0, new_blocks = 0, old_blocks = 0;
	size_t byte_off = 0, copy_sz = 0;
	uint32_t max_batch_blocks = RPMB_WRITE_BATCH, batch_count = 0;
	size_t new_size_sz = 0, write_end = 0, written_sz = 0;
	bool fat_committed = false, force_relocate = false;
	uint32_t alloc_start = 0, alloc_blocks = 0, old_start = 0;
	int ret = 0;
	struct rpmb_write_checkpoint checkpoint = {0};
	struct rpmb_data_block *batch_blocks = NULL;
	struct rpmb_frame *frame = NULL;
	uint8_t decrypted[RPMB_BLOCK_PAYLOAD];

	if (cnt == 0)
		return 0;

	if (f->pos + cnt < f->pos)
		return -EFBIG;

	frame = kmalloc(sizeof(*frame));
	if (!frame)
		return -ENOMEM;

	ret = mutex_lock_interruptible(&fs->mlock);
	if (ret != 0) {
		kfree(frame);
		return ret;
	}

	entry = rf->entry;

	if (entry->flags != RPMB_ENT_FILE) {
		ret = -EBADF;
		goto out;
	}

	/* Handle O_APPEND: always write to end of file */
	if (f->flags & O_APPEND)
		f->pos = entry->size;

	DMSG("WRITE: pos=%d wrbytes=%zu filesz=%d version=%d\n",
		(int)f->pos, cnt, (int)entry->size, (int)entry->version);

	write_end = f->pos + cnt;
	new_size_sz = max(write_end, (size_t)entry->size);

	if (new_size_sz > UINT32_MAX) {
		ret = -EFBIG;
		goto out;
	}
	new_size = new_size_sz;

	/* Save checkpoint EARLY - before any modifications */
	rpmb_save_checkpoint(&checkpoint, entry, f->pos);

	/* Calculate old_blocks (preserve during CoW) and new_blocks (final size) */
	old_blocks = rpmb_blocks_for_size(entry->size);
	new_blocks = rpmb_blocks_for_size(new_size);

	/* Decide strategy: force relocation only when overwrite is not atomic */
	if (f->pos < entry->size && write_end <= entry->size) {
		if (!rpmb_write_is_atomic(fs, f->pos, cnt)) {
			DMSG("WRITE: Non-atomic overwrite, using CoW relocation\n");
			force_relocate = true;
		}
	}

	/* Allocate batch buffer early for potential reuse in CoW */
	batch_blocks = kmalloc(max_batch_blocks * sizeof(*batch_blocks));
	if (!batch_blocks && max_batch_blocks > 1) {
		max_batch_blocks = 1;
		batch_blocks = kmalloc(sizeof(*batch_blocks));
	}
	if (!batch_blocks) {
		ret = -ENOMEM;
		goto out;
	}

	/* Allocate/extend/relocate file blocks using unified helper */
	if (new_blocks > 0 && (old_blocks == 0 || new_blocks > old_blocks || force_relocate)) {
		ret = rpmb_alloc_or_extend(rf, fs, new_blocks,
			force_relocate, batch_blocks, max_batch_blocks,
			&alloc_start, &alloc_blocks, &old_start);
		if (ret != 0)
			goto out;
	}

	/* Fill sparse file hole [checkpoint.size, f->pos) with zeros */
	if (f->pos > checkpoint.size) {
		ret = rpmb_fill_hole_range(rf, entry->start_addr,
				checkpoint.size, f->pos, &fs->write_counter);
		if (ret != 0)
			goto out;
	}

	/* RMW loop: batch buffer already allocated early (reused by CoW if needed) */
	while (written_sz < cnt) {
		blk_idx = (f->pos + written_sz) / RPMB_BLOCK_PAYLOAD;
		byte_off = (f->pos + written_sz) % RPMB_BLOCK_PAYLOAD;
		copy_sz = RPMB_BLOCK_PAYLOAD - byte_off;
		if (copy_sz > cnt - written_sz)
			copy_sz = cnt - written_sz;

		/* Read-Modify-Write for partial block */
		if (byte_off != 0 || copy_sz != RPMB_BLOCK_PAYLOAD) {
			/* Flush pending batch before RMW */
			ret = rpmb_flush_batch(entry->start_addr + batch_start_idx,
					       batch_blocks, &batch_count, &fs->write_counter);
			if (ret != 0)
				goto out;

			if (blk_idx < old_blocks) {
				/* Block exists: read for RMW */
				ret = rpmb_read_frames(entry->start_addr + blk_idx, frame, 1);
				if (ret != 0)
					goto out;
				encrypted_block = (struct rpmb_data_block *)frame->data;
				ret = rpmb_file_decrypt_block(rf, entry->start_addr + blk_idx,
							encrypted_block, decrypted, RPMB_BLOCK_PAYLOAD);
				if (ret != 0)
					goto out;
			} else {
				/* Block doesn't exist: zero-init */
				memset(decrypted, 0, RPMB_BLOCK_PAYLOAD);
			}
			memcpy(decrypted + byte_off, (uint8_t *)buf + written_sz, copy_sz);
		} else {
			/* Full block: direct copy */
			memcpy(decrypted, (uint8_t *)buf + written_sz, RPMB_BLOCK_PAYLOAD);
		}

		/* Encrypt block into batch buffer */
		ret = rpmb_file_encrypt_block(rf, entry->start_addr + blk_idx,
				decrypted, RPMB_BLOCK_PAYLOAD, &batch_blocks[batch_count]);
		if (ret != 0)
			goto out;

		if (batch_count == 0)
			batch_start_idx = blk_idx;
		batch_count++;

		/* Flush if buffer full or last block */
		if (batch_count >= max_batch_blocks || written_sz + copy_sz >= cnt) {
			ret = rpmb_flush_batch(entry->start_addr + batch_start_idx,
					  batch_blocks, &batch_count, &fs->write_counter);
			if (ret != 0)
				goto out;
		}

		written_sz += copy_sz;
	}

	/* Update file metadata */
	f->pos += written_sz;
	if (f->pos > entry->size)
		entry->size = f->pos;
	entry->version++;  /* Increment version */

	/* Single atomic FAT write */
	ret = rpmb_fs_write_fat_entry(fs, rf->fat_idx, entry);
	if (ret != 0) {
		/* FAT commit failed - rollback to checkpoint */
		EMSG("RPMB Write: FAT commit failed %d\n", ret);

		/* Free newly allocated blocks (relocation or in-place extension) */
		if (alloc_blocks > 0)
			rpmb_fs_free_blocks(fs, alloc_start, alloc_blocks);

		/* Rollback in-memory state */
		rpmb_restore_checkpoint(&checkpoint, entry, &f->pos);

		ret = -EIO;
		/* Skip general cleanup at 'out' - already handled here */
		fat_committed = true;  /* Prevent double-cleanup at out */
		goto out;
	}

	/* FAT committed successfully - now safe to free old blocks if relocated */
	fat_committed = true;
	if (old_start != 0 && old_start != entry->start_addr)
		rpmb_fs_free_blocks(fs, old_start, old_blocks);

	ret = written_sz;

out:
	/* Clean up batch buffer */
	kfree(batch_blocks);

	/* Error cleanup: free new blocks if CoW failed before FAT commit */
	if (ret < 0 && !fat_committed) {
		/* Free newly allocated blocks if any */
		if (alloc_blocks > 0)
			rpmb_fs_free_blocks(fs, alloc_start, alloc_blocks);
		/* Ensure in-memory state reflects rollback */
		rpmb_restore_checkpoint(&checkpoint, entry, &f->pos);
	}

	memset(decrypted, 0, sizeof(decrypted));

	rpmb_fs_integrity_check(fs, "rpmb_write");
	mutex_unlock(&fs->mlock);
	kfree(frame);
	return ret;
}

static int rpmb_ftruncate(struct file *f, off_t length)
{
	struct rpmb_fs *fs = file2rpmb(f);
	struct rpmb_file *rf = f->priv;
	struct rpmb_fat_entry *entry = NULL;
	uint32_t old_blocks = 0, new_blocks = 0, new_length = 0;
	uint32_t old_start = 0, alloc_start = 0, alloc_blocks = 0;
	struct rpmb_write_checkpoint checkpoint = {0};
	int ret = 0;
	bool committed = false;

	if (length < 0)
		return -EINVAL;
	if ((uint64_t)length > UINT32_MAX)
		return -EFBIG;
	new_length = length;

	ret = mutex_lock_interruptible(&fs->mlock);
	if (ret != 0)
		return ret;

	entry = rf->entry;

	if (entry->flags != RPMB_ENT_FILE) {
		ret = -EBADF;
		goto out;
	}

	if (new_length == entry->size) {
		ret = 0;
		goto out;
	}

	/* Calculate blocks using payload size */
	old_blocks = rpmb_blocks_for_size(entry->size);
	new_blocks = rpmb_blocks_for_size(new_length);

	/* Save checkpoint for rollback (pos is irrelevant for ftruncate) */
	rpmb_save_checkpoint(&checkpoint, entry, 0);

	if (new_blocks > old_blocks) {
		/* Expansion: use unified helper for alloc/extend/relocate */
		ret = rpmb_alloc_or_extend(rf, fs, new_blocks,
			false, NULL, 0, &alloc_start, &alloc_blocks, &old_start);
		if (ret != 0)
			goto out;

		/* Zero-fill logical gap [old_size, new_length) for POSIX semantics */
		ret = rpmb_fill_hole_range(rf, entry->start_addr,
				checkpoint.size, new_length, &fs->write_counter);
		if (ret != 0)
			goto out;
	}
	/* Shrink case: defer free until after FAT update */

	entry->size = new_length;
	entry->version++;  /* Increment version for integrity */
	ret = rpmb_fs_write_fat_entry(fs, rf->fat_idx, entry);
	if (ret != 0)
		goto out;

	committed = true;

	/* Commit success: free old blocks if relocated and/or tail blocks if shrunk */
	if (old_start != 0 && old_start != entry->start_addr)
		rpmb_fs_free_blocks(fs, old_start, old_blocks);
	if (new_blocks < old_blocks)
		rpmb_fs_free_blocks(fs, entry->start_addr + new_blocks,
				    old_blocks - new_blocks);

out:
	/* Clean up on error before FAT commit */
	if (ret < 0 && !committed) {
		if (alloc_blocks > 0)
			rpmb_fs_free_blocks(fs, alloc_start, alloc_blocks);
		rpmb_restore_checkpoint(&checkpoint, entry, NULL);
	}
	rpmb_fs_integrity_check(fs, "rpmb_ftruncate");
	mutex_unlock(&fs->mlock);
	return ret;
}

static off_t rpmb_lseek(struct file *f, off_t offset, int whence)
{
	struct rpmb_fs *fs = file2rpmb(f);
	struct rpmb_file *rf = f->priv;
	struct rpmb_fat_entry *entry;
	off_t ret = -1;

	if (mutex_lock_interruptible(&fs->mlock) != 0)
		return -EINTR;

	entry = rf->entry;

	if (entry->flags == RPMB_ENT_EMPTY &&
		!IS_ROOT_IDX(rf->fat_idx)) {
		ret = -EBADF;
		goto out;
	}

	/* Directories: only SEEK_SET allowed (for seekdir/rewinddir) */
	if (rf->type == DT_DIR) {
		if (whence != SEEK_SET) {
			ret = -EINVAL;
			goto out;
		}
		/* Allow setting position for readdir traversal */
		ret = offset;
		goto check_pos;
	}

	switch (whence) {
	case SEEK_SET:
		ret = offset;
		break;
	case SEEK_CUR:
		ret = f->pos + offset;
		break;
	case SEEK_END:
		ret = entry->size + offset;
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

check_pos:
	/* Allow seeking beyond EOF for files; validate directory position */
	if (ret < 0) {
		ret = -EINVAL;
		goto out;
	}

	/* For directories, validate position is within FAT entry range */
	if (rf->type == DT_DIR && ret > RPMB_FAT_ENTRIES) {
		ret = -EINVAL;
		goto out;
	}

	f->pos = ret;

out:
	mutex_unlock(&fs->mlock);
	return ret;
}

static int rpmb_fstat(struct file *f, struct stat *st)
{
	struct rpmb_fs *fs = file2rpmb(f);
	struct rpmb_file *rf = f->priv;
	struct rpmb_fat_entry *entry = NULL;

	if (mutex_lock_interruptible(&fs->mlock) != 0)
		return -EINTR;

	entry = rf->entry;

	memset(st, 0, sizeof(*st));
	st->st_blksize = RPMB_BLOCK_PAYLOAD;

	if (rf->type != DT_DIR) {
		st->st_mode = S_IFREG;
		st->st_size = entry->size;
		st->st_blocks = rpmb_blocks_for_size(entry->size);
	} else {
		st->st_mode = S_IFDIR;
		st->st_blocks = 1;
		st->st_size = st->st_blksize;
	}

	/* RPMB FAT entries don't store timestamps; use mount time or 0 */
	st->st_atime = rf->open_time;
	st->st_mtime = rf->open_time;
	st->st_ctime = rf->open_time;

	mutex_unlock(&fs->mlock);
	return 0;
}

static int rpmb_rename(struct file_system *pfs,
	const char *oldpath, const char *newpath)
{
	struct rpmb_fs *fs = pfs->priv;
	int old_idx = -1, new_idx = -1, ret = 0;
	struct rpmb_file *rf;
	uint32_t target_start_addr = 0;
	uint32_t target_blocks = 0;
	bool isdir = false;
	int target_has_open_refs = 0;
	struct rpmb_file *target_rf = NULL;
	struct {
		char oldname[RPMB_MAX_FILENAME];
		char newname[RPMB_MAX_FILENAME];
		struct rpmb_fat_entry old_entry;
		struct rpmb_fat_entry new_entry;
		struct rpmb_fat_entry target_entry_orig;
	} *ctx;

	ctx = kmalloc(sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;

	ret = rpmb_normalize_path(oldpath, ctx->oldname, sizeof(ctx->oldname));
	if (ret != 0)
		goto free_ctx;

	ret = rpmb_normalize_path(newpath, ctx->newname, sizeof(ctx->newname));
	if (ret != 0)
		goto free_ctx;

	ret = mutex_lock_interruptible(&fs->mlock);
	if (ret != 0)
		goto free_ctx;

	if (IS_ROOT_DIR(ctx->oldname) || IS_ROOT_DIR(ctx->newname)) {
		ret = -EINVAL;
		goto out;
	}

	DMSG("rename %s -> %s\n", ctx->oldname, ctx->newname);

	old_idx = rpmb_fs_find_file(fs, ctx->oldname, &ctx->old_entry);
	if (old_idx < 0) {
		ret = -ENOENT;
		goto out;
	}

	if (strnlen(ctx->newname, RPMB_MAX_FILENAME) >= RPMB_MAX_FILENAME) {
		ret = -ENAMETOOLONG;
		goto out;
	}

	/* POSIX: target path ending with '/' must be a directory */
	if (fspath_isdir(ctx->newname) && (ctx->old_entry.flags != RPMB_ENT_DIR)) {
		ret = -ENOTDIR;
		goto out;
	}

	/* Now check if target exists */
	new_idx = rpmb_fs_find_file(fs, ctx->newname, &ctx->new_entry);
	if (new_idx >= 0) {
		target_start_addr = ctx->new_entry.start_addr;
		target_blocks = rpmb_blocks_for_size(ctx->new_entry.size);
		isdir = ctx->new_entry.flags == RPMB_ENT_DIR;

		ctx->target_entry_orig = ctx->new_entry;

		/* POSIX: Cannot rename file over directory or vice versa */
		if (ctx->old_entry.flags != ctx->new_entry.flags) {
			ret = isdir ? -EISDIR : -ENOTDIR;
			goto out;
		}

		/* POSIX: If both are directories, target must be empty */
		if (isdir) {
			ret = rpmb_fs_is_dir_empty(fs, ctx->newname, new_idx);
			if (ret != 0)
				goto out;  /* Not empty or error */
		}

		/*
		 * If target is open, defer deletion: unlink it (clear name) but keep flags.
		 * Actual deletion (mark EMPTY + free blocks) must happen on last close.
		 */
		list_for_each_entry(rf, &fs->open_files, node) {
			if (rf->fat_idx == new_idx) {
				target_has_open_refs = 1;
				target_rf = rf;
				break;
			}
		}

		/* Step 1: Delete target path entry */
		ctx->new_entry.filename[0] = 0;
		if (!target_has_open_refs)
			ctx->new_entry.flags = RPMB_ENT_EMPTY;
		ret = rpmb_fs_write_fat_entry(fs, new_idx, &ctx->new_entry);
		if (ret != 0)
			goto out;

		if (target_has_open_refs && target_rf) {
			target_rf->deleted = 1;
			/* Ensure pathname lookup won't match for uncached entries */
			target_rf->entry->filename[0] = 0;
		}

		/* Step 2: Rename source entry */
		strlcpy(ctx->old_entry.filename, ctx->newname, RPMB_MAX_FILENAME);
		ret = rpmb_fs_write_fat_entry(fs, old_idx, &ctx->old_entry);
		if (ret != 0) {
			EMSG("RPMB rename: source rename failed after target deleted\n");
			/* Best-effort rollback of target deletion to avoid state drift */
			if (rpmb_fs_write_fat_entry(fs, new_idx,
					&ctx->target_entry_orig) == 0) {
				if (target_rf) {
					target_rf->deleted = 0;
					memcpy(target_rf->entry, &ctx->target_entry_orig,
						sizeof(*target_rf->entry));
				}
			}
			goto out;
		}

		if (old_idx >= RPMB_FAT_CACHED) {
			list_for_each_entry(rf, &fs->open_files, node) {
				if (rf->fat_idx == old_idx) {
					strlcpy(rf->entry->filename, ctx->newname,
						RPMB_MAX_FILENAME);
					break;
				}
			}
		}

		/*
		 * Free blocks of the overwritten file.
		 * If target was open, freeing is deferred until close.
		 */
		if (!target_has_open_refs && !isdir)
			rpmb_fs_free_blocks(fs, target_start_addr, target_blocks);

		/* Step 3: If source is a directory, rename all children */
		if (isdir) {
			ret = rpmb_fs_rename_dir_children(fs, ctx->oldname,
				ctx->newname);
			if (ret != 0) {
				EMSG("RPMB rename: failed to rename directory children\n");
				goto out;
			}
		}
		goto out;
	}

	/* Simple rename (target does not exist) */
	strlcpy(ctx->old_entry.filename, ctx->newname, RPMB_MAX_FILENAME);
	ret = rpmb_fs_write_fat_entry(fs, old_idx, &ctx->old_entry);

	/*
	 * Cache already updated by rpmb_fs_write_fat_entry.
	 * Only need to update rf->entry_local for files outside cache.
	 */
	if (ret == 0 && old_idx >= RPMB_FAT_CACHED) {
		list_for_each_entry(rf, &fs->open_files, node) {
			if (rf->fat_idx == old_idx) {
				strlcpy(rf->entry->filename, ctx->newname,
					RPMB_MAX_FILENAME);
				break;
			}
		}
	}

	/* If source is a directory, rename all children (regardless of cache location) */
	if (ret == 0 && ctx->old_entry.flags == RPMB_ENT_DIR) {
		ret = rpmb_fs_rename_dir_children(fs, ctx->oldname, ctx->newname);
		if (ret != 0) {
			EMSG("RPMB rename: failed to rename directory children\n");
			goto out;
		}
	}

out:
	rpmb_fs_integrity_check(fs, "rpmb_rename");
	mutex_unlock(&fs->mlock);
free_ctx:
	kfree(ctx);
	return ret;
}

static int rpmb_unlink(struct file_system *pfs, const char *path)
{
	struct rpmb_fs *fs = pfs->priv;
	struct rpmb_fat_entry entry;
	char name[RPMB_MAX_FILENAME];
	int idx = -1, ret = 0;
	uint32_t start_addr = 0;
	uint32_t num_blocks = 0;
	struct rpmb_file *rf = NULL;
	int has_open_refs = 0;

	ret = rpmb_normalize_path(path, name, sizeof(name));
	if (ret != 0)
		return ret;

	ret = mutex_lock_interruptible(&fs->mlock);
	if (ret != 0)
		return ret;

	if (IS_ROOT_DIR(name)) {
		ret = -EISDIR;
		goto out;
	}

	DMSG("unlinking %s\n", name);

	idx = rpmb_fs_find_file(fs, name, &entry);
	if (idx < 0) {
		ret = -ENOENT;
		goto out;
	}

	DMSG("found idx=%d %s\n", idx, entry.filename);

	if (entry.flags == RPMB_ENT_DIR) {
		ret = -EISDIR;
		goto out;
	}

	/*
	 * POSIX semantics: Check if file is currently open.
	 * If open, mark as deleted but defer actual deletion until close.
	 * Prevent new opens by clearing the pathname in FAT.
	 */
	list_for_each_entry(rf, &fs->open_files, node) {
		if (rf->fat_idx == idx && rf->type == DT_REG) {
			has_open_refs = 1;
			break;
		}
	}

	entry.filename[0] = 0;

	if (has_open_refs) {
		/* Open fds exist: clear filename, keep flags=FILE */
		ret = rpmb_fs_write_fat_entry(fs, idx, &entry);
		if (ret == 0 && rf) {
			rf->deleted = 1;
			/* Ensure pathname lookup won't match for uncached entries */
			rf->entry->filename[0] = 0;
		}
	} else {
		/*
		 * No open references:
		 * - Mark entry as EMPTY (FAT slot becomes reusable)
		 * - Free blocks immediately
		 */
		entry.flags = RPMB_ENT_EMPTY;
		start_addr = entry.start_addr;
		num_blocks = rpmb_blocks_for_size(entry.size);
		ret = rpmb_fs_write_fat_entry(fs, idx, &entry);
		if (ret == 0)
			rpmb_fs_free_blocks(fs, start_addr, num_blocks);
	}

out:
	rpmb_fs_integrity_check(fs, "rpmb_unlink");
	mutex_unlock(&fs->mlock);
	return ret;
}

static int rpmb_mkdir(struct file_system *pfs, const char *path, mode_t mode)
{
	struct rpmb_fs *fs = pfs->priv;
	struct rpmb_fat_entry entry;
	char name[RPMB_MAX_FILENAME];
	int idx = -1, ret = 0;

	ret = rpmb_normalize_path(path, name, sizeof(name));
	if (ret != 0)
		return ret;

	ret = mutex_lock_interruptible(&fs->mlock);
	if (ret != 0)
		return ret;

	if (IS_ROOT_DIR(name)) {
		ret = -EINVAL;
		goto out;
	}

	idx = rpmb_fs_find_file(fs, name, NULL);
	if (idx >= 0) {
		ret = -EEXIST;
		goto out;
	}

	idx = rpmb_fs_alloc_file(fs);
	if (idx < 0) {
		ret = idx;
		goto out;
	}

	memset(&entry, 0, sizeof(struct rpmb_fat_entry));
	strlcpy(entry.filename, name, RPMB_MAX_FILENAME);
	entry.flags = RPMB_ENT_DIR;
	entry.unique_id = ++fs->unique_id_gen;

	ret = rpmb_fs_write_fat_entry(fs, idx, &entry);

out:
	rpmb_fs_integrity_check(fs, "rpmb_mkdir");
	mutex_unlock(&fs->mlock);
	return ret;
}

static int rpmb_rmdir(struct file_system *pfs, const char *path)
{
	struct rpmb_fs *fs = pfs->priv;
	struct rpmb_fat_entry entry;
	char name[RPMB_MAX_FILENAME];
	int idx = -1, ret = 0;
	int has_open_refs = 0;
	struct rpmb_file *open_rf = NULL;

	ret = rpmb_normalize_path(path, name, sizeof(name));
	if (ret != 0)
		return ret;

	ret = mutex_lock_interruptible(&fs->mlock);
	if (ret != 0)
		return ret;

	/* Root directory cannot be removed */
	if (IS_ROOT_DIR(name)) {
		ret = -EBUSY;
		goto out;
	}

	DMSG("rmdir %s\n", name);

	idx = rpmb_fs_find_file(fs, name, &entry);
	if (idx < 0) {
		ret = -ENOENT;
		goto out;
	}

	if (entry.flags != RPMB_ENT_DIR) {
		ret = -ENOTDIR;
		goto out;
	}

	/* Check if directory is empty */
	ret = rpmb_fs_is_dir_empty(fs, name, idx);
	if (ret != 0)
		goto out;

	/*
	 * POSIX allows rmdir on open directories.
	 * If directory is open, it remains accessible until close.
	 * New lookups must fail immediately.
	 */
	list_for_each_entry(open_rf, &fs->open_files, node) {
		if (open_rf->fat_idx == idx && open_rf->type == DT_DIR) {
			has_open_refs = 1;
			break;
		}
	}

	entry.filename[0] = 0;
	if (has_open_refs) {
		/* Defer deletion until last close: keep flags=DIR but remove pathname */
		ret = rpmb_fs_write_fat_entry(fs, idx, &entry);
		if (ret == 0 && open_rf) {
			open_rf->deleted = 1;
			open_rf->entry->filename[0] = 0;
		}
	} else {
		entry.flags = RPMB_ENT_EMPTY;
		ret = rpmb_fs_write_fat_entry(fs, idx, &entry);
	}

out:
	rpmb_fs_integrity_check(fs, "rpmb_rmdir");
	mutex_unlock(&fs->mlock);
	return ret;
}

static int rpmb_ioctl(struct file *f, int cmd, unsigned long arg)
{
	switch (cmd) {
	case RPMB_IOC_PROGRAM_KEY:
		return rpmb_program_key();
	default:
		return -ENOTTY;
	}
}

static ssize_t rpmb_readdir(struct file *f, struct dirent *d, size_t cnt)
{
	struct rpmb_fs *fs = file2rpmb(f);
	struct rpmb_file *rf = f->priv;
	struct rpmb_frame *frames = NULL;
	struct rpmb_fat_entry entry;
	char dir_name[RPMB_MAX_FILENAME];
	const struct rpmb_fat_entry *enc = NULL;
	int i = 0, j = 0, max_batch = 0, start_idx = 0;
	ssize_t ret = 0, err = 0;
	size_t dir_len = 0;

	if (rf->type != DT_DIR)
		return -ENOTDIR;

	ret = rpmb_normalize_path(f->path, dir_name, sizeof(dir_name));
	if (ret != 0)
		return ret;

	dir_len = strlen(dir_name);

	if (mutex_lock_interruptible(&fs->mlock) != 0)
		return -EINTR;

	/* Phase 1: scan cached entries */
	start_idx = f->pos;
	if (fs->fat_cache) {
		for (i = f->pos; i < RPMB_FAT_CACHED; i++) {
			err = rpmb_fill_dirent(&fs->fat_cache[i], dir_name, dir_len,
					&d, &cnt, i + 1);
			if (err == -ENOSPC) {
				f->pos = i;
				goto out;
			} else if (err > 0) {
				ret += err;
			}
		}
		start_idx = RPMB_FAT_CACHED;
	}

	/* Phase 2: scan uncached entries from RPMB with batch read */
	i = (f->pos < start_idx) ? start_idx : f->pos;
	if (i < RPMB_FAT_ENTRIES) {
		max_batch = min(RPMB_READ_BATCH, RPMB_FAT_ENTRIES - i);
		frames = kmalloc(max_batch * sizeof(struct rpmb_frame));
		if (!frames && max_batch > 1) {
			max_batch = 1;
			frames = kmalloc(sizeof(struct rpmb_frame));
		}
		if (!frames) {
			err = -ENOMEM;
			goto out;
		}

		for (; i < RPMB_FAT_ENTRIES; i += max_batch) {
			max_batch = min(max_batch, RPMB_FAT_ENTRIES - i);

			err = rpmb_read_frames(RPMB_FAT_START + i, frames, max_batch);
			if (err != 0)
				goto out;

			for (j = 0; j < max_batch; j++) {
				enc = (const struct rpmb_fat_entry *)frames[j].data;
				err = rpmb_fat_decrypt(fs, i + j, enc, &entry);
				if (err != 0)
					continue;

				err = rpmb_fill_dirent(&entry, dir_name, dir_len,
							&d, &cnt, i + j + 1);
				if (err == -ENOSPC) {
					f->pos = i + j;
					goto out;
				} else if (err > 0) {
					ret += err;
				}
			}
		}
	}

	f->pos = RPMB_FAT_ENTRIES;

out:
	kfree(frames);
	mutex_unlock(&fs->mlock);
	return ret ? ret : err;
}

static void rpmb_getsize(struct file_system *pfs,
	size_t *total, size_t *idle)
{
	struct rpmb_fs *fs = pfs->priv;

	*total = fs->total_blkcnt * RPMB_BLOCK_SIZE;
	*idle = fs->idle_blkcnt * RPMB_BLOCK_SIZE;
}

static const struct file_operations rpmb_fops = {
	.open = rpmb_open,
	.close = rpmb_close,
	.read = rpmb_read,
	.write = rpmb_write,
	.unlink = rpmb_unlink,
	.ioctl = rpmb_ioctl,
	.readdir = rpmb_readdir,
	.mkdir = rpmb_mkdir,
	.rmdir = rpmb_rmdir,
	.lseek = rpmb_lseek,
	.ftruncate = rpmb_ftruncate,
	.fstat = rpmb_fstat,
	.rename = rpmb_rename,
};

int rpmb_mount(struct file_system *pfs)
{
	int ret = 0;
	struct rpmb_fs *fs = NULL;

	fs = kzalloc(sizeof(struct rpmb_fs));
	if (!fs)
		return -ENOMEM;

	mutex_init(&fs->mlock);
	INIT_LIST_HEAD(&fs->open_files);

	/* Initialize FAT GCM context */
	if (mbedcrypto_aes_gcm_setkey(&fs->fat_ctx,
			       rpmb_fat_key, 128) != 0) {
		EMSG("Failed to set FAT GCM key\n");
		ret = -EINVAL;
		goto out;
	}

	pfs->fops = &rpmb_fops;
	pfs->priv = fs;
	pfs->type = "rpmb";
	pfs->getsize = rpmb_getsize;

	ret = rpmb_program_key();
	IMSG("rpmb_program_key ret %d\n", ret);

	/* Check if RPMB needs initialization (counter = 0 = first use) */
	ret = rpmb_get_counter(&fs->write_counter);
	if (ret != 0) {
		EMSG("Failed to get RPMB write counter: %d\n", ret);
		goto out;
	}

	/* First-time use detection: counter=0 means uninitialized */
	if (fs->write_counter == 0) {
		IMSG("RPMB first use detected (counter=0)\n");
		ret = rpmb_fs_init_partition(fs);
		if (ret != 0) {
			EMSG("Failed to initialize RPMB partition: %d\n", ret);
			goto out;
		}

		/* After init, counter should be > 0 */
		ret = rpmb_get_counter(&fs->write_counter);
		if (ret != 0) {
			EMSG("Failed to verify counter after init: %d\n", ret);
			goto out;
		}
	}

	ret = rpmb_fs_scan(fs);
	if (ret != 0) {
		EMSG("Failed to scan RPMB filesystem: %d\n", ret);
		goto out;
	}

	return 0;

out:
	pfs->priv = NULL;
	kfree(fs->fat_cache);
	bitmap_free(fs->bitmap);
	mbedcrypto_aes_gcm_cleanup(&fs->fat_ctx);
	mutex_destroy(&fs->mlock);
	kfree(fs);
	return ret;
}

int rpmb_umount(struct file_system *pfs)
{
	struct rpmb_fs *fs = pfs->priv;

	mutex_destroy(&fs->mlock);

	mbedcrypto_aes_gcm_cleanup(&fs->fat_ctx);

	kfree(fs->fat_cache);
	bitmap_free(fs->bitmap);
	kfree(fs);
	return 0;
}

static struct file_system rpmb_fs = {
	.name = "rpmb",
	.mnt = {"/rpmb", 0, 0},
	.mount = rpmb_mount,
	.umount = rpmb_umount,
	.getpath = fs_getpath,
	.putpath = fs_putpath,
};

static void __rpmb_init(struct work *w)
{
	struct delayed_work *dw = container_of(w, struct delayed_work, w);
	struct rpmb_dev_info dev_info = {0};

	if (rpc_test_callee() && (rpmb_get_dev_info(&dev_info) == 0)) {
		IMSG("RPMB FS: %u blocks, rel_wr=%u frames\n",
			dev_info.total_blocks, dev_info.rel_wr_sec_c);

		if (rpmb_generate_keys() == 0)
			fs_mount(&rpmb_fs);

		kfree(dw);
	} else {
		schedule_delayed_work(dw, 200000);
	}
}

static void __init rpmb_init(void)
{
	BUILD_ERROR_ON(RPMB_FAT_CACHED > RPMB_FAT_ENTRIES);
	BUILD_ERROR_ON(sizeof(struct rpmb_fat_entry) != RPMB_BLOCK_SIZE);

#if defined(CONFIG_ARM)
	if (!is_security_extn_ena())
		return;
#endif

	struct delayed_work *dw = kmalloc(sizeof(*dw));
	if (!dw)
		return;

	INIT_DELAYED_WORK(dw, __rpmb_init);
	schedule_delayed_work(dw, 550000);
}
MODULE_INIT_LATE(rpmb_init);
