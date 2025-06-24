/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Unified mbedcrypto wrapper layer
 *
 * Upper-level abstraction providing algorithm-agnostic APIs for:
 *   - Hash dispatch (MD5, SHA-1, SHA-224/256, SHA-384/512, SM3)
 *   - HMAC (RFC 2104, generic over any hash)
 *   - Symmetric cipher (AES-ECB/CBC/CTR/CTS/XTS, DES/3DES, SM4)
 *   - Cipher-based MAC (AES-CMAC, AES/DES/3DES CBC-MAC)
 *
 * Callers only need to include this single header.
 */

#ifndef _MBEDCRYPTO_H
#define _MBEDCRYPTO_H

#include <stdbool.h>

#include <mbedcrypto/types.h>
#include <mbedcrypto/bignum.h>
#include <mbedcrypto/sha256.h>
#include <mbedcrypto/sha512.h>
#include <mbedcrypto/sha1.h>
#include <mbedcrypto/md5.h>
#include <mbedcrypto/aes.h>
#include <mbedcrypto/des.h>
#include <mbedcrypto/gcm.h>
#include <mbedcrypto/ccm.h>
#include <mbedcrypto/cmac.h>
#include <mbedcrypto/hkdf.h>
#include <mbedcrypto/rsa.h>
#include <mbedcrypto/asn1.h>
#include <mbedcrypto/dsa.h>
#include <mbedcrypto/dh.h>
#include <mbedcrypto/ecp.h>
#include <mbedcrypto/ecdsa.h>
#include <mbedcrypto/ecdh.h>
#include <mbedcrypto/pk.h>
#include <mbedcrypto/base64.h>

/* Optional algorithm headers (stubs when CONFIG not enabled) */
#include <mbedcrypto/sm3.h>
#include <mbedcrypto/sm4.h>
#include <mbedcrypto/sm2dsa.h>
#include <mbedcrypto/sm2pke.h>
#include <mbedcrypto/sm2kep.h>
#include <mbedcrypto/chacha20.h>
#include <mbedcrypto/sha3.h>
#include <mbedcrypto/pbkdf2.h>
#include <mbedcrypto/curve25519.h>
#include <mbedcrypto/curve448.h>
#include <mbedcrypto/aes_siv.h>

/* ---------------------------------------------------------------- */
/* Hash dispatch (algorithm-agnostic hash abstraction)              */
/* ---------------------------------------------------------------- */

#define MBEDCRYPTO_HASH_NONE   0
#define MBEDCRYPTO_HASH_MD5    1
#define MBEDCRYPTO_HASH_SHA1   2
#define MBEDCRYPTO_HASH_SHA224 3
#define MBEDCRYPTO_HASH_SHA256 4
#define MBEDCRYPTO_HASH_SHA384 5
#define MBEDCRYPTO_HASH_SHA512 6
#define MBEDCRYPTO_HASH_SM3    7
#define MBEDCRYPTO_HASH_SHA3_224 8
#define MBEDCRYPTO_HASH_SHA3_256 9
#define MBEDCRYPTO_HASH_SHA3_384 10
#define MBEDCRYPTO_HASH_SHA3_512 11

struct mbedcrypto_hash_ctx {
	uint8_t algo;
	union {
		struct mbedcrypto_md5_ctx md5;
		struct mbedcrypto_sha1_ctx sha1;
		struct mbedcrypto_sha256_ctx sha256; /* SHA-224 uses variant flag */
		struct mbedcrypto_sha512_ctx sha512; /* SHA-384 uses variant flag */
		struct mbedcrypto_sm3_ctx sm3;
		struct mbedcrypto_sha3_ctx sha3;
	};
};

/* Return the digest output size in bytes, or 0 if unknown. */
size_t mbedcrypto_hash_size(int algo);

/* Return the hash block size in bytes, or 0 if unknown. */
size_t mbedcrypto_hash_blksize(int algo);

/*
 * Initialize a hash context for the given algorithm.
 * Can be called again to re-initialize.
 */
int mbedcrypto_hash_init(struct mbedcrypto_hash_ctx *ctx, int algo);

/* Feed data into the hash computation. */
int mbedcrypto_hash_update(struct mbedcrypto_hash_ctx *ctx,
		const uint8_t *data, size_t len);

/* Finalize the hash and write the digest output. */
int mbedcrypto_hash_final(struct mbedcrypto_hash_ctx *ctx, uint8_t *out);

/* Clone a hash context (for intermediate state reuse). */
void mbedcrypto_hash_clone(struct mbedcrypto_hash_ctx *dst,
		const struct mbedcrypto_hash_ctx *src);

/* Release / zeroize the hash context. */
void mbedcrypto_hash_cleanup(struct mbedcrypto_hash_ctx *ctx);

/* ---------------------------------------------------------------- */
/* HMAC (generic over any hash, RFC 2104)                           */
/* ---------------------------------------------------------------- */

struct mbedcrypto_hmac_ctx {
	uint8_t algo;
	struct mbedcrypto_hash_ctx inner;
	/* Saved outer-pad hash state after absorbing K ^ opad */
	uint8_t opad_state[sizeof(struct mbedcrypto_hash_ctx)];
};

/*
 * Initialize HMAC with the given hash algorithm and key.
 * Can be called again to re-initialize with a new key.
 */
int mbedcrypto_hmac_init(struct mbedcrypto_hmac_ctx *ctx,
		int algo, const uint8_t *key, size_t keylen);

/* Feed data into the HMAC computation. */
int mbedcrypto_hmac_update(struct mbedcrypto_hmac_ctx *ctx,
		const uint8_t *data, size_t len);

/* Finalize and output the HMAC tag. */
int mbedcrypto_hmac_final(struct mbedcrypto_hmac_ctx *ctx,
		uint8_t *mac);

/* Release / zeroize the HMAC context. */
void mbedcrypto_hmac_cleanup(struct mbedcrypto_hmac_ctx *ctx);

/* ---------------------------------------------------------------- */
/* Symmetric cipher                                                 */
/* ---------------------------------------------------------------- */

/* Cipher direction */
#define MBEDCRYPTO_ENCRYPT           0
#define MBEDCRYPTO_DECRYPT           1

#define MBEDCRYPTO_CIPHER_NONE       0
/* AES modes */
#define MBEDCRYPTO_CIPHER_AES_ECB    1
#define MBEDCRYPTO_CIPHER_AES_CBC    2
#define MBEDCRYPTO_CIPHER_AES_CTR    3
#define MBEDCRYPTO_CIPHER_AES_CTS    4
#define MBEDCRYPTO_CIPHER_AES_XTS    5
/* DES modes */
#define MBEDCRYPTO_CIPHER_DES_ECB    6
#define MBEDCRYPTO_CIPHER_DES_CBC    7
#define MBEDCRYPTO_CIPHER_DES3_ECB   8
#define MBEDCRYPTO_CIPHER_DES3_CBC   9
/* SM4 modes */
#define MBEDCRYPTO_CIPHER_SM4_ECB    10
#define MBEDCRYPTO_CIPHER_SM4_CBC    11
#define MBEDCRYPTO_CIPHER_SM4_CTR    12
/* CTS (CBC-CS3) modes */
#define MBEDCRYPTO_CIPHER_DES3_CTS   13
#define MBEDCRYPTO_CIPHER_SM4_CTS    14
/* CBC with PKCS7 padding */
#define MBEDCRYPTO_CIPHER_AES_CBC_PKCS5   15
#define MBEDCRYPTO_CIPHER_DES_CBC_PKCS5   16
#define MBEDCRYPTO_CIPHER_DES3_CBC_PKCS5  17
#define MBEDCRYPTO_CIPHER_SM4_CBC_PKCS5   18
/* ECB with PKCS7 padding */
#define MBEDCRYPTO_CIPHER_SM4_ECB_PKCS5   19
/* Standalone stream cipher */
#define MBEDCRYPTO_CIPHER_CHACHA20        20

struct mbedcrypto_cipher_ctx {
	uint8_t type;
	uint8_t dir;              /* MBEDCRYPTO_ENCRYPT or MBEDCRYPTO_DECRYPT */
	uint8_t blksize;          /* 8 for DES/3DES, 16 for AES/SM4 */
	uint8_t partial_len;
	uint8_t partial_blk[32]; /* partial block buffer (up to 2 blocks for CTS) */
	uint8_t iv[16];
	uint8_t keystream[16];   /* CTR keystream block */
	size_t ctr_off;         /* CTR offset */
	union {
		struct mbedcrypto_aes_ctx aes;
		struct mbedcrypto_aes_xts_ctx xts;
		struct mbedcrypto_des_ctx des;
		struct mbedcrypto_des3_ctx des3;
		struct mbedcrypto_sm4_ctx sm4;
		struct mbedcrypto_chacha20_ctx chacha20;
	};
};

/*
 * Initialize cipher with the given algorithm, key, and direction.
 * dir: MBEDCRYPTO_ENCRYPT or MBEDCRYPTO_DECRYPT.
 */
int mbedcrypto_cipher_init(struct mbedcrypto_cipher_ctx *ctx,
		int type, const uint8_t *key,
		unsigned int keybits, int dir);

/*
 * Set the IV. For ECB modes, this is a no-op.
 * For XTS, the IV is the tweak - encrypted internally.
 */
int mbedcrypto_cipher_set_iv(struct mbedcrypto_cipher_ctx *ctx,
		const uint8_t *iv, size_t iv_len);

/* Reset the cipher state (keeps the key and IV, clears buffers). */
void mbedcrypto_cipher_reset(struct mbedcrypto_cipher_ctx *ctx);

/*
 * Process data through the cipher.
 *
 * For CTS/XTS modes, the output buffer must accommodate flushing of
 * internally buffered data from prior update calls, so it may need
 * up to (ilen + 2 * blksize) bytes - i.e. 32 bytes extra for AES.
 */
int mbedcrypto_cipher_update(struct mbedcrypto_cipher_ctx *ctx,
		const uint8_t *in, size_t ilen,
		uint8_t *out, size_t *olen);

/*
 * Finalize the cipher operation, optionally processing remaining
 * input data.
 *
 * For CTS/XTS modes, the output may be up to (ilen + 2 * blksize)
 * bytes - i.e. 32 bytes extra for AES - due to flushing of
 * internally buffered data from prior update calls.
 */
int mbedcrypto_cipher_final(struct mbedcrypto_cipher_ctx *ctx,
		const uint8_t *in, size_t ilen,
		uint8_t *out, size_t *olen);

/* Release / zeroize the cipher context. */
void mbedcrypto_cipher_cleanup(struct mbedcrypto_cipher_ctx *ctx);

/* ---------------------------------------------------------------- */
/* Cipher-based MAC (CMAC, CBC-MAC)                                 */
/* ---------------------------------------------------------------- */

#define MBEDCRYPTO_CMAC_NONE           0
#define MBEDCRYPTO_CMAC_AES            1  /* AES-CMAC (NIST SP 800-38B) */
#define MBEDCRYPTO_CMAC_AES_CBC_NOPAD  2  /* AES-CBC-MAC without padding */
#define MBEDCRYPTO_CMAC_AES_CBC_PKCS5  3  /* AES-CBC-MAC with PKCS5 padding */
#define MBEDCRYPTO_CMAC_DES_CBC_NOPAD  4  /* DES-CBC-MAC without padding */
#define MBEDCRYPTO_CMAC_DES_CBC_PKCS5  5  /* DES-CBC-MAC with PKCS5 padding */
#define MBEDCRYPTO_CMAC_DES3_CBC_NOPAD 6  /* 3DES-CBC-MAC without padding */
#define MBEDCRYPTO_CMAC_DES3_CBC_PKCS5 7  /* 3DES-CBC-MAC with PKCS5 padding */

struct mbedcrypto_mac_ctx {
	uint8_t type;
	uint8_t blksize;
	uint8_t nopad;
	union {
		struct mbedcrypto_cmac_ctx cmac;
		struct mbedcrypto_cipher_ctx cipher; /* CBC-MAC */
	};
};

/* Initialize MAC with the given algorithm and key. */
int mbedcrypto_mac_init(struct mbedcrypto_mac_ctx *ctx,
		int type, const uint8_t *key,
		unsigned int keybits);

/* Reset MAC state for a new computation (keeps the same key). */
int mbedcrypto_mac_reset(struct mbedcrypto_mac_ctx *ctx);

/* Feed data into the MAC computation. */
int mbedcrypto_mac_update(struct mbedcrypto_mac_ctx *ctx,
		const uint8_t *data, size_t len);

/* Finalize and output the MAC tag. */
int mbedcrypto_mac_final(struct mbedcrypto_mac_ctx *ctx,
		uint8_t *mac, size_t *maclen);

/* Release / zeroize the MAC context. */
void mbedcrypto_mac_cleanup(struct mbedcrypto_mac_ctx *ctx);

/* ---------------------------------------------------------------- */
/* AEAD (Authenticated Encryption with Associated Data)             */
/*                                                                  */
/* Unified API for GCM, CCM, ChaCha20-Poly1305.                    */
/* Supports: AES-GCM, AES-CCM, SM4-GCM, SM4-CCM, ChaCha20-Poly.   */
/* ---------------------------------------------------------------- */

/* AEAD algorithm identifiers */
#define MBEDCRYPTO_AEAD_AES_GCM             1
#define MBEDCRYPTO_AEAD_AES_CCM             2
#define MBEDCRYPTO_AEAD_SM4_GCM             3
#define MBEDCRYPTO_AEAD_SM4_CCM             4
#define MBEDCRYPTO_AEAD_CHACHA20_POLY1305   5

/* Direction */
#define MBEDCRYPTO_AEAD_ENCRYPT  0
#define MBEDCRYPTO_AEAD_DECRYPT  1

/* Maximum tag size across all supported algorithms */
#define MBEDCRYPTO_AEAD_TAG_MAXSIZE  16

/*
 * Unified AEAD context.
 *
 * Usage: setkey -> start -> [update_aad] -> update [1..n] -> final -> cleanup
 *
 * For CCM: total AAD and payload lengths must be known at start() time.
 * For GCM and ChaCha20-Poly1305: aad_len/payload_len in start() are ignored.
 */
struct mbedcrypto_aead_ctx {
	uint8_t algo;
	union {
		struct mbedcrypto_aes_gcm_ctx aes_gcm;
		struct mbedcrypto_aes_ccm_ctx aes_ccm;
		struct mbedcrypto_sm4_gcm_ctx sm4_gcm;
		struct mbedcrypto_sm4_ccm_ctx sm4_ccm;
		struct mbedcrypto_chachapoly_ctx chachapoly;
	};
};

/*
 * Set the AEAD key.
 * algo: MBEDCRYPTO_AEAD_* algorithm identifier.
 * keybits: 128, 192, or 256 (ChaCha20-Poly1305: must be 256).
 */
int mbedcrypto_aead_setkey(struct mbedcrypto_aead_ctx *ctx,
		int algo, const uint8_t *key, unsigned int keybits);

/*
 * Start an AEAD operation.
 * dir: MBEDCRYPTO_AEAD_ENCRYPT or MBEDCRYPTO_AEAD_DECRYPT.
 * iv/iv_len: initialization vector (12 bytes typical).
 * tag_len: tag size (CCM: required; GCM/ChaCha20: ignored, set at final).
 * aad_len/payload_len: total lengths (CCM: required; GCM/ChaCha20: ignored).
 */
int mbedcrypto_aead_start(struct mbedcrypto_aead_ctx *ctx, int dir,
		const uint8_t *iv, size_t iv_len,
		size_t tag_len, size_t aad_len, size_t payload_len);

/*
 * Feed additional authenticated data.
 * May be called multiple times. Must be done before update().
 */
int mbedcrypto_aead_update_aad(struct mbedcrypto_aead_ctx *ctx,
		const uint8_t *aad, size_t len);

/*
 * Encrypt or decrypt payload data.
 * May be called multiple times (streaming).
 * *olen receives the number of bytes written to output.
 */
int mbedcrypto_aead_update(struct mbedcrypto_aead_ctx *ctx,
		const uint8_t *input, size_t len,
		uint8_t *output, size_t *olen);

/*
 * Finalize and output the computed authentication tag.
 * tag must point to a buffer of at least tag_len bytes.
 * tag_len: 1..16 (ChaCha20-Poly1305 always outputs 16 bytes).
 */
int mbedcrypto_aead_final(struct mbedcrypto_aead_ctx *ctx,
		uint8_t *tag, size_t tag_len);

/*
 * Cleanup / zeroize the AEAD context.
 */
void mbedcrypto_aead_cleanup(struct mbedcrypto_aead_ctx *ctx);

#endif /* _MBEDCRYPTO_H */
