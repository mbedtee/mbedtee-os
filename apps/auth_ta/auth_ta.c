// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Authorizer to decrypt/verify other dynamic TAs
 *
 * Protocol V2: multi-algorithm, AEAD encryption, encrypt-then-sign
 * Verification flow: verify signature first, then decrypt (verify-then-decrypt)
 * Supports sign: RSA-PSS (2048/3072/4096), ECDSA (P-256/P-384/P-521/BP-256/BP-384/BP-512), Ed25519
 * Supports enc: AES-256-GCM, SM4-GCM, ChaCha20-Poly1305
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/syslimits.h>

#include <defs.h>
#include <utrace.h>
#include <syscall.h>
#include <pthread.h>
#include <mbedcrypto.h>
#include <tee_internal_api.h>

static volatile int redundant_counter;

static void secure_delay(void)
{
	uint8_t r = 0;

	TEE_GenerateRandom(&r, sizeof(r));
	usleep(r);
}

#define APP_DIR "/user/"
#define APP_RSA4096_PUB_KEY_FILE  "/apps/mbedtee-root.rsa4096.pub"
#define APP_RSA2048_PUB_KEY_FILE "/apps/mbedtee-root.rsa2048.pub"
#define APP_RSA3072_PUB_KEY_FILE "/apps/mbedtee-root.rsa3072.pub"
#define APP_EC256_PUB_KEY_FILE "/apps/mbedtee-root.ec256.pub"
#define APP_EC384_PUB_KEY_FILE "/apps/mbedtee-root.ec384.pub"
#define APP_EC521_PUB_KEY_FILE "/apps/mbedtee-root.ec521.pub"
#define APP_BP256_PUB_KEY_FILE "/apps/mbedtee-root.bp256.pub"
#define APP_BP384_PUB_KEY_FILE "/apps/mbedtee-root.bp384.pub"
#define APP_BP512_PUB_KEY_FILE "/apps/mbedtee-root.bp512.pub"
#define APP_ED25519_PUB_KEY_FILE "/apps/mbedtee-root.ed25519.pub"
#define APP_ECDH_SERVER_PUB_FILE "/apps/mbedtee-root.ecdh-srv.ec256.pub"
#define APP_ECDH_TEE_PRIV_FILE "/apps/mbedtee-root.ecdh-tee.ec256"
#define APP_CERTIFICATE_EXT   ".certi"

/* Protocol V2 constants (must match common.h in mbedtee-crypto) */
#define CERTI_MAGIC   (0x54524543)
#define CERTI_VERSION (2)
#define TA_OBJ_MAGIC  (0x544F424A)

/* Signature algorithms - RSA-PSS */
#define SIGN_ALGO_RSA2048_PSS_SHA256  0x0001
#define SIGN_ALGO_RSA3072_PSS_SHA256  0x0002
#define SIGN_ALGO_RSA3072_PSS_SHA384  0x0003
#define SIGN_ALGO_RSA4096_PSS_SHA256  0x0004
#define SIGN_ALGO_RSA4096_PSS_SHA384  0x0005
#define SIGN_ALGO_RSA4096_PSS_SHA512  0x0006
/* Signature algorithms - ECDSA NIST curves */
#define SIGN_ALGO_ECDSA_P256_SHA256   0x0007
#define SIGN_ALGO_ECDSA_P384_SHA384   0x0008
#define SIGN_ALGO_ECDSA_P521_SHA512   0x0009
/* Signature algorithms - ECDSA Brainpool curves */
#define SIGN_ALGO_ECDSA_BP256_SHA256  0x000a
#define SIGN_ALGO_ECDSA_BP384_SHA384  0x000b
#define SIGN_ALGO_ECDSA_BP512_SHA512  0x000c
/* Signature algorithms - EdDSA */
#define SIGN_ALGO_ED25519             0x000d

#define ENC_ALGO_AES_256_GCM          0x0001
#define ENC_ALGO_SM4_GCM              0x0002
#define ENC_ALGO_CHACHA20_POLY1305    0x0003

#define AEAD_IV_SIZE  12
#define AEAD_TAG_SIZE 16
#define GCM_IV_SIZE   AEAD_IV_SIZE
#define GCM_TAG_SIZE  AEAD_TAG_SIZE
#define AES256_KEY_SIZE  32
#define SM4_KEY_SIZE     16
#define CHACHA20_KEY_SIZE 32

#define ED25519_SIG_SIZE  64
#define ED25519_PUB_SIZE  32

struct certi_header {
	uint32_t magic;
	uint16_t version;
	uint16_t sign_algo;
	uint16_t enc_algo;
	uint16_t reserved;
	uint32_t body_len;
	char certi_type[20];
	uint32_t pubkey_offset;
	uint32_t pubkey_size;
	uint32_t enc_key_offset;
	uint32_t enc_key_size;
	uint32_t config_offset;
	uint32_t config_size;
	uint32_t segment_offset;
	uint32_t segment_size;
	uint64_t min_version;
	uint64_t cur_version;
	uint8_t iv[GCM_IV_SIZE];
	uint8_t tag[GCM_TAG_SIZE];
	uint32_t sig_size;
};

/*
 * TA object header - prepended to the encrypted TA binary (.o file).
 * sign_algo and enc_algo must match certi_header (validated in load_ta).
 * iv and tag are independent per encryption (different nonce/tag for TA vs certi).
 * sig_size is independent (different signature on TA object vs certificate).
 */
struct ta_obj_header {
	uint32_t magic;
	uint16_t sign_algo;                 /* must match certi_header.sign_algo */
	uint16_t enc_algo;                  /* must match certi_header.enc_algo */
	uint32_t body_len;
	uint8_t iv[GCM_IV_SIZE];            /* unique per TA encryption */
	uint8_t tag[GCM_TAG_SIZE];          /* unique per TA encryption */
	uint32_t sig_size;                  /* signature on this TA object */
};

static char *strstr_of(char *buf, char *e)
{
	char *pos = NULL;
	size_t elen = 0;

	if (!buf || !e)
		return NULL;

	elen = strlen(e);
	pos = buf;
	while ((pos = strstr(pos, e)) != NULL) {
		if ((pos == buf || pos[-1] == ' ' || pos[-1] == '\t' ||
			pos[-1] == '\n' || pos[-1] == '\r') &&
			(pos[elen] == '=' || pos[elen] == ' ' || pos[elen] == '\t'))
			break;
		pos++;
	}

	if (!pos)
		return NULL;

	pos = strchr(pos, '=');
	if (!pos)
		return NULL;

	pos++;
	while (*pos == ' ' || *pos == '\t')
		pos++;

	if (*pos == '"')
		pos++;
	return pos;
}

static int strlen_of(char *buf, char *e)
{
	char *pos = strstr_of(buf, e);
	int len = 0;

	if (!pos)
		return 0;

	if (pos[-1] == '"') {
		while (pos[len] != 0 && pos[len] != '"') {
			if (pos[len] == '=')
				return 0;
			len++;
		}
	} else {
		while (pos[len] != 0 && pos[len] != '\n' && pos[len] != '\r') {
			if (pos[len] == ';')
				break;
			if (pos[len] == '=')
				return 0;
			len++;
		}
		while (len > 0 && (pos[len-1] == ' ' || pos[len-1] == '\t'))
			len--;
	}
	return len;
}

/*
 * Verify signature using selected algorithm.
 * For RSA and ECDSA: hash the data first, then verify digest.
 * For Ed25519: pass full data directly (Ed25519 does internal hashing).
 */
static TEE_Result verify_signature(uint16_t sign_algo,
	uint8_t *pubkey, uint32_t pubkey_size,
	uint8_t *data, size_t data_len,
	uint8_t *signature, size_t sig_len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	switch (sign_algo) {
	case SIGN_ALGO_RSA4096_PSS_SHA256:
	case SIGN_ALGO_RSA4096_PSS_SHA384:
	case SIGN_ALGO_RSA3072_PSS_SHA384:
	case SIGN_ALGO_RSA4096_PSS_SHA512:
	case SIGN_ALGO_RSA2048_PSS_SHA256:
	case SIGN_ALGO_RSA3072_PSS_SHA256: {
		TEE_OperationHandle rsa_ops = NULL;
		TEE_OperationHandle digest_ops = NULL;
		TEE_ObjectHandle rsa_key_obj = NULL;
		TEE_Attribute attrs[2] = {0};
		struct mbedcrypto_rsa_ctx rsa;
		uint8_t modules[512];
		uint8_t hash[64]; /* up to SHA-512 */
		size_t hash_len = 0;
		size_t rsa_len;
		uint8_t exponent[8] = {0};
		uint32_t tee_rsa_algo;
		uint32_t tee_hash_algo;

		switch (sign_algo) {
		case SIGN_ALGO_RSA4096_PSS_SHA384:
		case SIGN_ALGO_RSA3072_PSS_SHA384:
			tee_rsa_algo = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384;
			tee_hash_algo = TEE_ALG_SHA384;
			hash_len = 48;
			break;
		case SIGN_ALGO_RSA4096_PSS_SHA512:
			tee_rsa_algo = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512;
			tee_hash_algo = TEE_ALG_SHA512;
			hash_len = 64;
			break;
		case SIGN_ALGO_RSA4096_PSS_SHA256:
		case SIGN_ALGO_RSA2048_PSS_SHA256:
		case SIGN_ALGO_RSA3072_PSS_SHA256:
			tee_rsa_algo = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256;
			tee_hash_algo = TEE_ALG_SHA256;
			hash_len = 32;
			break;
		}

		mbedcrypto_rsa_init(&rsa);
		if (mbedcrypto_pk_decode_rsa_pubkey_der(&rsa, pubkey,
			pubkey_size) != 0) {
			mbedcrypto_rsa_cleanup(&rsa);
			ret = TEE_ERROR_BAD_FORMAT;
			break;
		}

		rsa_len = mbedcrypto_rsa_len(&rsa);
		if (sig_len != rsa_len || rsa_len > sizeof(modules)) {
			mbedcrypto_rsa_cleanup(&rsa);
			ret = TEE_ERROR_SIGNATURE_INVALID;
			break;
		}

		mbedcrypto_bn_to_binary(&rsa.N, modules, rsa_len);
		mbedcrypto_bn_to_binary(&rsa.E, exponent,
			sizeof(exponent));
		mbedcrypto_rsa_cleanup(&rsa);

		ret = TEE_AllocateOperation(&rsa_ops, tee_rsa_algo,
			TEE_MODE_VERIFY, rsa_len * 8);
		if (ret != TEE_SUCCESS)
			break;

		ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY,
			rsa_len * 8, &rsa_key_obj);
		if (ret != TEE_SUCCESS)
			goto rsa_out;

		TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS,
			modules, rsa_len);
		TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT,
			exponent, sizeof(exponent));

		ret = TEE_PopulateTransientObject(rsa_key_obj, attrs, 2);
		if (ret != TEE_SUCCESS)
			goto rsa_out;

		ret = TEE_SetOperationKey(rsa_ops, rsa_key_obj);
		if (ret != TEE_SUCCESS)
			goto rsa_out;

		ret = TEE_AllocateOperation(&digest_ops, tee_hash_algo,
			TEE_MODE_DIGEST, 0);
		if (ret != TEE_SUCCESS)
			goto rsa_out;

		TEE_DigestUpdate(digest_ops, data, data_len);
		ret = TEE_DigestDoFinal(digest_ops, NULL, 0,
			hash, &hash_len);
		if (ret != TEE_SUCCESS)
			goto rsa_out;

		ret = TEE_AsymmetricVerifyDigest(rsa_ops, NULL, 0,
			hash, hash_len, signature, sig_len);

rsa_out:
		memset(hash, 0, sizeof(hash));
		TEE_FreeOperation(digest_ops);
		TEE_FreeTransientObject(rsa_key_obj);
		TEE_FreeOperation(rsa_ops);
		break;
	}
	case SIGN_ALGO_ECDSA_P256_SHA256:
	case SIGN_ALGO_ECDSA_BP256_SHA256:
	case SIGN_ALGO_ECDSA_P384_SHA384:
	case SIGN_ALGO_ECDSA_BP384_SHA384:
	case SIGN_ALGO_ECDSA_P521_SHA512:
	case SIGN_ALGO_ECDSA_BP512_SHA512: {
		TEE_OperationHandle ecdsa_ops = NULL;
		TEE_OperationHandle digest_ops = NULL;
		TEE_ObjectHandle ecdsa_key_obj = NULL;
		TEE_Attribute attrs[3] = {0};
		struct mbedcrypto_ecp_keypair ec_key;
		uint8_t x_buf[66], y_buf[66]; /* max P-521: 66 bytes */
		uint8_t hash[64]; /* max SHA-512: 64 bytes */
		size_t hash_len;
		uint32_t coord_size, key_bits, curve;
		uint32_t tee_ecdsa_algo, tee_hash_algo;
		int ec_ok = 0;

		/* Determine hash parameters from sign_algo */
		switch (sign_algo) {
		case SIGN_ALGO_ECDSA_P256_SHA256:
		case SIGN_ALGO_ECDSA_BP256_SHA256:
			tee_ecdsa_algo = TEE_ALG_ECDSA_SHA256;
			tee_hash_algo = TEE_ALG_SHA256;
			hash_len = 32;
			break;
		case SIGN_ALGO_ECDSA_P384_SHA384:
		case SIGN_ALGO_ECDSA_BP384_SHA384:
			tee_ecdsa_algo = TEE_ALG_ECDSA_SHA384;
			tee_hash_algo = TEE_ALG_SHA384;
			hash_len = 48;
			break;
		case SIGN_ALGO_ECDSA_P521_SHA512:
		case SIGN_ALGO_ECDSA_BP512_SHA512:
			tee_ecdsa_algo = TEE_ALG_ECDSA_SHA512;
			tee_hash_algo = TEE_ALG_SHA512;
			hash_len = 64;
			break;
		}

		/* Decode DER pubkey (SubjectPublicKeyInfo) */
		mbedcrypto_ecp_keypair_init(&ec_key);
		if (mbedcrypto_pk_decode_ec_pubkey_der(&ec_key,
				pubkey, pubkey_size) != 0) {
			mbedcrypto_ecp_keypair_cleanup(&ec_key);
			ret = TEE_ERROR_BAD_FORMAT;
			break;
		}

		coord_size = (ec_key.grp.pbits + 7) / 8;
		key_bits = ec_key.grp.pbits;

		/* Map grp.id to TEE curve */
		switch (ec_key.grp.id) {
		case MBEDCRYPTO_ECP_DP_SECP256R1:
			curve = TEE_ECC_CURVE_NIST_P256; ec_ok = 1; break;
		case MBEDCRYPTO_ECP_DP_SECP384R1:
			curve = TEE_ECC_CURVE_NIST_P384; ec_ok = 1; break;
		case MBEDCRYPTO_ECP_DP_SECP521R1:
			curve = TEE_ECC_CURVE_NIST_P521; ec_ok = 1; break;
		case MBEDCRYPTO_ECP_DP_BP256R1:
			curve = TEE_ECC_CURVE_BSI_P256r1; ec_ok = 1; break;
		case MBEDCRYPTO_ECP_DP_BP384R1:
			curve = TEE_ECC_CURVE_BSI_P384r1; ec_ok = 1; break;
		case MBEDCRYPTO_ECP_DP_BP512R1:
			curve = TEE_ECC_CURVE_BSI_P512r1; ec_ok = 1; break;
		default:
			break;
		}

		if (ec_ok) {
			/* Export raw X/Y coordinates */
			mbedcrypto_bn_to_binary(&ec_key.Q.X, x_buf, coord_size);
			mbedcrypto_bn_to_binary(&ec_key.Q.Y, y_buf, coord_size);
		}
		mbedcrypto_ecp_keypair_cleanup(&ec_key);

		if (!ec_ok) {
			ret = TEE_ERROR_NOT_SUPPORTED;
			break;
		}

		ret = TEE_AllocateOperation(&ecdsa_ops, tee_ecdsa_algo,
			TEE_MODE_VERIFY, key_bits);
		if (ret != TEE_SUCCESS)
			break;

		ret = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_PUBLIC_KEY,
			key_bits, &ecdsa_key_obj);
		if (ret != TEE_SUCCESS)
			goto ecdsa_out;

		TEE_InitRefAttribute(&attrs[0], TEE_ATTR_ECC_PUBLIC_VALUE_X,
			x_buf, coord_size);
		TEE_InitRefAttribute(&attrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y,
			y_buf, coord_size);
		TEE_InitValueAttribute(&attrs[2], TEE_ATTR_ECC_CURVE,
			curve, 0);

		ret = TEE_PopulateTransientObject(ecdsa_key_obj, attrs, 3);
		if (ret != TEE_SUCCESS)
			goto ecdsa_out;

		ret = TEE_SetOperationKey(ecdsa_ops, ecdsa_key_obj);
		if (ret != TEE_SUCCESS)
			goto ecdsa_out;

		ret = TEE_AllocateOperation(&digest_ops, tee_hash_algo,
			TEE_MODE_DIGEST, 0);
		if (ret != TEE_SUCCESS)
			goto ecdsa_out;

		TEE_DigestUpdate(digest_ops, data, data_len);
		ret = TEE_DigestDoFinal(digest_ops, NULL, 0,
			hash, &hash_len);
		if (ret != TEE_SUCCESS)
			goto ecdsa_out;

		ret = TEE_AsymmetricVerifyDigest(ecdsa_ops, NULL, 0,
			hash, hash_len, signature, sig_len);

ecdsa_out:
		memset(hash, 0, sizeof(hash));
		TEE_FreeOperation(digest_ops);
		TEE_FreeTransientObject(ecdsa_key_obj);
		TEE_FreeOperation(ecdsa_ops);
		break;
	}
	case SIGN_ALGO_ED25519: {
		TEE_OperationHandle ed_ops = NULL;
		TEE_ObjectHandle ed_key_obj = NULL;
		TEE_Attribute attrs[1] = {0};

		if (pubkey_size != ED25519_PUB_SIZE) {
			ret = TEE_ERROR_BAD_FORMAT;
			break;
		}
		if (sig_len != ED25519_SIG_SIZE) {
			ret = TEE_ERROR_SIGNATURE_INVALID;
			break;
		}

		ret = TEE_AllocateOperation(&ed_ops,
			TEE_ALG_ED25519, TEE_MODE_VERIFY, 256);
		if (ret != TEE_SUCCESS)
			break;

		ret = TEE_AllocateTransientObject(TEE_TYPE_ED25519_PUBLIC_KEY,
			256, &ed_key_obj);
		if (ret != TEE_SUCCESS)
			goto ed_out;

		TEE_InitRefAttribute(&attrs[0], TEE_ATTR_ECC_PUBLIC_VALUE_X,
			pubkey, ED25519_PUB_SIZE);

		ret = TEE_PopulateTransientObject(ed_key_obj, attrs, 1);
		if (ret != TEE_SUCCESS)
			goto ed_out;

		ret = TEE_SetOperationKey(ed_ops, ed_key_obj);
		if (ret != TEE_SUCCESS)
			goto ed_out;

		/* Ed25519: pass full data (TEE API handles internal hashing) */
		ret = TEE_AsymmetricVerifyDigest(ed_ops, NULL, 0,
			data, data_len, signature, sig_len);

ed_out:
		TEE_FreeTransientObject(ed_key_obj);
		TEE_FreeOperation(ed_ops);
		break;
	}
	default:
		EMSG("Unknown sign_algo %d\n", sign_algo);
		ret = TEE_ERROR_NOT_SUPPORTED;
	}

	return ret;
}

/*
 * Map protocol enc_algo to mbedcrypto AEAD algorithm identifier.
 */
static int enc_algo_to_aead(uint16_t enc_algo)
{
	switch (enc_algo) {
	case ENC_ALGO_AES_256_GCM:       return MBEDCRYPTO_AEAD_AES_GCM;
	case ENC_ALGO_SM4_GCM:           return MBEDCRYPTO_AEAD_SM4_GCM;
	case ENC_ALGO_CHACHA20_POLY1305: return MBEDCRYPTO_AEAD_CHACHA20_POLY1305;
	default: return -1;
	}
}

static unsigned int enc_algo_keybits(uint16_t enc_algo)
{
	switch (enc_algo) {
	case ENC_ALGO_AES_256_GCM:       return AES256_KEY_SIZE * 8;
	case ENC_ALGO_SM4_GCM:           return SM4_KEY_SIZE * 8;
	case ENC_ALGO_CHACHA20_POLY1305: return CHACHA20_KEY_SIZE * 8;
	}
	return 0;
}

/*
 * AEAD decrypt: unified helper for certificate and TA object decryption.
 */
static int aead_decrypt(uint16_t enc_algo, const uint8_t *key,
	const uint8_t *iv, const uint8_t *tag,
	const uint8_t *input, size_t input_len,
	uint8_t *output)
{
	struct mbedcrypto_aead_ctx aead;
	uint8_t computed_tag[AEAD_TAG_SIZE];
	size_t olen = input_len;
	int algo, ret;

	algo = enc_algo_to_aead(enc_algo);
	if (algo < 0)
		return -1;

	ret = mbedcrypto_aead_setkey(&aead, algo, key,
			enc_algo_keybits(enc_algo));
	if (ret != 0)
		return -1;

	ret = mbedcrypto_aead_start(&aead, MBEDCRYPTO_AEAD_DECRYPT,
			iv, AEAD_IV_SIZE, AEAD_TAG_SIZE, 0, 0);
	if (ret != 0)
		goto out;

	ret = mbedcrypto_aead_update(&aead, input, input_len,
			output, &olen);
	if (ret != 0)
		goto out;

	ret = mbedcrypto_aead_final(&aead, computed_tag,
			AEAD_TAG_SIZE);
	if (ret == 0 && mbedcrypto_ct_memcmp(computed_tag, tag,
			AEAD_TAG_SIZE) != 0)
		ret = -1;
out:
	memset(computed_tag, 0, sizeof(computed_tag));
	mbedcrypto_aead_cleanup(&aead);
	return ret;
}

/*
 * Get the root public key path based on signature algorithm.
 */
static const char *get_root_pubkey_path(uint16_t sign_algo)
{
	switch (sign_algo) {
	case SIGN_ALGO_ECDSA_P256_SHA256:
		return APP_EC256_PUB_KEY_FILE;
	case SIGN_ALGO_ECDSA_P384_SHA384:
		return APP_EC384_PUB_KEY_FILE;
	case SIGN_ALGO_ECDSA_P521_SHA512:
		return APP_EC521_PUB_KEY_FILE;
	case SIGN_ALGO_ECDSA_BP256_SHA256:
		return APP_BP256_PUB_KEY_FILE;
	case SIGN_ALGO_ECDSA_BP384_SHA384:
		return APP_BP384_PUB_KEY_FILE;
	case SIGN_ALGO_ECDSA_BP512_SHA512:
		return APP_BP512_PUB_KEY_FILE;
	case SIGN_ALGO_ED25519:
		return APP_ED25519_PUB_KEY_FILE;
	case SIGN_ALGO_RSA4096_PSS_SHA256:
	case SIGN_ALGO_RSA4096_PSS_SHA384:
	case SIGN_ALGO_RSA4096_PSS_SHA512:
		return APP_RSA4096_PUB_KEY_FILE;
	case SIGN_ALGO_RSA2048_PSS_SHA256:
		return APP_RSA2048_PUB_KEY_FILE;
	case SIGN_ALGO_RSA3072_PSS_SHA256:
	case SIGN_ALGO_RSA3072_PSS_SHA384:
		return APP_RSA3072_PUB_KEY_FILE;
	default:
		EMSG("Unknown sign_algo 0x%04x\n", sign_algo);
		return NULL;
	}
}

/*
 * Read a key file into a buffer.
 */
static int read_key_file(const char *path, uint8_t *buf, size_t buf_size)
{
	FILE *fp;
	int rd;
	int ret = -1;

	fp = fopen(path, "r");
	if (!fp) {
		EMSG("open %s failed\n", path);
		return -1;
	}

	fseek(fp, 0, SEEK_END);
	rd = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (rd <= 0 || rd > buf_size) {
		EMSG("key file %s size %d invalid\n", path, rd);
		goto out;
	}

	if (fread(buf, 1, rd, fp) != rd) {
		EMSG("read %s failed\n", path);
		goto out;
	}

	ret = rd;

out:
	fclose(fp);
	return ret;
}

/*
 * Load and verify a single TA object file.
 * Uses verify-then-decrypt: first verify signature, then AEAD decrypt.
 */
static int load_ta(struct certi_header *h, uint8_t *body)
{
	int ret = -1;
	int path_len = 0;
	size_t file_size = 0;
	uint32_t saved_sig_size = 0;
	FILE *fp = NULL, *wfp = NULL;
	uint8_t *file_buf = NULL;
	uint8_t *enc_key = NULL;
	char *c = NULL, *p = NULL;
	char ta_path[NAME_MAX/2];
	struct ta_obj_header *t = NULL;
	uint8_t *enc_ta = NULL;
	uint8_t *ta_sig = NULL;
	size_t signed_data_len = 0;

	if (!h || !body)
		return -1;

	/* Validate body offsets before accessing */
	if (h->config_offset + h->config_size > h->body_len ||
	    h->pubkey_offset + h->pubkey_size > h->body_len ||
	    h->enc_key_offset + h->enc_key_size > h->body_len) {
		EMSG("certificate body offset out of bounds\n");
		return TEE_ERROR_BAD_FORMAT;
	}

	/* Extract TA path from config */
	c = (char *)body + h->config_offset;
	p = strstr_of(c, "path");
	path_len = strlen_of(c, "path");

	if (!p || path_len == 0) {
		EMSG("app config has invalid path info\n");
		return -1;
	}

	memset(ta_path, 0, sizeof(ta_path));
	memcpy(ta_path, p, min((size_t)path_len, sizeof(ta_path) - 1));

	/* Read entire TA file into memory */
	fp = fopen(ta_path, "r");
	if (!fp) {
		EMSG("open %s failed\n", ta_path);
		return TEE_ERROR_BAD_STATE;
	}
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (file_size < sizeof(struct ta_obj_header)) {
		EMSG("TA file %s too small\n", ta_path);
		ret = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	file_buf = malloc(file_size);
	if (!file_buf) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if (fread(file_buf, 1, file_size, fp) != file_size) {
		EMSG("fread %s failed\n", ta_path);
		ret = TEE_ERROR_BAD_STATE;
		goto out;
	}

	/* Parse TA object header */
	t = (struct ta_obj_header *)file_buf;
	if (t->magic != TA_OBJ_MAGIC) {
		EMSG("TA object magic mismatch: 0x%x\n", t->magic);
		ret = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	if (t->sign_algo != h->sign_algo) {
		EMSG("TA sign_algo mismatch\n");
		ret = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	if (t->enc_algo != h->enc_algo) {
		EMSG("TA enc_algo mismatch\n");
		ret = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	enc_ta = file_buf + sizeof(struct ta_obj_header);
	ta_sig = enc_ta + t->body_len;

	if (t->body_len > SIZE_MAX - sizeof(struct ta_obj_header)) {
		EMSG("TA body_len overflow\n");
		ret = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	signed_data_len = sizeof(struct ta_obj_header) + t->body_len;

	/* Validate file size */
	if (t->sig_size > file_size || signed_data_len > file_size - t->sig_size) {
		EMSG("TA file size mismatch\n");
		ret = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	secure_delay();
	redundant_counter++;

	/* Step 1: VERIFY SIGNATURE on [ta_header + encrypted_ta] */
	saved_sig_size = t->sig_size;
	t->sig_size = 0;
	ret = verify_signature(t->sign_algo,
		body + h->pubkey_offset, h->pubkey_size,
		file_buf, signed_data_len,
		ta_sig, saved_sig_size);
	t->sig_size = saved_sig_size;
	if (ret != TEE_SUCCESS) {
		EMSG("Verify %s FAIL\n", ta_path);
		goto out;
	}

	IMSG("Verify %s PASS\n", ta_path);

	secure_delay();
	redundant_counter++;

	/* Step 2: AEAD decrypt the TA body (in-place) */
	enc_key = body + h->enc_key_offset;
	if (aead_decrypt(t->enc_algo, enc_key, t->iv, t->tag,
			enc_ta, t->body_len, enc_ta) != 0) {
		EMSG("AEAD decrypt %s FAIL (integrity check failed)\n",
			ta_path);
		ret = TEE_ERROR_MAC_INVALID;
		goto out;
	}

	wfp = fopen(ta_path, "w");
	if (!wfp) {
		EMSG("open %s for write failed\n", ta_path);
		ret = TEE_ERROR_BAD_STATE;
		goto out;
	}

	if (fwrite(enc_ta, 1, t->body_len, wfp) != t->body_len) {
		EMSG("fwrite %s failed\n", ta_path);
		fclose(wfp);
		wfp = NULL;
		ret = TEE_ERROR_BAD_STATE;
		goto out;
	}
	fclose(wfp);
	wfp = NULL;

	secure_delay();
	if (++redundant_counter != 6) {
		IMSG("redundant_counter error\n");
		ret = TEE_ERROR_SECURITY;
		goto out;
	}

	/* Step 4: Set TA configuration */
	DMSG("%s\n", c);
	ret = syscall2(SYSCALL_SET_CONFIG, c, h->config_size);
	if (ret != 0) {
		EMSG("set %s config error\n", ta_path);
		ret = TEE_ERROR_SECURITY;
		goto out;
	}

	secure_delay();
	if (redundant_counter != 6) {
		ret = TEE_ERROR_SECURITY;
		remove(ta_path);
		goto out;
	}

	ret = 0;

out:
	fclose(fp);
	free(file_buf);
	return ret;
}

static void auth_ta(void)
{
	FILE *fp = NULL;
	uint8_t *buffer = NULL;
	DIR *dir = NULL;
	size_t rd_bytes = 0;
	size_t file_size = 0;
	struct dirent *d = NULL;
	char file_name[NAME_MAX/2];
	uint8_t key[AES256_KEY_SIZE]; /* 32 bytes: derived via ECDH+HKDF */
	uint32_t saved_sig_size = 0;
	TEE_Result ret = TEE_SUCCESS;
	struct certi_header *h = NULL;
	uint8_t *enc_body = NULL;
	uint8_t *body = NULL;
	uint8_t *certi_sig = NULL;
	size_t signed_data_len = 0;
	static uint8_t root_pubkey[544];
	int root_pubkey_size = 0;
	const char *root_pubkey_path = NULL;
	struct mbedcrypto_ecdh_ctx ecdh;
	struct mbedcrypto_ecp_keypair tee_kp, server_kp;
	uint8_t shared_secret[66];
	size_t shared_len = 0;
	int ecdh_ret;

	/* Derive root crypto key via ECDH + HKDF */
	mbedcrypto_ecp_keypair_init(&tee_kp);
	mbedcrypto_ecp_keypair_init(&server_kp);
	mbedcrypto_ecdh_init(&ecdh);

	ecdh_ret = mbedcrypto_pk_decode_ec_privkey_file(&tee_kp,
		APP_ECDH_TEE_PRIV_FILE);
	if (ecdh_ret != 0) {
		EMSG("load TEE ECDH private key failed: %d\n", ecdh_ret);
		goto ecdh_fail;
	}

	ecdh_ret = mbedcrypto_pk_decode_ec_pubkey_file(&server_kp,
		APP_ECDH_SERVER_PUB_FILE);
	if (ecdh_ret != 0) {
		EMSG("load server ECDH public key failed: %d\n", ecdh_ret);
		goto ecdh_fail;
	}

	ecdh_ret = mbedcrypto_ecdh_setup(&ecdh,
		MBEDCRYPTO_ECP_DP_SECP256R1, &tee_kp.d, &server_kp.Q);
	if (ecdh_ret != 0)
		goto ecdh_fail;

	ecdh_ret = mbedcrypto_ecdh_derive_shared(&ecdh, &shared_len,
		shared_secret, sizeof(shared_secret), NULL, NULL);
	if (ecdh_ret != 0) {
		EMSG("ECDH derive shared failed: %d\n", ecdh_ret);
		goto ecdh_fail;
	}

	ecdh_ret = mbedcrypto_hkdf_derive(NULL, 0,
		shared_secret, shared_len,
		(const uint8_t *)"mbedtee-root-cryptokey", 22,
		key, sizeof(key));

ecdh_fail:
	memset(shared_secret, 0, sizeof(shared_secret));
	mbedcrypto_ecdh_cleanup(&ecdh);
	mbedcrypto_ecp_keypair_cleanup(&tee_kp);
	mbedcrypto_ecp_keypair_cleanup(&server_kp);

	if (ecdh_ret != 0) {
		EMSG("ECDH key derivation failed\n");
		goto out;
	}

	/* make sure auth_ta() executes only once */
	unlink(APP_ECDH_TEE_PRIV_FILE);
	unlink(APP_ECDH_SERVER_PUB_FILE);

	dir = opendir(APP_DIR);
	if (!dir) {
		EMSG("open app dir failed\n");
		goto out;
	}

	while ((d = readdir(dir)) != NULL) {
		if (!strstr(d->d_name, APP_CERTIFICATE_EXT))
			continue;
		if (strlen(strstr(d->d_name, APP_CERTIFICATE_EXT))
				!= strlen(APP_CERTIFICATE_EXT))
			continue;

		strlcpy(file_name, APP_DIR, sizeof(file_name));
		strlcpy(file_name + strlen(file_name), d->d_name,
			sizeof(file_name) - strlen(file_name));

		IMSG("Verifying %s\n", d->d_name);

		redundant_counter = 0;

		fp = fopen(file_name, "r");
		if (!fp)
			continue;

		fseek(fp, 0, SEEK_END);
		file_size = ftell(fp);
		fseek(fp, 0, SEEK_SET);

		if (file_size < sizeof(struct certi_header)) {
			EMSG("certificate %s too small\n", file_name);
			goto next_certi;
		}

		buffer = malloc(file_size);
		if (!buffer)
			goto next_certi;

		rd_bytes = fread(buffer, 1, file_size, fp);
		if (rd_bytes != file_size) {
			EMSG("fread error for %s\n", file_name);
			goto next_certi;
		}

		/* Parse cleartext header */
		h = (struct certi_header *)buffer;

		if (h->magic != CERTI_MAGIC) {
			EMSG("certificate magic mismatch: 0x%x\n", h->magic);
			goto next_certi;
		}

		if (h->version != CERTI_VERSION) {
			EMSG("certificate version mismatch: %d\n", h->version);
			goto next_certi;
		}

		if (h->enc_algo != ENC_ALGO_AES_256_GCM &&
			h->enc_algo != ENC_ALGO_SM4_GCM &&
			h->enc_algo != ENC_ALGO_CHACHA20_POLY1305) {
			EMSG("unsupported enc_algo: 0x%04x\n", h->enc_algo);
			goto next_certi;
		}

		/* Validate sizes */
		if (h->body_len > SIZE_MAX - sizeof(struct certi_header)) {
			EMSG("certificate body_len overflow\n");
			goto next_certi;
		}
		signed_data_len = sizeof(struct certi_header) + h->body_len;
		if (h->sig_size > file_size || signed_data_len > file_size - h->sig_size) {
			EMSG("certificate size mismatch\n");
			goto next_certi;
		}

		/* Anti-rollback check */
		if (h->cur_version < h->min_version) {
			EMSG("anti-rollback: cur_version %llu < min_version %llu\n",
				h->cur_version, h->min_version);
			goto next_certi;
		}

		/* Read root public key based on algorithm */
		root_pubkey_path = get_root_pubkey_path(h->sign_algo);
		if (!root_pubkey_path)
			goto next_certi;

		root_pubkey_size = read_key_file(root_pubkey_path,
			root_pubkey, sizeof(root_pubkey));
		if (root_pubkey_size <= 0) {
			EMSG("failed to read root pubkey for algo %d\n", h->sign_algo);
			goto next_certi;
		}

		enc_body = buffer + sizeof(struct certi_header);
		certi_sig = enc_body + h->body_len;

		secure_delay();
		redundant_counter++;

		/* Step 1: VERIFY SIGNATURE on [header + encrypted_body] */
		/* sig_size was 0 when data was signed, zero it before verify */
		saved_sig_size = h->sig_size;
		h->sig_size = 0;
		ret = verify_signature(h->sign_algo,
			root_pubkey, root_pubkey_size,
			buffer, signed_data_len,
			certi_sig, saved_sig_size);
		h->sig_size = saved_sig_size;

		secure_delay();
		redundant_counter++;

		if (ret != TEE_SUCCESS) {
			EMSG("Verify %s FAIL\n", file_name);
			goto next_certi;
		}

		IMSG("Verify %s PASS\n", file_name);

		/* Step 2: AEAD DECRYPT the body */
		body = malloc(h->body_len);
		if (!body)
			goto next_certi;

		if (aead_decrypt(h->enc_algo, key, h->iv, h->tag,
				enc_body, h->body_len, body) != 0) {
			EMSG("AEAD decrypt %s FAIL (integrity check failed)\n",
				file_name);
			goto next_certi;
		}

		secure_delay();
		redundant_counter++;

		/* Step 3: Load and verify the TA */
		load_ta(h, body);

next_certi:
		fclose(fp);
		fp = NULL;
		if (body)
			memset(body, 0, h->body_len);
		free(body);
		body = NULL;
		free(buffer);
		buffer = NULL;
	}

out:
	memset(key, 0, sizeof(key));
	free(buffer);
	closedir(dir);
}

static struct option long_options[] = {
	{"auth",			no_argument,	NULL, 'a'},
	{"help",			no_argument,	NULL, 'h'},
	{0, 0, NULL, 0}
};

int main(int argc, char *argv[])
{
	int ret = -EINVAL;
	int option_index = -1, opt = -1;
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);

	if (argc < 2)
		goto err;

	while ((opt = getopt_long(argc, argv, "ah",
			long_options, &option_index)) != -1) {
		switch (opt) {
		case 'a':
			auth_ta();
			return 0;
		case 'h': /* help information */
			ret = 0;
			goto err;
		default:
			goto err;
		}
	}

err:
	if (ret == -EINVAL) {
		printf("help info:\n");
		printf("--auth to run auth_ta()\n");
	}
	return ret;
}
