// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Authorizer to decrypt/verify other dynamic TAs
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/syslimits.h>

#include <defs.h>
#include <mmap.h>
#include <math.h>
#include <sched.h>
#include <mqueue.h>
#include <utrace.h>
#include <syscall.h>
#include <pthread.h>
#include <mbedtls/pk.h>
#include <tee_internal_api.h>

static int redundant_counter;

#define APP_DIR "/user/"
#define APP_RSA_PUB_KEY_FILE "/apps/mbedtee-root.pub.der"
#define APP_CRYPTO_KEY_FILE "/apps/mbedtee-root.cryptokey"
#define APP_CERTIFICATE_EXT ".certi"
#define CERTI_MAGIC (0x54524543)

struct certi_header {
	unsigned int magic;
	unsigned int total_len;
	char certi_type[40];
	unsigned int rsa_key_offset;
	unsigned int rsa_key_size;
	unsigned int crypto_key_offset;
	unsigned int crypto_key_size;
	unsigned int config_offset;
	unsigned int config_size;
	unsigned int segment_offset;
	unsigned int segment_size;
	unsigned int version_offset;
	unsigned int version_size;
};

static char *strstr_of_config(char *buf, char *e)
{
	char *pos = NULL;

	pos = strstr(buf, e);
	if (!pos)
		return NULL;

	pos = strchr(pos, '=');
	if (!pos)
		return NULL;

	pos++;
	while ((*pos != '\"')) {
		if (*pos == '=')
			return NULL;
		pos++;
	}

	pos++;
	return pos;
}

static int strlen_of_config(char *buf, char *e)
{
	char *pos = NULL;
	int len = 0;

	pos = strstr(buf, e);
	if (!pos)
		return 0;

	pos = strchr(pos, '=');
	if (!pos)
		return 0;

	pos++;
	while ((*pos != '\"')) {
		if (*pos == '=')
			return 0;
		pos++;
	}

	pos++;
	while (*(pos + len) != '\"') {
		if (*(pos + len) == '=')
			return 0;
		len++;
	}

	return len;
}

static int load_ta(struct certi_header *h)
{
	int ret = -1;
	size_t rd_bytes = 0, wr_bytes = 0;
	size_t rsa_len = 0;
	size_t file_size = 0, pos = 0;
	FILE *fp = NULL, *wfp = NULL;
	TEE_OperationHandle ta_digest_ops = NULL;
	TEE_OperationHandle ta_rsa_ops = NULL;
	TEE_ObjectHandle rsa_key_obj = NULL;
	TEE_OperationHandle cipher_aes_ops = NULL;
	TEE_ObjectHandle aes_key_obj = NULL;
	char *buffer = NULL;
	size_t buf_size = 8*1024;
	char *c = NULL, *p = NULL;
	char signature[256];
	char hash[64], ta_path[NAME_MAX];
	size_t hash_len = sizeof(hash);
	unsigned char iv[16], modules[256];
	int64_t exponent = 0;
	struct mbedtls_pk_context ctx = {NULL};
	TEE_Attribute attrs[2] = {0};

	if (!h)
		return -1;

	if (h->magic != CERTI_MAGIC) {
		EMSG("wrong certificate header\n");
		return -1;
	}

	c = (char *)h + h->config_offset;
	p = strstr_of_config(c, "path");
	if (!p || !strlen_of_config(c, "path")) {
		EMSG("app config has invalid path info\n");
		return -1;
	}

	memset(ta_path, 0, sizeof(ta_path));
	memcpy(ta_path, p, strlen_of_config(c, "path"));
	fp = fopen(ta_path, "r");
	if (!fp) {
		EMSG("open %s failed rfp\n", ta_path);
		return TEE_ERROR_BAD_STATE;
	}
	wfp = fopen(ta_path, "r+");
	if (!wfp) {
		EMSG("open %s failed wfp\n", ta_path);
		ret = TEE_ERROR_BAD_STATE;
		goto out;
	}
	fseek(wfp, 0, SEEK_END);
	file_size = ftell(wfp);
	fseek(wfp, 0, SEEK_SET);

	ret = TEE_AllocateOperation(&ta_rsa_ops,
				TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
				TEE_MODE_VERIFY, 2048);
	if (ret != TEE_SUCCESS)
		goto out;

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY,
					2048, &rsa_key_obj);
	if (ret != TEE_SUCCESS)
		goto out;

	mbedtls_pk_init(&ctx);
	ret = mbedtls_pk_parse_public_key(&ctx, (unsigned char *)h +
				h->rsa_key_offset, h->rsa_key_size);
	if (ret != 0) {
		ret = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	rsa_len = mbedtls_rsa_get_len(mbedtls_pk_rsa(ctx));

	mbedtls_rsa_export_raw(mbedtls_pk_rsa(ctx), modules, rsa_len,
		NULL, 0, NULL, 0, NULL, 0, (void *)&exponent, sizeof(exponent));

	mbedtls_pk_free(&ctx);

	TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS,
				modules, rsa_len);
	TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT,
				&exponent, sizeof(exponent));

	ret = TEE_PopulateTransientObject(rsa_key_obj, attrs, 2);
	if (ret != TEE_SUCCESS)
		goto out;

	ret = TEE_SetOperationKey(ta_rsa_ops, rsa_key_obj);
	if (ret != TEE_SUCCESS)
		goto out;

	ret = TEE_AllocateOperation(&ta_digest_ops, TEE_ALG_SHA256,
			TEE_MODE_DIGEST, 0);
	if (ret != TEE_SUCCESS)
		goto out;

	ret = TEE_AllocateOperation(&cipher_aes_ops, TEE_ALG_AES_CTS,
			TEE_MODE_DECRYPT, h->crypto_key_size * 8);
	if (ret != TEE_SUCCESS)
		goto out;

	ret = TEE_AllocateTransientObject(TEE_TYPE_AES,
				h->crypto_key_size * 8, &aes_key_obj);
	if (ret != TEE_SUCCESS)
		goto out;

	TEE_InitRefAttribute(&attrs[0], TEE_ATTR_SECRET_VALUE,
		(char *)h + h->crypto_key_offset, h->crypto_key_size);

	ret = TEE_PopulateTransientObject(aes_key_obj, attrs, 1);
	if (ret != TEE_SUCCESS)
		goto out;

	TEE_SetOperationKey(cipher_aes_ops, aes_key_obj);

	memset(iv, 0, sizeof(iv));
	TEE_CipherInit(cipher_aes_ops, iv, sizeof(iv));

	buffer = malloc(buf_size);
	if (!buffer) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	file_size -= rsa_len;

	/* Since we are using CTS RFC2040,
	 * make sure there are at least 2 blocks for TEE_CipherDoFinal()
	 */
	while ((file_size > buf_size) && ((file_size % buf_size) <= 16))
		buf_size -= 16;

	while (pos < file_size) {
		rd_bytes = fread(buffer, 1,
				(file_size - pos < buf_size) ?
				(file_size - pos) : buf_size, fp);
		if ((ssize_t)rd_bytes > 0) {
			if (pos + rd_bytes != file_size) {
				ret = TEE_CipherUpdate(cipher_aes_ops, buffer, rd_bytes,
							buffer, &rd_bytes);
			} else {
				ret = TEE_CipherDoFinal(cipher_aes_ops, buffer, rd_bytes,
							buffer, &rd_bytes);
			}
			if (ret != TEE_SUCCESS)
				goto out;

			TEE_DigestUpdate(ta_digest_ops, buffer, rd_bytes);

			wr_bytes = fwrite(buffer, 1, rd_bytes, wfp);
			if (wr_bytes != rd_bytes) {
				ret = TEE_ERROR_BAD_STATE;
				EMSG("fwrite metal error for ta fd=%d %d errno %d\n",
					wfp->_file, wr_bytes, errno);
				goto out;
			}
			pos += rd_bytes;
			/*IMSG("fread bytes %d, remain %d\n", rd_bytes,	file_size - pos);*/
		} else {
			EMSG("fread error %d errno %d @ fd=%d\n",
					rd_bytes, errno, fp->_file);
			ret = TEE_ERROR_BAD_STATE;
			goto out;
		}
	}

	rd_bytes = fread(signature, 1, buf_size, fp);
	if (rd_bytes != rsa_len) {
		EMSG("fread metal error for signature %d\n", rd_bytes);
		ret = TEE_ERROR_BAD_STATE;
		goto out;
	}

	memset(buffer, 0, rsa_len);
	wr_bytes = fwrite(buffer, 1, rsa_len, wfp);
	if (wr_bytes != rsa_len) {
		IMSG("fwrite rs error for ta %d\n", wr_bytes);
		ret = TEE_ERROR_BAD_STATE;
		goto out;
	}
	usleep(rand()%255);
	redundant_counter++;
	TEE_DigestDoFinal(ta_digest_ops, NULL, 0, hash, &hash_len);

	usleep(rand()%255);
	redundant_counter++;

	ret = TEE_AsymmetricVerifyDigest(ta_rsa_ops, NULL, 0,
				hash, hash_len,	signature,	rsa_len);
	if (ret != TEE_SUCCESS) {
		EMSG("Verify %s FAIL\n", ta_path);
	} else {
		IMSG("Verify %s PASS\n", ta_path);
		DMSG("%s\n", ((char *)h + h->config_offset));
		usleep(rand()%255);
		if (++redundant_counter != 6) {
			IMSG("redundant_counter error\n");
			ret = TEE_ERROR_SECURITY;
			goto out;
		}
		ret = syscall2(SYSCALL_SET_CONFIG,
				(char *)h + h->config_offset,
				h->config_size);
		if (ret != 0) {
			EMSG("set %s config error\n", ta_path);
			ret = TEE_ERROR_SECURITY;
			goto out;
		}
		usleep(rand()%255);
		if (redundant_counter != 6) {
			ret = TEE_ERROR_SECURITY;
			remove(ta_path);
			goto out;
		}
	}

	ret = 0;

out:
	if (rsa_key_obj)
		TEE_FreeTransientObject(rsa_key_obj);

	if (aes_key_obj)
		TEE_FreeTransientObject(aes_key_obj);

	if (ta_rsa_ops)
		TEE_FreeOperation(ta_rsa_ops);

	if (cipher_aes_ops)
		TEE_FreeOperation(cipher_aes_ops);

	if (ta_digest_ops)
		TEE_FreeOperation(ta_digest_ops);

	if (buffer)
		free(buffer);

	if (fp)
		fclose(fp);

	if (wfp)
		fclose(wfp);

	return ret;
}

static void auth_ta(void)
{
	FILE *fp = NULL;
	char *buffer = NULL;
	size_t buf_size = 8*1024;
	DIR *dir = NULL;
	char key[16] = {0};
	size_t rd_bytes = 0;
	size_t rsa_len = 0;
	size_t file_size = 0;
	TEE_OperationHandle certi_digest_ops = NULL;
	TEE_OperationHandle certi_rsa_ops = NULL;
	TEE_ObjectHandle rsa_key_obj = NULL;
	TEE_OperationHandle cipher_aes_ops = NULL;
	TEE_ObjectHandle aes_key_obj = NULL;
	struct dirent *d = NULL;
	struct mbedtls_pk_context ctx = {NULL};
	TEE_Attribute attrs[2] = {0};
	char file_name[NAME_MAX] = {0};
	unsigned char iv[16] = {0}, modules[256] = {0}, hash[64] = {0};
	size_t hash_len = sizeof(hash);
	int64_t exponent = 0;
	TEE_Result ret = TEE_SUCCESS;

	fp = fopen(APP_CRYPTO_KEY_FILE, "r");
	if (!fp) {
		EMSG("open %s failed\n", APP_CRYPTO_KEY_FILE);
		goto out;
	}

	if ((fread(key, 1, sizeof(key), fp)) != sizeof(key)) {
		EMSG("read %s failed\n", APP_CRYPTO_KEY_FILE);
		goto out;
	}

	fclose(fp);
	fp = NULL;

	/* make sure auth_ta() executes only once */
	unlink(APP_CRYPTO_KEY_FILE);

	dir = opendir(APP_DIR);
	if (dir == NULL) {
		EMSG("open app dir failed\n");
		goto out;
	}

	buffer = malloc(buf_size);
	if (!buffer)
		goto out;

	ret = TEE_AllocateOperation(&certi_rsa_ops,
				TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
				TEE_MODE_VERIFY, 2048);
	if (ret != TEE_SUCCESS)
		goto out;

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY,
					2048, &rsa_key_obj);
	if (ret != TEE_SUCCESS)
		goto out;

	mbedtls_pk_init(&ctx);
	ret = mbedtls_pk_parse_public_keyfile(&ctx, APP_RSA_PUB_KEY_FILE);
	if (ret != 0) {
		EMSG("error paring %s\n", APP_RSA_PUB_KEY_FILE);
		ret = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	rsa_len = mbedtls_rsa_get_len(mbedtls_pk_rsa(ctx));

	mbedtls_rsa_export_raw(mbedtls_pk_rsa(ctx), modules, rsa_len,
		NULL, 0, NULL, 0, NULL, 0, (void *)&exponent, sizeof(exponent));

	mbedtls_pk_free(&ctx);

	TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS,
				modules, rsa_len);
	TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT,
				&exponent, sizeof(exponent));

	ret = TEE_PopulateTransientObject(rsa_key_obj, attrs, 2);
	if (ret != TEE_SUCCESS)
		goto out;

	ret = TEE_SetOperationKey(certi_rsa_ops, rsa_key_obj);
	if (ret != TEE_SUCCESS)
		goto out;

	do {
		memset(file_name, 0, sizeof(file_name));
		strlcpy(file_name, APP_DIR, sizeof(file_name));
		d = readdir(dir);
		if (d && strstr(d->d_name, APP_CERTIFICATE_EXT)) {
			IMSG("Verifying %s\n", d->d_name);
			if (strlen(strstr(d->d_name, APP_CERTIFICATE_EXT)) != strlen(APP_CERTIFICATE_EXT))
				continue;
			strlcpy(file_name + strlen(file_name), d->d_name, sizeof(file_name));
			fp = fopen((const char *)file_name, "r");
			if (!fp)
				continue;

			redundant_counter = 0;

			fseek(fp, 0, SEEK_END);
			file_size = ftell(fp);
			fseek(fp, 0, SEEK_SET);

			ret = TEE_AllocateOperation(&certi_digest_ops, TEE_ALG_SHA256,
						TEE_MODE_DIGEST, 0);
			if (ret != TEE_SUCCESS)
				goto out;

			ret = TEE_AllocateOperation(&cipher_aes_ops, TEE_ALG_AES_CTS,
						TEE_MODE_DECRYPT, sizeof(key) * 8);
			if (ret != TEE_SUCCESS)
				goto out;

			ret = TEE_AllocateTransientObject(TEE_TYPE_AES, sizeof(key) * 8,
						&aes_key_obj);
			if (ret != TEE_SUCCESS)
				goto out;

			TEE_InitRefAttribute(&attrs[0], TEE_ATTR_SECRET_VALUE,
						key, sizeof(key));

			ret = TEE_PopulateTransientObject(aes_key_obj,
					attrs, 1);
			if (ret != TEE_SUCCESS)
				goto out;

			ret = TEE_SetOperationKey(cipher_aes_ops, aes_key_obj);
			if (ret != TEE_SUCCESS)
				goto out;

			TEE_FreeTransientObject(aes_key_obj);

			aes_key_obj = NULL;
			memset(iv, 0, sizeof(iv));
			TEE_CipherInit(cipher_aes_ops, iv, sizeof(iv));

			rd_bytes = fread(buffer, 1, file_size, fp);
			if (rd_bytes == file_size) {
				rd_bytes -= rsa_len;

				ret = TEE_CipherDoFinal(cipher_aes_ops, buffer, rd_bytes,
						buffer, &rd_bytes);
				if (ret != TEE_SUCCESS)
					goto out;

				TEE_DigestUpdate(certi_digest_ops, buffer, rd_bytes);
				/*udump("clear", buffer, rd_bytes);*/
			} else {
				IMSG("fread metal error %ld\n", (long)rd_bytes);
			}

			usleep(rand()%255);
			redundant_counter++;

			ret = TEE_DigestDoFinal(certi_digest_ops, NULL, 0, hash, &hash_len);
			TEE_FreeOperation(certi_digest_ops);
			certi_digest_ops = NULL;
			TEE_FreeOperation(cipher_aes_ops);
			cipher_aes_ops = NULL;
			/*udump("hash", hash, hash_len);*/

			usleep(rand()%255);
			redundant_counter++;

			ret = TEE_AsymmetricVerifyDigest(certi_rsa_ops, NULL, 0,
						hash, hash_len, buffer + file_size - rsa_len,
						rsa_len);
			if (ret != TEE_SUCCESS) {
				EMSG("Verify %s FAIL\n", file_name);
			} else {
				IMSG("Verify %s PASS\n", file_name);
				usleep(rand()%255);
				redundant_counter++;
				load_ta((struct certi_header *)buffer);
			}
			fclose(fp);
			fp = NULL;
		}
	} while (d);

out:
	if (fp)
		fclose(fp);
	if (buffer)
		free(buffer);
	if (dir)
		closedir(dir);
	if (rsa_key_obj)
		TEE_FreeTransientObject(rsa_key_obj);
	if (aes_key_obj)
		TEE_FreeTransientObject(aes_key_obj);
	if (certi_rsa_ops)
		TEE_FreeOperation(certi_rsa_ops);
	if (cipher_aes_ops)
		TEE_FreeOperation(cipher_aes_ops);
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
