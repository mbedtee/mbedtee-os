// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 *
 * Additional APIs for mbedtee which are not privoded by Mbed TLS
 * e.g. AES-CTS (CBC-CS3), e-GCD, DSA and partially cipher update
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#include <syscall.h>
#include <dirent.h>
#include <pthread.h>

#include "mbedtls.h"

/*
 * gcd -> GCD(x, y) -> u * x + y * v = gcd
 */
int mbedtls_mpi_egcd(mbedtls_mpi *gcd, mbedtls_mpi *u,
	mbedtls_mpi *v, const mbedtls_mpi *x, const mbedtls_mpi *y)
{
	int ret = -1;
	mbedtls_mpi T, R, TA, TC;
	mbedtls_mpi A, B, C, D, X, Y;

	/*
	 * Method 1: inverse order, from GCD multiply to X, Y  (e.g. X=13, Y=58)
	 * (use recursion function, consume lots of memory/stack, un-recommended)
	 * 58 % 13 = 6
	 * t = 4, ta= t * a = -8,	then b = a = -2; a = b - ta = 9  (a = -2  b = 1)
	 *
	 * 13 % 6 = 1
	 * t = 2, ta = t * a = 2,	then b = a = 1; a = b - ta = -2  (a =  1  b = 0)
	 *
	 * 6 % 1 = 0  -> GCD = 1
	 * t = 6, ta = t * a = 0,	then b = a = 0; a = b - ta = 1	 (a =  0  b = 1)
	 *
	 * Final result: gcd = GCD, u = a = 9, v = b = -2
	 */

	/*
	 * Method 2 (current implementation):
	 * normal order, from X, Y divided to GCD (e.g. X=13, Y=58)
	 *
	 * 58 % 13 = 6
	 * t = 4, ta= t * a = 4,	then b = a = 1; a = b - ta = -4 (a =  1   b = 0)
	 * t = 4, tc= t * c = 0,	then d = c = 0; c = d - tc = 1	(c =  0   d = 1)
	 *
	 * 13 % 6 = 1
	 * t = 2, ta = t * a = -8,	then b = a = -4; a = b - ta = 9 (a = -4   b = 1)
	 * t = 2, tc = t * c = 2,	then d = c = 1; c = d - tc = -2 (c =  1   d = 0)
	 *
	 * 6 % 1 = 0 -> GCD = 1
	 * t = 6, ta = t * a = 54,	then b = a = 9; a = b - ta = -58 (a =  9   b = -4)
	 * t = 6, tc = t * c = -12, then d = c = -2; c = d - tc = 13 (c = -2   d = 1)
	 *
	 * Final result: gcd = GCD, u = b = 9, v = d = -2
	 */

	mbedtls_mpi_init(&X);  mbedtls_mpi_init(&Y);
	mbedtls_mpi_init(&A);  mbedtls_mpi_init(&B);
	mbedtls_mpi_init(&C);  mbedtls_mpi_init(&D);
	mbedtls_mpi_init(&T);  mbedtls_mpi_init(&R);
	mbedtls_mpi_init(&TA); mbedtls_mpi_init(&TC);

	if ((mbedtls_mpi_cmp_int(x, 0) == 0) ||
		(mbedtls_mpi_cmp_mpi(x, y) == 0)) {
		MBEDTLS_MPI_CHK(mbedtls_mpi_lset(u, 1));
		MBEDTLS_MPI_CHK(mbedtls_mpi_lset(v, 0));
		goto cleanup;
	} else if (mbedtls_mpi_cmp_int(x, 0) == 0) {
		MBEDTLS_MPI_CHK(mbedtls_mpi_lset(u, 0));
		MBEDTLS_MPI_CHK(mbedtls_mpi_lset(v, 1));
		goto cleanup;
	}

	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&X, x));
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&Y, y));
	MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&A, 1));
	MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&B, 0));
	MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&C, 0));
	MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&D, 1));

	X.s = Y.s = 1;

	do {
		MBEDTLS_MPI_CHK(mbedtls_mpi_div_mpi(&T, &R, &Y, &X));

		MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&TA, &T, &A));
		MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&TA, &B, &TA));
		mbedtls_mpi_swap(&B, &A);
		mbedtls_mpi_swap(&A, &TA);

		MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&TC, &T, &C));
		MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&TC, &D, &TC));
		mbedtls_mpi_swap(&D, &C);
		mbedtls_mpi_swap(&C, &TC);

		mbedtls_mpi_swap(&Y, &X);
		mbedtls_mpi_swap(&X, &R);
		/*
		 * if div_mpi remainder is 0, done
		 * after swap, X holds the remainder
		 */
	} while (mbedtls_mpi_cmp_int(&X, 0) != 0);

	/*
	 * the last X holds the GCD
	 * after swap, Y is the holder
	 */
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(gcd, &Y));

	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(u, &B));
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(v, &D));

	u->s *= x->s;
	v->s *= y->s;

cleanup:
	mbedtls_mpi_free(&X);  mbedtls_mpi_free(&Y);
	mbedtls_mpi_free(&A);  mbedtls_mpi_free(&B);
	mbedtls_mpi_free(&C);  mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&T);  mbedtls_mpi_free(&R);
	mbedtls_mpi_free(&TA); mbedtls_mpi_free(&TC);

	return ret;
}

/*
 * AES-CTS buffer encryption/decryption
 * NIST SP800-38A Addendum (CTS = CBC-CS3)
 */
static int __mbedtls_aes_cts(mbedtls_cipher_context_t *cipher,
	const unsigned char *input, size_t length,
	unsigned char *output, size_t *olen, int is_final)
{
	int i, mode = MBEDTLS_AES_ENCRYPT;
	unsigned char temp[16];
	mbedtls_aes_context *ctx = cipher->cipher_ctx;
	unsigned char *iv = cipher->iv;

	if (cipher->operation == MBEDTLS_DECRYPT)
		mode = MBEDTLS_AES_DECRYPT;

	if (is_final == 0) {
		if (length % 16)
			return -EINVAL;

		*olen = length;

		if (mode == MBEDTLS_AES_DECRYPT) {
			while (length > 0) {
				memcpy(temp, input, 16);
				mbedtls_aes_crypt_ecb(ctx, mode, input, output);
				mbedtls_xor(output, output, iv, 16);
				memcpy(iv, temp, 16);

				input  += 16;
				output += 16;
				length -= 16;
			}
		} else {
			while (length > 0) {
				mbedtls_xor(output, input, iv, 16);
				mbedtls_aes_crypt_ecb(ctx, mode, output, output);
				memcpy(iv, output, 16);

				input  += 16;
				output += 16;
				length -= 16;
			}
		}
	} else {
		unsigned char cx[16], ccx[16];

		if (length <= 16)
			return -EINVAL;

		*olen = length;

		if (mode == MBEDTLS_AES_DECRYPT) {
			while (length > 32) {
				memcpy(temp, input, 16);
				mbedtls_aes_crypt_ecb(ctx, mode, input, output);
				mbedtls_xor(output, output, iv, 16);
				memcpy(iv, temp, 16);

				input  += 16;
				output += 16;
				length -= 16;
			}

			/*
			 * C'(x) = AES-DECRYPT <C(n-1)> (to buffer ccx)
			 * C(x) = Residue C(n) + C'(x)[Residue..Block_Len]
			 */
			mbedtls_aes_crypt_ecb(ctx, mode, input, ccx);
			length -= 16;
			input += 16;
			memcpy(cx, input, length);
			memcpy(cx + length, ccx + length, 16 - length);

			/*
			 * decrypt C(x) to buffer temp
			 * then XOR with C(n-2) or IV -> to get P(n-1)
			 */
			mbedtls_aes_crypt_ecb(ctx, mode, cx, temp);
			mbedtls_xor(output, temp, iv, 16);
			output += 16;

			/*
			 * XOR the C'(x) with C(x) -> to get Residue P(n)
			 */
			for (i = 0; i < length; i++)
				output[i] = (unsigned char)(ccx[i] ^ cx[i]);
		} else {
			while (length > 32) {
				mbedtls_xor(output, input, iv, 16);
				mbedtls_aes_crypt_ecb(ctx, mode, output, output);
				memcpy(iv, output, 16);

				input  += 16;
				output += 16;
				length -= 16;
			}

			/*
			 * P'(n) = Residue P(n) + 0[Residue..Block_Len]
			 * C(x) = AES-ENCRYPT <C(n-2) XOR P(n-1)>
			 * C(y) = AES-ENCRYPT <P'(n) XOR C(x)>
			 * C(n-1)=C(y)[1..Block_Len]
			 * C(n)=C(x)[1..Residue]
			 */
			mbedtls_xor(cx, input, iv, 16);

			mbedtls_aes_crypt_ecb(ctx, mode, cx, cx);

			/* build P'(n) into buffer temp */
			memset(temp, 0, sizeof(temp));
			memcpy(temp, input + 16, length - 16);

			/* get C(y) into buffer ccx */
			mbedtls_xor(ccx, temp, cx, 16);

			mbedtls_aes_crypt_ecb(ctx, mode, ccx, ccx);

			/* put result to C(n-1) and C(n) */
			memcpy(output, ccx, 16);
			memcpy(output + 16, cx, length - 16);
		}
	}

	return 0;
}

int mbedtls_aes_cts(mbedtls_cipher_context_t *cipher,
	void *input, size_t ilen, void *output, size_t *olen, bool is_final)
{
	int ret = 0, copy_len = 0;
	size_t blocksz = 0, offset = 0, tmp = 0;

	blocksz = mbedtls_cipher_get_block_size(cipher);

	*olen = 0;

	if (ilen < blocksz - cipher->unprocessed_len) {
		memcpy(&cipher->unprocessed_data[cipher->unprocessed_len], input, ilen);
		cipher->unprocessed_len += ilen;
		goto out;
	}

	if (cipher->unprocessed_len) {
		copy_len = blocksz - cipher->unprocessed_len;
		memcpy(&cipher->unprocessed_data[cipher->unprocessed_len], input, copy_len);

		cipher->unprocessed_len = 0;

		/* cts-final need at least 2 blocks (final-ilen > 16 bytes) */
		if (is_final && (ilen - copy_len <= blocksz)) {
			unsigned char ifinal[32] = {0};

			memcpy(ifinal, &cipher->unprocessed_data, blocksz);
			memcpy(ifinal + blocksz, input + copy_len, ilen - copy_len);
			return __mbedtls_aes_cts(cipher, ifinal, blocksz + ilen - copy_len, output, olen, is_final);
		}

		ret = __mbedtls_aes_cts(cipher, cipher->unprocessed_data, blocksz, output, &tmp, is_final);
		if (ret != 0)
			goto out;

		*olen += blocksz;
		output += blocksz;

		input += copy_len;
		ilen -= copy_len;
	}

	if (!is_final) {
		copy_len = ilen % blocksz;
		if (copy_len != 0) {
			memcpy(cipher->unprocessed_data, input + (ilen - copy_len), copy_len);
			cipher->unprocessed_len += copy_len;
			ilen -= copy_len;
		}
	}

	if (ilen) {
		ret = __mbedtls_aes_cts(cipher, input, ilen, output, &offset, is_final);
		if (ret != 0)
			goto out;
	}

out:
	if (is_final && cipher->unprocessed_len)
		ret = -EINVAL;

	*olen += offset;
	return ret;
}

/*
 * copied from lib/mbedtls/library/aes.c, modification
 * is intended to support the partially cipher text update
 */
static void mbedtls_gf128mul_x_ble(
	unsigned char r[16], const unsigned char x[16])
{
	uint64_t a, b, ra, rb;

	a = MBEDTLS_GET_UINT64_LE(x, 0);
	b = MBEDTLS_GET_UINT64_LE(x, 8);

	ra = (a << 1)  ^ 0x0087 >> (8 - ((b >> 63) << 3));
	rb = (a >> 63) | (b << 1);

	MBEDTLS_PUT_UINT64_LE(ra, r, 0);
	MBEDTLS_PUT_UINT64_LE(rb, r, 8);
}

/*
 * copied from lib/mbedtls/library/aes.c, modification
 * is intended to support the partially cipher text update
 */
static int __mbedtls_aes_xts(mbedtls_cipher_context_t *cipher,
	const unsigned char *input, size_t length,
	unsigned char *output, size_t *olen, int is_final)
{
	size_t blocks = length / 16;
	size_t leftover = length % 16;
	unsigned char tweak[16];
	unsigned char prev_tweak[16];
	unsigned char tmp[16];
	mbedtls_aes_xts_context *ctx = cipher->cipher_ctx;
	int mode = MBEDTLS_AES_ENCRYPT;
	size_t i;

	if (cipher->operation == MBEDTLS_DECRYPT)
		mode = MBEDTLS_AES_DECRYPT;

	if ((length < 16) || (length > (1 << 20) * 16))
		return -EINVAL;

	*olen = length;

	/* continue with last tweak. */
	memcpy(tweak, cipher->iv, 16);

	while (blocks--) {
		if (leftover && (mode == MBEDTLS_AES_DECRYPT) && blocks == 0) {
			memcpy(prev_tweak, tweak, sizeof(tweak));
			mbedtls_gf128mul_x_ble(tweak, tweak);
		}

		mbedtls_xor(tmp, input, tweak, 16);
		mbedtls_aes_crypt_ecb(&ctx->crypt, mode, tmp, tmp);
		mbedtls_xor(output, tmp, tweak, 16);

		/* compute tweak for next block. */
		mbedtls_gf128mul_x_ble(tweak, tweak);

		output += 16;
		input += 16;
	}

	if (leftover) {
		unsigned char *t = mode == MBEDTLS_AES_DECRYPT ? prev_tweak : tweak;
		unsigned char *prev_output = output - 16;

		for (i = 0; i < leftover; i++)
			output[i] = prev_output[i];

		mbedtls_xor(tmp, input, t, leftover);
		mbedtls_xor(tmp + i, prev_output + i, t + i, 16 - i);
		mbedtls_aes_crypt_ecb(&ctx->crypt, mode, tmp, tmp);
		mbedtls_xor(prev_output, tmp, t, 16);
	}

	/* update tweak for next block. */
	memcpy(cipher->iv, tweak, 16);
	return 0;
}

int mbedtls_aes_xts(mbedtls_cipher_context_t *cipher,
	void *input, size_t ilen, void *output, size_t *olen, bool is_final)
{
	int ret = 0, copy_len = 0;
	size_t blocksz = 0, offset = 0, tmp = 0;

	blocksz = mbedtls_cipher_get_block_size(cipher);

	*olen = 0;

	if (ilen < blocksz - cipher->unprocessed_len) {
		memcpy(&cipher->unprocessed_data[cipher->unprocessed_len], input, ilen);
		cipher->unprocessed_len += ilen;
		goto out;
	}

	if (cipher->unprocessed_len) {
		copy_len = blocksz - cipher->unprocessed_len;
		memcpy(&cipher->unprocessed_data[cipher->unprocessed_len], input, copy_len);

		cipher->unprocessed_len = 0;

		/* let the final-ilen >= 16 bytes */
		if (is_final && (ilen - copy_len < blocksz)) {
			unsigned char ifinal[32] = {0};

			memcpy(ifinal, &cipher->unprocessed_data, blocksz);
			memcpy(ifinal + blocksz, input + copy_len, ilen - copy_len);
			return __mbedtls_aes_xts(cipher, ifinal, blocksz + ilen - copy_len, output, olen, is_final);
		}

		ret = __mbedtls_aes_xts(cipher, cipher->unprocessed_data, blocksz, output, &tmp, is_final);
		if (ret != 0)
			goto out;

		*olen += blocksz;
		output += blocksz;

		input += copy_len;
		ilen -= copy_len;
	}

	if (!is_final) {
		copy_len = ilen % blocksz;
		if (copy_len != 0) {
			memcpy(cipher->unprocessed_data, input + (ilen - copy_len), copy_len);
			cipher->unprocessed_len += copy_len;
			ilen -= copy_len;
		}
	}

	if (ilen) {
		ret = __mbedtls_aes_xts(cipher, input, ilen, output, &offset, is_final);
		if (ret != 0)
			goto out;
	}

out:
	if (is_final && cipher->unprocessed_len)
		ret = -EINVAL;

	*olen += offset;
	return ret;
}

int mbedtls_ecb_crypt(mbedtls_cipher_context_t *cipher,
	void *input, size_t ilen, void *output, size_t *olen, bool is_final)
{
	int ret = 0, copy_len = 0;
	size_t blocksz = 0, offset = 0, tmp = 0;

	blocksz = mbedtls_cipher_get_block_size(cipher);

	*olen = 0;

	if (ilen < blocksz - cipher->unprocessed_len) {
		memcpy(&cipher->unprocessed_data[cipher->unprocessed_len], input, ilen);
		cipher->unprocessed_len += ilen;
		goto out;
	}

	if (cipher->unprocessed_len) {
		copy_len = blocksz - cipher->unprocessed_len;
		memcpy(&cipher->unprocessed_data[cipher->unprocessed_len], input, copy_len);
		ret = mbedtls_cipher_update(cipher, cipher->unprocessed_data, blocksz, output, &tmp);
		if (ret != 0)
			goto out;

		*olen += blocksz;
		output += blocksz;
		cipher->unprocessed_len = 0;

		input += copy_len;
		ilen -= copy_len;
	}

	copy_len = ilen % blocksz;
	if (copy_len != 0) {
		memcpy(cipher->unprocessed_data, input + (ilen - copy_len), copy_len);
		cipher->unprocessed_len += copy_len;
		ilen -= copy_len;
	}

	while (ilen) {
		ret = mbedtls_cipher_update(cipher, input + offset,
				blocksz, output + offset, &tmp);
		if (ret != 0)
			goto out;

		ilen -= blocksz;
		offset += blocksz;
	}

out:
	if (is_final && cipher->unprocessed_len)
		ret = -EINVAL;
	*olen += offset;
	return ret;
}

#define DSA_VALIDATE_RET(cond)							\
	do {												\
		if (!(cond))									\
			return MBEDTLS_ERR_DSA_BAD_INPUT_DATA;		\
	} while (0)

void mbedtls_dsa_init(mbedtls_dsa_context *ctx)
{
	memset(ctx, 0, sizeof(mbedtls_dsa_context));
}

void mbedtls_dsa_free(mbedtls_dsa_context *ctx)
{
	if (ctx == NULL)
		return;

	mbedtls_mpi_free(&ctx->X);
	mbedtls_mpi_free(&ctx->Y);
	mbedtls_mpi_free(&ctx->G);
	mbedtls_mpi_free(&ctx->Q);
	mbedtls_mpi_free(&ctx->P);
}

static int mbedtls_dsa_check_pq(int modulus, int divisor)
{
	int ret = -1;

	switch (modulus) {
	case 2048:
		if (divisor == 224 || divisor == 256)
			ret = 0;
		break;
	case 3072:
		if (divisor == 256)
			ret = 0;
		break;
	default:
		if (modulus >= 512 && modulus <= 1024 &&
			 !(modulus % 64) && (divisor == 160))
			ret = 0;
		break;
	}

	return ret;
}

int mbedtls_dsa_check_pubkey(const mbedtls_dsa_context *ctx)
{
	int modulus, divisor;

	DSA_VALIDATE_RET(ctx != NULL);

	modulus = mbedtls_mpi_bitlen(&ctx->P);
	divisor = mbedtls_mpi_bitlen(&ctx->Q);

	if (mbedtls_dsa_check_pq(modulus, divisor) != 0)
		return MBEDTLS_ERR_DSA_KEY_CHECK_FAILED;

	if (mbedtls_mpi_bitlen(&ctx->Y) > modulus)
		return MBEDTLS_ERR_DSA_KEY_CHECK_FAILED;

	if (mbedtls_mpi_get_bit(&ctx->Q, 0) == 0 ||
		mbedtls_mpi_get_bit(&ctx->P, 0) == 0 ||
		mbedtls_mpi_bitlen(&ctx->G) < 2 ||
		mbedtls_mpi_cmp_mpi(&ctx->G, &ctx->P) >= 0)
		return MBEDTLS_ERR_DSA_KEY_CHECK_FAILED;

	return 0;
}

int mbedtls_dsa_check_privkey(const mbedtls_dsa_context *ctx)
{
	int modulus, divisor;

	DSA_VALIDATE_RET(ctx != NULL);

	modulus = mbedtls_mpi_bitlen(&ctx->P);
	divisor = mbedtls_mpi_bitlen(&ctx->Q);

	if (mbedtls_dsa_check_pq(modulus, divisor) != 0)
		return MBEDTLS_ERR_DSA_KEY_CHECK_FAILED;

	if (mbedtls_mpi_bitlen(&ctx->X) > divisor)
		return MBEDTLS_ERR_DSA_KEY_CHECK_FAILED;

	if (mbedtls_mpi_get_bit(&ctx->Q, 0) == 0 ||
		mbedtls_mpi_get_bit(&ctx->P, 0) == 0 ||
		mbedtls_mpi_bitlen(&ctx->G) < 2 ||
		mbedtls_mpi_cmp_mpi(&ctx->G, &ctx->P) >= 0)
		return MBEDTLS_ERR_DSA_KEY_CHECK_FAILED;

	return 0;
}

static int mbedtls_dsa_check_params(const mbedtls_dsa_context *ctx)
{
	int modulus, divisor;

	DSA_VALIDATE_RET(ctx != NULL);

	modulus = mbedtls_mpi_bitlen(&ctx->P);
	divisor = mbedtls_mpi_bitlen(&ctx->Q);

	if (mbedtls_dsa_check_pq(modulus, divisor) != 0)
		return MBEDTLS_ERR_DSA_KEY_CHECK_FAILED;

	if (mbedtls_mpi_get_bit(&ctx->Q, 0) == 0 ||
		mbedtls_mpi_get_bit(&ctx->P, 0) == 0 ||
		mbedtls_mpi_bitlen(&ctx->G) < 2 ||
		mbedtls_mpi_cmp_mpi(&ctx->G, &ctx->P) >= 0)
		return MBEDTLS_ERR_DSA_KEY_CHECK_FAILED;

	return 0;
}

int mbedtls_dsa_gen_key(mbedtls_dsa_context *ctx,
		 int (*f_rng)(void *, unsigned char *, size_t),
		 void *p_rng)
{
	int count = 0, q_len = 0;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

	DSA_VALIDATE_RET(ctx != NULL);
	DSA_VALIDATE_RET(f_rng != NULL);

	ret = mbedtls_dsa_check_params(ctx);
	if (ret != 0)
		return ret;

	mbedtls_mpi_init(&ctx->X);
	mbedtls_mpi_init(&ctx->Y);

	q_len = mbedtls_mpi_size(&ctx->Q);

	/* Generate X, that 0 < X < Q, [1, Q - 1] */
	do {
		MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&ctx->X, q_len, f_rng, p_rng));

		while (mbedtls_mpi_cmp_mpi(&ctx->X, &ctx->Q) >= 0)
			MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&ctx->X, 1));

		if (count++ > 10) {
			ret = MBEDTLS_ERR_DSA_RNG_FAILED;
			goto cleanup;
		}
	} while (mbedtls_mpi_cmp_int(&ctx->X, 1) < 0);

	/* Y = G^X mod P */
	MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&ctx->Y, &ctx->G, &ctx->X, &ctx->P, NULL));

cleanup:
	if (ret != 0) {
		mbedtls_mpi_free(&ctx->Y);
		mbedtls_mpi_free(&ctx->X);
		if (ret != MBEDTLS_ERR_DSA_RNG_FAILED)
			return MBEDTLS_ERR_DSA_KEY_GEN_FAILED | ret;
	}

	return ret;
}

int mbedtls_dsa_gen_params(mbedtls_dsa_context *ctx,
		 int (*f_rng)(void *, unsigned char *, size_t),
		 void *p_rng, unsigned int nbits)
{
	int count = 0, q_len = 0, t_len = 0;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	mbedtls_mpi T, H, Q2;

	DSA_VALIDATE_RET(ctx != NULL);
	DSA_VALIDATE_RET(f_rng != NULL);

	if ((nbits == 3072) || (nbits == 2048))
		q_len = 32;
	else if (nbits >= 512 && nbits <= 1024 && !(nbits % 64))
		q_len = 20;
	else
		return MBEDTLS_ERR_DSA_BAD_INPUT_DATA;

	mbedtls_mpi_init(&ctx->P);
	mbedtls_mpi_init(&ctx->Q);
	mbedtls_mpi_init(&ctx->G);
	mbedtls_mpi_init(&T);
	mbedtls_mpi_init(&H);
	mbedtls_mpi_init(&Q2);

	t_len = (nbits >> 3) - q_len;

	MBEDTLS_MPI_CHK(mbedtls_mpi_gen_prime(&ctx->Q, q_len << 3,
			MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR, f_rng, p_rng));

	do {
		MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&T, t_len, f_rng, p_rng));
		/* Set MSB, let T * Q close to (1 << nbits) */
		MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&T, (t_len << 3) - 1, 1));
		MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&T, (t_len << 3) - 2, 1));

		MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&Q2, &ctx->Q, &ctx->Q));

		/* P = T * Q, T always even for performance */
		do {
			MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&T, &T, &ctx->Q));
			MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&T, 0, 0));
			MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&ctx->P, &T, &ctx->Q));
		} while (mbedtls_mpi_bitlen(&ctx->P) < nbits);

		/*
		 * P = T * Q + 1, T = (P - 1) / Q,
		 * Q will be the prime divisor of P - 1
		 */
		MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&ctx->P, &ctx->P, 1));

		count = 0;
		do {
			count += 2;
			MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&ctx->P, &ctx->P, &Q2));
			if (mbedtls_mpi_bitlen(&ctx->P) > nbits)
				break;
		} while (mbedtls_mpi_is_prime_ext(&ctx->P, 6, f_rng, p_rng));
	} while (mbedtls_mpi_bitlen(&ctx->P) > nbits);

	/* T = T + count */
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&T, &T, count));

	MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&H, 0, 1));

	/* Find G，T = (P - 1) / Q, G = H^T mod P*/
	do {
		MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&H, &H, 1));
		MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&ctx->G, &H, &T, &ctx->P, NULL));
	} while (mbedtls_mpi_cmp_int(&ctx->G, 1) == 0);

cleanup:
	mbedtls_mpi_free(&T);
	mbedtls_mpi_free(&H);
	mbedtls_mpi_free(&Q2);
	if (ret != 0) {
		mbedtls_mpi_free(&ctx->P);
		mbedtls_mpi_free(&ctx->Q);
		mbedtls_mpi_free(&ctx->G);
		return MBEDTLS_ERR_DSA_PARAM_GEN_FAILED | ret;
	}

	return ret;
}

int mbedtls_dsa_import_raw(mbedtls_dsa_context *ctx,
					unsigned char const *P, size_t P_len,
					unsigned char const *Q, size_t Q_len,
					unsigned char const *G, size_t G_len,
					unsigned char const *Y, size_t Y_len,
					unsigned char const *X, size_t X_len)
{
	int ret = 0;

	DSA_VALIDATE_RET(ctx != NULL);

	if (P != NULL)
		MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->P, P, P_len));

	if (Q != NULL)
		MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->Q, Q, Q_len));

	if (G != NULL)
		MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->G, G, G_len));

	if (Y != NULL)
		MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->Y, Y, Y_len));

	if (X != NULL)
		MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&ctx->X, X, X_len));

cleanup:
	if (ret != 0)
		return MBEDTLS_ERR_DSA_BAD_INPUT_DATA | ret;

	return 0;
}

int mbedtls_dsa_export_raw(const mbedtls_dsa_context *ctx,
								unsigned char *P, size_t P_len,
								unsigned char *Q, size_t Q_len,
								unsigned char *G, size_t G_len,
								unsigned char *Y, size_t Y_len,
								unsigned char *X, size_t X_len)
{
	int ret = 0;

	DSA_VALIDATE_RET(ctx != NULL);

	if (P != NULL)
		MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&ctx->P, P, P_len));

	if (Q != NULL)
		MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&ctx->Q, Q, Q_len));

	if (G != NULL)
		MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&ctx->G, G, G_len));

	if (Y != NULL)
		MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&ctx->Y, Y, Y_len));

	if (X != NULL)
		MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&ctx->X, X, X_len));

cleanup:

	return ret;
}

/*
 * Convert a signature (given by context) to ASN.1
 */
static int dsa_signature_to_asn1(const mbedtls_mpi *r,
	const mbedtls_mpi *s, unsigned char *sig, size_t *slen)
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	unsigned char buf[256];
	unsigned char *p = buf + sizeof(buf);
	size_t len = 0;

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, s));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, r));

	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf,
			MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	memcpy(sig, p, len);
	*slen = len;

	return 0;
}

/*
 * Convert a signature (given by ASN.1 context)
 */
static int dsa_signature_from_asn1(mbedtls_mpi *r,
	mbedtls_mpi *s, const unsigned char *sig, size_t slen)
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	unsigned char *p = (unsigned char *)sig;
	const unsigned char *end = sig + slen;
	size_t len;

	ret = mbedtls_asn1_get_tag(&p, end, &len,
		MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
	if (ret != 0) {
		ret += MBEDTLS_ERR_DSA_BAD_INPUT_DATA;
		return ret;
	}

	if (p + len != end) {
		ret = MBEDTLS_ERR_DSA_BAD_INPUT_DATA +
			  MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
		return ret;
	}

	ret = mbedtls_asn1_get_mpi(&p, end, r);
	ret |= mbedtls_asn1_get_mpi(&p, end, s);

	if (ret != 0) {
		ret += MBEDTLS_ERR_DSA_BAD_INPUT_DATA;
		return ret;
	}

	return 0;
}

int mbedtls_dsa_sign(mbedtls_dsa_context *ctx,
					int (*f_rng)(void *, unsigned char *, size_t),
					void *p_rng,
					unsigned int hashlen,
					const unsigned char *hash,
					unsigned char *sig,
					size_t *slen)
{
	int count = 0;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	mbedtls_mpi B, K, H, R, S;
	size_t q_len = 0;

	DSA_VALIDATE_RET(ctx != NULL);
	DSA_VALIDATE_RET(f_rng != NULL);
	DSA_VALIDATE_RET(hash != NULL);
	DSA_VALIDATE_RET(sig != NULL);
	DSA_VALIDATE_RET(hashlen != 0);

	ret = mbedtls_dsa_check_privkey(ctx);
	if (ret != 0)
		return ret;

	mbedtls_mpi_init(&B);
	mbedtls_mpi_init(&K);
	mbedtls_mpi_init(&H);
	mbedtls_mpi_init(&R);
	mbedtls_mpi_init(&S);

	q_len = mbedtls_mpi_size(&ctx->Q);

	/* Generate K, that 0 < K < Q, [1, Q - 1] */
	do {
		MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&K, q_len, f_rng, p_rng));

		while (mbedtls_mpi_cmp_mpi(&K, &ctx->Q) >= 0)
			MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&K, 1));

		if (count++ > 10) {
			ret = MBEDTLS_ERR_DSA_RNG_FAILED;
			goto cleanup;
		}
	} while (mbedtls_mpi_cmp_int(&K, 1) < 0);

	/* Generate blinding, that 0 < blind < Q, [1, Q - 1] */
	do {
		MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&B, q_len, f_rng, p_rng));

		while (mbedtls_mpi_cmp_mpi(&B, &ctx->Q) >= 0)
			MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&B, 1));

		if (count++ > 10) {
			ret = MBEDTLS_ERR_DSA_RNG_FAILED;
			goto cleanup;
		}
	} while (mbedtls_mpi_cmp_int(&B, 1) < 0);

	MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&H, hash, hashlen));

	/* Generate R, that R = (G^K mod P) mod Q */
	{
		MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&R, &ctx->G, &K, &ctx->P, NULL));
		MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&R, &R, &ctx->Q));
	}

	/* s = K^-1 (H + XR) (mod Q) = B(KB^-1 * H + KB^-1 * XR) (mod Q) */
	{
		/* K = KB^-1 */
		MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&K, &K, &B));
		MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&K, &K, &ctx->Q));

		/* S = KB^-1 * XR */
		MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&S, &ctx->X, &R));
		MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&S, &S, &K));
		MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&S, &S, &ctx->Q));

		/* H = KB^-1 * H */
		MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&H, &H, &K));
		MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&H, &H, &ctx->Q));

		/* S = B(KB^-1 * H + KB^-1 * XR) -> S = (H + XR)/K */
		MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&S, &S, &H));
		MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&S, &S, &B));
		MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&S, &S, &ctx->Q));
	}

	MBEDTLS_MPI_CHK(dsa_signature_to_asn1(&R, &S, sig, slen));

cleanup:
	mbedtls_mpi_free(&B);
	mbedtls_mpi_free(&K);
	mbedtls_mpi_free(&H);
	mbedtls_mpi_free(&R);
	mbedtls_mpi_free(&S);
	return ret;
}

int mbedtls_dsa_verify(mbedtls_dsa_context *ctx,
					  int (*f_rng)(void *, unsigned char *, size_t),
					  void *p_rng,
					  unsigned int hashlen,
					  const unsigned char *hash,
					  const unsigned char *sig,
					  size_t slen)
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	mbedtls_mpi U1, U2, W, R, S, V;

	DSA_VALIDATE_RET(ctx != NULL);
	DSA_VALIDATE_RET(f_rng != NULL);
	DSA_VALIDATE_RET(hash != NULL);
	DSA_VALIDATE_RET(sig != NULL);
	DSA_VALIDATE_RET(hashlen != 0);

	ret = mbedtls_dsa_check_pubkey(ctx);
	if (ret != 0)
		return ret;

	mbedtls_mpi_init(&U1);
	mbedtls_mpi_init(&U2);
	mbedtls_mpi_init(&W);
	mbedtls_mpi_init(&R);
	mbedtls_mpi_init(&S);
	mbedtls_mpi_init(&V);

	ret = dsa_signature_from_asn1(&R, &S, sig, slen);
	if (ret != 0) {
		ret = MBEDTLS_ERR_DSA_VERIFY_FAILED;
		goto cleanup;
	}

	if (!(mbedtls_mpi_cmp_int(&R, 0) > 0 && mbedtls_mpi_cmp_mpi(&R, &ctx->Q) < 0) ||
		!(mbedtls_mpi_cmp_int(&S, 0) > 0 && mbedtls_mpi_cmp_mpi(&S, &ctx->Q) < 0)) {
		ret = MBEDTLS_ERR_DSA_VERIFY_FAILED;
		goto cleanup;
	}

	MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&U1, hash, hashlen));

	/*	W = S^-1 (mod Q) */
	MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&W, &S, &ctx->Q));

	/* U1 = (hash * W) (mod Q) */
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&U1, &U1, &W));
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&U1, &U1, &ctx->Q));

	/* U2 = (R * W) (mod Q) */
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&U2, &R, &W));
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&U2, &U2, &ctx->Q));

	/* V = ((G^U1 * Y^U2) mod P) mod Q */
	MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&S, &ctx->G, &U1, &ctx->P, NULL));
	MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&V, &ctx->Y, &U2, &ctx->P, NULL));
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&V, &S, &V));
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&V, &V, &ctx->P));
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&V, &V, &ctx->Q));

	ret = mbedtls_mpi_cmp_mpi(&V, &R);
	if (ret != 0) {
		ret = MBEDTLS_ERR_DSA_VERIFY_FAILED;
		goto cleanup;
	}

cleanup:
	mbedtls_mpi_free(&U1);
	mbedtls_mpi_free(&U2);
	mbedtls_mpi_free(&W);
	mbedtls_mpi_free(&R);
	mbedtls_mpi_free(&S);
	mbedtls_mpi_free(&V);
	return ret;
}
