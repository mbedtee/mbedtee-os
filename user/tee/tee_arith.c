// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * GlobalPlatform TEE MPI (Multi-Precision Integer)
 */

#include <utrace.h>

#include <tee_internal_api.h>
#include "tee_api_priv.h"

struct bignum {
	int32_t s;
	uint32_t n;
};

size_t TEE_BigIntFMMSizeInU32(size_t modulusSizeInBits)
{
	return (((modulusSizeInBits) + 32 - 1) / 4);
}

size_t TEE_BigIntFMMContextSizeInU32(size_t modulusSizeInBits)
{
	return (((modulusSizeInBits) + 32 - 1) / 4);
}

void TEE_BigIntInit(TEE_BigInt *bigInt, size_t len)
{
	struct bignum *b = (struct bignum *)bigInt;

	memset(bigInt, 0, len * sizeof(uint32_t));

	b->s = 1;
	b->n = len - (sizeof(struct bignum) / sizeof(uint32_t));
	udump("b", b, ((*(int *)((char *)b + 4)) * 4) + 8);
}

void TEE_BigIntInitFMM(TEE_BigIntFMM *bigInt, size_t len)
{
	TEE_BigIntInit(bigInt, len);
}

void TEE_BigIntInitFMMContext(
	TEE_BigIntFMMContext *context,
	size_t len, TEE_BigInt *modulus)
{
}

TEE_Result TEE_BigIntInitFMMContext1(
	TEE_BigIntFMMContext *context,
	size_t len, TEE_BigInt *modulus)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result __TEE_MPI2BigInt(const mbedtls_mpi *X,
	TEE_BigInt *bigInt)
{
	int ret = -1;
	struct bignum *b = (struct bignum *)bigInt;

	ret = mbedtls_mpi_write_binary_le(X, (void *)(b + 1),
			b->n * sizeof(uint32_t));
	if (ret == MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL)
		return TEE_ERROR_OVERFLOW;
/*
 *	b->n = X->n * (sizeof(mbedtls_mpi_uint) / sizeof(uint32_t));
 */
	b->s = X->s;

	return ret;
}

static TEE_Result __TEE_BigInt2MPI(mbedtls_mpi *X,
	const TEE_BigInt *bigInt)
{
	int ret = -1;
	struct bignum *b = (struct bignum *)bigInt;

	ret = mbedtls_mpi_read_binary_le(X, (void *)(b + 1),
			b->n * sizeof(uint32_t));

	X->s = b->s;

	return ret;
}

TEE_Result TEE_BigIntConvertFromOctetString(
	TEE_BigInt *dest, uint8_t *buffer,
	size_t bufferLen, int32_t sign)
{
	mbedtls_mpi X;
	TEE_Result ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&X);

	udump("buffer", buffer, bufferLen);

	if (mbedtls_mpi_read_binary(&X, buffer, bufferLen)) {
		ret = ENOMEM;
		goto out;
	}

	if (sign < 0)
		X.s = -1;

	ret = __TEE_MPI2BigInt(&X, dest);
	udump("dest", dest, ((*(int *)((char *)dest + 4)) * 4) + 8);

out:
	mbedtls_mpi_free(&X);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_OVERFLOW)
		TEE_Panic(ret);
	return ret;
}

TEE_Result TEE_BigIntConvertToOctetString(void *buffer,
	size_t *bufferLen, TEE_BigInt *bigInt)
{
	mbedtls_mpi X;
	size_t len = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&X);

	ret = __TEE_BigInt2MPI(&X, bigInt);
	if (ret != 0)
		goto out;

	len = mbedtls_mpi_size(&X);

	if (*bufferLen < len) {
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	if (mbedtls_mpi_write_binary(&X, buffer, len)) {
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	*bufferLen = len;
out:
	mbedtls_mpi_free(&X);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(ret);

	return ret;
}

void TEE_BigIntConvertFromS32(TEE_BigInt *dest, int32_t shortVal)
{
	int sign = 1;
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (shortVal < 0) {
		shortVal = -shortVal;
		sign = -1;
	}

	shortVal = __builtin_bswap32(shortVal);

	ret = TEE_BigIntConvertFromOctetString(dest, (uint8_t *)&shortVal,
			sizeof(int32_t), sign);
	if (ret != 0)
		TEE_Panic(ret);
}

TEE_Result TEE_BigIntConvertToS32(int32_t *dest, TEE_BigInt *src)
{
	int32_t val = 0;
	mbedtls_mpi X;
	size_t len = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&X);

	ret = __TEE_BigInt2MPI(&X, src);
	if (ret != 0)
		goto out;

	len = mbedtls_mpi_size(&X);
	if (len > sizeof(val)) {
		ret = TEE_ERROR_OVERFLOW;
		goto out;
	}

	if (mbedtls_mpi_write_binary(&X, (void *)&val, len)) {
		ret = TEE_ERROR_OVERFLOW;
		goto out;
	}

	val = __builtin_bswap32(val);

	if ((val < 0 && X.s != -1) ||
		(val >= 0 && X.s != 1)) {
		ret = TEE_ERROR_OVERFLOW;
		goto out;
	}

	*dest = val;

out:
	mbedtls_mpi_free(&X);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_OVERFLOW)
		TEE_Panic(ret);

	return ret;
}

int32_t TEE_BigIntCmp(TEE_BigInt *op1, TEE_BigInt *op2)
{
	mbedtls_mpi X1, X2;
	int32_t ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&X1);
	mbedtls_mpi_init(&X2);

	ret = __TEE_BigInt2MPI(&X1, op1);
	ret |= __TEE_BigInt2MPI(&X2, op2);
	if (ret != 0)
		TEE_Panic(ret);

	ret = mbedtls_mpi_cmp_mpi(&X1, &X2);

	mbedtls_mpi_free(&X1);
	mbedtls_mpi_free(&X2);

	return ret;
}

int32_t TEE_BigIntCmpS32(TEE_BigInt *op, int32_t shortVal)
{
	mbedtls_mpi X;
	int32_t ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&X);

	ret = __TEE_BigInt2MPI(&X, op);
	if (ret != 0)
		TEE_Panic(ret);

	ret = mbedtls_mpi_cmp_int(&X, shortVal);

	mbedtls_mpi_free(&X);

	return ret;
}

void TEE_BigIntShiftRight(TEE_BigInt *dest, TEE_BigInt *op, size_t bits)
{
	mbedtls_mpi X;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&X);

	ret = __TEE_BigInt2MPI(&X, op);
	if (ret != 0)
		TEE_Panic(ret);

	ret = mbedtls_mpi_shift_r(&X, bits);
	if (ret != 0)
		TEE_Panic(ret);

	ret = __TEE_MPI2BigInt(&X, dest);
	if (ret != 0)
		TEE_Panic(ret);

	mbedtls_mpi_free(&X);
}

bool TEE_BigIntGetBit(TEE_BigInt *src, uint32_t bitIndex)
{
	mbedtls_mpi X;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&X);

	ret = __TEE_BigInt2MPI(&X, src);
	if (ret != 0)
		TEE_Panic(ret);

	ret = mbedtls_mpi_get_bit(&X, bitIndex);

	mbedtls_mpi_free(&X);

	return ret;
}

uint32_t TEE_BigIntGetBitCount(TEE_BigInt *src)
{
	mbedtls_mpi X;
	uint32_t ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&X);

	ret = __TEE_BigInt2MPI(&X, src);
	if (ret != 0)
		TEE_Panic(ret);

	ret = mbedtls_mpi_bitlen(&X);

	mbedtls_mpi_free(&X);

	return ret;
}

TEE_Result TEE_BigIntSetBit(TEE_BigInt *op, uint32_t bitIndex, bool value)
{
	mbedtls_mpi X;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&X);

	ret = __TEE_BigInt2MPI(&X, op);
	if (ret != 0)
		TEE_Panic(ret);

	if (X.n * 32 <= bitIndex) {
		ret = TEE_ERROR_OVERFLOW;
		goto out;
	}

	ret = mbedtls_mpi_set_bit(&X, bitIndex, value);

out:
	mbedtls_mpi_free(&X);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_OVERFLOW)
		TEE_Panic(ret);
	return ret;
}

TEE_Result TEE_BigIntAssign(TEE_BigInt *dest, TEE_BigInt *src)
{
	mbedtls_mpi S, D;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S);
	mbedtls_mpi_init(&D);

	ret = __TEE_BigInt2MPI(&S, src);
	if (ret != 0)
		goto out;

	ret = mbedtls_mpi_copy(&D, &S);
	if (ret != 0)
		goto out;

	ret = __TEE_MPI2BigInt(&D, dest);

out:
	mbedtls_mpi_free(&S);
	mbedtls_mpi_free(&D);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_OVERFLOW)
		TEE_Panic(ret);
	return ret;
}

TEE_Result TEE_BigIntAbs(TEE_BigInt *dest, TEE_BigInt *src)
{
	mbedtls_mpi S, D;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S);
	mbedtls_mpi_init(&D);

	ret = __TEE_BigInt2MPI(&S, src);
	if (ret != 0)
		goto out;

	ret = mbedtls_mpi_copy(&D, &S);
	if (ret != 0)
		goto out;

	D.s = 1;
	ret = __TEE_MPI2BigInt(&D, dest);

out:
	mbedtls_mpi_free(&S);
	mbedtls_mpi_free(&D);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_OVERFLOW)
		TEE_Panic(ret);
	return ret;
}

void TEE_BigIntAdd(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
	mbedtls_mpi S1, S2, D;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S1);
	mbedtls_mpi_init(&S2);
	mbedtls_mpi_init(&D);

	ret = __TEE_BigInt2MPI(&S1, op1);
	ret |= __TEE_BigInt2MPI(&S2, op2);
	if (ret != 0)
		goto out;

	ret = mbedtls_mpi_add_mpi(&D, &S1, &S2);
	if (ret != 0)
		goto out;

	ret = __TEE_MPI2BigInt(&D, dest);

out:
	mbedtls_mpi_free(&S1);
	mbedtls_mpi_free(&S2);
	mbedtls_mpi_free(&D);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

void TEE_BigIntSub(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
	mbedtls_mpi S1, S2, D;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S1);
	mbedtls_mpi_init(&S2);
	mbedtls_mpi_init(&D);

	ret = __TEE_BigInt2MPI(&S1, op1);
	ret |= __TEE_BigInt2MPI(&S2, op2);
	if (ret != 0)
		goto out;

	ret = mbedtls_mpi_sub_mpi(&D, &S1, &S2);
	if (ret != 0)
		goto out;

	ret = __TEE_MPI2BigInt(&D, dest);

out:
	mbedtls_mpi_free(&S1);
	mbedtls_mpi_free(&S2);
	mbedtls_mpi_free(&D);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

void TEE_BigIntNeg(TEE_BigInt *dest, TEE_BigInt *op)
{
	mbedtls_mpi S, D;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S);
	mbedtls_mpi_init(&D);

	ret = __TEE_BigInt2MPI(&S, op);
	if (ret != 0)
		goto out;

	S.s = -S.s;
	ret = mbedtls_mpi_copy(&D, &S);
	if (ret != 0)
		goto out;

	ret = __TEE_MPI2BigInt(&D, dest);

out:
	mbedtls_mpi_free(&S);
	mbedtls_mpi_free(&D);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

void TEE_BigIntMul(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
	mbedtls_mpi S1, S2, D;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S1);
	mbedtls_mpi_init(&S2);
	mbedtls_mpi_init(&D);

	ret = __TEE_BigInt2MPI(&S1, op1);
	ret |= __TEE_BigInt2MPI(&S2, op2);
	if (ret != 0)
		goto out;

	ret = mbedtls_mpi_mul_mpi(&D, &S1, &S2);
	if (ret != 0)
		goto out;

	ret = __TEE_MPI2BigInt(&D, dest);

out:
	mbedtls_mpi_free(&S1);
	mbedtls_mpi_free(&S2);
	mbedtls_mpi_free(&D);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

void TEE_BigIntSquare(TEE_BigInt *dest, TEE_BigInt *op)
{
	mbedtls_mpi S, D;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S);
	mbedtls_mpi_init(&D);

	ret = __TEE_BigInt2MPI(&S, op);
	if (ret != 0)
		goto out;

	ret = mbedtls_mpi_mul_mpi(&D, &S, &S);
	if (ret != 0)
		goto out;

	ret = __TEE_MPI2BigInt(&D, dest);

out:
	mbedtls_mpi_free(&S);
	mbedtls_mpi_free(&D);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

void TEE_BigIntDiv(TEE_BigInt *dest_q, TEE_BigInt *dest_r,
	TEE_BigInt *op1, TEE_BigInt *op2)
{
	mbedtls_mpi S1, S2, Q, R;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S1);
	mbedtls_mpi_init(&S2);
	mbedtls_mpi_init(&Q);
	mbedtls_mpi_init(&R);

	ret = __TEE_BigInt2MPI(&S1, op1);
	ret |= __TEE_BigInt2MPI(&S2, op2);
	if (ret != 0)
		goto out;

	ret = mbedtls_mpi_div_mpi(&Q, &R, &S1, &S2);
	if (ret != 0)
		goto out;

	ret = __TEE_MPI2BigInt(&Q, dest_q);
	ret |= __TEE_MPI2BigInt(&R, dest_r);

out:
	mbedtls_mpi_free(&S1);
	mbedtls_mpi_free(&S2);
	mbedtls_mpi_free(&Q);
	mbedtls_mpi_free(&R);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

void TEE_BigIntMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
	mbedtls_mpi S, D, N;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S);
	mbedtls_mpi_init(&D);
	mbedtls_mpi_init(&N);

	ret = __TEE_BigInt2MPI(&S, op);
	ret |= __TEE_BigInt2MPI(&N, n);
	if (ret != 0)
		goto out;

	udump("op", op, ((*(int *)((char *)op + 4)) * 4) + 8);
	udump("n", n, ((*(int *)((char *)n + 4)) * 4) + 8);

	if (mbedtls_mpi_cmp_int(&N, 2) < 0) {
		ret = EINVAL;
		goto out;
	}

	ret = mbedtls_mpi_mod_mpi(&D, &S, &N);
	if (ret != 0)
		goto out;

	ret = __TEE_MPI2BigInt(&D, dest);

	udump("dest", dest, ((*(int *)((char *)dest + 4)) * 4) + 8);

out:
	mbedtls_mpi_free(&S);
	mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&N);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

void TEE_BigIntAddMod(TEE_BigInt *dest, TEE_BigInt *op1,
	TEE_BigInt *op2, TEE_BigInt *n)
{
	mbedtls_mpi S1, S2, D, N;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S1);
	mbedtls_mpi_init(&S2);
	mbedtls_mpi_init(&D);
	mbedtls_mpi_init(&N);

	ret = __TEE_BigInt2MPI(&S1, op1);
	ret |= __TEE_BigInt2MPI(&S2, op2);
	ret |= __TEE_BigInt2MPI(&N, n);
	if (ret != 0)
		goto out;

	if (mbedtls_mpi_cmp_int(&N, 2) < 0) {
		ret = EINVAL;
		goto out;
	}

	ret = mbedtls_mpi_add_mpi(&S1, &S1, &S2);
	if (ret != 0)
		goto out;

	ret = mbedtls_mpi_mod_mpi(&D, &S1, &N);
	if (ret != 0)
		goto out;

	ret = __TEE_MPI2BigInt(&D, dest);

out:
	mbedtls_mpi_free(&S1);
	mbedtls_mpi_free(&S2);
	mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&N);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

void TEE_BigIntSubMod(TEE_BigInt *dest, TEE_BigInt *op1,
	TEE_BigInt *op2, TEE_BigInt *n)
{
	mbedtls_mpi S1, S2, D, N;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S1);
	mbedtls_mpi_init(&S2);
	mbedtls_mpi_init(&D);
	mbedtls_mpi_init(&N);

	ret = __TEE_BigInt2MPI(&S1, op1);
	ret |= __TEE_BigInt2MPI(&S2, op2);
	ret |= __TEE_BigInt2MPI(&N, n);
	if (ret != 0)
		goto out;

	if (mbedtls_mpi_cmp_int(&N, 2) < 0) {
		ret = EINVAL;
		goto out;
	}

	ret = mbedtls_mpi_sub_mpi(&S1, &S1, &S2);
	if (ret != 0)
		goto out;

	ret = mbedtls_mpi_mod_mpi(&D, &S1, &N);
	if (ret != 0)
		goto out;

	ret = __TEE_MPI2BigInt(&D, dest);

out:
	mbedtls_mpi_free(&S1);
	mbedtls_mpi_free(&S2);
	mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&N);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

void TEE_BigIntMulMod(TEE_BigInt *dest, TEE_BigInt *op1,
	TEE_BigInt *op2, TEE_BigInt *n)
{
	mbedtls_mpi S1, S2, D, N;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S1);
	mbedtls_mpi_init(&S2);
	mbedtls_mpi_init(&D);
	mbedtls_mpi_init(&N);

	ret = __TEE_BigInt2MPI(&S1, op1);
	ret |= __TEE_BigInt2MPI(&S2, op2);
	ret |= __TEE_BigInt2MPI(&N, n);
	if (ret != 0)
		goto out;

	udump("op1", op1, ((*(int *)((char *)op1 + 4)) * 4) + 8);
	udump("op2", op2, ((*(int *)((char *)op2 + 4)) * 4) + 8);
	udump("n", n, ((*(int *)((char *)n + 4)) * 4) + 8);

	if (mbedtls_mpi_cmp_int(&N, 2) < 0) {
		ret = EINVAL;
		goto out;
	}

	ret = mbedtls_mpi_mul_mpi(&S1, &S1, &S2);
	if (ret != 0)
		goto out;

	ret = mbedtls_mpi_mod_mpi(&D, &S1, &N);
	if (ret != 0)
		goto out;

	ret = __TEE_MPI2BigInt(&D, dest);

	udump("dest", dest, ((*(int *)((char *)dest + 4)) * 4) + 8);

out:
	mbedtls_mpi_free(&S1);
	mbedtls_mpi_free(&S2);
	mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&N);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

void TEE_BigIntSquareMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
	mbedtls_mpi S, D, N;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S);
	mbedtls_mpi_init(&D);
	mbedtls_mpi_init(&N);

	ret = __TEE_BigInt2MPI(&S, op);
	ret |= __TEE_BigInt2MPI(&N, n);
	if (ret != 0)
		goto out;

	if (mbedtls_mpi_cmp_int(&N, 2) < 0) {
		ret = EINVAL;
		goto out;
	}

	ret = mbedtls_mpi_mul_mpi(&S, &S, &S);
	if (ret != 0)
		goto out;

	ret = mbedtls_mpi_mod_mpi(&D, &S, &N);
	if (ret != 0)
		goto out;

	ret = __TEE_MPI2BigInt(&D, dest);

out:
	mbedtls_mpi_free(&S);
	mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&N);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

void TEE_BigIntInvMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
	mbedtls_mpi S, D, N;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S);
	mbedtls_mpi_init(&D);
	mbedtls_mpi_init(&N);

	ret = __TEE_BigInt2MPI(&S, op);
	ret |= __TEE_BigInt2MPI(&N, n);
	if (ret != 0)
		goto out;

	if ((mbedtls_mpi_cmp_int(&S, 0) == 0) ||
		(mbedtls_mpi_cmp_int(&N, 2) < 0)) {
		ret = EINVAL;
		goto out;
	}

	ret = mbedtls_mpi_inv_mod(&D, &S, &N);
	if (ret != 0)
		goto out;

	ret = __TEE_MPI2BigInt(&D, dest);

out:
	mbedtls_mpi_free(&S);
	mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&N);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

TEE_Result TEE_BigIntExpMod(TEE_BigInt *dest, TEE_BigInt *op1,
	TEE_BigInt *op2, TEE_BigInt *n, TEE_BigIntFMMContext *context)
{
	mbedtls_mpi S1, S2, D, N;
	TEE_Result ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S1);
	mbedtls_mpi_init(&S2);
	mbedtls_mpi_init(&D);
	mbedtls_mpi_init(&N);

	ret = __TEE_BigInt2MPI(&S1, op1);
	ret |= __TEE_BigInt2MPI(&S2, op2);
	ret |= __TEE_BigInt2MPI(&N, n);
	if (ret != 0)
		goto out;

	if (mbedtls_mpi_cmp_int(&N, 2) <= 0) {
		ret = EINVAL;
		goto out;
	}

	if (mbedtls_mpi_get_bit(&N, 0) == 0) {
		ret = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	ret = mbedtls_mpi_exp_mod(&D, &S1, &S2, &N, NULL);
	if (ret != 0)
		goto out;

	ret = __TEE_MPI2BigInt(&D, dest);

out:
	mbedtls_mpi_free(&S1);
	mbedtls_mpi_free(&S2);
	mbedtls_mpi_free(&D);
	mbedtls_mpi_free(&N);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_NOT_SUPPORTED)
		TEE_Panic(ret);
	return ret;
}

bool TEE_BigIntRelativePrime(TEE_BigInt *op1, TEE_BigInt *op2)
{
	mbedtls_mpi S1, S2, D;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S1);
	mbedtls_mpi_init(&S2);
	mbedtls_mpi_init(&D);

	ret = __TEE_BigInt2MPI(&S1, op1);
	ret |= __TEE_BigInt2MPI(&S2, op2);
	if (ret != 0)
		goto out;

	ret = mbedtls_mpi_gcd(&D, &S1, &S2);
	if (ret != 0)
		goto out;

	ret = mbedtls_mpi_cmp_int(&D, 1);

out:
	mbedtls_mpi_free(&S1);
	mbedtls_mpi_free(&S2);
	mbedtls_mpi_free(&D);
	return ret ? 0 : 1;
}

void TEE_BigIntComputeExtendedGcd(TEE_BigInt *gcd, TEE_BigInt *u,
	TEE_BigInt *v, TEE_BigInt *op1, TEE_BigInt *op2)
{
	mbedtls_mpi S1, S2, U, V, GCD;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S1);
	mbedtls_mpi_init(&S2);
	mbedtls_mpi_init(&GCD);
	mbedtls_mpi_init(&V);
	mbedtls_mpi_init(&U);

	ret = __TEE_BigInt2MPI(&S1, op1);
	ret |= __TEE_BigInt2MPI(&S2, op2);
	if (ret != 0)
		goto out;

	if (mbedtls_mpi_cmp_int(&S1, 0) == 0 &&
		mbedtls_mpi_cmp_int(&S2, 0) == 0) {
		ret = EINVAL;
		goto out;
	}

	ret = mbedtls_mpi_egcd(&GCD, &U, &V, &S1, &S2);
	if (ret != 0)
		goto out;

	ret = __TEE_MPI2BigInt(&GCD, gcd);
	if (u != NULL)
		ret |= __TEE_MPI2BigInt(&U, u);
	if (v != NULL)
		ret |= __TEE_MPI2BigInt(&V, v);

out:
	mbedtls_mpi_free(&S1);
	mbedtls_mpi_free(&S2);
	mbedtls_mpi_free(&GCD);
	mbedtls_mpi_free(&U);
	mbedtls_mpi_free(&V);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

int32_t TEE_BigIntIsProbablePrime(TEE_BigInt *op,
	uint32_t confidenceLevel)
{
	mbedtls_mpi S;
	int ret = TEE_ERROR_GENERIC;

	mbedtls_mpi_init(&S);

	ret = __TEE_BigInt2MPI(&S, op);
	if (ret != 0)
		goto out;

	ret = mbedtls_mpi_is_prime_ext(&S, max(confidenceLevel, (uint32_t)80),
			tee_prng, NULL);

out:
	mbedtls_mpi_free(&S);
	return ret ? 0 : 1;
}

void TEE_BigIntConvertToFMM(TEE_BigIntFMM *dest,
	TEE_BigInt *src, TEE_BigInt *n,
	TEE_BigIntFMMContext *context)
{
	TEE_BigIntMod(dest, src, n);
}

void TEE_BigIntConvertFromFMM(TEE_BigInt *dest,
	TEE_BigIntFMM *src, TEE_BigInt *n,
	TEE_BigIntFMMContext *context)
{
	TEE_BigIntMod(dest, src, n);
}

void TEE_BigIntComputeFMM(TEE_BigIntFMM *dest,
	TEE_BigIntFMM *op1, TEE_BigIntFMM *op2,
	TEE_BigInt *n, TEE_BigIntFMMContext *context)
{
	TEE_BigIntMulMod(dest, op1, op2, n);
}
