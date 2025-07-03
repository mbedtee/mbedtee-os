// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * GlobalPlatform TEE MPI (Multi-Precision Integer)
 */

#include <utrace.h>

#include <tee_internal_api.h>
#include "tee_api_priv.h"

struct bignum {
	int32_t s;
	uint32_t n;
};

static void __TEE_BigIntCheck(const TEE_BigInt *bigInt)
{
	struct bignum *b = (struct bignum *)bigInt;

	if ((b->s != 1 && b->s != -1) || (b->n > 2048))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
}

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

	if (len < 2)
		TEE_Panic(0);

	memset(bigInt, 0, len * sizeof(uint32_t));

	b->s = 1;
	b->n = len - (sizeof(struct bignum) / sizeof(uint32_t));
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

static TEE_Result __TEE_BN2BigInt(const struct mbedcrypto_bignum *X,
	TEE_BigInt *bigInt)
{
	int ret = -1;
	struct bignum *b = (struct bignum *)bigInt;

	__TEE_BigIntCheck(bigInt);

	ret = mbedcrypto_bn_to_binary_le(X, (void *)(b + 1),
			b->n * sizeof(uint32_t));
	if (ret == -EINVAL)
		return TEE_ERROR_OVERFLOW;

	b->s = X->neg ? -1 : 1;

	return ret;
}

static TEE_Result __TEE_BigInt2BN(struct mbedcrypto_bignum *X,
	const TEE_BigInt *bigInt)
{
	int ret = -1;
	struct bignum *b = (struct bignum *)bigInt;

	__TEE_BigIntCheck(bigInt);

	ret = mbedcrypto_bn_from_binary_le(X, (void *)(b + 1),
			b->n * sizeof(uint32_t));

	X->neg = (b->s < 0);

	return ret;
}

TEE_Result TEE_BigIntConvertFromOctetString(
	TEE_BigInt *dest, uint8_t *buffer,
	size_t bufferLen, int32_t sign)
{
	struct mbedcrypto_bignum X;
	TEE_Result ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&X);

	if (mbedcrypto_bn_from_binary(&X, buffer, bufferLen)) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if (sign < 0)
		X.neg = 1;

	ret = __TEE_BN2BigInt(&X, dest);

out:
	mbedcrypto_bn_cleanup(&X);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_OVERFLOW)
		TEE_Panic(ret);
	return ret;
}

TEE_Result TEE_BigIntConvertToOctetString(void *buffer,
	size_t *bufferLen, TEE_BigInt *bigInt)
{
	struct mbedcrypto_bignum X;
	size_t len = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&X);

	ret = __TEE_BigInt2BN(&X, bigInt);
	if (ret != 0)
		goto out;

	len = mbedcrypto_bn_byte_count(&X);

	if (*bufferLen < len) {
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	if (mbedcrypto_bn_to_binary(&X, buffer, len)) {
		ret = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	*bufferLen = len;
out:
	mbedcrypto_bn_cleanup(&X);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(ret);

	return ret;
}

void TEE_BigIntConvertFromS32(TEE_BigInt *dest, int32_t shortVal)
{
	int sign = 1;
	uint32_t abs_val = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (shortVal < 0) {
		abs_val = -(uint32_t)shortVal;
		sign = -1;
	} else {
		abs_val = shortVal;
	}

	abs_val = bswap32(abs_val);

	ret = TEE_BigIntConvertFromOctetString(dest, (uint8_t *)&abs_val,
			sizeof(uint32_t), sign);
	if (ret != 0)
		TEE_Panic(ret);
}

TEE_Result TEE_BigIntConvertToS32(int32_t *dest, TEE_BigInt *src)
{
	int32_t val = 0;
	struct mbedcrypto_bignum X;
	size_t len = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&X);

	ret = __TEE_BigInt2BN(&X, src);
	if (ret != 0)
		goto out;

	len = mbedcrypto_bn_byte_count(&X);
	if (len > sizeof(val)) {
		ret = TEE_ERROR_OVERFLOW;
		goto out;
	}

	if (mbedcrypto_bn_to_binary(&X, (void *)&val, len)) {
		ret = TEE_ERROR_OVERFLOW;
		goto out;
	}

	val = bswap32(val);

	if ((val < 0 && !X.neg) ||
		(val >= 0 && X.neg)) {
		ret = TEE_ERROR_OVERFLOW;
		goto out;
	}

	*dest = val;

out:
	mbedcrypto_bn_cleanup(&X);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_OVERFLOW)
		TEE_Panic(ret);

	return ret;
}

int32_t TEE_BigIntCmp(TEE_BigInt *op1, TEE_BigInt *op2)
{
	struct mbedcrypto_bignum X1, X2;
	int32_t ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&X1);
	mbedcrypto_bn_init(&X2);

	ret = __TEE_BigInt2BN(&X1, op1);
	if (ret == 0)
		ret = __TEE_BigInt2BN(&X2, op2);
	if (ret != 0)
		TEE_Panic(ret);

	ret = mbedcrypto_bn_cmp(&X1, &X2);

	mbedcrypto_bn_cleanup(&X1);
	mbedcrypto_bn_cleanup(&X2);

	return ret;
}

int32_t TEE_BigIntCmpS32(TEE_BigInt *op, int32_t shortVal)
{
	struct mbedcrypto_bignum X;
	int32_t ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&X);

	ret = __TEE_BigInt2BN(&X, op);
	if (ret != 0)
		TEE_Panic(ret);

	ret = mbedcrypto_bn_cmp_word(&X, shortVal);

	mbedcrypto_bn_cleanup(&X);

	return ret;
}

void TEE_BigIntShiftRight(TEE_BigInt *dest, TEE_BigInt *op, size_t bits)
{
	struct mbedcrypto_bignum X;
	int ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&X);

	ret = __TEE_BigInt2BN(&X, op);
	if (ret != 0)
		TEE_Panic(ret);

	ret = mbedcrypto_bn_rshift(&X, bits);
	if (ret != 0)
		TEE_Panic(ret);

	ret = __TEE_BN2BigInt(&X, dest);
	if (ret != 0)
		TEE_Panic(ret);

	mbedcrypto_bn_cleanup(&X);
}

bool TEE_BigIntGetBit(TEE_BigInt *src, uint32_t bitIndex)
{
	struct mbedcrypto_bignum X;
	int ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&X);

	ret = __TEE_BigInt2BN(&X, src);
	if (ret != 0)
		TEE_Panic(ret);

	ret = mbedcrypto_bn_test_bit(&X, bitIndex);

	mbedcrypto_bn_cleanup(&X);

	return ret;
}

uint32_t TEE_BigIntGetBitCount(TEE_BigInt *src)
{
	struct mbedcrypto_bignum X;
	uint32_t ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&X);

	ret = __TEE_BigInt2BN(&X, src);
	if (ret != 0)
		TEE_Panic(ret);

	ret = mbedcrypto_bn_bit_count(&X);

	mbedcrypto_bn_cleanup(&X);

	return ret;
}

TEE_Result TEE_BigIntSetBit(TEE_BigInt *op, uint32_t bitIndex, bool value)
{
	struct mbedcrypto_bignum X;
	int ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&X);

	ret = __TEE_BigInt2BN(&X, op);
	if (ret != 0)
		TEE_Panic(ret);

	if (X.used * 32 <= bitIndex) {
		ret = TEE_ERROR_OVERFLOW;
		goto out;
	}

	ret = mbedcrypto_bn_assign_bit(&X, bitIndex, value);
	if (ret != 0)
		goto out;

	ret = __TEE_BN2BigInt(&X, op);

out:
	mbedcrypto_bn_cleanup(&X);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_OVERFLOW)
		TEE_Panic(ret);
	return ret;
}

TEE_Result TEE_BigIntAssign(TEE_BigInt *dest, TEE_BigInt *src)
{
	struct mbedcrypto_bignum S;
	int ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&S);

	ret = __TEE_BigInt2BN(&S, src);
	if (ret == 0)
		ret = __TEE_BN2BigInt(&S, dest);

	mbedcrypto_bn_cleanup(&S);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_OVERFLOW)
		TEE_Panic(ret);
	return ret;
}

TEE_Result TEE_BigIntAbs(TEE_BigInt *dest, TEE_BigInt *src)
{
	struct mbedcrypto_bignum S;
	int ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&S);

	ret = __TEE_BigInt2BN(&S, src);
	if (ret == 0) {
		S.neg = 0;
		ret = __TEE_BN2BigInt(&S, dest);
	}

	mbedcrypto_bn_cleanup(&S);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_OVERFLOW)
		TEE_Panic(ret);
	return ret;
}

typedef int (*bn_binop_t)(struct mbedcrypto_bignum *,
	const struct mbedcrypto_bignum *, const struct mbedcrypto_bignum *);

static void __TEE_BigIntBinOp(TEE_BigInt *dest, TEE_BigInt *op1,
	TEE_BigInt *op2, bn_binop_t op_fn)
{
	struct mbedcrypto_bignum S1, S2, D;
	int ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&S1);
	mbedcrypto_bn_init(&S2);
	mbedcrypto_bn_init(&D);

	ret = __TEE_BigInt2BN(&S1, op1);
	if (ret == 0)
		ret = __TEE_BigInt2BN(&S2, op2);
	if (ret != 0)
		goto out;

	ret = op_fn(&D, &S1, &S2);
	if (ret != 0)
		goto out;

	ret = __TEE_BN2BigInt(&D, dest);

out:
	mbedcrypto_bn_cleanup(&S1);
	mbedcrypto_bn_cleanup(&S2);
	mbedcrypto_bn_cleanup(&D);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

static void __TEE_BigIntBinOpMod(TEE_BigInt *dest, TEE_BigInt *op1,
	TEE_BigInt *op2, TEE_BigInt *n, bn_binop_t op_fn)
{
	struct mbedcrypto_bignum S1, S2, D, N;
	int ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&S1);
	mbedcrypto_bn_init(&S2);
	mbedcrypto_bn_init(&D);
	mbedcrypto_bn_init(&N);

	ret = __TEE_BigInt2BN(&S1, op1);
	if (ret == 0)
		ret = __TEE_BigInt2BN(&S2, op2);
	if (ret == 0)
		ret = __TEE_BigInt2BN(&N, n);
	if (ret != 0)
		goto out;

	if (mbedcrypto_bn_cmp_word(&N, 2) < 0) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	ret = op_fn(&S1, &S1, &S2);
	if (ret != 0)
		goto out;

	ret = mbedcrypto_bn_mod(&D, &S1, &N);
	if (ret != 0)
		goto out;

	ret = __TEE_BN2BigInt(&D, dest);

out:
	mbedcrypto_bn_cleanup(&S1);
	mbedcrypto_bn_cleanup(&S2);
	mbedcrypto_bn_cleanup(&D);
	mbedcrypto_bn_cleanup(&N);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

void TEE_BigIntAdd(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
	__TEE_BigIntBinOp(dest, op1, op2, mbedcrypto_bn_add);
}

void TEE_BigIntSub(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
	__TEE_BigIntBinOp(dest, op1, op2, mbedcrypto_bn_sub);
}

void TEE_BigIntNeg(TEE_BigInt *dest, TEE_BigInt *op)
{
	struct mbedcrypto_bignum S;
	int ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&S);

	ret = __TEE_BigInt2BN(&S, op);
	if (ret == 0) {
		S.neg = !S.neg;
		ret = __TEE_BN2BigInt(&S, dest);
	}

	mbedcrypto_bn_cleanup(&S);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

void TEE_BigIntMul(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2)
{
	__TEE_BigIntBinOp(dest, op1, op2, mbedcrypto_bn_mul);
}

void TEE_BigIntSquare(TEE_BigInt *dest, TEE_BigInt *op)
{
	TEE_BigIntMul(dest, op, op);
}

void TEE_BigIntDiv(TEE_BigInt *dest_q, TEE_BigInt *dest_r,
	TEE_BigInt *op1, TEE_BigInt *op2)
{
	struct mbedcrypto_bignum S1, S2, Q, R;
	int ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&S1);
	mbedcrypto_bn_init(&S2);
	mbedcrypto_bn_init(&Q);
	mbedcrypto_bn_init(&R);

	ret = __TEE_BigInt2BN(&S1, op1);
	if (ret == 0)
		ret = __TEE_BigInt2BN(&S2, op2);
	if (ret != 0)
		goto out;

	ret = mbedcrypto_bn_div(&Q, &R, &S1, &S2);
	if (ret != 0)
		goto out;

	ret = __TEE_BN2BigInt(&Q, dest_q);
	if (ret == 0)
		ret = __TEE_BN2BigInt(&R, dest_r);

out:
	mbedcrypto_bn_cleanup(&S1);
	mbedcrypto_bn_cleanup(&S2);
	mbedcrypto_bn_cleanup(&Q);
	mbedcrypto_bn_cleanup(&R);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

void TEE_BigIntMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
	struct mbedcrypto_bignum S, D, N;
	int ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&S);
	mbedcrypto_bn_init(&D);
	mbedcrypto_bn_init(&N);

	ret = __TEE_BigInt2BN(&S, op);
	if (ret == 0)
		ret = __TEE_BigInt2BN(&N, n);
	if (ret != 0)
		goto out;

	if (mbedcrypto_bn_cmp_word(&N, 2) < 0) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	ret = mbedcrypto_bn_mod(&D, &S, &N);
	if (ret != 0)
		goto out;

	ret = __TEE_BN2BigInt(&D, dest);

out:
	mbedcrypto_bn_cleanup(&S);
	mbedcrypto_bn_cleanup(&D);
	mbedcrypto_bn_cleanup(&N);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

void TEE_BigIntAddMod(TEE_BigInt *dest, TEE_BigInt *op1,
	TEE_BigInt *op2, TEE_BigInt *n)
{
	__TEE_BigIntBinOpMod(dest, op1, op2, n, mbedcrypto_bn_add);
}

void TEE_BigIntSubMod(TEE_BigInt *dest, TEE_BigInt *op1,
	TEE_BigInt *op2, TEE_BigInt *n)
{
	__TEE_BigIntBinOpMod(dest, op1, op2, n, mbedcrypto_bn_sub);
}

void TEE_BigIntMulMod(TEE_BigInt *dest, TEE_BigInt *op1,
	TEE_BigInt *op2, TEE_BigInt *n)
{
	__TEE_BigIntBinOpMod(dest, op1, op2, n, mbedcrypto_bn_mul);
}

void TEE_BigIntSquareMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
	TEE_BigIntMulMod(dest, op, op, n);
}

void TEE_BigIntInvMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n)
{
	struct mbedcrypto_bignum S, D, N;
	int ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&S);
	mbedcrypto_bn_init(&D);
	mbedcrypto_bn_init(&N);

	ret = __TEE_BigInt2BN(&S, op);
	if (ret == 0)
		ret = __TEE_BigInt2BN(&N, n);
	if (ret != 0)
		goto out;

	if ((mbedcrypto_bn_cmp_word(&S, 0) == 0) ||
		(mbedcrypto_bn_cmp_word(&N, 2) < 0)) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	ret = mbedcrypto_bn_modinv(&D, &S, &N);
	if (ret != 0)
		goto out;

	ret = __TEE_BN2BigInt(&D, dest);

out:
	mbedcrypto_bn_cleanup(&S);
	mbedcrypto_bn_cleanup(&D);
	mbedcrypto_bn_cleanup(&N);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

TEE_Result TEE_BigIntExpMod(TEE_BigInt *dest, TEE_BigInt *op1,
	TEE_BigInt *op2, TEE_BigInt *n, TEE_BigIntFMMContext *context)
{
	struct mbedcrypto_bignum S1, S2, D, N;
	TEE_Result ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&S1);
	mbedcrypto_bn_init(&S2);
	mbedcrypto_bn_init(&D);
	mbedcrypto_bn_init(&N);

	ret = __TEE_BigInt2BN(&S1, op1);
	if (ret == 0)
		ret = __TEE_BigInt2BN(&S2, op2);
	if (ret == 0)
		ret = __TEE_BigInt2BN(&N, n);
	if (ret != 0)
		goto out;

	if (mbedcrypto_bn_cmp_word(&N, 2) <= 0) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (mbedcrypto_bn_test_bit(&N, 0) == 0) {
		ret = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	ret = mbedcrypto_bn_modpow(&D, &S1, &S2, &N, NULL);
	if (ret != 0)
		goto out;

	ret = __TEE_BN2BigInt(&D, dest);

out:
	mbedcrypto_bn_cleanup(&S1);
	mbedcrypto_bn_cleanup(&S2);
	mbedcrypto_bn_cleanup(&D);
	mbedcrypto_bn_cleanup(&N);
	if (ret != TEE_SUCCESS &&
		ret != TEE_ERROR_NOT_SUPPORTED)
		TEE_Panic(ret);
	return ret;
}

bool TEE_BigIntRelativePrime(TEE_BigInt *op1, TEE_BigInt *op2)
{
	struct mbedcrypto_bignum S1, S2, D;
	int ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&S1);
	mbedcrypto_bn_init(&S2);
	mbedcrypto_bn_init(&D);

	ret = __TEE_BigInt2BN(&S1, op1);
	if (ret == 0)
		ret = __TEE_BigInt2BN(&S2, op2);
	if (ret != 0)
		goto out;

	ret = mbedcrypto_bn_gcd(&D, &S1, &S2);
	if (ret != 0)
		goto out;

	ret = mbedcrypto_bn_cmp_word(&D, 1);

out:
	mbedcrypto_bn_cleanup(&S1);
	mbedcrypto_bn_cleanup(&S2);
	mbedcrypto_bn_cleanup(&D);
	if (ret == 0)
		return 1;
	if (ret > 0)
		return 0;
	TEE_Panic(ret);
}

void TEE_BigIntComputeExtendedGcd(TEE_BigInt *gcd, TEE_BigInt *u,
	TEE_BigInt *v, TEE_BigInt *op1, TEE_BigInt *op2)
{
	struct mbedcrypto_bignum S1, S2, U, V, GCD;
	int ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&S1);
	mbedcrypto_bn_init(&S2);
	mbedcrypto_bn_init(&GCD);
	mbedcrypto_bn_init(&V);
	mbedcrypto_bn_init(&U);

	ret = __TEE_BigInt2BN(&S1, op1);
	if (ret == 0)
		ret = __TEE_BigInt2BN(&S2, op2);
	if (ret != 0)
		goto out;

	if (mbedcrypto_bn_cmp_word(&S1, 0) == 0 &&
		mbedcrypto_bn_cmp_word(&S2, 0) == 0) {
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	ret = mbedcrypto_bn_egcd(&GCD, &U, &V, &S1, &S2);
	if (ret != 0)
		goto out;

	ret = __TEE_BN2BigInt(&GCD, gcd);
	if (ret == 0 && u)
		ret = __TEE_BN2BigInt(&U, u);
	if (ret == 0 && v)
		ret = __TEE_BN2BigInt(&V, v);

out:
	mbedcrypto_bn_cleanup(&S1);
	mbedcrypto_bn_cleanup(&S2);
	mbedcrypto_bn_cleanup(&GCD);
	mbedcrypto_bn_cleanup(&U);
	mbedcrypto_bn_cleanup(&V);
	if (ret != TEE_SUCCESS)
		TEE_Panic(ret);
}

int32_t TEE_BigIntIsProbablePrime(TEE_BigInt *op,
	uint32_t confidenceLevel)
{
	struct mbedcrypto_bignum S;
	int ret = TEE_ERROR_GENERIC;

	mbedcrypto_bn_init(&S);

	ret = __TEE_BigInt2BN(&S, op);
	if (ret != 0)
		goto out;

	ret = mbedcrypto_bn_test_prime(&S, max(confidenceLevel, (uint32_t)80),
			tee_prng, NULL);

out:
	mbedcrypto_bn_cleanup(&S);
	if (ret == 0)
		return 1;
	if (ret == -EINVAL)
		return 0;
	TEE_Panic(ret);
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
