// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 *
 * mbedtest_float.c -- Float/Double/LongDouble arithmetic tests.
 *
 * Tests: float_f_test, float_d_test, float_ld_test,
 *        float_f_neg_test, float_d_neg_test,
 *        float_test, float_convert_test, float_corner_test.
 */

#include <float.h>
#include <math.h>
#include "mbedtest.h"
#include "mbedtest_internal.h"

static volatile double in_d1[4] = {
	1234.987673, 918124.673981, 67821.1203, 311891.067128,
};
static volatile double in_d2[4] = {
	89914.181767, 17224.83985, 737821.0123, 73421.570345,
};

static volatile double mul_d[4] = {
	111042906.110126358191, 15814550471.65618694285,
	50039847635.06607969, 22899531925.11556911916,
};
static volatile double div_d[4] = {
	0.01373518224522464613132267108428, 53.302363445834882464814324529119,
	0.09192083062067057371063163471795, 4.2479487385308933765219374238379,
};
static volatile double add_d[4] = {
	91149.16944, 935349.513831, 805642.1326, 385312.637473,
};

static volatile float in_f1[4] = {
	24.6981, 1234.987673, 621.1203, 391.067128,
};
static volatile float in_f2[4] = {
	12.83985, 814.181767, 7821.0123, 1.570345,
};
static volatile float add_f[4] = {
	37.53795, 2049.16944, 8442.1326, 392.637473,
};
static volatile float div_f[4] = {
	1.923550508767625790020911459246, 1.5168451604492882238666000487825,
	0.07941686781390178864697604426476, 249.03261894679194699253985589154,
};
static volatile float mul_f[4] = {
	317.119899285, 1005504.445826358191, 4857789.50607969, 614.11030911916,
};

static volatile long double in_ld1[4] = {
	1234.987673, 918124.673981, 67821.1203, 311891.067128,
};
static volatile long double in_ld2[4] = {
	89914.181767, 17224.83985, 737821.0123, 73421.570345,
};

static volatile long double mul_ld[4] = {
	111042906.110126358191, 15814550471.65618694285,
	50039847635.06607969, 22899531925.11556911916,
};
static volatile long double div_ld[4] = {
	0.01373518224522464613132267108428, 53.302363445834882464814324529119,
	0.09192083062067057371063163471795, 4.2479487385308933765219374238379,
};
static volatile long double add_ld[4] = {
	91149.16944, 935349.513831, 805642.1326, 385312.637473,
};
static volatile long double sub_ld[4] = {
	-88679.194094, 900899.834131, -669999.892, 238469.496783,
};

/* ---- negative-value test data (mixed signs, same precision as original) ---- */
/*
 * Derived from the original positive data by negating selected inputs:
 *   in_f1_neg = {-a,  b, -c, -d}     in_f2_neg = { e, -f, -g,  h}
 *   in_d1_neg = {-A,  B, -C, -D}     in_d2_neg = { E, -F, -G,  H}
 * Where {a,b,c,d}/{A,B,C,D} are the original in_f1/in_d1 and
 *       {e,f,g,h}/{E,F,G,H} are the original in_f2/in_d2.
 */
static volatile float in_f1_neg[4] = {
	-24.6981f, 1234.987673f, -621.1203f, -391.067128f,
};
static volatile float in_f2_neg[4] = {
	12.83985f, -814.181767f, -7821.0123f, 1.570345f,
};
static volatile float add_f_neg[4] = {
	-11.85825f, 420.805906f, -8442.1326f, -389.496783f,
};
static volatile float mul_f_neg[4] = {
	-317.119899285f, -1005504.445826358191f,
	4857789.50607969f, -614.11030911916f,
};
static volatile float div_f_neg[4] = {
	-1.923550508767625790020911459246f,
	-1.5168451604492882238666000487825f,
	0.07941686781390178864697604426476f,
	-249.03261894679194699253985589154f,
};

static volatile double in_d1_neg[4] = {
	-1234.987673, 918124.673981, -67821.1203, -311891.067128,
};
static volatile double in_d2_neg[4] = {
	89914.181767, -17224.83985, -737821.0123, 73421.570345,
};
static volatile double add_d_neg[4] = {
	88679.194094, 900899.834131, -805642.1326, -238469.496783,
};
static volatile double mul_d_neg[4] = {
	-111042906.110126358191, -15814550471.65618694285,
	50039847635.06607969, -22899531925.11556911916,
};
static volatile double div_d_neg[4] = {
	-0.01373518224522464613132267108428,
	-53.302363445834882464814324529119,
	0.09192083062067057371063163471795,
	-4.2479487385308933765219374238379,
};

__noinline int float_f_test(int rounds)
{
	int i = 0, loops = 0;
	float tmp = 0.0f, diff = 0.0f;

	for (loops = 0; loops < rounds; loops++) {
		for (i = 0; i < ARRAY_SIZE(in_f1); i++) {
			tmp = in_f1[i] + in_f2[i];
			diff = fabs(tmp - add_f[i]);
			CHECK(diff < 0.00001, EDOM,
				"i=%d add_f diff=%f exp=%f got=%f",
				i, diff, add_f[i], tmp);
		}

		for (i = 0; i < ARRAY_SIZE(in_f1); i++) {
			tmp = in_f1[i] * in_f2[i];

			if (test_rand() % 17 == 0)
				pthread_yield();

			diff = fabs(tmp - mul_f[i]);
			CHECK(diff < 0.0001, EDOM,
				"i=%d mul_f diff=%f exp=%f got=%f",
				i, diff, mul_f[i], tmp);
		}

		for (i = 0; i < ARRAY_SIZE(in_f1); i++) {
			tmp = in_f1[i] / in_f2[i];

			diff = fabs(tmp - div_f[i]);
			CHECK(diff < 0.0001, EDOM,
				"i=%d div_f diff=%f exp=%f got=%f",
				i, diff, div_f[i], tmp);
		}
	}

out:
	return TEST_ERRNO();
}

__noinline int float_d_test(int rounds)
{
	int i = 0, loops = 0;
	double tmp[ARRAY_SIZE(in_d1) * 3] = {0};
	double diff[ARRAY_SIZE(in_d1) * 3] = {0};

	for (loops = 0; loops < rounds; loops++) {

		tmp[0] = in_d1[0] + in_d2[0];
		tmp[1] = in_d1[1] + in_d2[1];
		tmp[2] = in_d1[2] + in_d2[2];
		tmp[3] = in_d1[3] + in_d2[3];

		tmp[4] = in_d1[0] * in_d2[0];
		tmp[5] = in_d1[1] * in_d2[1];
		tmp[6] = in_d1[2] * in_d2[2];
		tmp[7] = in_d1[3] * in_d2[3];

		if (test_rand() % 23 == 0)
			pthread_yield();

		tmp[8] = in_d1[0] / in_d2[0];
		tmp[9] = in_d1[1] / in_d2[1];
		tmp[10] = in_d1[2] / in_d2[2];
		tmp[11] = in_d1[3] / in_d2[3];

		diff[0] = fabs(tmp[0] - add_d[0]);
		diff[1] = fabs(tmp[1] - add_d[1]);
		diff[2] = fabs(tmp[2] - add_d[2]);
		diff[3] = fabs(tmp[3] - add_d[3]);

		diff[4] = fabs(tmp[4] - mul_d[0]);
		diff[5] = fabs(tmp[5] - mul_d[1]);
		diff[6] = fabs(tmp[6] - mul_d[2]);
		diff[7] = fabs(tmp[7] - mul_d[3]);

		diff[8] = fabs(tmp[8] - div_d[0]);
		diff[9] = fabs(tmp[9] - div_d[1]);
		diff[10] = fabs(tmp[10] - div_d[2]);
		diff[11] = fabs(tmp[11] - div_d[3]);

		if (test_rand() % 23 == 0)
			pthread_yield();

		for (i = 0; i < ARRAY_SIZE(in_d1); i++) {
			CHECK(diff[i] < 0.000001, EDOM,
				"i=%d add_d diff=%f exp=%f got=%f",
				i, diff[i], add_d[i], tmp[i]);
		}

		for (i = 4; i < ARRAY_SIZE(in_d1) + 4; i++) {
			CHECK(diff[i] < 0.0001, EDOM,
				"i=%d mul_d diff=%f exp=%f got=%f",
				i - 4, diff[i], mul_d[i - 4], tmp[i]);
		}

		for (i = 8; i < ARRAY_SIZE(in_d1) + 8; i++) {
			CHECK(diff[i] < 0.00001, EDOM,
				"i=%d div_d diff=%f exp=%f got=%f",
				i - 8, diff[i], div_d[i - 8], tmp[i]);
		}
	}

out:
	return TEST_ERRNO();
}

__noinline int float_ld_test(int rounds)
{
	int i = 0, loops = 0;
	long double tmp[ARRAY_SIZE(in_ld1) * 4] = {0};
	long double diff[ARRAY_SIZE(in_ld1) * 4] = {0};

	for (loops = 0; loops < rounds; loops++) {
		tmp[0] = in_ld1[0] + in_ld2[0];
		tmp[1] = in_ld1[1] + in_ld2[1];
		tmp[2] = in_ld1[2] + in_ld2[2];
		tmp[3] = in_ld1[3] + in_ld2[3];

		tmp[4] = in_ld1[0] * in_ld2[0];
		tmp[5] = in_ld1[1] * in_ld2[1];
		tmp[6] = in_ld1[2] * in_ld2[2];
		tmp[7] = in_ld1[3] * in_ld2[3];

		if (test_rand() % 23 == 0)
			pthread_yield();

		tmp[8] = in_ld1[0] / in_ld2[0];
		tmp[9] = in_ld1[1] / in_ld2[1];
		tmp[10] = in_ld1[2] / in_ld2[2];
		tmp[11] = in_ld1[3] / in_ld2[3];

		tmp[12] = in_ld1[0] - in_ld2[0];
		tmp[13] = in_ld1[1] - in_ld2[1];
		tmp[14] = in_ld1[2] - in_ld2[2];
		tmp[15] = in_ld1[3] - in_ld2[3];

		diff[0] = fabs(tmp[0] - add_ld[0]);
		diff[1] = fabs(tmp[1] - add_ld[1]);
		diff[2] = fabs(tmp[2] - add_ld[2]);
		diff[3] = fabs(tmp[3] - add_ld[3]);

		diff[4] = fabs(tmp[4] - mul_ld[0]);
		diff[5] = fabs(tmp[5] - mul_ld[1]);
		diff[6] = fabs(tmp[6] - mul_ld[2]);
		diff[7] = fabs(tmp[7] - mul_ld[3]);

		diff[8] = fabs(tmp[8] - div_ld[0]);
		diff[9] = fabs(tmp[9] - div_ld[1]);
		diff[10] = fabs(tmp[10] - div_ld[2]);
		diff[11] = fabs(tmp[11] - div_ld[3]);

		diff[12] = fabs(tmp[12] - sub_ld[0]);
		diff[13] = fabs(tmp[13] - sub_ld[1]);
		diff[14] = fabs(tmp[14] - sub_ld[2]);
		diff[15] = fabs(tmp[15] - sub_ld[3]);

		if (test_rand() % 23 == 0)
			pthread_yield();

		for (i = 0; i < ARRAY_SIZE(in_ld1); i++)
			CHECK(diff[i] < 0.000001, EDOM,
				"i=%d add_ld diff=%f exp=%f got=%f",
				i, diff[i], add_ld[i], tmp[i]);

		for (i = 4; i < ARRAY_SIZE(in_ld1) + 4; i++)
			CHECK(diff[i] < 0.00001, EDOM,
				"i=%d mul_ld diff=%f exp=%f got=%f",
				i - 4, diff[i], mul_ld[i - 4], tmp[i]);

		for (i = 8; i < ARRAY_SIZE(in_ld1) + 8; i++)
			CHECK(diff[i] < 0.00001, EDOM,
				"i=%d div_ld diff=%f exp=%f got=%f",
				i - 8, diff[i], div_ld[i - 8], tmp[i]);

		for (i = 12; i < ARRAY_SIZE(in_ld1) + 12; i++)
			CHECK(diff[i] < 0.000001, EDOM,
				"i=%d sub_ld diff=%f exp=%f got=%f",
				i - 12, diff[i], sub_ld[i - 12], tmp[i]);
	}

out:
	return TEST_ERRNO();
}

/*
 * float_f_neg_test -- float arithmetic with negative/mixed-sign operands.
 * Same structure as float_f_test but covers sign handling paths.
 */
__noinline int float_f_neg_test(int rounds)
{
	int i = 0, loops = 0;
	float tmp = 0.0f, diff = 0.0f;

	for (loops = 0; loops < rounds; loops++) {
		for (i = 0; i < ARRAY_SIZE(in_f1_neg); i++) {
			tmp = in_f1_neg[i] + in_f2_neg[i];
			diff = fabsf(tmp - add_f_neg[i]);
			CHECK(diff < 0.00001f, EDOM,
				"i=%d add_neg diff=%f exp=%f got=%f",
				i, (double)diff, (double)add_f_neg[i],
				(double)tmp);
		}
		for (i = 0; i < ARRAY_SIZE(in_f1_neg); i++) {
			tmp = in_f1_neg[i] * in_f2_neg[i];
			if (test_rand() % 17 == 0)
				pthread_yield();
			diff = fabsf(tmp - mul_f_neg[i]);
			CHECK(diff < 0.0001f, EDOM,
				"i=%d mul_neg diff=%f exp=%f got=%f",
				i, (double)diff, (double)mul_f_neg[i],
				(double)tmp);
		}
		for (i = 0; i < ARRAY_SIZE(in_f1_neg); i++) {
			tmp = in_f1_neg[i] / in_f2_neg[i];
			diff = fabsf(tmp - div_f_neg[i]);
			CHECK(diff < 0.0001f, EDOM,
				"i=%d div_neg diff=%f exp=%f got=%f",
				i, (double)diff, (double)div_f_neg[i],
				(double)tmp);
		}
	}

out:
	return TEST_ERRNO();
}

__noinline int float_d_neg_test(int rounds)
{
	int i = 0, loops = 0;
	double tmp[ARRAY_SIZE(in_d1_neg) * 3] = {0};
	double diff[ARRAY_SIZE(in_d1_neg) * 3] = {0};

	for (loops = 0; loops < rounds; loops++) {
		tmp[0] = in_d1_neg[0] + in_d2_neg[0];
		tmp[1] = in_d1_neg[1] + in_d2_neg[1];
		tmp[2] = in_d1_neg[2] + in_d2_neg[2];
		tmp[3] = in_d1_neg[3] + in_d2_neg[3];
		tmp[4] = in_d1_neg[0] * in_d2_neg[0];
		tmp[5] = in_d1_neg[1] * in_d2_neg[1];
		tmp[6] = in_d1_neg[2] * in_d2_neg[2];
		tmp[7] = in_d1_neg[3] * in_d2_neg[3];
		if (test_rand() % 23 == 0)
			pthread_yield();
		tmp[8]  = in_d1_neg[0] / in_d2_neg[0];
		tmp[9]  = in_d1_neg[1] / in_d2_neg[1];
		tmp[10] = in_d1_neg[2] / in_d2_neg[2];
		tmp[11] = in_d1_neg[3] / in_d2_neg[3];
		diff[0] = fabs(tmp[0] - add_d_neg[0]);
		diff[1] = fabs(tmp[1] - add_d_neg[1]);
		diff[2] = fabs(tmp[2] - add_d_neg[2]);
		diff[3] = fabs(tmp[3] - add_d_neg[3]);
		diff[4] = fabs(tmp[4] - mul_d_neg[0]);
		diff[5] = fabs(tmp[5] - mul_d_neg[1]);
		diff[6] = fabs(tmp[6] - mul_d_neg[2]);
		diff[7] = fabs(tmp[7] - mul_d_neg[3]);
		diff[8]  = fabs(tmp[8]  - div_d_neg[0]);
		diff[9]  = fabs(tmp[9]  - div_d_neg[1]);
		diff[10] = fabs(tmp[10] - div_d_neg[2]);
		diff[11] = fabs(tmp[11] - div_d_neg[3]);
		if (test_rand() % 23 == 0)
			pthread_yield();
		for (i = 0; i < ARRAY_SIZE(in_d1_neg); i++)
			CHECK(diff[i] < 0.000001, EDOM,
				"i=%d add_d_neg diff=%f exp=%f got=%f",
				i, diff[i], add_d_neg[i], tmp[i]);
		for (i = 4; i < ARRAY_SIZE(in_d1_neg) + 4; i++)
			CHECK(diff[i] < 0.0001, EDOM,
				"i=%d mul_d_neg diff=%f exp=%f got=%f",
				i - 4, diff[i], mul_d_neg[i - 4], tmp[i]);
		for (i = 8; i < ARRAY_SIZE(in_d1_neg) + 8; i++)
			CHECK(diff[i] < 0.00001, EDOM,
				"i=%d div_d_neg diff=%f exp=%f got=%f",
				i - 8, diff[i], div_d_neg[i - 8], tmp[i]);
	}

out:
	return TEST_ERRNO();
}

/*
 * float_convert_test -- float <-> int and float <-> double conversions.
 * Exercises FCVT / FCVTS / FCVTD instructions.
 */
void float_convert_test(void)
{
	int i32 = 0;
	unsigned u32 = 0;
	float f = 0.0f;
	double d = 0.0;

	TEST_START("float_convert_test");

	/* int -> float -> int roundtrip */
	i32 = -42;
	f = (float)i32;
	CHECK(f == -42.0f, EDOM, "i32->f i32=%d f=%f", i32, (double)f);
	i32 = (int)f;
	CHECK(i32 == -42, EDOM, "f->i32 i32=%d", i32);

	/* float -> int truncation */
	f = 3.7f;
	i32 = (int)f;
	CHECK(i32 == 3, EDOM, "trunc f->i i32=%d", i32);

	/* negative float -> int */
	f = -3.7f;
	i32 = (int)f;
	CHECK(i32 == -3, EDOM, "trunc neg f->i i32=%d", i32);

	/* unsigned -> float */
	u32 = 100;
	f = (float)u32;
	CHECK(f == 100.0f, EDOM, "u32->f");

	/* float -> double -> float roundtrip */
	f = 3.14159265f;
	d = (double)f;
	CHECK(d > 3.1415 && d < 3.1416, EDOM, "f->d d=%.10f", d);
	f = (float)d;
	CHECK(f > 3.1415f && f < 3.1416f, EDOM, "d->f");

	/* double -> int (large value) */
	d = 123456789.0;
	i32 = (int)d;
	CHECK(i32 == 123456789, EDOM, "d->i32 i32=%d", i32);

out:
	TEST_END();
}

/*
 * float_test: Test float/double/long double arithmetic
 * Tests: +, -, *, / operations with precision verification
 */
void float_test(void)
{
	int i = 0;

	TEST_START("float");

	for (i = 0; i < test_rand() % 8 + 1; i++) {
		CHECK(float_d_test(test_rand() % 10 + 1) == 0, EDOM);
		CHECK(float_f_test(test_rand() % 50 + 1) == 0, EDOM);
		CHECK(float_ld_test(test_rand() % 5 + 1) == 0, EDOM);
	}

	/* negative/mixed-sign coverage */
	for (i = 0; i < test_rand() % 4 + 1; i++) {
		CHECK(float_f_neg_test(test_rand() % 30 + 1) == 0, EDOM);
		CHECK(float_d_neg_test(test_rand() % 8 + 1) == 0, EDOM);
	}

	float_convert_test();

out:
	TEST_END();
}

void float_corner_test(void)
{
	volatile double d_nan, d_inf_pos, d_inf_neg, d_zero_neg, d_one;
	volatile float f_nan, f_inf, f_zero_neg, f_denorm;
	volatile double d_denorm;

	TEST_START("float_corner_test");

	d_one = 1.0;
	d_nan = (double)NAN;
	d_inf_pos = (double)INFINITY;
	d_inf_neg = -d_inf_pos;
	d_zero_neg = -0.0;

	/* NaN compares unequal to itself. */
	CHECK(d_nan != d_nan, EDOM, "NaN==NaN unexpected");
	CHECK(isnan(d_nan), EDOM, "isnan(NaN) false");
	CHECK(!isnan(d_one), EDOM, "isnan(1.0) true");

	/* Inf compares as expected. */
	CHECK(isinf(d_inf_pos), EDOM, "isinf(+inf) false");
	CHECK(isinf(d_inf_neg), EDOM, "isinf(-inf) false");
	CHECK(d_inf_pos > 1.0e308, EDOM, "+inf <= huge");
	CHECK(d_inf_neg < -1.0e308, EDOM, "-inf >= -huge");

	/* signbit on -0.0 must be true; on +0.0 false. */
	CHECK(signbit(d_zero_neg) != 0, EDOM, "signbit(-0.0) false");
	CHECK(signbit(0.0) == 0, EDOM, "signbit(+0.0) true");

	/* float NaN/inf parity */
	f_nan = (float)NAN;
	f_inf = (float)INFINITY;
	CHECK(isnan(f_nan), EDOM, "float isnan false");
	CHECK(isinf(f_inf), EDOM, "float isinf false");

	/* float -0.0 signbit */
	f_zero_neg = -0.0f;
	CHECK(signbit(f_zero_neg) != 0, EDOM, "float signbit(-0.0) false");
	CHECK(signbit(0.0f) == 0, EDOM, "float signbit(+0.0) true");

	/* Inf arithmetic: Inf + Inf = Inf, Inf - Inf = NaN, Inf / Inf = NaN */
	CHECK(isinf(d_inf_pos + d_inf_pos), EDOM, "Inf+Inf != Inf");
	CHECK(isnan(d_inf_pos - d_inf_pos), EDOM, "Inf-Inf != NaN");
	CHECK(isnan(d_inf_pos / d_inf_pos), EDOM, "Inf/Inf != NaN");

	/* Division by zero: +finite / 0.0 gives +Inf; 0.0/0.0 gives NaN */
	CHECK(isinf(1.0 / 0.0) && !signbit(1.0 / 0.0),
		EDOM, "1.0/0.0 != +Inf");
	CHECK(isinf(-1.0 / 0.0) && signbit(-1.0 / 0.0),
		EDOM, "-1.0/0.0 != -Inf");
	CHECK(isnan(0.0 / 0.0), EDOM, "0.0/0.0 != NaN");

	/* Float overflow: FLT_MAX * 2.0f -> Inf */
	CHECK(isinf(FLT_MAX * 2.0f), EDOM, "FLT_MAX*2 != Inf");

	/*
	 * Denormal smoke: smallest positive non-zero / 2 may flush to 0
	 * but must not crash. We just verify division works and result
	 * is finite or zero (no NaN, no inf).
	 */
	d_denorm = DBL_MIN / 2.0;
	CHECK(!isnan(d_denorm) && !isinf(d_denorm), EDOM,
		"double denormal NaN/Inf");
	f_denorm = FLT_MIN / 2.0f;
	CHECK(!isnan(f_denorm) && !isinf(f_denorm), EDOM,
		"float denormal NaN/Inf");

out:
	TEST_END();
}
