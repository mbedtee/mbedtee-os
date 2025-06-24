// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>
 * Elliptic Curve Diffie-Hellman (ECDH)
 *
 * Shared secret = X coordinate of (d * Qp), zero-padded to field size.
 */

#include <mbedcrypto/ecdh.h>

void mbedcrypto_ecdh_init(struct mbedcrypto_ecdh_ctx *ctx)
{
	mbedcrypto_ecp_group_init(&ctx->grp);
	mbedcrypto_bn_init(&ctx->d);
	mbedcrypto_ecp_point_init(&ctx->Q);
	mbedcrypto_ecp_point_init(&ctx->Qp);
}

void mbedcrypto_ecdh_cleanup(struct mbedcrypto_ecdh_ctx *ctx)
{
	mbedcrypto_ecp_group_cleanup(&ctx->grp);
	mbedcrypto_bn_cleanup(&ctx->d);
	mbedcrypto_ecp_point_cleanup(&ctx->Q);
	mbedcrypto_ecp_point_cleanup(&ctx->Qp);
}

int mbedcrypto_ecdh_setup(struct mbedcrypto_ecdh_ctx *ctx,
		int grp_id,
		const struct mbedcrypto_bignum *priv,
		const struct mbedcrypto_ecp_point *peer_pub)
{
	int ret = 0;

	ret = mbedcrypto_ecp_load_group(&ctx->grp, grp_id);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_bn_copy(&ctx->d, priv);
	if (ret != 0)
		return ret;

	ret = mbedcrypto_bn_copy(&ctx->Qp.X, &peer_pub->X);
	if (ret != 0)
		return ret;
	ret = mbedcrypto_bn_copy(&ctx->Qp.Y, &peer_pub->Y);
	if (ret != 0)
		return ret;
	ret = mbedcrypto_bn_copy(&ctx->Qp.Z, &peer_pub->Z);

	return ret;
}

int mbedcrypto_ecdh_derive_shared(struct mbedcrypto_ecdh_ctx *ctx,
		size_t *olen, uint8_t *buf, size_t blen,
		mbedcrypto_rng_fn f_rng, void *p_rng)
{
	int ret = 0;
	struct mbedcrypto_ecp_point P;
	size_t field_size = (ctx->grp.pbits + 7) / 8;

	if (blen < field_size)
		return -EINVAL;

	/* Validate peer public key */
	if ((ret = mbedcrypto_ecp_validate_point(&ctx->grp, &ctx->Qp)) != 0)
		return ret;

	mbedcrypto_ecp_point_init(&P);

	/* P = d * Qp */
	ret = mbedcrypto_ecp_scalar_mul(&ctx->grp, &P, &ctx->d, &ctx->Qp,
			f_rng, p_rng);
	if (ret != 0)
		goto cleanup;

	if (mbedcrypto_ecp_is_infinity(&P)) {
		ret = -EINVAL;
		goto cleanup;
	}

	/* Output X coordinate, zero-padded to field size */
	if ((ret = mbedcrypto_bn_to_binary(&P.X, buf, field_size)) != 0)
		goto cleanup;

	*olen = field_size;

cleanup:
	mbedcrypto_ecp_point_cleanup(&P);
	return ret;
}
