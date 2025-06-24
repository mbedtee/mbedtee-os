// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2024 Xing Loong <xing.xl.loong@gmail.com>
 * SM2 Key Exchange Protocol (GB/T 32918.3-2016)
 *
 * Implements the SM2 two-party authenticated key exchange.
 * Reference: GM/T 0003.3-2012 / GB/T 32918.3-2016
 */

#include <stdlib.h>
#include <string.h>

#include <mbedcrypto/sm2kep.h>

/*
 * SM2 KDF (Key Derivation Function based on SM3)
 * Reusable by both sm2pke and sm2kep.
 *
 * KDF(Z, klen):
 *   ct = 0x00000001
 *   for i = 1 to ceil(klen / 32):
 *     Ha_i = SM3(Z || ct)
 *     ct++
 *   K = Ha_1 || Ha_2 || ... truncated to klen bytes
 */
int mbedcrypto_sm2_kdf(const uint8_t *z, size_t zlen,
		uint8_t *out, size_t klen)
{
	uint32_t ct = 1;
	uint8_t ct_buf[4];
	size_t off = 0;

	while (off < klen) {
		struct mbedcrypto_sm3_ctx sm3;
		uint8_t hash[32];
		size_t chunk = 0;
		int ret = 0;

		ret = mbedcrypto_sm3_init(&sm3);
		if (ret != 0)
			return ret;

		mbedcrypto_sm3_update(&sm3, z, zlen);

		ct_buf[0] = (ct >> 24) & 0xff;
		ct_buf[1] = (ct >> 16) & 0xff;
		ct_buf[2] = (ct >>  8) & 0xff;
		ct_buf[3] = ct & 0xff;
		mbedcrypto_sm3_update(&sm3, ct_buf, 4);

		ret = mbedcrypto_sm3_final(&sm3, hash);
		mbedcrypto_sm3_cleanup(&sm3);
		if (ret != 0)
			return ret;

		chunk = klen - off;
		if (chunk > 32)
			chunk = 32;
		memcpy(out + off, hash, chunk);
		off += chunk;
		ct++;
	}

	return 0;
}

/*
 * Compute Z = SM3(ENTL || ID || a || b || xG || yG || xP || yP)
 *
 * grp: the SM2 elliptic curve group
 * id/idlen: user identity string
 * pub: public point (xP, yP)
 * z: output, 32 bytes
 */
static int sm2kep_compute_z(const struct mbedcrypto_ecp_group *grp,
		const uint8_t *id, size_t idlen,
		const struct mbedcrypto_ecp_point *pub, uint8_t z[32])
{
	struct mbedcrypto_sm3_ctx sm3;
	uint8_t entl[2];
	uint8_t buf[SM2_INT_SIZE_BYTES];
	struct mbedcrypto_bignum a_mod;
	size_t bitlen = 0;
	int ret = 0;

	if (idlen > 8191)
		return -EINVAL;

	bitlen = idlen * 8;
	entl[0] = (bitlen >> 8) & 0xff;
	entl[1] = bitlen & 0xff;

	ret = mbedcrypto_sm3_init(&sm3);
	if (ret != 0)
		return ret;

	mbedcrypto_sm3_update(&sm3, entl, 2);
	mbedcrypto_sm3_update(&sm3, id, idlen);

	/*
	 * a: grp->A may be stored as -3 (signed). Convert to
	 * the modular representative (P + A) for hashing.
	 */
	mbedcrypto_bn_init(&a_mod);
	if (grp->A.neg) {
		ret = mbedcrypto_bn_add(&a_mod, &grp->P, &grp->A);
		if (ret != 0) {
			mbedcrypto_bn_cleanup(&a_mod);
			mbedcrypto_sm3_cleanup(&sm3);
			return ret;
		}
		mbedcrypto_bn_to_binary(&a_mod, buf, SM2_INT_SIZE_BYTES);
	} else
		mbedcrypto_bn_to_binary(&grp->A, buf, SM2_INT_SIZE_BYTES);

	mbedcrypto_bn_cleanup(&a_mod);
	mbedcrypto_sm3_update(&sm3, buf, SM2_INT_SIZE_BYTES);

	/* b */
	mbedcrypto_bn_to_binary(&grp->B, buf, SM2_INT_SIZE_BYTES);
	mbedcrypto_sm3_update(&sm3, buf, SM2_INT_SIZE_BYTES);

	/* xG */
	mbedcrypto_bn_to_binary(&grp->G.X, buf, SM2_INT_SIZE_BYTES);
	mbedcrypto_sm3_update(&sm3, buf, SM2_INT_SIZE_BYTES);

	/* yG */
	mbedcrypto_bn_to_binary(&grp->G.Y, buf, SM2_INT_SIZE_BYTES);
	mbedcrypto_sm3_update(&sm3, buf, SM2_INT_SIZE_BYTES);

	/* xP */
	mbedcrypto_bn_to_binary(&pub->X, buf, SM2_INT_SIZE_BYTES);
	mbedcrypto_sm3_update(&sm3, buf, SM2_INT_SIZE_BYTES);

	/* yP */
	mbedcrypto_bn_to_binary(&pub->Y, buf, SM2_INT_SIZE_BYTES);
	mbedcrypto_sm3_update(&sm3, buf, SM2_INT_SIZE_BYTES);

	ret = mbedcrypto_sm3_final(&sm3, z);
	mbedcrypto_sm3_cleanup(&sm3);
	return ret;
}

/*
 * Compute verification hash S:
 *   inner = SM3(xU || ZA || ZB || x1 || y1 || x2 || y2)
 *   S = SM3(flag || yU || inner)
 *
 * flag: 0x02 for initiator checking, 0x03 for responder checking
 */
static int sm2kep_compute_s(uint8_t *s, uint8_t flag,
		const struct mbedcrypto_ecp_point *uv,
		const uint8_t *za, const uint8_t *zb,
		const struct mbedcrypto_ecp_point *r1,
		const struct mbedcrypto_ecp_point *r2)
{
	uint8_t hash[32];
	uint8_t buf[SM2_INT_SIZE_BYTES];
	struct mbedcrypto_sm3_ctx sm3;
	int ret = 0;

	/* Inner hash: SM3(xU || ZA || ZB || x1 || y1 || x2 || y2) */
	ret = mbedcrypto_sm3_init(&sm3);
	if (ret != 0)
		return ret;

	mbedcrypto_bn_to_binary(&uv->X, buf, SM2_INT_SIZE_BYTES);
	mbedcrypto_sm3_update(&sm3, buf, SM2_INT_SIZE_BYTES);
	mbedcrypto_sm3_update(&sm3, za, 32);
	mbedcrypto_sm3_update(&sm3, zb, 32);
	mbedcrypto_bn_to_binary(&r1->X, buf, SM2_INT_SIZE_BYTES);
	mbedcrypto_sm3_update(&sm3, buf, SM2_INT_SIZE_BYTES);
	mbedcrypto_bn_to_binary(&r1->Y, buf, SM2_INT_SIZE_BYTES);
	mbedcrypto_sm3_update(&sm3, buf, SM2_INT_SIZE_BYTES);
	mbedcrypto_bn_to_binary(&r2->X, buf, SM2_INT_SIZE_BYTES);
	mbedcrypto_sm3_update(&sm3, buf, SM2_INT_SIZE_BYTES);
	mbedcrypto_bn_to_binary(&r2->Y, buf, SM2_INT_SIZE_BYTES);
	mbedcrypto_sm3_update(&sm3, buf, SM2_INT_SIZE_BYTES);

	ret = mbedcrypto_sm3_final(&sm3, hash);
	mbedcrypto_sm3_cleanup(&sm3);
	if (ret != 0)
		return ret;

	/* Outer hash: SM3(flag || yU || inner) */
	ret = mbedcrypto_sm3_init(&sm3);
	if (ret != 0)
		return ret;

	mbedcrypto_sm3_update(&sm3, &flag, 1);
	mbedcrypto_bn_to_binary(&uv->Y, buf, SM2_INT_SIZE_BYTES);
	mbedcrypto_sm3_update(&sm3, buf, SM2_INT_SIZE_BYTES);
	mbedcrypto_sm3_update(&sm3, hash, 32);

	ret = mbedcrypto_sm3_final(&sm3, s);
	mbedcrypto_sm3_cleanup(&sm3);
	return ret;
}

/*
 * SM2 Key Exchange Protocol - GB/T 32918.3-2016 Section 6.1
 *
 * Both initiator and responder execute the same algorithm
 * (my_key is the local static key, my_eph_key is the local ephemeral key).
 *
 * Key derivation:
 *   w = ceil(ceil(log2(n)) / 2) - 1
 *   x_bar = 2^w + (x & (2^w - 1))
 *   tA = (dA + x_bar_A * rA) mod n
 *   U  = [h * tA] * (PB + [x_bar_B] * RB)
 *   KA = KDF(xU || yU || ZA || ZB, klen)
 *
 * For SM2's 256-bit curve, w = 127.
 */
int mbedcrypto_sm2kep_derive(
		struct mbedcrypto_ecp_keypair *my_key,
		struct mbedcrypto_ecp_keypair *my_eph_key,
		struct mbedcrypto_ecp_point *peer_key,
		struct mbedcrypto_ecp_point *peer_eph_key,
		struct mbedcrypto_sm2kep_parms *p)
{
	/* kdf_input: xU(32) || yU(32) || ZA(32) || ZB(32) */
	uint8_t kdf_input[4 * SM2_INT_SIZE_BYTES];
	uint8_t za[32], zb[32];
	uint8_t tmp[SM2_INT_SIZE_BYTES];
	struct mbedcrypto_ecp_group *grp = &my_key->grp;
	struct mbedcrypto_ecp_point pb_pt, rb_pt, u_pt;
	struct mbedcrypto_bignum x1bar, x2bar, ta, one;
	const struct mbedcrypto_ecp_point *init_eph = NULL;
	const struct mbedcrypto_ecp_point *resp_eph = NULL;
	int ret = -EINVAL;

	mbedcrypto_ecp_point_init(&pb_pt);
	mbedcrypto_ecp_point_init(&rb_pt);
	mbedcrypto_ecp_point_init(&u_pt);
	mbedcrypto_bn_init(&x1bar);
	mbedcrypto_bn_init(&x2bar);
	mbedcrypto_bn_init(&ta);
	mbedcrypto_bn_init(&one);

	if (p->is_initiator) {
		init_eph = &my_eph_key->Q;
		resp_eph = peer_eph_key;
	} else {
		init_eph = peer_eph_key;
		resp_eph = &my_eph_key->Q;
	}

	/*
	 * Step A4: x1bar = 2^w + (x1 & (2^w - 1))
	 * For SM2 256-bit, w = 127. So we take the low 128 bits (16 bytes)
	 * of x and set the top bit (bit 127).
	 */

	ret = mbedcrypto_bn_to_binary(&my_eph_key->Q.X,
				      tmp, SM2_INT_SIZE_BYTES);
	if (ret != 0)
		goto out;
	tmp[SM2_INT_SIZE_BYTES / 2] |= 0x80;

	ret = mbedcrypto_bn_from_binary(&x1bar,
					tmp + SM2_INT_SIZE_BYTES / 2,
					SM2_INT_SIZE_BYTES / 2);
	if (ret != 0)
		goto out;

	/* Step A5: tA = (dA + x1bar * rA) mod n */

	ret = mbedcrypto_bn_mul(&ta, &x1bar, &my_eph_key->d);
	if (ret != 0)
		goto out;

	ret = mbedcrypto_bn_mod(&ta, &ta, &grp->N);
	if (ret != 0)
		goto out;

	ret = mbedcrypto_bn_add(&ta, &ta, &my_key->d);
	if (ret != 0)
		goto out;

	ret = mbedcrypto_bn_mod(&ta, &ta, &grp->N);
	if (ret != 0)
		goto out;

	/* Step A6: x2bar = 2^w + (x2 & (2^w - 1)) for peer ephemeral */

	ret = mbedcrypto_bn_to_binary(&peer_eph_key->X,
				      tmp, SM2_INT_SIZE_BYTES);
	if (ret != 0)
		goto out;
	tmp[SM2_INT_SIZE_BYTES / 2] |= 0x80;

	ret = mbedcrypto_bn_from_binary(&x2bar,
					tmp + SM2_INT_SIZE_BYTES / 2,
					SM2_INT_SIZE_BYTES / 2);
	if (ret != 0)
		goto out;

	/* Step A6: verify RB is on curve */
	mbedcrypto_bn_copy(&rb_pt.X, &peer_eph_key->X);
	mbedcrypto_bn_copy(&rb_pt.Y, &peer_eph_key->Y);
	mbedcrypto_bn_set_word(&rb_pt.Z, 1);

	ret = mbedcrypto_ecp_validate_point(grp, &rb_pt);
	if (ret != 0)
		goto out;

	/* Step A7: U = [tA] * (PB + [x2bar] * RB) */
	/* SM2 cofactor h = 1, so [h * tA] = [tA] */
	mbedcrypto_bn_copy(&pb_pt.X, &peer_key->X);
	mbedcrypto_bn_copy(&pb_pt.Y, &peer_key->Y);
	mbedcrypto_bn_set_word(&pb_pt.Z, 1);

	ret = mbedcrypto_bn_set_word(&one, 1);
	if (ret != 0)
		goto out;

	/* U = 1*PB + x2bar*RB */

	ret = mbedcrypto_ecp_dual_scalar_mul(grp, &u_pt,
				    &one, &pb_pt,
				    &x2bar, &rb_pt);
	if (ret != 0)
		goto out;

	/* U = [tA] * U */

	ret = mbedcrypto_ecp_scalar_mul(grp, &u_pt, &ta, &u_pt,
					NULL, NULL);
	if (ret != 0)
		goto out;

	/* Check U is not point at infinity */

	if (mbedcrypto_ecp_is_infinity(&u_pt)) {
		ret = -EINVAL;
		goto out;
	}

	/* Step A8: KA = KDF(xU || yU || ZA || ZB, klen) */

	mbedcrypto_bn_to_binary(&u_pt.X, kdf_input, SM2_INT_SIZE_BYTES);
	mbedcrypto_bn_to_binary(&u_pt.Y,
				kdf_input + SM2_INT_SIZE_BYTES,
				SM2_INT_SIZE_BYTES);

	/* Compute ZA (initiator's Z value) */

	if (p->is_initiator)
		ret = sm2kep_compute_z(grp, p->initiator_id,
				       p->initiator_id_len,
				       &my_key->Q, za);
	else
		ret = sm2kep_compute_z(grp, p->initiator_id,
				       p->initiator_id_len,
				       peer_key, za);
	if (ret != 0)
		goto out;

	/* Compute ZB (responder's Z value) */

	if (p->is_initiator)
		ret = sm2kep_compute_z(grp, p->responder_id,
				       p->responder_id_len,
				       peer_key, zb);
	else
		ret = sm2kep_compute_z(grp, p->responder_id,
				       p->responder_id_len,
				       &my_key->Q, zb);
	if (ret != 0)
		goto out;

	memcpy(kdf_input + 2 * SM2_INT_SIZE_BYTES, za, 32);
	memcpy(kdf_input + 2 * SM2_INT_SIZE_BYTES + 32, zb, 32);

	ret = mbedcrypto_sm2_kdf(kdf_input, sizeof(kdf_input),
				 p->out, p->out_len);
	if (ret != 0)
		goto out;

	/* Step A9: optional confirmation verification */
	if (p->conf_in && p->conf_in_len >= 32) {
		uint8_t s1[32];
		uint8_t flag = p->is_initiator ? 0x02 : 0x03;

		ret = sm2kep_compute_s(s1, flag, &u_pt, za, zb,
				       init_eph, resp_eph);
		if (ret != 0)
			goto out;

		if (mbedcrypto_ct_memcmp(s1, p->conf_in, 32) != 0) {
			ret = -EBADMSG;
			goto out;
		}
	}

	/* Step A10: optional confirmation output */
	if (p->conf_out && p->conf_out_len >= 32) {
		uint8_t flag = p->is_initiator ? 0x03 : 0x02;

		ret = sm2kep_compute_s(p->conf_out, flag, &u_pt,
				       za, zb, init_eph, resp_eph);
		if (ret != 0)
			goto out;
	}

	ret = 0;

out:
	mbedcrypto_ecp_point_cleanup(&pb_pt);
	mbedcrypto_ecp_point_cleanup(&rb_pt);
	mbedcrypto_ecp_point_cleanup(&u_pt);
	mbedcrypto_bn_cleanup(&x1bar);
	mbedcrypto_bn_cleanup(&x2bar);
	mbedcrypto_bn_cleanup(&ta);
	mbedcrypto_bn_cleanup(&one);
	memset(kdf_input, 0, sizeof(kdf_input));
	memset(za, 0, sizeof(za));
	memset(zb, 0, sizeof(zb));
	return ret;
}
