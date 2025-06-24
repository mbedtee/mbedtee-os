/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2024 Xing Loong <xing.xl.loong@gmail.com>
 * SM2 Key Exchange Protocol (GB/T 32918.3-2016)
 */

#ifndef _MBEDCRYPTO_SM2KEP_H
#define _MBEDCRYPTO_SM2KEP_H

#include <mbedcrypto/ecp.h>
#include <mbedcrypto/sm3.h>

#define SM2_INT_SIZE_BYTES 32

struct mbedcrypto_sm2kep_parms {
	int is_initiator;
	const uint8_t *initiator_id;
	size_t initiator_id_len;
	const uint8_t *responder_id;
	size_t responder_id_len;
	uint8_t *out;
	size_t out_len;
	const uint8_t *conf_in;
	size_t conf_in_len;
	uint8_t *conf_out;
	size_t conf_out_len;
};

#if defined(CONFIG_MBEDCRYPTO_SM2)

/*
 * SM2 KDF (Key Derivation Function based on SM3)
 * GB/T 32918.4 Section 5.4.3
 */
int mbedcrypto_sm2_kdf(const uint8_t *z, size_t zlen,
		uint8_t *out, size_t klen);

/*
 * SM2 Key Exchange Protocol
 * GB/T 32918.3-2016 Section 6.1
 *
 * my_key:       local static keypair (grp, d, Q)
 * my_eph_key:   local ephemeral keypair (grp, d, Q)
 * peer_key:     peer's static public key (Q)
 * peer_eph_key: peer's ephemeral public key (Q)
 * p:            key exchange parameters
 *
 * The caller must load SM2 group into my_key->grp and my_eph_key->grp
 * before calling this function.
 */
int mbedcrypto_sm2kep_derive(
		struct mbedcrypto_ecp_keypair *my_key,
		struct mbedcrypto_ecp_keypair *my_eph_key,
		struct mbedcrypto_ecp_point *peer_key,
		struct mbedcrypto_ecp_point *peer_eph_key,
		struct mbedcrypto_sm2kep_parms *p);

#else /* !CONFIG_MBEDCRYPTO_SM2 */

static inline int mbedcrypto_sm2_kdf(const uint8_t *z, size_t zlen,
		uint8_t *out, size_t klen)
{ return -ENOTSUP; }

static inline int mbedcrypto_sm2kep_derive(
		struct mbedcrypto_ecp_keypair *my_key,
		struct mbedcrypto_ecp_keypair *my_eph_key,
		struct mbedcrypto_ecp_point *peer_key,
		struct mbedcrypto_ecp_point *peer_eph_key,
		struct mbedcrypto_sm2kep_parms *p)
{ return -ENOTSUP; }

#endif /* CONFIG_MBEDCRYPTO_SM2 */

#endif /* _MBEDCRYPTO_SM2KEP_H */
