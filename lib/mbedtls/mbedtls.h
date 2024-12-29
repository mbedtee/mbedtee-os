/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 *
 * Additional APIs for mbedtee which are not privoded by Mbed TLS
 * e.g. AES-CTS (CBC-CS3), e-GCD, DSA and partially cipher update
 */

#ifndef _MBEDTLS_H
#define _MBEDTLS_H

#include <stdbool.h>

#include <library/common.h>

#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/aes.h>
#include <mbedtls/rsa.h>
#include <mbedtls/dhm.h>
#include <mbedtls/ccm.h>
#include <mbedtls/gcm.h>
#include <mbedtls/cmac.h>
#include <mbedtls/asn1.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/error.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/cipher.h>
#include <mbedtls/bignum.h>
#include <mbedtls/asn1write.h>

/*
 * gcd -> GCD(x, y) -> u * x + y * v = gcd
 */
int mbedtls_mpi_egcd(mbedtls_mpi *gcd, mbedtls_mpi *u,
	mbedtls_mpi *v, const mbedtls_mpi *x, const mbedtls_mpi *y);

/*
 * AES-CTS buffer encryption/decryption
 * NIST SP800-38A Addendum (CTS = CBC-CS3)
 */
int mbedtls_aes_cts(mbedtls_cipher_context_t *cipher,
	void *input, size_t ilen, void *output, size_t *olen, bool is_final);

/*
 * copied from lib/mbedtls/library/aes.c, modification
 * is intended to support the partially cipher text update
 */
int mbedtls_aes_xts(mbedtls_cipher_context_t *cipher,
	void *input, size_t ilen, void *output, size_t *olen, bool is_final);

int mbedtls_ecb_crypt(mbedtls_cipher_context_t *cipher,
	void *input, size_t ilen, void *output, size_t *olen, bool is_final);

/*
 * DSA Error codes
 */
#define MBEDTLS_ERR_DSA_BAD_INPUT_DATA		-0x8080  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_DSA_PARAM_GEN_FAILED	-0x8100  /**< Input data contains invalid padding and is rejected. */
#define MBEDTLS_ERR_DSA_KEY_GEN_FAILED		-0x8180  /**< Something failed during generation of a key. */
#define MBEDTLS_ERR_DSA_KEY_CHECK_FAILED	-0x8200  /**< Key failed to pass the validity check of the library. */
#define MBEDTLS_ERR_DSA_VERIFY_FAILED		-0x8280  /**< The signature verification failed. */
#define MBEDTLS_ERR_DSA_RNG_FAILED			-0x8300  /**< The random generator failed to generate non-zeros. */

#define MBEDTLS_DSA_MAX_SIG_LEN(qbits)								\
	(/*T,L of SEQUENCE*/ ((qbits) >= 61 * 8 ? 3 : 2) +				\
	/*T,L of r,s*/			2 * (((qbits) >= 127 * 8 ? 3 : 2) +	\
	/*V of r,s*/			((qbits) + 8) / 8))

/**
 * \brief	The DSA context structure.
 *
 * \note	Direct manipulation of the members of this structure
 *			is deprecated. All manipulation should instead be done through
 *			the public interface functions.
 */
typedef struct mbedtls_dsa_context {
	mbedtls_mpi P;			/*!<  The prime modulus. */
	mbedtls_mpi Q;			/*!<  The prime divisor. */

	mbedtls_mpi G;			/*!<  base. */
	mbedtls_mpi Y;			/*!<  public value. */
	mbedtls_mpi X;			/*!<  private value. */
} mbedtls_dsa_context;

/**
 * \brief			This function initializes an DSA context.
 *
 * \param ctx		The DSA context to initialize. This must not be \c NULL.
 */
void mbedtls_dsa_init(mbedtls_dsa_context *ctx);


/**
 * \brief			This function imports core DSA parameters, in raw big-endian
 *					binary format, into an DSA context.
 *
 * \note			mbedtls_dsa_init() must be called before this function,
 *					to set up the DSA context.
 *
 * \note			This function can be called multiple times for successive
 *					imports, if the parameters are not simultaneously present.
 *
 * \note			The imported parameters are copied and need not be preserved
 *					for the lifetime of the DSA context being set up.
 *
 * \param ctx		The initialized DSA context to store the parameters in.
 * \param P			The prime modulus. This must not be \c NULL.
 * \param P_len		The Byte length of \p P; This must not be \c 0.
 * \param Q			The prime divisor. This must not be \c NULL.
 * \param Q_len		The Byte length of \p Q;  This must not be \c 0.
 * \param G			The base. This must not be \c NULL.
 * \param G_len		The Byte length of \p G; This must not be \c 0.
 * \param Y			The public value. This may be \c NULL.
 * \param Y_len		The Byte length of \p Y; it is ignored if \p Y == NULL.
 * \param X			The private value. This may be \c NULL.
 * \param X_len		The Byte length of \p X; it is ignored if \p X == NULL.
 *
 * \return			\c 0 on success.
 * \return			A non-zero error code on failure.
 */
int mbedtls_dsa_import_raw(mbedtls_dsa_context *ctx,
				unsigned char const *P, size_t P_len,
				unsigned char const *Q, size_t Q_len,
				unsigned char const *G, size_t G_len,
				unsigned char const *Y, size_t Y_len,
				unsigned char const *X, size_t X_len);

/**
 * \brief			This function exports core parameters of an DSA key
 *					in raw big-endian binary format.
 *
 *					If this function runs successfully, the non-NULL buffers
 *					pointed to by \p P, \p Q, \p G, \p Y, and \p X are fully
 *					written, with additional unused space filled leading by
 *					zero Bytes.
 *
 * \note			The length parameters are ignored if the corresponding
 *					buffer pointers are NULL.
 *
 * \param ctx		The initialized DSA context.
 * \param P			The Byte array to store the DSA modulus,
 *					or \c NULL if this field need not be exported.
 * \param P_len		The size of the buffer for the modulus.
 * \param Q			The Byte array to hold the prime divisor,
 *					or \c NULL if this field need not be exported.
 * \param Q_len		The size of the buffer for the prime divisor.
 * \param G			The Byte array to hold the base,
 *					or \c NULL if this field need not be exported.
 * \param G_len		The size of the buffer for the base.
 * \param Y			The Byte array to hold the public value,
 *					or \c NULL if this field need not be exported.
 * \param Y_len		The size of the buffer for the public value.
 * \param X			The Byte array to hold the private value,
 *					or \c NULL if this field need not be exported.
 * \param X_len		The size of the buffer for the private value.
 *
 * \return			\c 0 on success.
 * \return			A non-zero return code on any other failure.
 */
int mbedtls_dsa_export_raw(const mbedtls_dsa_context *ctx,
				unsigned char *P, size_t P_len,
				unsigned char *Q, size_t Q_len,
				unsigned char *G, size_t G_len,
				unsigned char *Y, size_t Y_len,
				unsigned char *X, size_t X_len);

/**
 * \brief			This function generates an DSA Params (P, Q and G).
 *
 * \note			mbedtls_dsa_init() must be called before this function,
 *					to set up the DSA context.
 *
 * \param ctx		The initialized DSA context used to hold the Params.
 * \param f_rng		The RNG function to be used for Params generation.
 *					This must not be \c NULL.
 * \param p_rng		The RNG context to be passed to \p f_rng.
 *					This may be \c NULL if \p f_rng doesn't need a context.
 * \param nbits		The size of the modulus in bits.
 *
 * \return			\c 0 on success.
 * \return			An \c MBEDTLS_ERR_DSA_XXX error code on failure.
 */
int mbedtls_dsa_gen_params(mbedtls_dsa_context *ctx,
			 int (*f_rng)(void *, unsigned char *, size_t),
			 void *p_rng, unsigned int nbits);

/**
 * \brief			This function generates an DSA keypair (Y and X).
 *
 * \note			mbedtls_dsa_init() must be called before this function,
 *					to set up the DSA context.
 *
 * \note			mbedtls_dsa_import_raw() or mbedtls_dsa_gen_params()
 *					must be called before this function, to set up the
 *					DSA parameters P, Q and G.
 *
 * \param ctx		The initialized DSA context used to hold the key.
 * \param f_rng		The RNG function to be used for key generation.
 *					This must not be \c NULL.
 * \param p_rng		The RNG context to be passed to \p f_rng.
 *					This may be \c NULL if \p f_rng doesn't need a context.
 *
 * \return			\c 0 on success.
 * \return			An \c MBEDTLS_ERR_DSA_XXX error code on failure.
 */
int mbedtls_dsa_gen_key(mbedtls_dsa_context *ctx,
			 int (*f_rng)(void *, unsigned char *, size_t),
			 void *p_rng);

/**
 * \brief			This function checks if a context contains at least an DSA
 *					public key (P, Q, G and Y).
 *
 *					If the function runs successfully, it is guaranteed that
 *					enough information is present to perform an DSA public key
 *					operation using mbedtls_dsa_verify().
 *
 * \param ctx		The initialized DSA context to check.
 *
 * \return			\c 0 on success.
 * \return			An \c MBEDTLS_ERR_DSA_XXX error code on failure.
 *
 */
int mbedtls_dsa_check_pubkey(const mbedtls_dsa_context *ctx);

/**
 * \brief			This function checks if a context contains an DSA private key
 *					and (P, Q, G, and X).
 *
 *					If the function runs successfully, it is guaranteed that
 *					enough information is present to perform an DSA private key
 *					operation using mbedtls_dsa_sign().
 *
 * \param ctx		The initialized DSA context to check.
 *
 * \return			\c 0 on success.
 * \return			An \c MBEDTLS_ERR_DSA_XXX error code on failure.
 */
int mbedtls_dsa_check_privkey(const mbedtls_dsa_context *ctx);

/**
 * \brief			This function performs a private DSA operation to sign
 *					a message digest.
 *
 * \note			The \p sig buffer must be as large as the size
 *					of \p ctx->P. For example, 128 Bytes if DSA-1024 is used.
 *
 * \param ctx		The initialized DSA context to use.
 * \param f_rng		The RNG function to use.
 * \param p_rng		The RNG context to be passed to \p f_rng. This may be \c NULL
 *					if \p f_rng is \c NULL or doesn't need a context argument.
 * \param hashlen	The length of the message digest.
 *					Ths is only used if \p md_alg is #MBEDTLS_MD_NONE.
 * \param hash		The buffer holding the message digest or raw data.
 *					If \p md_alg is #MBEDTLS_MD_NONE, this must be a readable
 *					buffer of length \p hashlen Bytes. If \p md_alg is not
 *					#MBEDTLS_MD_NONE, it must be a readable buffer of length
 *					the size of the hash corresponding to \p md_alg.
 * \param sig		The buffer to hold the signature. This must be a writable
 *					buffer of length \c at least 2 * hashlen plus 2 Bytes.
 *					A buffer length of #MBEDTLS_MPI_MAX_SIZE is always safe.
 * \param slen		The address at which to store the actual length of
 *					the signature written. Must not be \c NULL.
 *
 * \return			\c 0 if the signing operation was successful.
 * \return			An \c MBEDTLS_ERR_DSA_XXX error code on failure.
 */
int mbedtls_dsa_sign(mbedtls_dsa_context *ctx,
			int (*f_rng)(void *, unsigned char *, size_t),
			void *p_rng,
			unsigned int hashlen,
			const unsigned char *hash,
			unsigned char *sig,
			size_t *slen);

/**
 * \brief			This function performs a public DSA operation and checks
 *					the message digest.
 *
 * \param ctx		The initialized DSA public key context to use.
 * \param hashlen	The length of the message digest.
 *					This is only used if \p md_alg is #MBEDTLS_MD_NONE.
 * \param hash		The buffer holding the message digest or raw data.
 *					If \p md_alg is #MBEDTLS_MD_NONE, this must be a readable
 *					buffer of length \p hashlen Bytes. If \p md_alg is not
 *					#MBEDTLS_MD_NONE, it must be a readable buffer of length
 *					the size of the hash corresponding to \p md_alg.
 * \param sig		The buffer holding the signature. This must be a readable
 *					buffer of length \c ctx->len Bytes. For example, \c 256 Bytes
 *					for an 2048-bit DSA modulus.
 * \param slen		The size of \p sig in Bytes.
 *
 * \return			\c 0 if the verify operation was successful.
 * \return			An \c MBEDTLS_ERR_DSA_XXX error code on failure.
 */
int mbedtls_dsa_verify(mbedtls_dsa_context *ctx,
			  int (*f_rng)(void *, unsigned char *, size_t),
			  void *p_rng,
			  unsigned int hashlen,
			  const unsigned char *hash,
			  const unsigned char *sig,
			  size_t slen);

/**
 * \brief			This function frees the components of an DSA key.
 *
 * \param ctx		The DSA context to free. May be \c NULL, in which case
 *					this function is a no-op. If it is not \c NULL, it must
 *					point to an initialized DSA context.
 */
void mbedtls_dsa_free(mbedtls_dsa_context *ctx);

#endif
