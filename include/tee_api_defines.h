/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Definition of GlobalPlatform TEE internal API
 */

#ifndef _TEE_API_DEFINES_H
#define _TEE_API_DEFINES_H

/* API Error Codes */
#define TEE_SUCCESS                          0x00000000
#define TEE_ERROR_CORRUPT_OBJECT             0xF0100001
#define TEE_ERROR_CORRUPT_OBJECT_2           0xF0100002
#define TEE_ERROR_STORAGE_NOT_AVAILABLE      0xF0100003
#define TEE_ERROR_STORAGE_NOT_AVAILABLE_2    0xF0100004
#define TEE_ERROR_CIPHERTEXT_INVALID         0xF0100006
#define TEE_ERROR_GENERIC                    0xFFFF0000
#define TEE_ERROR_ACCESS_DENIED              0xFFFF0001
#define TEE_ERROR_CANCEL                     0xFFFF0002
#define TEE_ERROR_ACCESS_CONFLICT            0xFFFF0003
#define TEE_ERROR_EXCESS_DATA                0xFFFF0004
#define TEE_ERROR_BAD_FORMAT                 0xFFFF0005
#define TEE_ERROR_BAD_PARAMETERS             0xFFFF0006
#define TEE_ERROR_BAD_STATE                  0xFFFF0007
#define TEE_ERROR_ITEM_NOT_FOUND             0xFFFF0008
#define TEE_ERROR_NOT_IMPLEMENTED            0xFFFF0009
#define TEE_ERROR_NOT_SUPPORTED              0xFFFF000A
#define TEE_ERROR_NO_DATA                    0xFFFF000B
#define TEE_ERROR_OUT_OF_MEMORY              0xFFFF000C
#define TEE_ERROR_BUSY                       0xFFFF000D
#define TEE_ERROR_COMMUNICATION              0xFFFF000E
#define TEE_ERROR_SECURITY                   0xFFFF000F
#define TEE_ERROR_SHORT_BUFFER               0xFFFF0010
#define TEE_ERROR_EXTERNAL_CANCEL            0xFFFF0011
#define TEE_ERROR_OVERFLOW                   0xFFFF300F
#define TEE_ERROR_TARGET_DEAD                0xFFFF3024
#define TEE_ERROR_STORAGE_NO_SPACE           0xFFFF3041
#define TEE_ERROR_MAC_INVALID                0xFFFF3071
#define TEE_ERROR_SIGNATURE_INVALID          0xFFFF3072
#define TEE_ERROR_TIME_NOT_SET               0xFFFF5000
#define TEE_ERROR_TIME_NEEDS_RESET           0xFFFF5001

#define TEE_HANDLE_NULL                      0
#define TEE_TIMEOUT_INFINITE                 0xFFFFFFFF

/* TEE_Whence Constants */
#define TEE_DATA_SEEK_SET                    0x00000000
#define TEE_DATA_SEEK_CUR                    0x00000001
#define TEE_DATA_SEEK_END                    0x00000002
#define TEE_WHENCE_ILLEGAL_VALUE             0x7FFFFFFF

/* Parameter Type Constants */
#define TEE_PARAM_TYPE_NONE                  0
#define TEE_PARAM_TYPE_VALUE_INPUT           1
#define TEE_PARAM_TYPE_VALUE_OUTPUT          2
#define TEE_PARAM_TYPE_VALUE_INOUT           3
#define TEE_PARAM_TYPE_MEMREF_INPUT          5
#define TEE_PARAM_TYPE_MEMREF_OUTPUT         6
#define TEE_PARAM_TYPE_MEMREF_INOUT          7

/* Login Type Constants */
#define TEE_LOGIN_PUBLIC                     0x00000000
#define TEE_LOGIN_USER                       0x00000001
#define TEE_LOGIN_GROUP                      0x00000002
#define TEE_LOGIN_APPLICATION                0x00000004
#define TEE_LOGIN_APPLICATION_USER           0x00000005
#define TEE_LOGIN_APPLICATION_GROUP          0x00000006
#define TEE_LOGIN_TRUSTED_APP                0xF0000000

/* Origin Code Constants */
#define TEE_ORIGIN_API                       0x00000001
#define TEE_ORIGIN_COMMS                     0x00000002
#define TEE_ORIGIN_TEE                       0x00000003
#define TEE_ORIGIN_TRUSTED_APP               0x00000004

/* Property Sets pseudo handles */
#define TEE_PROPSET_TEE_IMPLEMENTATION  ((TEE_PropSetHandle)0xFFFFFFFD)
#define TEE_PROPSET_CURRENT_CLIENT      ((TEE_PropSetHandle)0xFFFFFFFE)
#define TEE_PROPSET_CURRENT_TA          ((TEE_PropSetHandle)0xFFFFFFFF)

/* Memory Access Rights Constants */
#define TEE_MEMORY_ACCESS_READ                  0x00000001
#define TEE_MEMORY_ACCESS_WRITE                 0x00000002
#define TEE_MEMORY_ACCESS_ANY_OWNER             0x00000004
#define TEE_MEMORY_ACCESS_NONSECURE             0x10000000
#define TEE_MEMORY_ACCESS_SECURE                0x20000000

/* Memory Management Constant */
#define TEE_MALLOC_FILL_ZERO                    0x00000000

/* Other constants */
#define TEE_STORAGE_PRIVATE                     0x00000001
#define TEE_STORAGE_ILLEGAL_VALUE               0x7FFFFFFF

#define STORAGE_ID_NOT_EXISTING                 0x01234567

#define TEE_DATA_FLAG_ACCESS_READ               0x00000001
#define TEE_DATA_FLAG_ACCESS_WRITE              0x00000002
#define TEE_DATA_FLAG_ACCESS_WRITE_META         0x00000004
#define TEE_DATA_FLAG_SHARE_READ                0x00000010
#define TEE_DATA_FLAG_SHARE_WRITE               0x00000020
#define TEE_DATA_FLAG_OVERWRITE                 0x00000400

#define TEE_USAGE_EXTRACTABLE                   0x00000001
#define TEE_USAGE_ENCRYPT                       0x00000002
#define TEE_USAGE_DECRYPT                       0x00000004
#define TEE_USAGE_MAC                           0x00000008
#define TEE_USAGE_SIGN                          0x00000010
#define TEE_USAGE_VERIFY                        0x00000020
#define TEE_USAGE_DERIVE                        0x00000040

#define TEE_DATA_MAX_POSITION                   0xFFFFFFFF
#define TEE_OBJECT_ID_MAX_LEN                   64

#define TEE_HANDLE_FLAG_PERSISTENT              0x00010000
#define TEE_HANDLE_FLAG_INITIALIZED             0x00020000
#define TEE_HANDLE_FLAG_KEY_SET                 0x00040000
#define TEE_HANDLE_FLAG_EXPECT_TWO_KEYS         0x00080000

#define TEE_OPERATION_CIPHER                    1
#define TEE_OPERATION_MAC                       3
#define TEE_OPERATION_AE                        4
#define TEE_OPERATION_DIGEST                    5
#define TEE_OPERATION_ASYMMETRIC_CIPHER         6
#define TEE_OPERATION_ASYMMETRIC_SIGNATURE      7
#define TEE_OPERATION_KEY_DERIVATION            8

#define TEE_OPERATION_STATE_INITIAL             0x00000000
#define TEE_OPERATION_STATE_ACTIVE              0x00000001

#define TEE_MODE_ENCRYPT                        0x00000000
#define TEE_MODE_DECRYPT                        0x00000001
#define TEE_MODE_SIGN                           0x00000002
#define TEE_MODE_VERIFY                         0x00000003
#define TEE_MODE_MAC                            0x00000004
#define TEE_MODE_DIGEST                         0x00000005
#define TEE_MODE_DERIVE                         0x00000006
#define TEE_MODE_ILLEGAL_VALUE                  0x7FFFFFFF

#define TEE_ALG_AES_ECB_NOPAD                   0x10000010
#define TEE_ALG_AES_CBC_NOPAD                   0x10000110
#define TEE_ALG_AES_CTR                         0x10000210
#define TEE_ALG_AES_CTS                         0x10000310
#define TEE_ALG_AES_XTS                         0x10000410
#define TEE_ALG_AES_CBC_MAC_NOPAD               0x30000110
#define TEE_ALG_AES_CBC_MAC_PKCS5               0x30000510
#define TEE_ALG_AES_CMAC                        0x30000610
#define TEE_ALG_AES_CCM                         0x40000710
#define TEE_ALG_AES_GCM                         0x40000810
#define TEE_ALG_DES_ECB_NOPAD                   0x10000011
#define TEE_ALG_DES_CBC_NOPAD                   0x10000111
#define TEE_ALG_DES_CBC_MAC_NOPAD               0x30000111
#define TEE_ALG_DES_CBC_MAC_PKCS5               0x30000511
#define TEE_ALG_DES3_ECB_NOPAD                  0x10000013
#define TEE_ALG_DES3_CBC_NOPAD                  0x10000113
#define TEE_ALG_DES3_CBC_MAC_NOPAD              0x30000113
#define TEE_ALG_DES3_CBC_MAC_PKCS5              0x30000513
#define TEE_ALG_RSASSA_PKCS1_V1_5_MD5           0x70001830
#define TEE_ALG_RSASSA_PKCS1_V1_5_SHA1          0x70002830
#define TEE_ALG_RSASSA_PKCS1_V1_5_SHA224        0x70003830
#define TEE_ALG_RSASSA_PKCS1_V1_5_SHA256        0x70004830
#define TEE_ALG_RSASSA_PKCS1_V1_5_SHA384        0x70005830
#define TEE_ALG_RSASSA_PKCS1_V1_5_SHA512        0x70006830
#define TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1      0x70212930
#define TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224    0x70313930
#define TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256    0x70414930
#define TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384    0x70515930
#define TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512    0x70616930
#define TEE_ALG_RSAES_PKCS1_V1_5                0x60000130
#define TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1      0x60210230
#define TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224    0x60310230
#define TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256    0x60410230
#define TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384    0x60510230
#define TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512    0x60610230
#define TEE_ALG_RSA_NOPAD                       0x60000030
#define TEE_ALG_DSA_SHA1                        0x70002131
#define TEE_ALG_DSA_SHA224                      0x70003131
#define TEE_ALG_DSA_SHA256                      0x70004131
#define TEE_ALG_DH_DERIVE_SHARED_SECRET         0x80000032
#define TEE_ALG_MD5                             0x50000001
#define TEE_ALG_SHA1                            0x50000002
#define TEE_ALG_SHA224                          0x50000003
#define TEE_ALG_SHA256                          0x50000004
#define TEE_ALG_SHA384                          0x50000005
#define TEE_ALG_SHA512                          0x50000006
#define TEE_ALG_SM3                             0x50000007
#define TEE_ALG_HMAC_MD5                        0x30000001
#define TEE_ALG_HMAC_SHA1                       0x30000002
#define TEE_ALG_HMAC_SHA224                     0x30000003
#define TEE_ALG_HMAC_SHA256                     0x30000004
#define TEE_ALG_HMAC_SHA384                     0x30000005
#define TEE_ALG_HMAC_SHA512                     0x30000006
#define TEE_ALG_HMAC_SM3                        0x30000007
#define TEE_ALG_ECDSA_SHA1                      0x70001042
#define TEE_ALG_ECDSA_SHA224                    0x70002042
#define TEE_ALG_ECDSA_SHA256                    0x70003042
#define TEE_ALG_ECDSA_SHA384                    0x70004042
#define TEE_ALG_ECDSA_SHA512                    0x70005042
#define TEE_ALG_ED25519                         0x70006043
#define TEE_ALG_ECDH_DERIVE_SHARED_SECRET       0x80000042
#define TEE_ALG_X25519                          0x80000044
#define TEE_ALG_SM2_DSA_SM3                     0x70006045
#define TEE_ALG_SM2_KEP                         0x60000045
#define TEE_ALG_SM2_PKE                         0x80000045
#define TEE_ALG_SM4_ECB_NOPAD                   0x10000014
#define TEE_ALG_SM4_CBC_NOPAD                   0x10000114
#define TEE_ALG_SM4_CTR                         0x10000214
#define TEE_ALG_ILLEGAL_VALUE                   0xEFFFFFFF


#define TEE_TYPE_AES                            0xA0000010
#define TEE_TYPE_DES                            0xA0000011
#define TEE_TYPE_DES3                           0xA0000013
#define TEE_TYPE_HMAC_MD5                       0xA0000001
#define TEE_TYPE_HMAC_SHA1                      0xA0000002
#define TEE_TYPE_HMAC_SHA224                    0xA0000003
#define TEE_TYPE_HMAC_SHA256                    0xA0000004
#define TEE_TYPE_HMAC_SHA384                    0xA0000005
#define TEE_TYPE_HMAC_SHA512                    0xA0000006
#define TEE_TYPE_HMAC_SM3                       0xA0000007
#define TEE_TYPE_RSA_PUBLIC_KEY                 0xA0000030
#define TEE_TYPE_RSA_KEYPAIR                    0xA1000030
#define TEE_TYPE_DSA_PUBLIC_KEY                 0xA0000031
#define TEE_TYPE_DSA_KEYPAIR                    0xA1000031
#define TEE_TYPE_DH_KEYPAIR                     0xA1000032
#define TEE_TYPE_ECDSA_PUBLIC_KEY               0xA0000041
#define TEE_TYPE_ECDSA_KEYPAIR                  0xA1000041
#define TEE_TYPE_ECDH_PUBLIC_KEY                0xA0000042
#define TEE_TYPE_ECDH_KEYPAIR                   0xA1000042
#define TEE_TYPE_ED25519_PUBLIC_KEY             0xA0000043
#define TEE_TYPE_ED25519_KEYPAIR                0xA1000043
#define TEE_TYPE_X25519_PUBLIC_KEY              0xA0000044
#define TEE_TYPE_X25519_KEYPAIR                 0xA1000044
#define TEE_TYPE_SM2_DSA_PUBLIC_KEY             0xA0000045
#define TEE_TYPE_SM2_DSA_KEYPAIR                0xA1000045
#define TEE_TYPE_SM2_KEP_PUBLIC_KEY             0xA0000046
#define TEE_TYPE_SM2_KEP_KEYPAIR                0xA1000046
#define TEE_TYPE_SM2_PKE_PUBLIC_KEY             0xA0000047
#define TEE_TYPE_SM2_PKE_KEYPAIR                0xA1000047
#define TEE_TYPE_SM4                            0xA0000014
#define TEE_TYPE_GENERIC_SECRET                 0xA0000000
#define TEE_TYPE_CORRUPTED_OBJECT               0xA00000BE
#define TEE_TYPE_DATA                           0xA00000BF
#define TEE_TYPE_ILLEGAL_VALUE                  0xEFFFFFFF

/* List of Object or Operation Attributes */
#define TEE_ATTR_SECRET_VALUE                   0xC0000000
#define TEE_ATTR_RSA_MODULUS                    0xD0000130
#define TEE_ATTR_RSA_PUBLIC_EXPONENT            0xD0000230
#define TEE_ATTR_RSA_PRIVATE_EXPONENT           0xC0000330
#define TEE_ATTR_RSA_PRIME1                     0xC0000430
#define TEE_ATTR_RSA_PRIME2                     0xC0000530
#define TEE_ATTR_RSA_EXPONENT1                  0xC0000630
#define TEE_ATTR_RSA_EXPONENT2                  0xC0000730
#define TEE_ATTR_RSA_COEFFICIENT                0xC0000830
#define TEE_ATTR_DSA_PRIME                      0xD0001031
#define TEE_ATTR_DSA_SUBPRIME                   0xD0001131
#define TEE_ATTR_DSA_BASE                       0xD0001231
#define TEE_ATTR_DSA_PUBLIC_VALUE               0xD0000131
#define TEE_ATTR_DSA_PRIVATE_VALUE              0xC0000231
#define TEE_ATTR_DH_PRIME                       0xD0001032
#define TEE_ATTR_DH_SUBPRIME                    0xD0001132
#define TEE_ATTR_DH_BASE                        0xD0001232
#define TEE_ATTR_DH_X_BITS                      0xF0001332
#define TEE_ATTR_DH_PUBLIC_VALUE                0xD0000132
#define TEE_ATTR_DH_PRIVATE_VALUE               0xC0000232
#define TEE_ATTR_RSA_OAEP_LABEL                 0xD0000930
#define TEE_ATTR_RSA_PSS_SALT_LENGTH            0xF0000A30
#define TEE_ATTR_ECC_PUBLIC_VALUE_X             0xD0000141
#define TEE_ATTR_ECC_PUBLIC_VALUE_Y             0xD0000241
#define TEE_ATTR_ECC_PRIVATE_VALUE              0xC0000341
#define TEE_ATTR_ECC_CURVE                      0xF0000441

#define TEE_ATTR_FLAG_VALUE                     0x20000000
#define TEE_ATTR_FLAG_PUBLIC                    0x10000000

#define TEE_CRYPTO_ELEMENT_NONE                 0x00000000
#define TEE_ECC_CURVE_NIST_P192                 0x00000001
#define TEE_ECC_CURVE_NIST_P224                 0x00000002
#define TEE_ECC_CURVE_NIST_P256                 0x00000003
#define TEE_ECC_CURVE_NIST_P384                 0x00000004
#define TEE_ECC_CURVE_NIST_P521                 0x00000005
#define TEE_ECC_CURVE_BSI_P160r1                0x00000101
#define TEE_ECC_CURVE_BSI_P192r1                0x00000102
#define TEE_ECC_CURVE_BSI_P224r1                0x00000103
#define TEE_ECC_CURVE_BSI_P256r1                0x00000104
#define TEE_ECC_CURVE_BSI_P320r1                0x00000105
#define TEE_ECC_CURVE_BSI_P384r1                0x00000106
#define TEE_ECC_CURVE_BSI_P512r1                0x00000107
#define TEE_ECC_CURVE_BSI_P160t1                0x00000201
#define TEE_ECC_CURVE_BSI_P192t1                0x00000202
#define TEE_ECC_CURVE_BSI_P224t1                0x00000203
#define TEE_ECC_CURVE_BSI_P256t1                0x00000204
#define TEE_ECC_CURVE_BSI_P320t1                0x00000205
#define TEE_ECC_CURVE_BSI_P384t1                0x00000206
#define TEE_ECC_CURVE_BSI_P512t1                0x00000207
#define TEE_ECC_CURVE_25519                     0x00000300
#define TEE_ECC_CURVE_SM2                       0x00000300

/*
 * The macro TEE_PARAM_TYPES can be used to construct a value that you can
 * compare against an incoming paramTypes to check the type of all the
 * parameters in one comparison, like in the following example:
 * if (paramTypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
 *                                  TEE_PARAM_TYPE_MEMREF_OUPUT,
 *                                  TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)) {
 *      return TEE_ERROR_BAD_PARAMETERS;
 *  }
 */
#define TEE_PARAM_TYPES(t0, t1, t2, t3) \
	((t0) | ((t1) << 4) | ((t2) << 8) | ((t3) << 12))

/*
 * The macro TEE_PARAM_TYPE_GET can be used to extract the type of a given
 * parameter from paramTypes if you need more fine-grained type checking.
 */
#define TEE_PARAM_TYPE_GET(t, i) ((((uint32_t)t) >> ((i) * 4)) & 0xF)

/*
 * The macro TEE_PARAM_TYPE_SET can be used to load the type of a given
 * parameter from paramTypes without specifying all types (TEE_PARAM_TYPES)
 */
#define TEE_PARAM_TYPE_SET(t, i) (((uint32_t)(t) & 0xF) << ((i) * 4))

/* TEE Arithmetical APIs */
#define TEE_BigIntSizeInU32(n) ((((n) + 31) / 32)  + 2)

#define TA_EXPORT __used

#endif
