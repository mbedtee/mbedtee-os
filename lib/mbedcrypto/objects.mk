# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Xing Loong <xing.xl.loong@gmail.com>

lib-mbedcrypto-cflags-y +=
lib-mbedcrypto-src-cflags-y +=

# Crypto @ Kernel Space
lib-mbedcrypto-$(CONFIG_KERNEL_MBEDCRYPTO) = \
		src/sha256.o \
		src/aes.o \
		src/gcm.o \
		src/hkdf.o \
		src/utils.o

# SM4 needed in kernel space when GCM has SM4 support
lib-mbedcrypto-$(CONFIG_MBEDCRYPTO_SM4) += \
		src/sm4.o

# Crypto @ User Space
lib-mbedcrypto-uobjs-$(CONFIG_USER_MBEDCRYPTO) = \
		src/sha256.o \
		src/sha512.o \
		src/sha1.o \
		src/md5.o \
		src/aes.o \
		src/des.o \
		src/gcm.o \
		src/ccm.o \
		src/cmac.o \
		src/hkdf.o \
		mbedcrypto.o \
		src/bignum.o \
		src/rsa.o \
		src/asn1.o \
		src/dsa.o \
		src/dh.o \
		src/ecp.o \
		src/ecdsa.o \
		src/ecdh.o \
		src/pk.o \
		src/base64.o \
		src/utils.o

# Optional algorithms (user space, behind CONFIG)
lib-mbedcrypto-uobjs-$(CONFIG_MBEDCRYPTO_SM3) += \
		src/sm3.o
lib-mbedcrypto-uobjs-$(CONFIG_MBEDCRYPTO_SM4) += \
		src/sm4.o
lib-mbedcrypto-uobjs-$(CONFIG_MBEDCRYPTO_SM2) += \
		src/sm2dsa.o \
		src/sm2pke.o \
		src/sm2kep.o
lib-mbedcrypto-uobjs-$(CONFIG_MBEDCRYPTO_CHACHA20) += \
		src/chacha20.o
lib-mbedcrypto-uobjs-$(CONFIG_MBEDCRYPTO_SHA3) += \
		src/sha3.o
lib-mbedcrypto-uobjs-$(CONFIG_MBEDCRYPTO_PBKDF2) += \
		src/pbkdf2.o
lib-mbedcrypto-uobjs-$(CONFIG_MBEDCRYPTO_CURVE25519) += \
		src/curve25519.o
lib-mbedcrypto-uobjs-$(CONFIG_MBEDCRYPTO_CURVE448) += \
		src/curve448.o
lib-mbedcrypto-uobjs-$(CONFIG_MBEDCRYPTO_AES_SIV) += \
		src/aes_siv.o
