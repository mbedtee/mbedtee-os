# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)

lib-mbedtls-cflags-y +=

# Crypto
lib-mbedtls-uobjs-$(CONFIG_USER_MBEDTLS) = \
		mbedtls.o \
		library/aes.o \
		library/aesce.o \
		library/aesni.o \
		library/aria.o \
		library/asn1parse.o \
		library/asn1write.o \
		library/base64.o \
		library/bignum.o \
		library/bignum_core.o \
		library/bignum_mod.o \
		library/bignum_mod_raw.o \
		library/block_cipher.o \
		library/camellia.o \
		library/ccm.o \
		library/chacha20.o \
		library/chachapoly.o \
		library/cipher.o \
		library/cipher_wrap.o \
		library/cmac.o \
		library/constant_time.o \
		library/ctr_drbg.o \
		library/des.o \
		library/dhm.o \
		library/ecdh.o \
		library/ecdsa.o \
		library/ecjpake.o \
		library/ecp.o \
		library/ecp_curves.o \
		library/ecp_curves_new.o \
		library/entropy.o \
		library/entropy_poll.o \
		library/error.o \
		library/gcm.o \
		library/hkdf.o \
		library/hmac_drbg.o \
		library/lmots.o \
		library/lms.o \
		library/md.o \
		library/md5.o \
		library/memory_buffer_alloc.o \
		library/mps_reader.o \
		library/mps_trace.o \
		library/nist_kw.o \
		library/oid.o \
		library/padlock.o \
		library/pem.o \
		library/pk.o \
		library/pk_ecc.o \
		library/pk_wrap.o \
		library/pkcs5.o \
		library/pkcs7.o \
		library/pkcs12.o \
		library/pkparse.o \
		library/pkwrite.o \
		library/platform.o \
		library/platform_util.o \
		library/poly1305.o \
		library/ripemd160.o \
		library/rsa.o \
		library/rsa_alt_helpers.o \
		library/sha1.o \
		library/sha3.o \
		library/sha256.o \
		library/sha512.o \
		library/threading.o \
		library/timing.o \
		library/version.o \
		library/version_features.o

lib-mbedtls-$(CONFIG_KERNEL_MBEDTLS) = \
		library/aes.o library/gcm.o \
		library/cipher.o library/constant_time.o \
		library/cipher_wrap.o library/platform_util.o

# PSA
lib-mbedtls-uobjs-$(CONFIG_USER_MBEDTLS_PSA) += \
		library/psa_crypto.o \
		library/psa_crypto_aead.o \
		library/psa_crypto_cipher.o \
		library/psa_crypto_client.o \
		library/psa_crypto_driver_wrappers_no_static.o \
		library/psa_crypto_ecp.o \
		library/psa_crypto_ffdh.o \
		library/psa_crypto_hash.o \
		library/psa_crypto_mac.o \
		library/psa_crypto_pake.o \
		library/psa_crypto_rsa.o \
		library/psa_crypto_se.o \
		library/psa_crypto_slot_management.o \
		library/psa_crypto_storage.o \
		library/psa_its_file.o \
		library/psa_util.o

# X509
lib-mbedtls-uobjs-$(CONFIG_USER_MBEDTLS_X509) += \
		library/x509.o \
		library/x509_create.o \
		library/x509_crl.o \
		library/x509_crt.o \
		library/x509_csr.o \
		library/x509_write.o \
		library/x509write_crt.o \
		library/x509write_csr.o

# SSL
lib-mbedtls-uobjs-$(CONFIG_USER_MBEDTLS_SSL) += \
		library/debug.o \
		library/net_sockets.o \
		library/ssl_cache.o \
		library/ssl_ciphersuites.o \
		library/ssl_client.o \
		library/ssl_cookie.o \
		library/ssl_debug_helpers_generated.o \
		library/ssl_msg.o \
		library/ssl_ticket.o \
		library/ssl_tls.o \
		library/ssl_tls12_client.o \
		library/ssl_tls12_server.o \
		library/ssl_tls13_client.o \
		library/ssl_tls13_generic.o \
		library/ssl_tls13_keys.o \
		library/ssl_tls13_server.o
