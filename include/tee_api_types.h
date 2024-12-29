/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Types definition of GlobalPlatform TEE internal API
 */

#ifndef _TEE_API_TYPES_H
#define _TEE_API_TYPES_H

#include <stdint.h>

typedef struct __TEE_TASessionHandle *TEE_TASessionHandle;

typedef uint32_t TEE_Result;

typedef uint32_t TEE_Whence;

typedef struct __TEE_PropSetHandle *TEE_PropSetHandle;

typedef struct {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t clockSeqAndNode[8];
} TEE_UUID;

typedef struct {
	uint32_t login;
	TEE_UUID uuid;
} TEE_Identity;

typedef struct {
	uint32_t attributeID;
	union {
		struct {
			void *buffer;
			size_t length;
		} ref;
		struct {
			uint32_t a;
			uint32_t b;
		} value;
	} content;
} TEE_Attribute;

typedef struct {
	uint32_t objectType;
	uint32_t objectSize;
	uint32_t maxObjectSize;
	uint32_t objectUsage;
	size_t dataSize;
	size_t dataPosition;
	uint32_t handleFlags;
} TEE_ObjectInfo;

typedef struct __TEE_ObjectHandle *TEE_ObjectHandle;

typedef struct __TEE_ObjectEnumHandle *TEE_ObjectEnumHandle;

typedef union {
	struct {
		void *buffer;
		size_t size;
	} memref;

	struct {
		uint32_t a;
		uint32_t b;
	} value;
} TEE_Param;

typedef struct __TEE_OperationHandle *TEE_OperationHandle;

typedef uint32_t TEE_OperationMode;

typedef struct {
	uint32_t algorithm;
	uint32_t operationClass;
	uint32_t mode;
	uint32_t digestLength;
	uint32_t maxKeySize;
	uint32_t keySize;
	uint32_t requiredKeyUsage;
	uint32_t handleState;
} TEE_OperationInfo;

typedef struct {
	uint32_t keySize;
	uint32_t requiredKeyUsage;
} TEE_OperationInfoKey;

typedef struct {
	uint32_t algorithm;
	uint32_t operationClass;
	uint32_t mode;
	uint32_t digestLength;
	uint32_t maxKeySize;
	uint32_t handleState;
	uint32_t operationState;
	uint32_t numberOfKeys;
	TEE_OperationInfoKey keyInformation[];
} TEE_OperationInfoMultiple;

typedef struct {
	uint32_t seconds;
	uint32_t millis;
} TEE_Time;

typedef uint32_t TEE_BigInt;
typedef uint32_t TEE_BigIntFMM;
typedef uint32_t TEE_BigIntFMMContext;

#endif
