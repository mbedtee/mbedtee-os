/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * GlobalPlatform TEE Internal Core API
 */

#ifndef _TEE_API_H
#define _TEE_API_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <utrace.h>
#include <pthread.h>

#include <tee_api_types.h>
#include <tee_api_defines.h>

TEE_Result TEE_OpenTASession(TEE_UUID *destination,
	uint32_t cancellationRequestTimeout,
	uint32_t paramTypes, TEE_Param params[4],
	TEE_TASessionHandle *session, uint32_t *returnOrigin);

void TEE_CloseTASession(TEE_TASessionHandle session);

TEE_Result TEE_InvokeTACommand(
	TEE_TASessionHandle session,
	uint32_t cancellationRequestTimeout,
	uint32_t commandID, uint32_t paramTypes,
	TEE_Param params[4], uint32_t *returnOrigin);

TEE_Result TA_EXPORT TA_CreateEntryPoint(void);

void TA_EXPORT TA_DestroyEntryPoint(void);

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(
	uint32_t paramTypes, TEE_Param params[4], void **sessionContext);

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext);

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(
	void *sessionContext, uint32_t commandID,
	uint32_t paramTypes, TEE_Param params[4]);

bool TEE_GetCancellationFlag(void);

bool TEE_UnmaskCancellation(void);

bool TEE_MaskCancellation(void);

void TEE_PanicCleanup(void);

#define TEE_Panic(ret)											\
	do {														\
		EMSG("TEE_Panic - 0x%x (%d)\n", (int)ret, (int)ret);	\
		TEE_PanicCleanup();										\
		exit(-ESRCH);											\
	} while (0)

TEE_Result TEE_CheckMemoryAccessRights(
	uint32_t accessFlags, void *buffer, size_t size);

void TEE_SetInstanceData(void *instanceData);

void *TEE_GetInstanceData(void);

void *TEE_Malloc(size_t size, uint32_t hint);

void *TEE_Realloc(void *buffer, size_t newSize);

void TEE_Free(void *buffer);

void TEE_MemMove(void *dest, void *src, size_t size);

int32_t TEE_MemCompare(void *buffer1, void *buffer2, size_t size);

void TEE_MemFill(void *buffer, uint8_t x, size_t size);

void TEE_GetSystemTime(TEE_Time *time);

TEE_Result TEE_Wait(uint32_t timeout);

TEE_Result TEE_SetTAPersistentTime(TEE_Time *time);

TEE_Result TEE_GetTAPersistentTime(TEE_Time *time);

void TEE_GetREETime(TEE_Time *time);

TEE_Result TEE_GetPropertyAsString(
	TEE_PropSetHandle propsetOrEnumerator,
	char *name, char *valueBuffer, size_t *valueBufferLen);

TEE_Result TEE_GetPropertyAsBool(
	TEE_PropSetHandle propsetOrEnumerator,
	char *name, bool *value);

TEE_Result TEE_GetPropertyAsU32(
	TEE_PropSetHandle propsetOrEnumerator,
	char *name, uint32_t *value);

TEE_Result TEE_GetPropertyAsBinaryBlock(
	TEE_PropSetHandle propsetOrEnumerator,
	char *name, void *valueBuffer,
	size_t *valueBufferLen);

TEE_Result TEE_GetPropertyAsUUID(
	TEE_PropSetHandle propsetOrEnumerator,
	char *name, TEE_UUID *value);

TEE_Result TEE_GetPropertyAsIdentity(
	TEE_PropSetHandle propsetOrEnumerator,
	char *name, TEE_Identity *value);

TEE_Result TEE_AllocatePropertyEnumerator(
	TEE_PropSetHandle *enumerator);

void TEE_FreePropertyEnumerator(
	TEE_PropSetHandle enumerator);

void TEE_StartPropertyEnumerator(
	TEE_PropSetHandle enumerator,
	TEE_PropSetHandle propSet);

void TEE_ResetPropertyEnumerator(
	TEE_PropSetHandle enumerator);

TEE_Result TEE_GetPropertyName(
	TEE_PropSetHandle enumerator,
	void *nameBuffer, size_t *nameBufferLen);

TEE_Result TEE_GetNextProperty(
	TEE_PropSetHandle enumerator);

void TEE_GetObjectInfo(
	TEE_ObjectHandle object,
	TEE_ObjectInfo *objectInfo);

TEE_Result TEE_GetObjectInfo1(
	TEE_ObjectHandle object,
	TEE_ObjectInfo *objectInfo);

void TEE_RestrictObjectUsage(
	TEE_ObjectHandle object,
	uint32_t objectUsage);

TEE_Result TEE_RestrictObjectUsage1(
	TEE_ObjectHandle object,
	uint32_t objectUsage);

TEE_Result TEE_GetObjectBufferAttribute(
	TEE_ObjectHandle object, uint32_t attributeID,
	void *buffer, size_t *size);

TEE_Result TEE_GetObjectValueAttribute(
	TEE_ObjectHandle object, uint32_t attributeID,
	uint32_t *a, uint32_t *b);

void TEE_CloseObject(TEE_ObjectHandle object);

TEE_Result TEE_AllocateTransientObject(
	uint32_t objectType, uint32_t maxObjectSize,
	TEE_ObjectHandle *object);

void TEE_FreeTransientObject(TEE_ObjectHandle object);

void TEE_ResetTransientObject(TEE_ObjectHandle object);

TEE_Result TEE_PopulateTransientObject(
	TEE_ObjectHandle object, TEE_Attribute *attrs,
	uint32_t attrCount);

void TEE_InitRefAttribute(TEE_Attribute *attr,
	uint32_t attributeID, void *buffer, size_t length);

void TEE_InitValueAttribute(TEE_Attribute *attr,
	uint32_t attributeID, uint32_t a, uint32_t b);

void TEE_CopyObjectAttributes(
	TEE_ObjectHandle destObject,
	TEE_ObjectHandle srcObject);

TEE_Result TEE_CopyObjectAttributes1(
	TEE_ObjectHandle destObject,
	TEE_ObjectHandle srcObject);

TEE_Result TEE_OpenPersistentObject(
	uint32_t storageID, void *objectID, size_t objectIDLen,
	uint32_t flags, TEE_ObjectHandle *object);

TEE_Result TEE_CreatePersistentObject(
	uint32_t storageID, void *objectID,
	size_t objectIDLen, uint32_t flags,
	TEE_ObjectHandle attributes, void *initialData,
	size_t initialDataLen, TEE_ObjectHandle *object);

void TEE_CloseAndDeletePersistentObject(
	TEE_ObjectHandle object);

TEE_Result TEE_CloseAndDeletePersistentObject1(
	TEE_ObjectHandle object);

TEE_Result TEE_RenamePersistentObject(
	TEE_ObjectHandle object, void *newObjectID,
	size_t newObjectIDLen);

TEE_Result TEE_AllocatePersistentObjectEnumerator(
	TEE_ObjectEnumHandle *objectEnumerator);

void TEE_FreePersistentObjectEnumerator(
	TEE_ObjectEnumHandle objectEnumerator);

void TEE_ResetPersistentObjectEnumerator(
	TEE_ObjectEnumHandle objectEnumerator);

TEE_Result TEE_StartPersistentObjectEnumerator(
	TEE_ObjectEnumHandle objectEnumerator, uint32_t storageID);

TEE_Result TEE_GetNextPersistentObject(
	TEE_ObjectEnumHandle objectEnumerator,
	TEE_ObjectInfo *objectInfo, void *objectID,
	size_t *objectIDLen);

TEE_Result TEE_ReadObjectData(TEE_ObjectHandle object,
	void *buffer, size_t size, uint32_t *count);

TEE_Result TEE_WriteObjectData(TEE_ObjectHandle object,
	void *buffer, size_t size);

TEE_Result TEE_TruncateObjectData(
	TEE_ObjectHandle object, size_t size);

TEE_Result TEE_SeekObjectData(TEE_ObjectHandle object,
	size_t offset, TEE_Whence whence);

TEE_Result TEE_AllocateOperation(
	TEE_OperationHandle *operation,
	uint32_t algorithm, uint32_t mode,
	uint32_t maxKeySize);

void TEE_FreeOperation(TEE_OperationHandle operation);

void TEE_GetOperationInfo(
	TEE_OperationHandle operation,
	TEE_OperationInfo *operationInfo);

TEE_Result TEE_GetOperationInfoMultiple(
	TEE_OperationHandle operation,
	TEE_OperationInfoMultiple *operationInfoMultiple,
	size_t *operationSize);

void TEE_ResetOperation(TEE_OperationHandle operation);

TEE_Result TEE_SetOperationKey(
	TEE_OperationHandle operation,
	TEE_ObjectHandle key);

TEE_Result TEE_SetOperationKey2(
	TEE_OperationHandle operation,
	TEE_ObjectHandle key1,
	TEE_ObjectHandle key2);

void TEE_CopyOperation(
	TEE_OperationHandle dstOperation,
	TEE_OperationHandle srcOperation);

TEE_Result TEE_IsAlgorithmSupported(
	uint32_t algId, uint32_t element);

TEE_Result TEE_GenerateKey(TEE_ObjectHandle object,
	uint32_t keySize, TEE_Attribute *params, uint32_t paramCount);

void TEE_DigestUpdate(TEE_OperationHandle operation,
	void *chunk, size_t chunkSize);

TEE_Result TEE_DigestDoFinal(TEE_OperationHandle operation,
	void *chunk, size_t chunkLen, void *hash, size_t *hashLen);

void TEE_CipherInit(TEE_OperationHandle operation, void *IV, size_t IVLen);

TEE_Result TEE_CipherUpdate(TEE_OperationHandle operation,
	void *srcData, size_t srcLen, void *destData, size_t *destLen);

TEE_Result TEE_CipherDoFinal(TEE_OperationHandle operation,
	void *srcData, size_t srcLen, void *destData, size_t *destLen);

void TEE_MACInit(TEE_OperationHandle operation, void *IV, size_t IVLen);

void TEE_MACUpdate(TEE_OperationHandle operation, void *chunk, size_t chunkSize);

TEE_Result TEE_MACComputeFinal(TEE_OperationHandle operation,
	void *message, size_t messageLen, void *mac, size_t *macLen);

TEE_Result TEE_MACCompareFinal(TEE_OperationHandle operation,
	void *message, size_t messageLen, void *mac, size_t macLen);

TEE_Result TEE_AEInit(TEE_OperationHandle operation,
	void *nonce, size_t nonceLen, uint32_t tagLen,
	uint32_t AADLen, uint32_t payloadLen);

void TEE_AEUpdateAAD(TEE_OperationHandle operation,
	void *AADdata, size_t AADdataLen);

TEE_Result TEE_AEUpdate(TEE_OperationHandle operation, void *srcData,
	size_t srcLen, void *destData, size_t *destLen);

TEE_Result TEE_AEEncryptFinal(TEE_OperationHandle operation,
	void *srcData, size_t srcLen, void *destData, size_t *destLen,
	void *tag, size_t *tagLen);

TEE_Result TEE_AEDecryptFinal(TEE_OperationHandle operation,
	void *srcData, size_t srcLen, void *destData, size_t *destLen,
	void *tag, size_t tagLen);

TEE_Result TEE_AsymmetricEncrypt(TEE_OperationHandle operation,
	TEE_Attribute *params, uint32_t paramCount, void *srcData,
	size_t srcLen, void *destData, size_t *destLen);

TEE_Result TEE_AsymmetricDecrypt(TEE_OperationHandle operation,
	TEE_Attribute *params, uint32_t paramCount, void *srcData,
	size_t srcLen, void *destData, size_t *destLen);

TEE_Result TEE_AsymmetricSignDigest(TEE_OperationHandle operation,
	TEE_Attribute *params, uint32_t paramCount, void *digest,
	size_t digestLen, void *signature, size_t *signatureLen);

TEE_Result TEE_AsymmetricVerifyDigest(TEE_OperationHandle operation,
	TEE_Attribute *params, uint32_t paramCount, void *digest,
	size_t digestLen, void *signature, size_t signatureLen);

void TEE_DeriveKey(TEE_OperationHandle operation, TEE_Attribute *params,
	uint32_t paramCount, TEE_ObjectHandle derivedKey);

void TEE_GenerateRandom(void *randomBuffer, size_t randomBufferLen);

size_t TEE_BigIntFMMSizeInU32(size_t modulusSizeInBits);

size_t TEE_BigIntFMMContextSizeInU32(size_t modulusSizeInBits);

void TEE_BigIntInit(TEE_BigInt *bigInt, size_t len);

void TEE_BigIntInitFMM(TEE_BigIntFMM *bigInt, size_t len);

void TEE_BigIntInitFMMContext(
	TEE_BigIntFMMContext *context,
	size_t len, TEE_BigInt *modulus);
TEE_Result TEE_BigIntInitFMMContext1(
	TEE_BigIntFMMContext *context,
	size_t len, TEE_BigInt *modulus);

TEE_Result TEE_BigIntConvertFromOctetString(
	TEE_BigInt *dest, uint8_t *buffer,
	size_t bufferLen, int32_t sign);

TEE_Result TEE_BigIntConvertToOctetString(void *buffer,
	size_t *bufferLen, TEE_BigInt *bigInt);

void TEE_BigIntConvertFromS32(TEE_BigInt *dest, int32_t shortVal);

TEE_Result TEE_BigIntConvertToS32(int32_t *dest, TEE_BigInt *src);

int32_t TEE_BigIntCmp(TEE_BigInt *op1, TEE_BigInt *op2);

int32_t TEE_BigIntCmpS32(TEE_BigInt *op, int32_t shortVal);

void TEE_BigIntShiftRight(TEE_BigInt *dest, TEE_BigInt *op, size_t bits);

bool TEE_BigIntGetBit(TEE_BigInt *src, uint32_t bitIndex);

uint32_t TEE_BigIntGetBitCount(TEE_BigInt *src);

TEE_Result TEE_BigIntSetBit(TEE_BigInt *op, uint32_t bitIndex, bool value);

TEE_Result TEE_BigIntAssign(TEE_BigInt *dest, TEE_BigInt *src);

TEE_Result TEE_BigIntAbs(TEE_BigInt *dest, TEE_BigInt *src);

void TEE_BigIntAdd(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2);

void TEE_BigIntSub(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2);

void TEE_BigIntNeg(TEE_BigInt *dest, TEE_BigInt *op);

void TEE_BigIntMul(TEE_BigInt *dest, TEE_BigInt *op1, TEE_BigInt *op2);

void TEE_BigIntSquare(TEE_BigInt *dest, TEE_BigInt *op);

void TEE_BigIntDiv(TEE_BigInt *dest_q, TEE_BigInt *dest_r,
	TEE_BigInt *op1, TEE_BigInt *op2);

void TEE_BigIntMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n);

void TEE_BigIntAddMod(TEE_BigInt *dest, TEE_BigInt *op1,
	TEE_BigInt *op2, TEE_BigInt *n);

void TEE_BigIntSubMod(TEE_BigInt *dest, TEE_BigInt *op1,
	TEE_BigInt *op2, TEE_BigInt *n);

void TEE_BigIntMulMod(TEE_BigInt *dest, TEE_BigInt *op1,
	TEE_BigInt *op2, TEE_BigInt *n);

void TEE_BigIntSquareMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n);

void TEE_BigIntInvMod(TEE_BigInt *dest, TEE_BigInt *op, TEE_BigInt *n);

TEE_Result TEE_BigIntExpMod(TEE_BigInt *dest, TEE_BigInt *op1,
	TEE_BigInt *op2, TEE_BigInt *n, TEE_BigIntFMMContext *context);

bool TEE_BigIntRelativePrime(TEE_BigInt *op1, TEE_BigInt *op2);

void TEE_BigIntComputeExtendedGcd(TEE_BigInt *gcd, TEE_BigInt *u,
	TEE_BigInt *v, TEE_BigInt *op1, TEE_BigInt *op2);

int32_t TEE_BigIntIsProbablePrime(TEE_BigInt *op,
	uint32_t confidenceLevel);

void TEE_BigIntConvertToFMM(TEE_BigIntFMM *dest,
	TEE_BigInt *src, TEE_BigInt *n,
	TEE_BigIntFMMContext *context);

void TEE_BigIntConvertFromFMM(TEE_BigInt *dest,
	TEE_BigIntFMM *src, TEE_BigInt *n,
	TEE_BigIntFMMContext *context);

void TEE_BigIntComputeFMM(TEE_BigIntFMM *dest,
	TEE_BigIntFMM *op1, TEE_BigIntFMM *op2,
	TEE_BigInt *n, TEE_BigIntFMMContext *context);

#endif
