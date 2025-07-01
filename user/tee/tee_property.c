// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * GlobalPlatform TEE Property APIs
 */

#include <utrace.h>
#include <syscall.h>
#include <property.h>
#include <mbedcrypto.h>

#include <tee_internal_api.h>

#include "tee_api_priv.h"

struct prop_enumerator {
	struct object_tag tag;
	uint32_t idx;
	bool start_flag;
	TEE_PropSetHandle hdl;
};

struct tee_property {
	unsigned int type;
	const char *name;
	const void *data;
};

static const TEE_UUID mbedtee_uuid = {0xebc8cd37, 0xbfff, 0x44f9,
			{0x8e, 0x3c, 0xff, 0x59, 0x30, 0xa9, 0x8a, 0xac}};

static const struct tee_property tee_properties[] = {
	{PROP_TYPE_UUID, GPD_TEE_DEVICEID, &mbedtee_uuid},
	{PROP_TYPE_STRING, GPD_TEE_DESCRIPTION, TEE_DESCRIPTION},
	{PROP_TYPE_U32, GPD_TEE_INTERNALCORE_VERSION, &(const uint32_t){TEE_INTERNALCORE_VERSION}},
	{PROP_TYPE_U32, GPD_TEE_SYSTEMTIME_PROTECTIONLEVEL, &(const uint32_t){TEE_SYSTEMTIME_PROTECTIONLEVEL}},
	{PROP_TYPE_U32, GPD_TEE_TAPERSISTENTTIME_PROTECTIONLEVEL, &(const uint32_t){TEE_TAPERSISTENTTIME_PROTECTIONLEVEL}},
	{PROP_TYPE_U32, GPD_TEE_ARITH_MAXBIGINTSIZE, &(const uint32_t){TEE_ARITH_MAXBIGINTSIZE}},
	{PROP_TYPE_BOOLEAN, GPD_TEE_CRYPTOGRAPHY_NIST, &(const uint32_t){true}},
	{PROP_TYPE_BOOLEAN, GPD_TEE_CRYPTOGRAPHY_BSI_R, &(const uint32_t){true}},
	{PROP_TYPE_BOOLEAN, GPD_TEE_CRYPTOGRAPHY_BSI_T, &(const uint32_t){true}},
	{PROP_TYPE_BOOLEAN, GPD_TEE_CRYPTOGRAPHY_IETF, &(const uint32_t){true}},
	{PROP_TYPE_BOOLEAN, GPD_TEE_CRYPTOGRAPHY_OCTA, &(const uint32_t){true}},
	{PROP_TYPE_U32, GPD_TEE_TRUSTEDSTORAGE_ANTIROLLBACK_PROTECTIONLEVEL, &(const uint32_t){TEE_TRUSTEDSTORAGE_ANTIROLLBACK_PROTECTIONLEVEL}},
	{PROP_TYPE_U32, GPD_TEE_TRUSTEDSTORAGE_ROLLBACKDETECTION_PROTECTIONLEVEL, &(const uint32_t){TEE_TRUSTEDSTORAGE_ROLLBACKDETECTION_PROTECTIONLEVEL}},
	{PROP_TYPE_STRING, GPD_TEE_TRUSTEDOS_IMPLEMENTATION_VERSION, TEE_TRUSTEDOS_IMPLEMENTATION_VERSION},
	{PROP_TYPE_BINARY, GPD_TEE_TRUSTEDOS_IMPLEMENTATION_BINARYVERSION, TEE_TRUSTEDOS_IMPLEMENTATION_VERSION},
	{PROP_TYPE_STRING, GPD_TEE_TRUSTEDOS_MANUFACTURER, TEE_TRUSTEDOS_MANUFACTURER},
	{PROP_TYPE_STRING, GPD_TEE_FIRMWARE_IMPLEMENTATION_VERSION, TEE_FIRMWARE_IMPLEMENTATION_VERSION},
	{PROP_TYPE_BINARY, GPD_TEE_FIRMWARE_IMPLEMENTATION_BINARYVERSION, TEE_FIRMWARE_IMPLEMENTATION_VERSION},
	{PROP_TYPE_STRING, GPD_TEE_FIRMWARE_MANUFACTURER, TEE_FIRMWARE_MANUFACTURER},
};

static void copy_property_value(struct property *p, const struct tee_property *tp)
{
	size_t size = 0;

	p->type = tp->type;
	strlcpy(p->name, tp->name, sizeof(p->name));

	switch (tp->type) {
	case PROP_TYPE_BOOLEAN:
		size = sizeof(bool);
		break;
	case PROP_TYPE_U32:
		size = sizeof(uint32_t);
		break;
	case PROP_TYPE_UUID:
		size = sizeof(TEE_UUID);
		break;
	case PROP_TYPE_IDENTITY:
		size = sizeof(TEE_Identity);
		break;
	case PROP_TYPE_STRING:
	case PROP_TYPE_BINARY:
		size = strlen((const char *)tp->data) + 1;
		break;
	default:
		size = sizeof(p->data);
		break;
	}

	if (size > sizeof(p->data))
		size = sizeof(p->data);

	memcpy(p->data, tp->data, size);

	if ((tp->type == PROP_TYPE_STRING) ||
		(tp->type == PROP_TYPE_BINARY)) {
		if (size == sizeof(p->data))
			p->data[sizeof(p->data) - 1] = 0;
	}
}

static int propset_of_name(TEE_PropSetHandle hdl, const char *name, struct property *p)
{
	int i = 0;
	int ret = -1;

	if (hdl == TEE_PROPSET_TEE_IMPLEMENTATION) {
		for (i = 0; i < ARRAY_SIZE(tee_properties); i++) {
			if (strncmp(name, tee_properties[i].name, PROP_SIZE_MAX) == 0)
				break;
		}
		if (i == ARRAY_SIZE(tee_properties))
			return TEE_ERROR_ITEM_NOT_FOUND;
		copy_property_value(p, &tee_properties[i]);
		ret = 0;
	} else {
		if (hdl == TEE_PROPSET_CURRENT_TA)
			ret = syscall3(SYSCALL_GET_PROPERTY, PROP_HANDLES_TA, name, p);
		else if (hdl == TEE_PROPSET_CURRENT_CLIENT)
			ret = syscall3(SYSCALL_GET_PROPERTY, PROP_HANDLES_CLIENT, name, p);
		if (ret != 0)
			ret = TEE_ERROR_ITEM_NOT_FOUND;
	}

	return ret;
}

static int propset_of_idx(TEE_PropSetHandle hdl, int idx, struct property *p)
{
	int ret = -1;

	if (hdl == TEE_PROPSET_TEE_IMPLEMENTATION) {
		if (idx >= ARRAY_SIZE(tee_properties))
			return TEE_ERROR_ITEM_NOT_FOUND;
		copy_property_value(p, &tee_properties[idx]);
		ret = 0;
	} else {
		if (hdl == TEE_PROPSET_CURRENT_TA)
			ret = syscall3(SYSCALL_GET_PROPERTY, PROP_HANDLES_TA, idx, p);
		else if (hdl == TEE_PROPSET_CURRENT_CLIENT)
			ret = syscall3(SYSCALL_GET_PROPERTY, PROP_HANDLES_CLIENT, idx, p);
		if (ret != 0)
			ret = TEE_ERROR_ITEM_NOT_FOUND;
	}

	return ret;
}


static inline int is_propset(TEE_PropSetHandle hdl)
{
	return (hdl == TEE_PROPSET_CURRENT_TA) ||
		(hdl == TEE_PROPSET_TEE_IMPLEMENTATION) ||
		(hdl == TEE_PROPSET_CURRENT_CLIENT);
}

static int tee_property_get(
	TEE_PropSetHandle propsetOrEnumerator,
	const char *name, struct property *p)
{
	TEE_PropSetHandle h = propsetOrEnumerator;
	struct prop_enumerator *e = NULL;

	if (is_propset(h)) {
		if (!name)
			TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
		return propset_of_name(h, name, p);
	}

	e = object_of(h);
	if (!e)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (e->start_flag)
		e->start_flag = false;

	return propset_of_idx(e->hdl, e->idx, p);
}

static int uuid_snprintf(TEE_UUID *id,
	char *valueBuffer, size_t valueBufferLen)
{
	return snprintf(valueBuffer, valueBufferLen,
			"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			(unsigned int)id->timeLow,
			(unsigned int)id->timeMid,
			(unsigned int)id->timeHiAndVersion,
			id->clockSeqAndNode[0], id->clockSeqAndNode[1],
			id->clockSeqAndNode[2], id->clockSeqAndNode[3],
			id->clockSeqAndNode[4], id->clockSeqAndNode[5],
			id->clockSeqAndNode[6], id->clockSeqAndNode[7]);
}

static TEE_Result tee_property_to_string(struct property *p,
	char *valueBuffer, size_t *valueBufferLen)
{
	int len = 0;
	TEE_Result ret = TEE_SUCCESS;
	TEE_Identity *id = NULL;

	switch (p->type) {
	case PROP_TYPE_UUID:
		len = uuid_snprintf((TEE_UUID *)p->data,
				valueBuffer, *valueBufferLen);
		break;

	case PROP_TYPE_U32: {
		unsigned int u32_data = 0;

		memcpy(&u32_data, p->data, sizeof(u32_data));
		len = snprintf(valueBuffer, *valueBufferLen,
				"%u", u32_data);
		break;
	}

	case PROP_TYPE_U64: {
		unsigned long long u64_data = 0;

		memcpy(&u64_data, p->data, sizeof(u64_data));
		len = snprintf(valueBuffer, *valueBufferLen,
				"%llu", u64_data);
		break;
	}

	case PROP_TYPE_BOOLEAN: {
		bool b = 0;

		memcpy(&b, p->data, sizeof(bool));
		len = strlcpy(valueBuffer, b ?
			"true" : "false", *valueBufferLen);
		break;
	}

	case PROP_TYPE_BINARY:
	case PROP_TYPE_STRING:
		len = strlcpy(valueBuffer, p->data, *valueBufferLen);
		break;

	case PROP_TYPE_IDENTITY:
		id = (TEE_Identity *)p->data;

		len = snprintf(valueBuffer, *valueBufferLen,
				"%u:", (unsigned int)id->login);

		if (*valueBufferLen > len) {
			int ext_len = uuid_snprintf(&id->uuid,
				valueBuffer + len, *valueBufferLen - len);
			if (ext_len >= 0)
				len += ext_len;
			else
				len = -1;
		}
		break;

	default:
		ret = TEE_ERROR_BAD_FORMAT;
		break;
	}

	if (len < 0) {
		*valueBufferLen = 0;
		return TEE_ERROR_BAD_FORMAT;
	}

	if (++len > *valueBufferLen)
		ret = TEE_ERROR_SHORT_BUFFER;

	*valueBufferLen = len;

	return ret;
}

TEE_Result TEE_GetPropertyAsString(
	TEE_PropSetHandle propsetOrEnumerator,
	const char *name, char *valueBuffer, size_t *valueBufferLen)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct property p;

	if ((!valueBuffer) ||
		(!valueBufferLen))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	ret = tee_property_get(propsetOrEnumerator, name, &p);
	if (ret != 0)
		return ret;

	/*
	 * The property data may not be null-terminated if it comes from
	 * the kernel or if it was truncated.
	 */
	if ((p.type == PROP_TYPE_STRING) ||
		(p.type == PROP_TYPE_BINARY))
		p.data[sizeof(p.data) - 1] = 0;

	ret = tee_property_to_string(&p, valueBuffer, valueBufferLen);
	if (ret != TEE_SUCCESS && ret != TEE_ERROR_SHORT_BUFFER)
		TEE_Panic(ret);

	return ret;
}

static TEE_Result __TEE_GetPropertyTyped(TEE_PropSetHandle propsetOrEnumerator,
	const char *name, void *value, int type, size_t size)
{
	TEE_Result ret;
	struct property p;

	if (!value)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	ret = tee_property_get(propsetOrEnumerator, name, &p);
	if (ret != 0)
		return ret;

	if (p.type != type)
		return TEE_ERROR_BAD_FORMAT;

	memcpy(value, p.data, size);
	return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsBool(
	TEE_PropSetHandle propsetOrEnumerator,
	const char *name, bool *value)
{
	return __TEE_GetPropertyTyped(propsetOrEnumerator, name, value,
			PROP_TYPE_BOOLEAN, sizeof(bool));
}

TEE_Result TEE_GetPropertyAsU32(
	TEE_PropSetHandle propsetOrEnumerator,
	const char *name, uint32_t *value)
{
	return __TEE_GetPropertyTyped(propsetOrEnumerator, name, value,
			PROP_TYPE_U32, sizeof(uint32_t));
}

TEE_Result TEE_GetPropertyAsU64(
	TEE_PropSetHandle propsetOrEnumerator,
	const char *name, uint64_t *value)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct property p;
	uint32_t u32 = 0;

	if (!value)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	ret = tee_property_get(propsetOrEnumerator, name, &p);
	if (ret != 0)
		return ret;

	if (p.type == PROP_TYPE_U64) {
		memcpy(value, p.data, sizeof(uint64_t));
		return TEE_SUCCESS;
	}

	if (p.type == PROP_TYPE_U32) {
		memcpy(&u32, p.data, sizeof(uint32_t));
		*value = u32;
		return TEE_SUCCESS;
	}

	return TEE_ERROR_BAD_FORMAT;
}

static TEE_Result tee_property_to_binary(struct property *p,
	char *valueBuffer, size_t *valueBufferLen)
{
	size_t len = 0;
	TEE_Result ret = TEE_SUCCESS;

	switch (p->type) {
	case PROP_TYPE_UUID:
		len = sizeof(TEE_UUID);
		break;

	case PROP_TYPE_U32:
		len = sizeof(uint32_t);
		break;

	case PROP_TYPE_U64:
		len = sizeof(uint64_t);
		break;

	case PROP_TYPE_STRING:
		len = strnlen(p->data, PROP_SIZE_MAX) + 1;
		break;

	case PROP_TYPE_BINARY:
		/* Check the required buffer size */
		ret = mbedcrypto_base64_decode(NULL, 0, &len, (const unsigned char *)p->data,
			strnlen(p->data, PROP_SIZE_MAX));
		break;

	case PROP_TYPE_BOOLEAN:
	case PROP_TYPE_IDENTITY:
	default:
		ret = TEE_ERROR_BAD_FORMAT;
		break;
	}

	if (ret != 0 && ret != (-ERANGE))
		return TEE_ERROR_BAD_FORMAT;

	if (len > *valueBufferLen) {
		*valueBufferLen = len;
		return TEE_ERROR_SHORT_BUFFER;
	}

	*valueBufferLen = len;

	switch (p->type) {
	case PROP_TYPE_UUID:
	case PROP_TYPE_U32:
	case PROP_TYPE_U64:
	case PROP_TYPE_STRING:
		memcpy(valueBuffer, p->data, len);
		break;

	case PROP_TYPE_BINARY:
		if (mbedcrypto_base64_decode((unsigned char *)valueBuffer, len, &len,
			(const unsigned char *)p->data, strnlen(p->data, PROP_SIZE_MAX)) != 0)
			return TEE_ERROR_BAD_FORMAT;
		break;
	}

	return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsBinaryBlock(
	TEE_PropSetHandle propsetOrEnumerator,
	const char *name, void *valueBuffer, size_t *valueBufferLen)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct property p;

	if ((!valueBuffer) ||
		(!valueBufferLen))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	ret = tee_property_get(propsetOrEnumerator, name, &p);
	if (ret != 0)
		return ret;

	ret = tee_property_to_binary(&p, valueBuffer, valueBufferLen);
	if (ret != TEE_SUCCESS && ret != TEE_ERROR_SHORT_BUFFER &&
		ret != TEE_ERROR_BAD_FORMAT)
		TEE_Panic(ret);

	return ret;
}

TEE_Result TEE_GetPropertyAsUUID(
	TEE_PropSetHandle propsetOrEnumerator,
	const char *name, TEE_UUID *value)
{
	return __TEE_GetPropertyTyped(propsetOrEnumerator, name, value,
			PROP_TYPE_UUID, sizeof(TEE_UUID));
}

TEE_Result TEE_GetPropertyAsIdentity(
	TEE_PropSetHandle propsetOrEnumerator,
	const char *name, TEE_Identity *value)
{
	return __TEE_GetPropertyTyped(propsetOrEnumerator, name, value,
			PROP_TYPE_IDENTITY, sizeof(TEE_Identity));
}

void TEE_ResetPropertyEnumerator(TEE_PropSetHandle enumerator)
{
	struct prop_enumerator *p = object_of(enumerator);

	if (!p)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	p->idx = -1;
	p->start_flag = false;
	p->hdl = NULL;
}

TEE_Result TEE_AllocatePropertyEnumerator(
	TEE_PropSetHandle *enumerator)
{
	struct prop_enumerator *p = NULL;

	p = object_alloc(sizeof(struct prop_enumerator));
	if (!p)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_ResetPropertyEnumerator((TEE_PropSetHandle)p->tag.idx);

	*enumerator = (TEE_PropSetHandle)p->tag.idx;

	return TEE_SUCCESS;
}

void TEE_FreePropertyEnumerator(TEE_PropSetHandle enumerator)
{
	struct prop_enumerator *p = object_of(enumerator);

	if (!p)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	object_free(p);
}

void TEE_StartPropertyEnumerator(
	TEE_PropSetHandle enumerator,
	TEE_PropSetHandle propSet)
{
	struct prop_enumerator *p = object_of(enumerator);

	if (!p || !is_propset(propSet))
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	p->idx = 0;
	p->start_flag = true;
	p->hdl = propSet;
}

TEE_Result TEE_GetPropertyName(
	TEE_PropSetHandle enumerator,
	void *nameBuffer, size_t *nameBufferLen)
{
	size_t len = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct property p;

	if (!enumerator || !nameBuffer
		|| !nameBufferLen)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	ret = tee_property_get(enumerator, NULL, &p);
	if (ret != 0)
		return ret;

	len = strlcpy(nameBuffer, p.name, *nameBufferLen) + 1;

	ret = (len > *nameBufferLen) ? TEE_ERROR_SHORT_BUFFER : TEE_SUCCESS;

	*nameBufferLen = len;

	return ret;
}

TEE_Result TEE_GetNextProperty(TEE_PropSetHandle enumerator)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct property p;
	struct prop_enumerator *e = object_of(enumerator);

	if (!e)
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

	if (e->start_flag)
		e->start_flag = false;
	else
		e->idx++;

	ret = tee_property_get(enumerator, NULL, &p);
	if (ret != 0)
		return ret;

	return TEE_SUCCESS;
}
