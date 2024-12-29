/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * GlobalPlatform TEE Property defines
 */

#ifndef _PROPERTY_H
#define _PROPERTY_H

#include <version.h>
#include <tee_api_defines.h>

#define GPD_TA_APPID "gpd.ta.appID\0"
#define GPD_TA_SINGLEINSTANCE "gpd.ta.singleInstance\0"
#define GPD_TA_MULTISESSION "gpd.ta.multiSession\0"
#define GPD_TA_INSTANCEKEEPALIVE "gpd.ta.instanceKeepAlive\0"
#define GPD_TA_DATASIZE "gpd.ta.dataSize\0"
#define GPD_TA_STACKSIZE "gpd.ta.stackSize\0"
#define GPD_TA_VERSION "gpd.ta.version\0" /* since v1.1 */
#define GPD_TA_DESCRIPTION "gpd.ta.description\0" /* since v1.1 */
#define GPD_TA_ENDIAN "gpd.ta.endian\0" /* since v1.2 */

#define GPD_CLIENT_IDENTITY "gpd.client.identity\0"
#define GPD_CLIENT_ENDIAN "gpd.client.endian\0" /* since v1.2 */

#define GPD_TEE_INTERNALCORE_VERSION "gpd.tee.internalCore.version\0" /* since v1.1.2 */
#define GPD_TEE_DESCRIPTION "gpd.tee.description\0"
#define GPD_TEE_DEVICEID "gpd.tee.deviceID\0"
#define GPD_TEE_SYSTEMTIME_PROTECTIONLEVEL	"gpd.tee.systemTime.protectionLevel\0"
#define GPD_TEE_TAPERSISTENTTIME_PROTECTIONLEVEL "gpd.tee.TAPersistentTime.protectionLevel\0"
#define GPD_TEE_ARITH_MAXBIGINTSIZE "gpd.tee.arith.maxBigIntSize\0"
#define GPD_TEE_CRYPTOGRAPHY_NIST "gpd.tee.cryptography.nist\0" /* since v1.2 */
#define GPD_TEE_CRYPTOGRAPHY_BSI_R "gpd.tee.cryptography.bsi-r\0" /* since v1.2 */
#define GPD_TEE_CRYPTOGRAPHY_BSI_T "gpd.tee.cryptography.bsi-t\0" /* since v1.2 */
#define GPD_TEE_CRYPTOGRAPHY_IETF "gpd.tee.cryptography.ietf\0" /* since v1.2 */
#define GPD_TEE_CRYPTOGRAPHY_OCTA "gpd.tee.cryptography.octa\0" /* since v1.2 */
#define GPD_TEE_TRUSTEDSTORAGE_ANTIROLLBACK_PROTECTIONLEVEL "gpd.tee.trustedStorage.antiRollback.protectionLevel\0" /* since v1.2 */
#define GPD_TEE_TRUSTEDSTORAGE_ROLLBACKDETECTION_PROTECTIONLEVEL "gpd.tee.trustedStorage.rollbackDetection.protectionLevel\0" /* since v1.1 */
#define GPD_TEE_TRUSTEDOS_IMPLEMENTATION_VERSION "gpd.tee.trustedos.implementation.version\0" /* since v1.1 */
#define GPD_TEE_TRUSTEDOS_IMPLEMENTATION_BINARYVERSION "gpd.tee.trustedos.implementation.binaryversion\0" /* since v1.1 */
#define GPD_TEE_TRUSTEDOS_MANUFACTURER "gpd.tee.trustedos.manufacturer\0" /* since v1.1 */
#define GPD_TEE_FIRMWARE_IMPLEMENTATION_VERSION "gpd.tee.firmware.implementation.version\0" /* since v1.1 */
#define GPD_TEE_FIRMWARE_IMPLEMENTATION_BINARYVERSION "gpd.tee.firmware.implementation.binaryversion\0" /* since v1.1 */
#define GPD_TEE_FIRMWARE_MANUFACTURER "gpd.tee.firmware.manufacturer\0" /* since v1.1 */
#define GPD_TEE_EVENT_MAXSOURCES "gpd.tee.event.maxSources\0" /* since v1.2 */

#define PROP_TYPE_U32		0x10000000
#define PROP_TYPE_U64		0x10000001
#define PROP_TYPE_UUID		0x10000002
#define PROP_TYPE_BOOLEAN	0x10000003
#define PROP_TYPE_STRING	0x10000004
#define PROP_TYPE_IDENTITY	0x10000005
#define PROP_TYPE_BINARY	0x10000006

#define PROP_HANDLES_TA         1
#define PROP_HANDLES_CLIENT     2

#define PROP_NR_TEE				20
#define PROP_NR_TA				9
#define PROP_NR_CLIENT			2
#define PROP_NR_MAX				64

#define TEE_INTERNALCORE_VERSION				0x01000100
#define TEE_SYSTEMTIME_PROTECTIONLEVEL			1000
#define TEE_TAPERSISTENTTIME_PROTECTIONLEVEL	1000
#define TEE_ARITH_MAXBIGINTSIZE					32	/* size in bit */
#define TEE_DESCRIPTION							PRODUCT_NAME
#define TEE_TRUSTEDSTORAGE_ANTIROLLBACK_PROTECTIONLEVEL			100
#define TEE_TRUSTEDSTORAGE_ROLLBACKDETECTION_PROTECTIONLEVEL	100
#define TEE_TRUSTEDOS_IMPLEMENTATION_VERSION	PRODUCT_VERSION
#define TEE_TRUSTEDOS_MANUFACTURER				"Kapa"
#define TEE_FIRMWARE_IMPLEMENTATION_VERSION		"1.0.1"
#define TEE_FIRMWARE_MANUFACTURER				PRODUCT_NAME

#define PROP_SIZE_MAX 64

struct property {
	unsigned int type;
	char name[PROP_SIZE_MAX];
	char data[PROP_SIZE_MAX];
};

#endif
