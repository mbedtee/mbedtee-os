// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * GlobalPlatform TEE Internal Core API
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <utrace.h>
#include <syscall.h>

#include <globalplatform.h>
#include <pthread_session.h>
#include <pthread_mutexdep.h>

#include <tee_internal_api.h>
#include "tee_api_priv.h"

static void *ta_instance_data;

static LIST_HEAD(sess_list);
static DECLARE_DEFAULT_PTHREAD_MUTEX(sess_lock);
struct sess_node { intptr_t sess; struct list_head node; };
static intptr_t globalplatform_fd = -1;
static bool tee_api_panicked;
static bool tee_api_mask_panics;

static void TEE_APIDeInit(int code, void *arg)
{
	if (tee_api_panicked)
		TEE_PanicCleanup();

	close((intptr_t)arg);
}

static int TEE_APIInit(void)
{
	globalplatform_fd = open("/dev/globalplatform", O_RDWR);
	if (globalplatform_fd < 0) {
		EMSG("open globalplatform failed %d\n", errno);
		return -ENXIO;
	}

	on_exit(TEE_APIDeInit, (void *)globalplatform_fd);

	return 0;
}

static int globalplatform_ioctl(int cmd, void *arg)
{
	int ret = -1;

	if (globalplatform_fd < 0) {
		ret = TEE_APIInit();
		if (ret != 0)
			return ret;
	}

	ret = ioctl(globalplatform_fd, cmd, arg);

	return ret == -1 ? -errno : ret;
}

void TEE_PanicCleanup(void)
{
	struct sess_node *n = NULL;

	tee_api_panicked = true;

	__pthread_mutex_lock(&sess_lock);
	while ((n = list_first_entry_or_null(&sess_list,
				struct sess_node, node)) != NULL) {
		list_del(&n->node);

		globalplatform_ioctl(GLOBALPLATFORM_CMD_CLOSE_SESSION, (void *)n->sess);
		free(n);
	}
	__pthread_mutex_unlock(&sess_lock);
}

TEE_Result TEE_OpenTASession(
	const TEE_UUID *destination,
	uint32_t cancellationRequestTimeout,
	uint32_t paramTypes, TEE_Param params[4],
	TEE_TASessionHandle	*session,
	uint32_t *returnOrigin)
{
	intptr_t ret = -1;
	uint32_t org = TEE_ORIGIN_TEE;
	struct globalplatform_open_session sess = {
		.uid = (TEE_UUID *)destination,
		.timeout = TEE_TIMEOUT_INFINITE,
		.type = paramTypes,
		.param = params
	};
	struct sess_node *n = NULL;

	if (!session)
		TEE_Panic(EFAULT);

	if (!destination)
		TEE_Panic(EFAULT);

	n = malloc(sizeof(struct sess_node));
	if (!n)
		TEE_Panic(ENOMEM);

	__pthread_mutex_lock(&sess_lock);

	/* transfer to microseconds */
	if (cancellationRequestTimeout != TEE_TIMEOUT_INFINITE)
		sess.timeout = cancellationRequestTimeout * 1000;

	ret = globalplatform_ioctl(GLOBALPLATFORM_CMD_OPEN_SESSION, &sess);
	if (ret < 0) {
		*session = (TEE_TASessionHandle)NULL;

		if (ret == -ENOMEM)
			ret = TEE_ERROR_OUT_OF_MEMORY;
		else if (ret == -ENOENT)
			ret = TEE_ERROR_ITEM_NOT_FOUND;
		else if (ret == -ESRCH || ret == -EFAULT)
			ret = TEE_ERROR_TARGET_DEAD;
		else if (ret == -EACCES || ret == -EPERM)
			ret = TEE_ERROR_ACCESS_DENIED;
		else if (ret == -EBUSY)
			ret = TEE_ERROR_BUSY;
		else
			org = TEE_ORIGIN_TRUSTED_APP;

		goto out;
	}

	n->sess = ret;
	list_add_tail(&n->node, &sess_list);
	*session = (TEE_TASessionHandle)ret;

	ret = TEE_SUCCESS;
	org = TEE_ORIGIN_TRUSTED_APP;

out:
	__pthread_mutex_unlock(&sess_lock);

	if (returnOrigin)
		*returnOrigin = org;
	if (ret != TEE_SUCCESS)
		free(n);
	return ret;
}

TEE_Result TEE_OpenRemoteTASession(const char *remoteTEE,
	const TEE_UUID *destination,
	uint32_t cancellationRequestTimeout,
	uint32_t paramTypes, TEE_Param params[4],
	TEE_TASessionHandle *session,
	uint32_t *returnOrigin)
{
	if (remoteTEE && remoteTEE[0] != 0) {
		if (session)
			*session = TEE_HANDLE_NULL;
		if (returnOrigin)
			*returnOrigin = TEE_ORIGIN_TEE;
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	return TEE_OpenTASession(destination,
		cancellationRequestTimeout,
		paramTypes, params,
		session, returnOrigin);
}

void TEE_CloseTASession(TEE_TASessionHandle	session)
{
	struct sess_node *n = NULL;

	if (session == TEE_HANDLE_NULL)
		return;

	__pthread_mutex_lock(&sess_lock);
	list_for_each_entry(n, &sess_list, node) {
		if (n->sess == (intptr_t)session) {
			list_del(&n->node);
			free(n);
			break;
		}
	}
	__pthread_mutex_unlock(&sess_lock);

	globalplatform_ioctl(GLOBALPLATFORM_CMD_CLOSE_SESSION, session);
}

TEE_Result TEE_InvokeTACommand(
	TEE_TASessionHandle	session,
	uint32_t cancellationRequestTimeout,
	uint32_t commandID, uint32_t paramTypes,
	TEE_Param params[4], uint32_t *returnOrigin)
{
	intptr_t ret = -1;
	uint32_t orig = TEE_ORIGIN_TEE;
	struct globalplatform_invoke_session sess = {
		.tid = (intptr_t)session,
		.cmd = commandID,
		.timeout = TEE_TIMEOUT_INFINITE,
		.type = paramTypes,
		.param = params
	};

	/* transfer to microseconds */
	if (cancellationRequestTimeout != TEE_TIMEOUT_INFINITE)
		sess.timeout = cancellationRequestTimeout * 1000;

	ret = globalplatform_ioctl(GLOBALPLATFORM_CMD_INVOKE_SESSION, &sess);
	if (ret == -ENOMEM)
		ret = TEE_ERROR_OUT_OF_MEMORY;
	else if (ret == -ESRCH || ret == -EFAULT)
		ret = TEE_ERROR_TARGET_DEAD;
	else if (ret == -EACCES || ret == -EPERM)
		ret = TEE_ERROR_ACCESS_DENIED;
	else
		orig = TEE_ORIGIN_TRUSTED_APP;

	if (returnOrigin)
		*returnOrigin = orig;

	return ret;
}

bool TEE_GetCancellationFlag(void)
{
	return pthread_session_cancel_flag();
}

bool TEE_UnmaskCancellation(void)
{
	return pthread_session_cancel_unmask();
}

bool TEE_MaskCancellation(void)
{
	return pthread_session_cancel_mask();
}

TEE_Result TEE_MaskPanics(bool mask)
{
	tee_api_mask_panics = mask;
	return TEE_SUCCESS;
}

bool __TEE_ArePanicsMasked(void)
{
	return tee_api_mask_panics;
}

void __TEE_Panic(int panicCode, const char *func, int line)
{
	/* Normalize negative errno values to their positive form */
	if (panicCode < 0 && panicCode > -__ELASTERROR)
		panicCode = -panicCode;

	utrace(func, line, TRACE_LEVEL_ERROR,
		"TEE_Panic - 0x%x\n", panicCode);

	if (tee_api_mask_panics)
		WMSG("TEE_Panic called while panic masking is enabled\n");

	TEE_PanicCleanup();

	exit(-ESRCH);
}

/*
 * For non-_PS TEE_Result functions: return panic_code if panics are masked,
 * otherwise panic unconditionally at the original caller site.
 */
TEE_Result __TEE_PanicOrReturnImpl(TEE_Result panic_code,
	const char *func, int line)
{
	if (__TEE_ArePanicsMasked())
		return panic_code;

	__TEE_Panic(panic_code, func, line);
}

TEE_Result __TEE_PanicOrDieImpl(TEE_Result ret, TEE_Result panic_code,
	const char *func, int line)
{
	if (panic_code)
		return __TEE_PanicOrReturnImpl(panic_code, func, line);

	__TEE_Panic(ret, func, line);
}

TEE_Result TEE_CheckMemoryAccessRights(
	uint32_t accessFlags, const void *buffer, size_t size)
{
	TEE_Result ret = TEE_ERROR_ACCESS_DENIED;
	struct globalplatform_memacc acc = {
		.va = (void *)buffer,
		.size = size,
		.flags = accessFlags
	};

	if (size == 0)
		return TEE_SUCCESS;

	ret = globalplatform_ioctl(GLOBALPLATFORM_CMD_CHECK_MEMACC, &acc);

	return ret ? TEE_ERROR_ACCESS_DENIED : TEE_SUCCESS;
}

void TEE_SetInstanceData(void *instanceData)
{
	ta_instance_data = instanceData;
}

void *TEE_GetInstanceData(void)
{
	return ta_instance_data;
}

void *TEE_Malloc(size_t size, uint32_t hint)
{
	void *buffer = NULL;

	if (hint & ~(TEE_MALLOC_NO_FILL | TEE_MALLOC_NO_SHARE))
		TEE_Panic(EINVAL);

	if ((hint & TEE_MALLOC_NO_FILL) && !(hint & TEE_MALLOC_NO_SHARE))
		TEE_Panic(EINVAL);

	/* Spec: TEE_Malloc(0) returns a non-NULL non-dereferenceable value */
	buffer = malloc(size ? size : 1);
	if (!buffer)
		return NULL;

	if (!(hint & TEE_MALLOC_NO_FILL))
		memset(buffer, 0, size ? size : 1);

	return buffer;
}

void *TEE_Realloc(void *buffer, size_t newSize)
{
	if (!buffer)
		return TEE_Malloc(newSize, TEE_MALLOC_FILL_ZERO);

	if (newSize == 0) {
		free(buffer);
		return TEE_Malloc(0, TEE_MALLOC_FILL_ZERO);
	}

	return realloc(buffer, newSize);
}

void TEE_Free(void *buffer)
{
	free(buffer);
}

void TEE_MemMove(void *dest, const void *src, size_t size)
{
	memmove(dest, src, size);
}

int32_t TEE_MemCompare(const void *buffer1, const void *buffer2, size_t size)
{
	const volatile unsigned char *p1 = buffer1;
	const volatile unsigned char *p2 = buffer2;
	volatile int32_t result = 0;
	volatile unsigned int found = 0;
	unsigned int xor_val = 0;
	unsigned int neq = 0;
	unsigned int is_first = 0;
	size_t i = 0;

	for (i = 0; i < size; i++) {
		xor_val = p1[i] ^ p2[i];
		/* neq: all-ones if bytes differ, zero if same */
		neq = 0u - ((xor_val | (0u - xor_val)) >> 31);
		/* is_first: all-ones only at the first differing byte */
		is_first = neq & ~found;

		result |= (p1[i] - p2[i]) & is_first;
		found |= neq;
	}

	return result;
}

void TEE_MemFill(void *buffer, uint8_t x, size_t size)
{
	memset(buffer, x, size);
}

void TEE_GetSystemTime(TEE_Time *time)
{
	int ret = 0;
	struct timeval t;

	if (!time)
		TEE_Panic(EINVAL);

	ret = gettimeofday(&t, NULL);
	if (ret == 0) {
		time->seconds = t.tv_sec;
		time->millis = t.tv_usec / 1000;
	} else
		TEE_Panic(errno);
}

TEE_Result TEE_GetSystemTime_PS(TEE_Time *time)
{
	struct timeval t;
	int err = 0;

	if (!time)
		TEE_Panic(EINVAL);

	if (gettimeofday(&t, NULL) != 0) {
		err = errno;
		if (err == ENOMEM)
			return TEE_ERROR_OUT_OF_MEMORY;
		if (err == EOVERFLOW)
			return TEE_ERROR_OVERFLOW;
		if (err == ENOENT || err == ENODATA)
			return TEE_ERROR_TIME_NOT_SET;
		TEE_Panic(err);
	}

	if ((uint64_t)t.tv_sec > UINT32_MAX) {
		/* Required by v1.4: return overflow with truncated seconds. */
		time->seconds = (uint32_t)t.tv_sec;
		time->millis = t.tv_usec / 1000;
		return TEE_ERROR_OVERFLOW;
	}

	time->seconds = t.tv_sec;
	time->millis = t.tv_usec / 1000;
	return TEE_SUCCESS;
}

TEE_Result TEE_Wait(uint32_t timeout)
{
	if (timeout == TEE_TIMEOUT_INFINITE) {
		while (1) {
			usleep(1000000);
			if (TEE_GetCancellationFlag())
				return TEE_ERROR_CANCEL;
		}
	}

	while (timeout > 0) {
		uint32_t step = (timeout > 1000) ? 1000 : timeout;
		usleep(step * 1000);
		if (TEE_GetCancellationFlag())
			return TEE_ERROR_CANCEL;
		timeout -= step;
	}

	return TEE_SUCCESS;
}

static TEE_Result __TEE_TAPersistentTime(
	struct timespec *sys, struct timespec *ta, int flag)
{
	FILE *fp = NULL;
	size_t len = 0;
	TEE_Result ret = TEE_ERROR_TIME_NEEDS_RESET;
	struct __ta_persistent_time {
		struct timespec sys;
		struct timespec ta;
	} pt;

	fp = fopen("/ree/time", (flag == O_RDONLY) ? "r" : "w+");
	if (!fp)
		return TEE_ERROR_TIME_NOT_SET;

	if (flag == O_RDONLY) {
		len = fread(&pt, 1, sizeof(pt), fp);
		if (len != sizeof(pt))
			goto out;
		*sys = pt.sys;
		*ta = pt.ta;
	} else {
		pt.sys = *sys;
		pt.ta = *ta;
		len = fwrite(&pt, 1, sizeof(pt), fp);
		if (len != sizeof(pt))
			goto out;
	}

	ret = 0;

out:
	fclose(fp);
	return ret;
}

TEE_Result TEE_GetTAPersistentTime(TEE_Time *time)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct timespec sys, nsys;
	struct timespec ta, nta, diff;

	if (!time)
		TEE_Panic(EINVAL);

	ret = __TEE_TAPersistentTime(&sys, &ta, O_RDONLY);
	if (ret != TEE_SUCCESS) {
		/* For all non-overflow errors, time output must be zeroed. */
		time->seconds = 0;
		time->millis = 0;
		return ret;
	}

	clock_gettime(CLOCK_REALTIME, &nsys);

	timespecsub(&nsys, &sys, &diff);
	timespecadd(&ta, &diff, &nta);

	if ((nta.tv_sec < ta.tv_sec) ||
		(diff.tv_sec < 0) ||
		(nta.tv_sec > UINT32_MAX)) {
		/* Required by v1.4: return overflow with truncated seconds. */
		time->seconds = (uint32_t)nta.tv_sec;
		time->millis = nta.tv_nsec / 1000000;
		return TEE_ERROR_OVERFLOW;
	}

	time->seconds = nta.tv_sec;
	time->millis = nta.tv_nsec / 1000000;

	return ret;
}

TEE_Result TEE_SetTAPersistentTime(TEE_Time *time)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct timespec sys, nsys, diff = {0};
	struct timespec ta, nta;

	if (!time)
		TEE_Panic(EINVAL);

	ret = __TEE_TAPersistentTime(&sys, &ta, O_RDONLY);
	clock_gettime(CLOCK_REALTIME, &nsys);
	if (ret == TEE_SUCCESS) {
		timespecsub(&nsys, &sys, &diff);
		if (diff.tv_sec < 0)
			return TEE_ERROR_TIME_NEEDS_RESET;
	}

	nta.tv_sec = time->seconds;
	nta.tv_nsec = time->millis * 1000000;
	timespecadd(&ta, &diff, &ta);
	/*
	 * monotonic increasing ?
	 * if (nta.tv_sec < ta.tv_sec)
	 *	TEE_Panic(TEE_ERROR_GENERIC);
	 */

	return __TEE_TAPersistentTime(&nsys, &nta, O_RDWR);
}

void TEE_GetREETime(TEE_Time *time)
{
	struct timespec t;
	int ret = -1;

	if (!time)
		TEE_Panic(EINVAL);

	ret = globalplatform_ioctl(GLOBALPLATFORM_CMD_GET_REETIME, &t);

	if (ret == 0) {
		time->seconds = t.tv_sec;
		time->millis = t.tv_nsec / 1000000;
	} else
		TEE_Panic(ret);
}

TEE_Result TEE_GetREETime_PS(TEE_Time *time)
{
	struct timespec t;
	int ret = 0;
	int err = 0;

	if (!time)
		TEE_Panic(EINVAL);

	ret = globalplatform_ioctl(GLOBALPLATFORM_CMD_GET_REETIME, &t);
	if (ret != 0) {
		err = (ret < 0) ? -ret : ret;
		if (err == ENOMEM)
			return TEE_ERROR_OUT_OF_MEMORY;
		if (err == EOVERFLOW)
			return TEE_ERROR_OVERFLOW;
		if (err == ENOENT || err == ENODATA)
			return TEE_ERROR_TIME_NOT_SET;
		TEE_Panic(ret);
	}

	if ((uint64_t)t.tv_sec > UINT32_MAX) {
		/* Required by v1.4: return overflow with truncated seconds. */
		time->seconds = (uint32_t)t.tv_sec;
		time->millis = t.tv_nsec / 1000000;
		return TEE_ERROR_OVERFLOW;
	}

	time->seconds = t.tv_sec;
	time->millis = t.tv_nsec / 1000000;
	return TEE_SUCCESS;
}
