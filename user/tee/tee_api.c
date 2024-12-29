// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
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

static void *ta_instance_data;

static LIST_HEAD(sess_list);
static DECLARE_DEFAULT_PTHREAD_MUTEX(sess_lock);
struct sess_node { intptr_t sess; struct list_head node; };
static intptr_t globalplatform_fd = -1;
static bool tee_api_panicked;

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
	TEE_UUID *destination,
	uint32_t cancellationRequestTimeout,
	uint32_t paramTypes, TEE_Param params[4],
	TEE_TASessionHandle	*session,
	uint32_t *returnOrigin)
{
	intptr_t ret = -1;
	uint32_t org = TEE_ORIGIN_TEE;
	struct globalplatform_open_session sess = {
		.uid = destination,
		.timeout = TEE_TIMEOUT_INFINITE,
		.type = paramTypes,
		.param = params
	};
	struct sess_node *n = NULL;

	if (session == NULL) {
		TEE_Panic(EFAULT);
		return ret;
	}

	if (destination == NULL) {
		TEE_Panic(EFAULT);
		return ret;
	}

	n = malloc(sizeof(struct sess_node));
	if (n == NULL) {
		TEE_Panic(ENOMEM);
		return ret;
	}

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

void TEE_CloseTASession(TEE_TASessionHandle	session)
{
	struct sess_node *n = NULL;

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

TEE_Result TEE_CheckMemoryAccessRights(
	uint32_t accessFlags, void *buffer, size_t size)
{
	TEE_Result ret = TEE_ERROR_ACCESS_DENIED;
	struct globalplatform_memacc acc = {
		.va = buffer,
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

	buffer = malloc(size);
	if (buffer == NULL)
		return NULL;

	if (hint == TEE_MALLOC_FILL_ZERO)
		memset(buffer, 0, size);

	return buffer;
}

void *TEE_Realloc(void *buffer, size_t newSize)
{
	return realloc(buffer, newSize);
}

void TEE_Free(void *buffer)
{
	free(buffer);
}

void TEE_MemMove(void *dest, void *src, size_t size)
{
	memmove(dest, src, size);
}

int32_t TEE_MemCompare(void *buffer1, void *buffer2, size_t size)
{
	return memcmp(buffer1, buffer2, size);
}

void TEE_MemFill(void *buffer, uint8_t x, size_t size)
{
	memset(buffer, x, size);
}

void TEE_GetSystemTime(TEE_Time *time)
{
	int ret = 0;
	struct timeval t;

	if (time == NULL)
		TEE_Panic(EINVAL);

	ret = gettimeofday(&t, NULL);
	if (ret == 0) {
		time->seconds = t.tv_sec;
		time->millis = t.tv_usec / 1000;
	} else
		TEE_Panic(errno);
}

TEE_Result TEE_Wait(uint32_t timeout)
{
	int remain = 0;

	remain = usleep((useconds_t)timeout * 1000UL);

	if (remain > 512) {
		EMSG("%ld remain %d\n", (long)timeout * 1000UL, remain);
		return TEE_ERROR_CANCEL;
	}

	return TEE_SUCCESS;
}

static TEE_Result __TEE_TAPersistentTime(
	struct timespec *sys, struct timespec *ta, int flag)
{
	FILE *fp = NULL;
	size_t len = 0;
	TEE_Result ret = TEE_ERROR_TIME_NEEDS_RESET;

	fp = fopen("/ree/time", (flag == O_RDONLY) ? "r" : "w+");
	if (fp == NULL)
		return TEE_ERROR_TIME_NOT_SET;

	if (flag == O_RDONLY) {
		len = fread(sys, 1, sizeof(*sys), fp);
		if (len != sizeof(*sys))
			goto out;
		len = fread(ta, 1, sizeof(*ta), fp);
		if (len != sizeof(*ta))
			goto out;
	} else {
		len = fwrite(sys, 1, sizeof(*sys), fp);
		if (len != sizeof(*sys))
			goto out;
		len = fwrite(ta, 1, sizeof(*ta), fp);
		if (len != sizeof(*ta))
			goto out;
	}

	ret = fclose(fp);

out:
	return ret;
}

TEE_Result TEE_GetTAPersistentTime(TEE_Time *time)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct timespec sys, nsys;
	struct timespec ta, nta, diff;

	if (time == NULL)
		TEE_Panic(EINVAL);

	ret = __TEE_TAPersistentTime(&sys, &ta, O_RDONLY);
	if (ret != TEE_SUCCESS)
		return ret;

	clock_gettime(CLOCK_REALTIME, &nsys);

	timespecsub(&nsys, &sys, &diff);
	timespecadd(&ta, &diff, &nta);

	DMSG("ta %llu.%09uns, nta %llu.%09uns\n",
		ta.tv_sec, ta.tv_nsec,
		nta.tv_sec, nta.tv_nsec);

	if ((nta.tv_sec < ta.tv_sec) ||
		((int64_t)diff.tv_sec < 0) ||
		(nta.tv_sec > UINT32_MAX)) {
		time->seconds = 0;
		time->millis = 0;
		return TEE_ERROR_OVERFLOW;
	}

	time->seconds = nta.tv_sec;
	time->millis = nta.tv_nsec / 1000000;

	return ret;
}

TEE_Result TEE_SetTAPersistentTime(TEE_Time *time)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct timespec sys, nsys, diff;
	struct timespec ta, nta;

	if (time == NULL)
		TEE_Panic(EINVAL);

	ret = __TEE_TAPersistentTime(&sys, &ta, O_RDONLY);
	clock_gettime(CLOCK_REALTIME, &nsys);
	if (ret == TEE_SUCCESS) {
		DMSG("sys %llu.%09uns, nsys %llu.%09uns\n",
			sys.tv_sec, sys.tv_nsec,
			nsys.tv_sec, nsys.tv_nsec);
		timespecsub(&nsys, &sys, &diff);
		if (((int64_t)diff.tv_sec < 0))
			TEE_Panic(TEE_ERROR_GENERIC);
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

	if (time == NULL)
		TEE_Panic(EINVAL);

	ret = globalplatform_ioctl(GLOBALPLATFORM_CMD_GET_REETIME, &t);

	if (ret == 0) {
		time->seconds = t.tv_sec;
		time->millis = t.tv_nsec / 1000000;
	} else
		TEE_Panic(ret);
}
