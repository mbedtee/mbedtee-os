// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * GlobalPlatform Misc functions
 */

#include <io.h>
#include <of.h>
#include <ipc.h>
#include <list.h>
#include <sched.h>
#include <trace.h>
#include <driver.h>
#include <uaccess.h>

#include <globalplatform.h>

static int globalplatform_open(struct file *f, mode_t mode, void *arg)
{
	return 0;
}

static int globalplatform_close(struct file *f)
{
	return 0;
}

static int do_open_session(void *uid,
	uint32_t timeout, uint32_t type, TEE_Param *p)
{
	int ret = -EFAULT;
	TEE_UUID uuid;
	TEE_Param param[4];

	ret = copy_from_user((void *)&uuid, uid, sizeof(uuid));
	if (ret != 0)
		return -EFAULT;

	if (type != TEE_PARAM_TYPE_NONE) {
		ret = copy_from_user(&param, p, sizeof(param));
		if (ret != 0)
			return -EFAULT;
	}

	ret = ipc_session_open(&uuid, timeout, type, param);

	if (type != TEE_PARAM_TYPE_NONE)
		copy_to_user(p, &param, sizeof(param));

	return ret;
}

static int do_invoke_session(pid_t tid,
	uint32_t timeout, uint32_t cmd, uint32_t type, TEE_Param *p)
{
	int ret = -EFAULT;
	TEE_Param param[4];

	if (type != TEE_PARAM_TYPE_NONE) {
		ret = copy_from_user(&param, p, sizeof(param));
		if (ret != 0)
			return -EFAULT;
	}

	ret = ipc_session_invoke(tid, timeout, cmd, type, param);

	if (type != TEE_PARAM_TYPE_NONE)
		copy_to_user(p, &param, sizeof(param));

	return ret;
}

static int do_close_session(pid_t tid)
{
	return ipc_session_close(tid);
}

static int do_getreetime(struct timespec *dst)
{
	struct timespec ts = {0};

	if (!access_ok(dst, sizeof(ts)))
		return -EFAULT;

#if defined(CONFIG_RPC)
#include <rpc.h>
	int ret = -1;

	ret = rpc_call_sync(RPC_REETIME, &ts, sizeof(ts));
	if (ret != 0)
		return ret;
#endif

	return copy_to_user(dst, &ts, sizeof(ts));
}

static int do_memacc_check(void *va, size_t size, uint32_t flags)
{
	struct process *p = current->proc;

	LMSG("va:%p sz:%ld, flags:%x\n", va, (long)size, (int)flags);

/*
 * check if the User-VA range belongs to non-secure memory
 * USER_VM4REE_VA ~ USER_VA_TOP
 */
#define ree_range_ok(p, addr, size) (size_ok(addr, size) && \
				(unsigned long)(addr) >= USER_VM4REE_VA(p) && \
				(unsigned long)(addr) + (size) < USER_VA_TOP)
/*
 * check if the User-VA range belongs to secure memory
 * USER_HEAP_VA ~ USER_VM4REE_VA
 */
#define tee_range_ok(p, addr, size) (size_ok(addr, size) && \
				(unsigned long)(addr) >= USER_HEAP_VA(p) && \
				(unsigned long)(addr) + (size) < USER_VM4REE_VA(p))

	if ((flags & TEE_MEMORY_ACCESS_NONSECURE) &&
		 !ree_range_ok(p, va, size))
		return -EACCES;

	if ((flags & TEE_MEMORY_ACCESS_SECURE) &&
	    !tee_range_ok(p, va, size))
		return -EACCES;

	if (!(flags & TEE_MEMORY_ACCESS_ANY_OWNER) &&
	    !tee_range_ok(p, va, size))
		return -EACCES;

	if (!access_user_ok((void *)va, size, (flags &
		TEE_MEMORY_ACCESS_WRITE) ? PG_RW : PG_RO))
		return -EACCES;

	return 0;
}

static int globalplatform_ioctl(struct file *f,
	int cmd, unsigned long args)
{
	int ret = -1;

	switch (cmd) {
	case GLOBALPLATFORM_CMD_OPEN_SESSION: {
		struct globalplatform_open_session sess, *usess = (void *)args;

		if (copy_from_user(&sess, usess, sizeof(sess)))
			return -EFAULT;
		ret = do_open_session(sess.uid, sess.timeout, sess.type, sess.param);
		break;
	}

	case GLOBALPLATFORM_CMD_INVOKE_SESSION: {
		struct globalplatform_invoke_session sess;

		if (copy_from_user(&sess, (void *)args, sizeof(sess)))
			return -EFAULT;
		ret = do_invoke_session(sess.tid, sess.timeout,
				sess.cmd, sess.type, sess.param);
		break;
	}

	case GLOBALPLATFORM_CMD_CLOSE_SESSION: {
		ret = do_close_session(args);
		break;
	}

	case GLOBALPLATFORM_CMD_GET_REETIME: {
		ret = do_getreetime((struct timespec *)args);
		break;
	}

	case GLOBALPLATFORM_CMD_CHECK_MEMACC: {
		struct globalplatform_memacc memacc;

		if (copy_from_user(&memacc, (void *)args, sizeof(memacc)))
			return -EFAULT;
		ret = do_memacc_check(memacc.va, memacc.size, memacc.flags);
		break;
	}

	default:
		ret = -ENOTSUP;
		break;
	}

	return ret;
}

static const struct file_operations globalplatform_fops = {
	.open = globalplatform_open,
	.close = globalplatform_close,
	.ioctl = globalplatform_ioctl,
};

static void __init globalplatform_init(void)
{
	static struct device dev = {NULL};

	dev.fops = &globalplatform_fops;
	dev.path = "/dev/globalplatform";

	device_register(&dev);
}

MODULE_INIT_LATE(globalplatform_init);
