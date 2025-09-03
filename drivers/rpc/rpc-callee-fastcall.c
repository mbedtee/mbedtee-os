// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * RPC Callee (Fastcall REE->TEE kernel)
 */

#include <trace.h>
#include <string.h>
#include <percpu.h>
#include <thread.h>
#include <sched.h>
#include <kthread.h>
#include <tasklet.h>
#include <cpu.h>
#include <timer.h>
#include <kmalloc.h>
#include <delay.h>
#include <device.h>
#include <power.h>
#include <str.h>
#include <kvma.h>
#include <version.h>

#include <rpc_callee.h>

long rpc_fastcall_handler(unsigned long fn,
	unsigned long a0, unsigned long a1, unsigned long a2)
{
	long ret = -1;

	switch (fn & MBEDTEE_RPC_FUNC_MASK) {
	case MBEDTEE_RPC_VERSION:
		ret = 2;
		break;

	case MBEDTEE_RPC_OS_VERSION:
		ret = PRODUCT_VERSION_INT;
		break;

	case MBEDTEE_RPC_SUPPORT_YIELD:
		ret = IS_ENABLED(CONFIG_RPC_YIELD);
		break;

	case MBEDTEE_RPC_COMPLETE_TEE:
		ret = rpc_complete(a0);
		break;

	case MBEDTEE_RPC_SYSTEM_SUSPEND:
		str_suspend();
		break;

#if CONFIG_NR_CPUS > 1
	case MBEDTEE_RPC_CPU_SUSPEND:
		break;

	case MBEDTEE_RPC_CPU_OFF:
		cpu_die();
		break;

	case MBEDTEE_RPC_CPU_ON:
		if (!mem_in_secure(a1))
			ret = cpu_up(cpuid_of(a0), a1);
		else
			ret = -EFAULT;
		break;

	case MBEDTEE_RPC_KILL_SECONDARY: {
		int cpu = cpuid_of(a0);

		if (cpu == 0)
			ret = -1;
		else {
			cpu_down(cpu);
			ret = 1;
		}
		break;
	}

	case MBEDTEE_RPC_MIGRATE_INFO_TYPE:
		ret = 2;
		break;
#endif
	default:
		EMSG("unknown RPC: 0x%08lx\n", fn);
		break;
	}

	return ret;
}
