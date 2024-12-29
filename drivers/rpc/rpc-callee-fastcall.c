// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
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

	switch (fn & RPC_FUNC_MASK) {
	case RPC_VERSION:
		ret = 2;
		break;

	case RPC_OS_VERSION:
		ret = PRODUCT_VERSION_INT;
		break;

	case RPC_SUPPORT_YIELD:
		ret = false;
#ifdef CONFIG_RPC_YIELD
		ret = true;
#endif
		break;

	case RPC_COMPLETE_TEE:
		ret = rpc_complete(a0);
		break;

	case RPC_SYSTEM_SUSPEND:
		str_suspend();
		break;

#if CONFIG_NR_CPUS > 1
	case RPC_CPU_SUSPEND:
		break;

	case RPC_CPU_OFF:
		cpu_die();
		break;

	case RPC_CPU_ON:
		if (!mem_in_secure(a1))
			ret = cpu_up(cpuid_of(a0), a1);
		else
			ret = -EFAULT;
		break;

	case RPC_KILL_SECONDARY:
		int cpu = cpuid_of(a0);

		if (cpu == 0) {
			ret = -1;
		} else {
			cpu_down(cpu);
			ret = 1;
		}
		break;

	case RPC_MIGRATE_INFO_TYPE:
		ret = 2;
		break;
#endif
	default:
		EMSG("unknown RPC: 0x%08lx\n", fn);
		break;
	}

	return ret;
}
