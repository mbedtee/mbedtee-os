/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * process internal definitions for both user/kernel space
 */

#ifndef _PROCESS_PRIV_H
#define _PROCESS_PRIV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <reent.h>
#include <sched.h>
#include <list.h>

/*
 * Process userspace wrapper functions (@libc)
 */
struct process_wrapper {
	void *proc_entry;
	void *pthread_entry;
	void *signal_entry;
	void *backtrace;
	void *open;
	void *invoke;
	void *close;
};

/*
 * Process's Global Platform functions (@app)
 */
#include <tee_api_types.h>
struct process_gp {
	long (*open)(uint32_t types,
		TEE_Param params[4], void **session);
	long (*invoke)(void *session, uint32_t cmd,
		uint32_t types, TEE_Param params[4]);
	void (*close)(void *session);
	long (*create)(void);
	void (*destroy)(void);
};

/*
 * the app's or dynamic libs' unwinding table address
 * currently support max to 10 addresses
 *
 * aarch64, riscv and mips use the .eh_frame for unwinding
 * aarch32 uses the .ARM.exidx and .ARM.extab for unwinding
 */
#define MAX_UNWIND_TABLES 10
struct unwind_info {
	/* number of tables */
	int nrtabs;
	/* for .ARM.exidx or .eh_frame tables */
	void *tabs[MAX_UNWIND_TABLES];
	int tabsize[MAX_UNWIND_TABLES];
	/*
	 * .text start-addr and size to locate the exidx tab, only
	 * for arm (aarch64, riscv and mips do not need these info)
	 */
	void *l_addr[MAX_UNWIND_TABLES];
	int l_size[MAX_UNWIND_TABLES];
};

/*
 * Combined process info for single-fetch syscall
 */
struct proc_info {
	struct process_gp gp;
	struct unwind_info unwind;
};

#ifdef __cplusplus
}
#endif

#endif
