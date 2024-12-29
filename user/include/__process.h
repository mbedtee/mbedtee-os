/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * process internal definitions for both user/kernel space
 */

#ifndef _PROCESS_PRIV_H
#define _PROCESS_PRIV_H

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
 * currently support max to 20 addresses
 *
 * aarch64, riscv and mips use the .eh_frame for unwinding
 * aarch32 uses the .ARM.exidx and .ARM.extab for unwinding
 */
#define MAX_UNWIND_TABLES 20
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

struct __process {
	/*
	 * inner-system process ID
	 */
	pid_t id;

	bool exiting;

	struct process_wrapper wrapper;
	struct process_gp gp;

	/*
	 * information for unwind backtrace
	 */
	struct unwind_info unwind;

	void *pobjs[400];
};

#endif
