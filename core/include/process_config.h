/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 Xing Loong <xing.xl.loong@gmail.com>
 * Userspace Process Configuration
 */

#ifndef _PROCESS_CONFIG_H
#define _PROCESS_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <mutex.h>
#include <property.h>
#include <tee_api_types.h>

#include <__process.h>

#define PROCESS_VER_LEN (16)
#define PROCESS_NAME_LEN (48)
#define PROCESS_PATH_LEN (128)
#define PROCESS_DESCRIPTION_LEN (64)

/*
 * Process configuration from the certificate
 */
struct process_config {
	/* Node in the configs list */
	struct list_head node;
	/* Process Name */
	char name[PROCESS_NAME_LEN];
	/* Process UUID */
	TEE_UUID uuid;
	/* Process ELF file path*/
	char path[PROCESS_PATH_LEN];
	/* Process version */
	char version[PROCESS_VER_LEN];
	/* Process description */
	char description[PROCESS_DESCRIPTION_LEN];
	/*
	 * semaphore-lock for single instance
	 * multiple instance don't need it.
	 */
	struct mutex inst_lock;
	/* TA's device access control list*/
	char *dev_acl;
	/* TA's ipc access control list*/
	char *ipc_acl;

	/* Heap size of the process */
	unsigned long heap_size;
	/* Stack size of the thread in this process */
	unsigned int ustack_size;
	/* single instance - true or false */
	bool single_instance;
	/*
	 * multiple session - true or false,
	 * only valid in single instance
	 */
	bool multi_session;
	/*
	 * instance keep alive - true or false,
	 * only valid in single instance
	 */
	bool inst_keepalive;
	/* Privileged APP - true or false */
	bool privilege;

	/* Additional Process properties */
	void *additionalprops;
	int nr_additionalprops;
};

void process_handle_fs(const char *mnt);

/* Get the config by the UUID */
struct process_config *process_config_of_uuid(const TEE_UUID *uuid);

/* Get the config by the name */
struct process_config *process_config_of(const char *name);

/*
 * Set the config into kernel config list
 * privilege==false means called from user-space
 * privilege==true means called from kernel-space
 */
int process_config_set(char *config, size_t size, bool privilege);

/*
 * Get the TA+Client Properties, TEE Properties
 * are obtained from the userspace API.
 */
int process_get_property(struct process_config *c,
	unsigned long hdl, const void *nameoridx, struct property *p);

#ifdef __cplusplus
}
#endif
#endif
