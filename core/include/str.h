/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Suspend to RAM
 * Suspend/Resume framework
 */

#ifndef _STR_H
#define _STR_H

#include <list.h>

struct device;

/*
 * STR ops structrue for the modularized devices
 */
struct str_operations {
	int (*suspend)(struct device *dev);
	int (*resume)(struct device *dev);
};

/*
 * STR ops structrue for the non-modularized parts
 */
struct str_declaration {
	const char *name;
	int (*suspend)(void *data);
	int (*resume)(void *data);
	void *data;
};

/*
 * priority is down-decreased when RESUME
 * priority is down-increased when SUSPEND
 *
 * STR registration for the non-modularized parts,
 * for the modules which are registered by module_system()
 * or module_driver() etc. shall not call these declarations.
 */
#define DECLARE_STR_ROOT(id, susfn, resfn, ptr)                         \
	static const struct str_declaration __strroot_##id                  \
	__section(".str_root") __used                                       \
	= {.name = #id, .suspend = (susfn), .resume = (resfn), .data = (ptr)}

#define DECLARE_STR_ARCH(id, susfn, resfn, ptr)                         \
	static const struct str_declaration __strarch_##id                  \
	__section(".str_arch") __used                                       \
	= {.name = #id, .suspend = (susfn), .resume = (resfn), .data = (ptr)}

#define DECLARE_STR_CORE(id, susfn, resfn, ptr)                         \
	static const struct str_declaration __strcore_##id                  \
	__section(".str_core") __used                                       \
	= {.name = #id, .suspend = (susfn), .resume = (resfn), .data = (ptr)}

#define DECLARE_STR_SYS(id, susfn, resfn, ptr)                          \
	static const struct str_declaration __strsys_##id                   \
	__section(".str_sys") __used                                        \
	= {.name = #id, .suspend = (susfn), .resume = (resfn), .data = (ptr)}

#define DECLARE_STR(id, susfn, resfn, ptr)                              \
	static const struct str_declaration __str_##id                      \
	__section(".str_normal") __used                                     \
	= {.name = #id, .suspend = (susfn), .resume = (resfn), .data = (ptr)}

#define DECLARE_STR_LATE(id, susfn, resfn, ptr)                         \
	static const struct str_declaration __strlate_##id                  \
	__section(".str_late") __used                                       \
	= {.name = #id, .suspend = (susfn), .resume = (resfn), .data = (ptr)}

/*
 * Suspend entry
 */
void str_suspend(void);

/*
 * Resume all the registered modules
 */
void str_resume(void);

#endif
