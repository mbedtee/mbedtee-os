/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Driver Register Implementation
 */

#ifndef _DRIVER_H
#define _DRIVER_H

#include <of.h>
#include <str.h>
#include <init.h>
#include <device.h>

/*
 * module late
 */
#define __module_late(__driver, __register, __unregister, ...) \
	static void __init __driver##_init(void) \
	{ \
		__register(&(__driver), ##__VA_ARGS__); \
	} \
	MODULE_INIT_LATE(__driver##_init); \
	static void __driver##_exit(void) \
	{ \
		__unregister(&(__driver), ##__VA_ARGS__); \
	} \
	MODULE_EXIT_LATE(__driver##_exit)
#define module_late(__device_driver) \
	__module_late(__device_driver, driver_register, \
			driver_unregister)

/*
 * module normal
 */
#define __module_driver(__driver, __register, __unregister, ...) \
	static void __init __driver##_init(void) \
	{ \
		__register(&(__driver), ##__VA_ARGS__); \
	} \
	MODULE_INIT(__driver##_init); \
	static void __driver##_exit(void) \
	{ \
		__unregister(&(__driver), ##__VA_ARGS__); \
	} \
	MODULE_EXIT(__driver##_exit)
#define module_driver(__device_driver) \
	__module_driver(__device_driver, driver_register, \
			driver_unregister)

/*
 * module system
 */
#define __module_system(__driver, __register, __unregister, ...) \
	static void __init __driver##_init(void) \
	{ \
		__register(&(__driver), ##__VA_ARGS__); \
	} \
	MODULE_INIT_SYS(__driver##_init); \
	static void __driver##_exit(void) \
	{ \
		__unregister(&(__driver), ##__VA_ARGS__); \
	} \
	MODULE_EXIT_SYS(__driver##_exit)
#define module_system(__device_driver) \
	__module_system(__device_driver, driver_register, \
			driver_unregister)

/*
 * module OS core
 */
#define __module_core(__driver, __register, __unregister, ...) \
	static void __init __driver##_init(void) \
	{ \
		__register(&(__driver), ##__VA_ARGS__); \
	} \
	MODULE_INIT_CORE(__driver##_init); \
	static void __driver##_exit(void) \
	{ \
		__unregister(&(__driver), ##__VA_ARGS__); \
	} \
	MODULE_EXIT_CORE(__driver##_exit)
#define module_core(__device_driver) \
	__module_core(__device_driver, driver_register, \
			driver_unregister)

/*
 * module arch
 */
#define __module_arch(__driver, __register, __unregister, ...) \
	static void __init __driver##_init(void) \
	{ \
		__register(&(__driver), ##__VA_ARGS__); \
	} \
	MODULE_INIT_ARCH(__driver##_init); \
	static void __driver##_exit(void) \
	{ \
		__unregister(&(__driver), ##__VA_ARGS__); \
	} \
	MODULE_EXIT_ARCH(__driver##_exit)
#define module_arch(__device_driver) \
	__module_arch(__device_driver, driver_register, \
			driver_unregister)

/*
 * module root
 */
#define __module_root(__driver, __register, __unregister, ...) \
	static void __init __driver##_init(void) \
	{ \
		__register(&(__driver), ##__VA_ARGS__); \
	} \
	MODULE_INIT_ROOT(__driver##_init); \
	static void __driver##_exit(void) \
	{ \
		__unregister(&(__driver), ##__VA_ARGS__); \
	} \
	MODULE_EXIT_ROOT(__driver##_exit)
#define module_root(__device_driver) \
	__module_root(__device_driver, driver_register, \
			driver_unregister)

struct device_driver {
	const char *name;
	int (*probe)(struct device *dev);
	void (*remove)(struct device *dev);
	const struct of_device_id *of_match_table;
};

int driver_register(const struct device_driver *drv);
void driver_unregister(const struct device_driver *drv);

#endif
