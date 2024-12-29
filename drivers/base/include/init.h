/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * section macros for init/exit/cleanup etc.
 */

#ifndef _INIT_H
#define _INIT_H

#define EARLY_INIT_SECTIONS		\
	. = ALIGN(BYTES_PER_LONG);	\
	__EARLY_INIT_START = .;		\
	KEEP(*(.early_init_root))	\
	KEEP(*(.early_init_arch))	\
	KEEP(*(.early_init_core))	\
	KEEP(*(.early_init_sys))	\
	KEEP(*(.early_init))		\
	__EARLY_INIT_END = .;

#define PERCPU_INIT_SECTIONS	\
	. = ALIGN(BYTES_PER_LONG);	\
	__PERCPU_INIT_START = .;	\
	KEEP(*(.percpu_init_root))	\
	KEEP(*(.percpu_init_arch))	\
	KEEP(*(.percpu_init_core))	\
	KEEP(*(.percpu_init_sys))	\
	KEEP(*(.percpu_init))		\
	__PERCPU_INIT_END = .;

#define MODULE_INIT_SECTIONS	\
	. = ALIGN(BYTES_PER_LONG);	\
	__MOD_INIT_START = .;		\
	KEEP(*(.mod_init_root))		\
	KEEP(*(.mod_init_arch))		\
	KEEP(*(.mod_init_core))		\
	KEEP(*(.mod_init_sys))		\
	KEEP(*(.mod_init))			\
	KEEP(*(.mod_init_late))		\
	__MOD_INIT_END = .;

#define IRQ_INIT_SECTIONS		\
	. = ALIGN(BYTES_PER_LONG);	\
	__IRQ_INIT_START = .;		\
	KEEP(*(.of_irq_init))		\
	__IRQ_INIT_END = .;

#define TIMER_INIT_SECTIONS		\
	. = ALIGN(BYTES_PER_LONG);	\
	__TIMER_INIT_START = .;		\
	KEEP(*(.of_timer_init))		\
	__TIMER_INIT_END = .;

#define UART_INIT_SECTIONS		\
	. = ALIGN(BYTES_PER_LONG);	\
	__UART_INIT_START = .;		\
	KEEP(*(.of_uart_init))		\
	__UART_INIT_END = .;

/*
 * callbacks for process resource reclaim
 */
#define CLEANUP_CALLBACKS		\
	. = ALIGN(BYTES_PER_LONG);	\
	__CLEANUP_START = .;		\
	KEEP(*(.cleanup.high))		\
	KEEP(*(.cleanup.medium))	\
	KEEP(*(.cleanup.low))		\
	__CLEANUP_END = .;

/*
 * callbacks for Suspend-to-RAM (STR)
 */
#define STR_SECTIONS			\
	. = ALIGN(BYTES_PER_LONG);	\
	__STR_START = .;			\
	KEEP(*(.str_root))			\
	KEEP(*(.str_arch))			\
	KEEP(*(.str_core))			\
	KEEP(*(.str_sys))			\
	KEEP(*(.str_normal))		\
	KEEP(*(.str_late))			\
	__STR_END = .;

/*
 * early init sections
 */
#define __early_init_root __section(".early_init_root") __used
#define __early_init_arch __section(".early_init_arch") __used
#define __early_init_core __section(".early_init_core") __used
#define __early_init_sys __section(".early_init_sys") __used
#define __early_init __section(".early_init") __used

/*
 * percpu init sections
 */
#define __percpu_init_root __section(".percpu_init_root") __used
#define __percpu_init_arch __section(".percpu_init_arch") __used
#define __percpu_init_core __section(".percpu_init_core") __used
#define __percpu_init_sys __section(".percpu_init_sys") __used
#define __percpu_init __section(".percpu_init") __used

/*
 * Module/driver init sections
 */
#define __mod_init_root __section(".mod_init_root") __used
#define __mod_init_arch __section(".mod_init_arch") __used
#define __mod_init_core __section(".mod_init_core") __used
#define __mod_init_sys __section(".mod_init_sys") __used
#define __mod_init __section(".mod_init") __used
#define __mod_init_late __section(".mod_init_late") __used

/*
 * OF IRQ/Timer/Uart init sections
 */
#define __of_irqinit __section(".of_irq_init") __used
#define __of_timerinit __section(".of_timer_init") __used
#define __of_uartinit __section(".of_uart_init") __used

#define __init __section(".init") __used
#define __exit __section(".exit") __used

#ifndef __ASSEMBLY__

typedef void (*init_func_t) (void);
typedef void (*exit_func_t) (void);

/*
 * init macros, priority is down-decreased
 */
#define EARLY_INIT_ROOT(fn) \
	static	__early_init_root init_func_t _earlyroot_##fn = fn
#define EARLY_INIT_ARCH(fn) \
	static	__early_init_arch init_func_t _earlyarch_##fn = fn
#define EARLY_INIT_CORE(fn) \
	static	__early_init_core init_func_t _earlycore_##fn = fn
#define EARLY_INIT_SYS(fn) \
	static	__early_init_sys init_func_t _earlysys_##fn = fn
#define EARLY_INIT(fn) \
	static	__early_init init_func_t _early_##fn = fn

#define PERCPU_INIT_ROOT(fn) \
	static	__percpu_init_root init_func_t _percpuroot_##fn = fn
#define PERCPU_INIT_ARCH(fn) \
	static	__percpu_init_arch init_func_t _percpuarch_##fn = fn
#define PERCPU_INIT_CORE(fn) \
	static	__percpu_init_core init_func_t _percpucore_##fn = fn
#define PERCPU_INIT_SYS(fn) \
	static	__percpu_init_sys init_func_t _percpusys_##fn = fn
#define PERCPU_INIT(fn) \
	static	__percpu_init init_func_t _percpu_##fn = fn

#define MODULE_INIT_ROOT(fn) \
	static	__mod_init_root init_func_t _root_##fn = fn
#define MODULE_INIT_ARCH(fn) \
	static	__mod_init_arch init_func_t _arch_##fn = fn
#define MODULE_INIT_CORE(fn) \
	static	__mod_init_core init_func_t _core_##fn = fn
#define MODULE_INIT_SYS(fn) \
	static	__mod_init_sys init_func_t _sys_##fn = fn
#define MODULE_INIT(fn) \
	static	__mod_init init_func_t _module_##fn = fn
#define MODULE_INIT_LATE(fn) \
	static	__mod_init_late init_func_t _late_##fn = fn

/*
 * exit macros
 */
#define  MODULE_EXIT(fn) \
	static	__exit exit_func_t	_exit_##fn = fn
#define MODULE_EXIT_ROOT(fn) MODULE_EXIT(fn)
#define MODULE_EXIT_ARCH(fn) MODULE_EXIT(fn)
#define MODULE_EXIT_CORE(fn) MODULE_EXIT(fn)
#define MODULE_EXIT_SYS(fn)  MODULE_EXIT(fn)
#define MODULE_EXIT_LATE(fn) MODULE_EXIT(fn)

#endif

#endif
