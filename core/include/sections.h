/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Get the sections from the link script
 */

#ifndef _SECTIONS_H
#define _SECTIONS_H

extern unsigned long __CODE_START[];
extern unsigned long __CODE_END[];

extern unsigned long __TEXT_START[];
extern unsigned long __TEXT_END[];

extern unsigned long __RODATA_START[];
extern unsigned long __RODATA_END[];

extern unsigned long __EHFRAME_START[];

extern unsigned long __CLEANUP_START[];
extern unsigned long __CLEANUP_END[];

extern unsigned long __STR_START[];
extern unsigned long __STR_END[];

extern unsigned long __DATA_START[];
extern unsigned long __DATA_END[];

extern unsigned long __INIT_START[];
extern unsigned long __INIT_END[];

extern unsigned long __BSS_START[];
extern unsigned long __BSS_END[];

extern unsigned long __DTB_START[];

extern unsigned long __RAMFS_START[];
extern unsigned long __RAMFS_END[];

extern unsigned long __EARLY_INIT_START[];
extern unsigned long __EARLY_INIT_END[];
extern unsigned long __PERCPU_INIT_START[];
extern unsigned long __PERCPU_INIT_END[];
extern unsigned long __MOD_INIT_START[];
extern unsigned long __MOD_INIT_END[];
extern unsigned long __IRQ_INIT_START[];
extern unsigned long __IRQ_INIT_END[];
extern unsigned long __TIMER_INIT_START[];
extern unsigned long __TIMER_INIT_END[];
extern unsigned long __UART_INIT_START[];
extern unsigned long __UART_INIT_END[];

extern unsigned long __EARLY_BSS_START[];
extern unsigned long __EARLY_BSS_END[];

extern unsigned long __global_pointer$[];

static inline unsigned long __code_start(void)
{
	return (unsigned long)&__CODE_START;
}

static inline unsigned long __code_end(void)
{
	return (unsigned long)&__CODE_END;
}

static inline unsigned long __code_size(void)
{
	return (unsigned long)&__CODE_END -
		(unsigned long)&__CODE_START;
}

static inline unsigned long __text_start(void)
{
	return (unsigned long)&__TEXT_START;
}

static inline unsigned long __text_size(void)
{
	return (unsigned long)&__TEXT_END -
		(unsigned long)&__TEXT_START;
}

static inline unsigned long __rodata_start(void)
{
	return (unsigned long)&__RODATA_START;
}

static inline unsigned long __rodata_size(void)
{
	return (unsigned long)&__RODATA_END -
		(unsigned long)&__RODATA_START;
}

static inline unsigned long __cleanup_start(void)
{
	return (unsigned long)&__CLEANUP_START;
}

static inline unsigned long __cleanup_end(void)
{
	return (unsigned long)&__CLEANUP_END;
}

static inline unsigned long __str_start(void)
{
	return (unsigned long)&__STR_START;
}

static inline unsigned long __str_end(void)
{
	return (unsigned long)&__STR_END;
}

static inline unsigned long __dtb_start(void)
{
	return (unsigned long)&__DTB_START;
}

static inline unsigned long __ramfs_start(void)
{
	return (unsigned long)&__RAMFS_START;
}

static inline unsigned long __ramfs_end(void)
{
	return (unsigned long)&__RAMFS_END;
}

static inline unsigned long __ramfs_size(void)
{
	return ((unsigned long)&__RAMFS_END -
		(unsigned long)&__RAMFS_START);
}

static inline unsigned long __data_start(void)
{
	return (unsigned long)&__DATA_START;
}

static inline unsigned long __data_size(void)
{
	return (unsigned long)&__DATA_END -
		(unsigned long)&__DATA_START;
}

static inline unsigned long __bss_start(void)
{
	return (unsigned long)&__BSS_START;
}

static inline unsigned long __bss_end(void)
{
	return (unsigned long)&__BSS_END;
}

static inline unsigned long __bss_size(void)
{
	return (unsigned long)&__BSS_END -
		(unsigned long)&__BSS_START;
}

static inline unsigned long __early_init_start(void)
{
	return (unsigned long)&__EARLY_INIT_START;
}

static inline unsigned long __early_init_end(void)
{
	return (unsigned long)&__EARLY_INIT_END;
}

static inline unsigned long __percpu_init_start(void)
{
	return (unsigned long)&__PERCPU_INIT_START;
}

static inline unsigned long __percpu_init_end(void)
{
	return (unsigned long)&__PERCPU_INIT_END;
}

static inline unsigned long __mod_init_start(void)
{
	return (unsigned long)&__MOD_INIT_START;
}

static inline unsigned long __mod_init_end(void)
{
	return (unsigned long)&__MOD_INIT_END;
}

static inline unsigned long __init_start(void)
{
	return (unsigned long)&__INIT_START;
}

static inline unsigned long __init_size(void)
{
	return (unsigned long)&__INIT_END -
		(unsigned long)&__INIT_START;
}

static inline unsigned long __early_bss_start(void)
{
	return (unsigned long)&__EARLY_BSS_START;
}

static inline unsigned long __early_bss_end(void)
{
	return (unsigned long)&__EARLY_BSS_END;
}

static inline unsigned long __early_bss_size(void)
{
	return (unsigned long)&__EARLY_BSS_END -
		(unsigned long)&__EARLY_BSS_START;
}

static inline void *__irq_init_start(void)
{
	return (void *)&__IRQ_INIT_START;
}

static inline void *__irq_init_end(void)
{
	return (void *)&__IRQ_INIT_END;
}

static inline void *__timer_init_start(void)
{
	return (void *)&__TIMER_INIT_START;
}

static inline void *__timer_init_end(void)
{
	return (void *)&__TIMER_INIT_END;
}

static inline void *__uart_init_start(void)
{
	return (void *)&__UART_INIT_START;
}

static inline void *__uart_init_end(void)
{
	return (void *)&__UART_INIT_END;
}


#endif
