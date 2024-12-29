/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * Stack Protector functions
 */

#ifndef _STACKPROT_H
#define _STACKPROT_H

#include <timer.h>
#include <generated/autoconf.h>

#ifdef CONFIG_STACK_PROTECTOR
void __stack_chk_fail(void);

static __always_inline void __stack_chk_guard_set(void)
{
	extern unsigned long __stack_chk_guard;

	__stack_chk_guard *= (long)&__stack_chk_guard;
	__stack_chk_guard += rand();
	__stack_chk_guard += rand() << 13;
}

#else

static __always_inline void __stack_chk_guard_set(void) {}

#endif
#endif
