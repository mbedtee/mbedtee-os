// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * failed routine for stack protector
 */

#include <panic.h>
#include <thread.h>

unsigned long __stack_chk_guard = 0x1314a55a;

void __nosprot __stack_chk_fail(void)
{
	panic("Kernel stack corrupted %p\n",
		__builtin_return_address(0));
}
