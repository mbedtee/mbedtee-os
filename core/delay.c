// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * mdelay() and udelay()
 */

#include <timer.h>
#include <tevent.h>
#include <trace.h>

void udelay(unsigned long usecs)
{
	uint64_t cycles = usecs_to_cycles(usecs);
	uint64_t now = 0, last = read_cycles();

	do  {
		now = read_cycles();
	} while (cycles > (now - last));
}

void mdelay(unsigned long msecs)
{
	uint64_t cycles = msecs_to_cycles(msecs);
	uint64_t now = 0, last = read_cycles();

	do  {
		now = read_cycles();
	} while (cycles > (now - last));
}
