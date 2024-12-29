/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 */

#include <cpu.h>
#include <map.h>
#include <page.h>
#include <init.h>
#include <generated/autoconf.h>

OUTPUT_FORMAT(elf32-littlearm)
OUTPUT_ARCH(arm)

ENTRY(_start)

SECTIONS
{
	. = VA_OFFSET;

	__CODE_START = .;

	__TEXT_START = .;
	.text : {
		*(.head.text)
		*(.text .text.*)
		KEEP (*(.exit))
	}
	. = ALIGN(PAGE_SIZE);
	__TEXT_END = .;

	__RODATA_START = .;
	.rodata : {
		*(.rodata .rodata.*)
		PERCPU_INIT_SECTIONS
		CLEANUP_CALLBACKS
		STR_SECTIONS
		. = ALIGN(BYTES_PER_LONG);
	}

	/* unwind table for AArch32@ARMV7-A backtrace */
#ifdef CONFIG_BACKTRACE
	.ARM.extab : {KEEP (*(.ARM.extab*))}
	__exidx_start = .;
	.ARM.exidx : {KEEP (*(.ARM.exidx*))}
	__exidx_end = .;
#else
	/DISCARD/ : {*(.ARM.extab*) *(.ARM.exidx*)}
	__exidx_start = .;
	__exidx_end = .;
#endif

	. = ALIGN(PAGE_SIZE);
	__RODATA_END = .;

	/* .init section */
	__INIT_START = .;
	.init : {
		EARLY_INIT_SECTIONS
		MODULE_INIT_SECTIONS
		IRQ_INIT_SECTIONS
		TIMER_INIT_SECTIONS
		UART_INIT_SECTIONS
		KEEP (*(.init))
	}
	. = ALIGN(PAGE_SIZE);
	__INIT_END = .;

	__DATA_START = .;
	.data : {
		__RAMFS_START = .;
		KEEP (*(.ramfs))
		__RAMFS_END = .;

		__DTB_START = .;
		KEEP (*(.builtin_dtb))
		. = ALIGN(BYTES_PER_LONG);

		*(.data .data.*)
	}

	.got : {*(.got .got.*)}

	. = ALIGN(BYTES_PER_LONG);
	__DATA_END = .;

	__BSS_START = .;
	.bss : {
		__EARLY_BSS_START = .;
		KEEP (*(.bss.early))
		__EARLY_BSS_END = .;
		*(.bss .bss.*)
	}
	. = ALIGN(BYTES_PER_LONG);
	__BSS_END = .;

	. = ALIGN(PAGE_SIZE);
	__CODE_END = .;

	/DISCARD/ : {
		*(.pdr)
		*(.note)
		*(.note.*)
		*(.init_*)
		*(.options)
		*(.reginfo)
		*(.comment)
		*(.gnu.attributes)
		*(.ARM.attributes)
	}
}
