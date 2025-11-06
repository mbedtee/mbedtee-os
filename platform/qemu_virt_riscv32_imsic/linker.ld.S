/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 */

#include <cpu.h>
#include <map.h>
#include <page.h>
#include <init.h>
#include <version.h>
#include <generated/autoconf.h>

#define MIN_ALIGNMENT 32

OUTPUT_FORMAT(TOOLCHAIN_FORMAT);
OUTPUT_ARCH("riscv")

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
		*(.srodata .srodata.*)
		PERCPU_INIT_SECTIONS
		CLEANUP_CALLBACKS
		STR_SECTIONS
		. = ALIGN(MIN_ALIGNMENT);
	}

	.rel.dyn : { *(.rel .rel* .rel.*) }

	__EHFRAME_START = .;
#ifdef CONFIG_BACKTRACE
	.eh_frame : {KEEP (*(.eh_frame))}
#else
	/DISCARD/ : {*(.eh_frame)}
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
		. = ALIGN(MIN_ALIGNMENT);
		*(.data .data.*)
		PROVIDE(__global_pointer$ = .);
		*(.sdata .sdata.*)
		. = ALIGN(MIN_ALIGNMENT);
	}

	.got : {*(.got .got.*)}
	. = ALIGN(MIN_ALIGNMENT);
	__DATA_END = .;

	__BSS_START = .;
	.bss : {
		__EARLY_BSS_START = .;
		KEEP (*(.bss.early))
		__EARLY_BSS_END = .;
		*(.bss .bss.*)
		*(.sbss .sbss.*)
	}
	. = ALIGN(MIN_ALIGNMENT);
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
		*(.gnu.version*)
		*(.gnu.attributes)
		*(.riscv.attributes)
	}
}
