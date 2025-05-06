// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2025 KapaXL (kapa.xl@outlook.com)
 * RISCV APLIC-IMSIC Interrupt-controller
 */
#ifndef _INTC_APLIC_IMSIC_H
#define _INTC_APLIC_IMSIC_H

#include <io.h>
#include <of.h>
#include <bitops.h>
#include <interrupt.h>

#define APLIC_DOMAINCFG			0x0000
#define APLIC_SOURCECFG_BASE	0x0004

#define APLIC_MMSICFGADDR		0x1bc0
#define APLIC_MMSICFGADDRH		0x1bc4
#define APLIC_SMSICFGADDR		0x1bc8
#define APLIC_SMSICFGADDRH		0x1bcc

#define APLIC_SETIP_BASE		0x1c00
#define APLIC_SETIPNUM			0x1cdc

#define APLIC_CLRIP_BASE		0x1d00
#define APLIC_CLRIPNUM			0x1ddc

#define APLIC_SETIE_BASE		0x1e00
#define APLIC_SETIENUM			0x1edc

#define APLIC_CLRIE_BASE		0x1f00
#define APLIC_CLRIENUM			0x1fdc

#define APLIC_TARGET_BASE		0x3004
#define APLIC_IDC_BASE			0x4000

#define APLIC_IDC_SIZE			32

#define APLIC_DOMAINCFG_IE		(1 << 8)
#define APLIC_DOMAINCFG_DM		(1 << 2)

#define APLIC_SOURCECFG_EDGE_RISE	4
#define APLIC_SOURCECFG_EDGE_FALL	5
#define APLIC_SOURCECFG_LEVEL_HIGH	6
#define APLIC_SOURCECFG_LEVEL_LOW	7

#define APLIC_IDC_IDELIVERY		0x00
#define APLIC_IDC_IFORCE		0x04
#define APLIC_IDC_ITHRESHOLD	0x08
#define APLIC_IDC_TOPI			0x18
#define APLIC_IDC_CLAIMI		0x1c

#define APLIC_DEFAULT_PRIO		1
#define APLIC_MAX_INT			1024

#define APLIC_xMSICFGADDR_PPN_SHIFT	12

#define APLIC_REG_OFFSET(n)		(BYTES_PER_INT * ((n) / BITS_PER_INT))
#define APLIC_BIT_OFFSET(n)		((n) % BITS_PER_INT)

#define IMSIC_EIDELIVERY		0x70
#define IMSIC_EITHRESHOLD		0x72

#define IMSIC_EIP0				0x80
#define IMSIC_EIE0				0xc0

#define IMSIC_MAX_INT			2048

#define IMSIC_PAGE_SHIFT		12

#define IMSIC_IRQ_OF(cpu, id) (((cpu) * (imsic->max + 1)) + (id))
#define IMSIC_IRQ_ID_OF(irq) ((irq) % (imsic->max + 1))
#define IMSIC_IRQ_CPU_OF(irq) ((irq) / (imsic->max + 1))

struct imsic_percpu {
	unsigned int available;
	unsigned int next;
	unsigned long *bmap;
};

struct imsic_desc {
	/* max interrupts in IMSIC */
	unsigned int max;

	unsigned int guest_index_bits;
	unsigned int hart_index_bits;

	struct spinlock sl;

	struct imsic_percpu pcpu_priv[CONFIG_NR_CPUS];

	struct irq_controller *controller;

	/* physical and memory-mapped addresses */
	unsigned long phys_addr;
	void *regs;
};

void imsic_post_set_affinity(struct irq_desc *d,
	unsigned int oldcpu, unsigned int oldid);

#endif
