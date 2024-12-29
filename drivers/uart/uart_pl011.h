/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * PL011 UART driver internal definition
 */

#ifndef _UART_PL011_H
#define _UART_PL011_H

#include <uart.h>

#define PL011_DR			0x00	/* Data read or written from the interface. */
#define PL011_FR			0x18	/* Flag register (Read only). */
#define PL011_IBRD			0x24	/* Integer baud rate divisor register. */
#define PL011_FBRD			0x28	/* Fractional baud rate divisor register. */
#define PL011_LCRH			0x2c	/* Line control register. */
#define PL011_CR			0x30	/* Control register. */
#define PL011_IFLS			0x34	/* Interrupt fifo level select. */
#define PL011_IMSC			0x38	/* Interrupt mask. */
#define PL011_RIS			0x3c	/* Raw interrupt status. */
#define PL011_ICR			0x44	/* Interrupt clear register. */

#define PL011_LCRH_SPS		0x80
#define PL011_LCRH_WLEN_8	0x60
#define PL011_LCRH_WLEN_7	0x40
#define PL011_LCRH_WLEN_6	0x20
#define PL011_LCRH_WLEN_5	0x00
#define PL011_LCRH_FEN		0x10
#define PL011_LCRH_STP2		0x08
#define PL011_LCRH_EPS		0x04
#define PL011_LCRH_PEN		0x02
#define PL011_LCRH_BRK		0x01

#define PL011_OEIC			(1 << 10)	/* overrun error interrupt clear */
#define PL011_BEIC			(1 << 9)	/* break error interrupt clear */
#define PL011_PEIC			(1 << 8)	/* parity error interrupt clear */
#define PL011_FEIC			(1 << 7)	/* framing error interrupt clear */
#define PL011_RTIC			(1 << 6)	/* receive timeout interrupt clear */
#define PL011_TXIC			(1 << 5)	/* transmit interrupt clear */
#define PL011_RXIC			(1 << 4)	/* receive interrupt clear */

#define PL011_CR_RXE		0x0200	/* receive enable */
#define PL011_CR_TXE		0x0100	/* transmit enable */
#define PL011_CR_UARTEN		0x0001	/* UART enable */

#define PL011_IFLS_RX1_8	(0 << 3)
#define PL011_IFLS_RX2_8	(1 << 3)
#define PL011_IFLS_RX4_8	(2 << 3)
#define PL011_IFLS_RX6_8	(3 << 3)
#define PL011_IFLS_RX7_8	(4 << 3)
#define PL011_IFLS_TX1_8	(0 << 0)
#define PL011_IFLS_TX2_8	(1 << 0)
#define PL011_IFLS_TX4_8	(2 << 0)
#define PL011_IFLS_TX6_8	(3 << 0)
#define PL011_IFLS_TX7_8	(4 << 0)

#define PL011_RTIM			(1 << 6)	/* receive timeout interrupt mask */
#define PL011_RXIM			(1 << 4)	/* receive interrupt mask */

#define PL011_FR_RI			0x100
#define PL011_FR_TXFE		0x080
#define PL011_FR_RXFF		0x040
#define PL011_FR_TXFF		0x020
#define PL011_FR_RXFE		0x010
#define PL011_FR_BUSY		0x008
#define PL011_FR_DCD		0x004
#define PL011_FR_DSR		0x002
#define PL011_FR_CTS		0x001

#endif
