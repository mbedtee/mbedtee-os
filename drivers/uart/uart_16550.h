/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * UART 16550 driver internal definition
 */

#ifndef _UART16550_H
#define _UART16550_H

#define UART_TX				0x0	/* Out: Transmit buffer */
#define UART_RX				0x0	/* In: Receive buffer */
#define UART_IER			0x1	/* Out: Interrupt Enable Register */
#define UART_IIR			0x2	/* In: Interrupt Identification */
#define UART_FCR			0x2 /* Out: FIFO Control */
#define UART_LCR			0x3	/* In:	Line Status Register */
#define UART_MCR			0x4	/* In:	Line Status Register */
#define UART_LSR			0x5	/* In:	Line Status Register */
#define UART_MSR			0x6	/* In:	Modem Status Register */
#define UART_SCR			0x7	/* In:	Scratch Register */

#define UART_DLL			0x0	/* Out: Divisor Latch Low */
#define UART_DLM			0x1	/* Out: Divisor Latch High */

#define UART_IIR_NOINT		0x01 /* No interrupt */
#define UART_LSR_DR			0x01 /* Data ready */
#define UART_LSR_THRE		0x20 /* Transmit-hold-register empty */
#define UART_LSR_TEMT		0x40 /* Transmitter empty */

#endif
