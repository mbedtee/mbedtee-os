/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 KapaXL (kapa.xl@outlook.com)
 * IMX UART driver internal definition
 */

#ifndef _UART_IMX_H
#define _UART_IMX_H

#include <uart.h>

/* necessary registers */
#define IMX_RX				0x00	/* Receiver Register */
#define IMX_TX				0x40	/* Transmitter Register */
#define IMX_UCR1			0x80	/* Control Register 1 */
#define IMX_UCR2			0x84	/* Control Register 2 */
#define IMX_UCR3			0x88	/* Control Register 3 */
#define IMX_UCR4			0x8c	/* Control Register 4 */
#define IMX_UFCR			0x90	/* FIFO Control Register */
#define IMX_UTS				0xb4	/* UART Test Register */

/* necessary bit-fields */
#define IMX_RX_CHARRDY		(1 << 15)	/* RX ready */
#define IMX_RX_ERR			(1 << 14)	/* RX error */

#define IMX_UCR1_UARTEN		(1 << 0)	/* UART enabled */

#define IMX_UCR2_IRTS		(1 << 14)	/* Ignore RTS */
#define IMX_UCR2_STPB		(1 << 6)	/* Stop */
#define IMX_UCR2_WS			(1 << 5)	/* Word size */
#define IMX_UCR2_TXEN		(1 << 2)	/* Transmitter enabled */
#define IMX_UCR2_RXEN		(1 << 1)	/* Receiver enabled */
#define IMX_UCR2_SRST		(1 << 0)	/* SW reset */

#define IMX_UCR4_OREN		(1 << 1)	/* Receiver overrun interrupt enable */
#define IMX_UCR4_DREN		(1 << 0)	/* Recv data ready interrupt enable */

#define IMX_UFCR_RFDIV(x)	(((x) < 7 ? 6 - (x) : 6) << 7)
#define IMX_UFCR_TXTL_SHF	10		/* Transmitter trigger level shift */

#define IMX_UTS_TXFULL		(1<<4)	/* UART Test Register - TxFIFO full */

#endif
