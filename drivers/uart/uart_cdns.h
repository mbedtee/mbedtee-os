/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2025 KapaXL (kapa.xl@outlook.com)
 * Cadence UART driver internal definition
 */

#ifndef _UART_CDNS_H
#define _UART_CDNS_H

#include <uart.h>

#define CDNS_CR					0x00	/* Control register. */
#define CDNS_MR					0x04	/* Mode Register. */
#define CDNS_IER				0x08	/* Interrupt Enable */
#define CDNS_ISR				0x14	/* Interrupt Status */
#define CDNS_BAUDGEN			0x18	/* Baud Rate Generator */
#define CDNS_RXTOUT				0x1C	/* RX Timeout */
#define CDNS_RXWM				0x20	/* RX FIFO Trigger Level */
#define CDNS_SR					0x2C	/* Status register. */
#define CDNS_FIFO				0x30	/* Data read or written from the interface. */
#define CDNS_BAUDDIV			0x34	/* Baud rate divisor register. */

#define CDNS_CR_TXE				0x00000010	/* Control register - TX enable. */
#define CDNS_CR_RXE				0x00000004	/* Control register - RX enable. */
#define CDNS_CR_TXRST			0x00000002	/* Control register - TX reset. */
#define CDNS_CR_RXRST			0x00000001	/* Control register - RX reset. */

#define CDNS_MR_STOPMODE_2_BIT	0x00000080  /* Mode Register - 2 stop bits. */
#define CDNS_MR_STOPMODE_1_BIT	0x00000000  /* Mode Register - 1 stop bit. */

#define CDNS_MR_PARITY_NONE		0x00000020  /* Mode Register - No parity mode. */
#define CDNS_MR_PARITY_ODD		0x00000008  /* Mode Register - Odd parity mode. */
#define CDNS_MR_PARITY_EVEN		0x00000000  /* Mode Register - Even parity mode. */

#define CDNS_MR_CHARLEN_6_BIT	0x00000006  /* Mode Register - 6 bits data. */
#define CDNS_MR_CHARLEN_7_BIT	0x00000004  /* Mode Register - 7 bits data. */
#define CDNS_MR_CHARLEN_8_BIT	0x00000000  /* Mode Register - 8 bits data. */
#define CDNS_MR_CLKSEL			0x00000001  /* Mode Register - Pre-scalar selection. */
#define CDNS_MR_CHMODE_NORM		0x00000000  /* Mode Register - Normal mode. */

#define CDNS_IER_TOUT			0x00000100	/* Interrupt Enable - RX Timeout interrupt. */
#define CDNS_IER_FRAMING		0x00000040	/* Interrupt Enable - Framing err interrupt. */
#define CDNS_IER_OVERRUN		0x00000020	/* Interrupt Enable - Overrun interrupt. */
#define CDNS_IER_RXTRIG			0x00000001	/* Interrupt Enable - RX FIFO trigger interrupt. */

#define CDNS_SR_RXEMPTY			0x00000002	/* Status register - RX FIFO empty. */
#define CDNS_SR_TXEMPTY			0x00000008	/* Status register - TX FIFO empty. */
#define CDNS_SR_TXFULL			0x00000010	/* Status register - TX FIFO full. */

#endif
