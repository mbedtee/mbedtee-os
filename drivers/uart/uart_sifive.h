/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2019 KapaXL (kapa.xl@outlook.com)
 * SiFive UART driver internal definition
 */

#ifndef _UARTSIFIVE_H
#define _UARTSIFIVE_H

#define UART_TXFIFO			0 /* Rx FIFO Register */
#define UART_RXFIFO			1 /* Tx FIFO Register */
#define UART_TXCTRL			2 /* Tx Control Register */
#define UART_RXCTRL			3 /* Rx Control Register */
#define UART_IE				4 /* Interrupt Enable Register */
#define UART_IP				5 /* Interrupt Pending Register */
#define UART_DIV			6 /* Divisor control Register */

#define UART_TXEN			(1u << 0)  /* Tx Enable */
#define UART_RXEN			(1u << 0)  /* Rx Enable */
#define UART_IPTX			(1u << 0)  /* Tx Asserted in IP */
#define UART_IPRX			(1u << 1)  /* Rx Asserted in IP */

#define UART_IETX			(1u << 0)  /* Tx Interrupt Enabled */
#define UART_IERX			(1u << 1)  /* Rx Interrupt Enabled */

#define UART_TXFULL			(1u << 31) /* Tx FIFO full */
#define UART_RXEMPTY		(1u << 31) /* Rx FIFO Empty */

#endif
