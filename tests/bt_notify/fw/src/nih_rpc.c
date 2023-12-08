/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#include <errno.h>
#include <string.h>

#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/sys/ring_buffer.h>

#include <zephyr/sys/__assert.h>
#include <nih_rpc.h>

#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(nih_rpc, 3);

// TODO: Use a buf pool depending on evt size
NET_BUF_POOL_DEFINE(rpc_pool, 50, 2048, 0, NULL);

nih_rpc_handler_t *rpc_cmd_handlers;
nih_rpc_handler_t *rpc_evt_handlers;

static char g_data[CONFIG_NIH_RPC_UART_BUF_SIZE];
static struct nih_rpc_uart g_uart_config;
static struct nih_rpc_uart_header g_uart_header;
RING_BUF_DECLARE(g_ringbuf, CONFIG_NIH_RPC_UART_BUF_SIZE);

struct net_buf *nih_rpc_alloc_buf(size_t size)
{
	struct net_buf *buf = net_buf_alloc(&rpc_pool, K_SECONDS(1));

	if (buf) {
		net_buf_reserve(buf, NIH_RPC_BUF_RESERVE);
	}

	return buf;
}

static int transport_send(struct nih_rpc_uart *uart_config, struct net_buf *buf);

int nih_rpc_send_rsp(struct net_buf *buf, uint16_t opcode)
{
	net_buf_push_le16(buf, opcode);
	net_buf_push_u8(buf, RPC_TYPE_RSP);

	int err = transport_send(&g_uart_config, buf);

	net_buf_unref(buf);

	return err;
}

int nih_rpc_send_event(struct net_buf *buf, uint16_t opcode)
{
	net_buf_push_le16(buf, opcode);
	net_buf_push_u8(buf, RPC_TYPE_EVT);

	int err = transport_send(&g_uart_config, buf);

	net_buf_unref(buf);

	return err;
}

void nih_rpc_register_cmd_handlers(nih_rpc_handler_t handlers[], size_t num)
{
	rpc_cmd_handlers = handlers;
}

void nih_rpc_register_evt_handlers(nih_rpc_handler_t handlers[], size_t num)
{
	rpc_evt_handlers = handlers;
}

static int rpc_handle_buf(struct net_buf *buf)
{
	uint8_t type = net_buf_pull_u8(buf);
	__ASSERT(type < RPC_TYPE_MAX, "Unkown packet type");
	__ASSERT(type != RPC_TYPE_RSP, "Target -> PC command direction not yet supported");

	uint16_t op = net_buf_pull_le16(buf);

	switch (type) {
		case RPC_TYPE_CMD:
			__ASSERT(rpc_cmd_handlers, "No registered command handlers");
			__ASSERT(rpc_cmd_handlers[op], "No registered command handler for opcode %x", op);
			return rpc_cmd_handlers[op](buf);
		case RPC_TYPE_EVT:
			__ASSERT(rpc_evt_handlers, "No registered event handlers");
			__ASSERT(rpc_evt_handlers[op], "No registered event handler for opcode %x", op);
			return rpc_evt_handlers[op](buf);
		default:
			__ASSERT(0, "ohno");
			return -1;
	}
}

static int nih_rpc_uart_init(struct nih_rpc_uart *uart_config);

int sys_init_rpc(void)
{
	g_uart_config.packet = &g_data[0];
	g_uart_config.header = &g_uart_header;
	g_uart_config.ringbuf = &g_ringbuf;

	return nih_rpc_uart_init(&g_uart_config);
}

SYS_INIT(sys_init_rpc, POST_KERNEL, CONFIG_APPLICATION_INIT_PRIORITY);

/* BIG ASS COMMENT ******************************************************************************************************************************** */

static inline void cleanup_state(struct nih_rpc_uart *config)
{
	LOG_DBG("");
	memset(config->header, 0, sizeof(struct nih_rpc_uart_header));
}

static void process_ringbuf(struct nih_rpc_uart *uart_config);

static void rpc_tr_uart_handler(struct k_work *item)
{
	LOG_DBG("");

	struct nih_rpc_uart *uart_config =
		CONTAINER_OF(item, struct nih_rpc_uart, work);
	LOG_DBG("work %p", &uart_config->work);

	struct nih_rpc_uart_header *header = uart_config->header;

	__ASSERT_NO_MSG(uart_config->used);

	ring_buf_get(uart_config->ringbuf, uart_config->packet, header->len);
	LOG_HEXDUMP_DBG(uart_config->packet, header->len, "packet");

	struct net_buf buf;

	net_buf_simple_init_with_data(&buf.b, uart_config->packet, header->len);

	LOG_DBG("calling rx cb");
	/* We memcpy the data out because the packet might reside on the ringbuf
	 * boundary, and nrf-rpc can't handle that, it expects a single linear
	 * array.
	 */
	rpc_handle_buf(&buf);
	LOG_DBG("rx cb returned");
	cleanup_state(uart_config);

	/* Re-trigger processing in case we have another packet pending. */
	process_ringbuf(uart_config);
}

/* False if header is invalid or incomplete
 * True if header complete and valid
 */
static bool build_header(struct nih_rpc_uart *uart_config)
{
	struct nih_rpc_uart_header *header = uart_config->header;

	__ASSERT_NO_MSG(header != NULL);

	if (uart_config->idx > 6) {
		/* Header is complete, the current byte doesn't belong to it */
		return true;
	}

	uint8_t byte;

	if (ring_buf_get(uart_config->ringbuf, &byte, 1) != 1) {
		return false;
	}

	if (uart_config->idx < 4) {
		if (byte != "UART"[uart_config->idx]) {
			return false;
		}
		/* If the rx char matches its required value, uart_config->idx will
		 * be incremented and parsing will continue in the next call.
		 * Else, we cleanup the state and return.
		 */
	} else if (uart_config->idx == 3) {
		/* Don't trigger a memset for each rx'd byte (that doesn't match
		 * the header).
		 */
		cleanup_state(uart_config);
	}

	switch (uart_config->idx) {
	case 4:
		header->len = byte;
		break;
	case 5:
		header->len += byte << 8;
		break;
	case 6:
		header->crc = byte;
		break;
	default:
		break;
	}

	LOG_DBG("byte[%d]: %x", uart_config->idx, byte);

	uart_config->idx++;
	return false;
}

static uint8_t compute_crc(struct nih_rpc_uart_header *header, struct ring_buf *buf)
{
	/* TODO: implement crc. could be crc8_ccitt() */
	return header->crc;
}

static void process_ringbuf(struct nih_rpc_uart *uart_config)
{
	struct nih_rpc_uart_header *header = uart_config->header;

	/* try to parse header */
	while (!ring_buf_is_empty(uart_config->ringbuf) &&
	       !build_header(uart_config)) {};

	/* receive the packet data */
	if (build_header(uart_config)) {
		if (ring_buf_size_get(uart_config->ringbuf) >= header->len) {
			if (compute_crc(header, uart_config->ringbuf) == header->crc) {
				LOG_DBG("submit to nrf-rpc");
				k_work_submit(&uart_config->work);
				/* LOG_DBG("early return"); */
				return;
			}
		}
	}
}

/*
 * Read any available characters from UART, and place them in a ring buffer. The
 * ring buffer is in turn processed by process_ringbuf().
 */
void serial_cb(const struct device *uart, void *user_data)
{
	struct nih_rpc_uart *uart_config = (struct nih_rpc_uart *)user_data;

	if (!uart_irq_update(uart)) {
		return;
	}

	while (uart_irq_rx_ready(uart)) {
		uint8_t byte = 0; /* Have to assign to stop GCC from whining */
		uart_fifo_read(uart, &byte, 1);
		uint32_t ret = ring_buf_put(uart_config->ringbuf, &byte, 1);
		(void)ret; /* Don't warn if logging is disabled */

		LOG_DBG("rx: %x, rb put %u", byte, ret);

		/* Only try to decode if wq item is not pending */
		if (!k_work_busy_get(&uart_config->work)) {
			process_ringbuf(uart_config);
		}
	}
}

static int nih_rpc_uart_init(struct nih_rpc_uart *uart_config)
{
	LOG_DBG("");

	k_work_init(&uart_config->work, rpc_tr_uart_handler);

	if (uart_config->used) {
		return 0;
	}

	/* Initialize UART driver */
	if (!device_is_ready(uart_config->uart)) {
		LOG_ERR("UART device not found!");
		return -EAGAIN;
	}

	uart_config->used = true;

	uart_irq_callback_user_data_set(uart_config->uart,
					serial_cb,
					(void *)uart_config);
	uart_irq_rx_enable(uart_config->uart);

	LOG_DBG("init ok");

	return 0;
}

static int transport_send(struct nih_rpc_uart *uart_config, struct net_buf *buf)
{
	LOG_DBG("");
	uint16_t length = buf->len;

	if (!uart_config->used) {
		LOG_ERR("nRF RPC transport is not initialized");
		return -ENOTCONN;
	}

	LOG_DBG("Sending %u bytes", length);
	LOG_HEXDUMP_DBG(buf->data, length, "Data: ");

	/* TODO: use async instead of poll-out, push header on netbuf */

	/* Add UART transport header */
	uart_poll_out(uart_config->uart, 'U');
	uart_poll_out(uart_config->uart, 'A');
	uart_poll_out(uart_config->uart, 'R');
	uart_poll_out(uart_config->uart, 'T');
	/* Add length */
	uart_poll_out(uart_config->uart, 0xFF & length);
	uart_poll_out(uart_config->uart, 0xFF & (length >> 8));
	/* Add CRC (not computed for now) */
	uart_poll_out(uart_config->uart, 0);

	for (size_t i = 0; i < length; i++) {
		uart_poll_out(uart_config->uart, buf->data[i]);
	}

	LOG_DBG("exit");

	return 0;
}