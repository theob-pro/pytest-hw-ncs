#!/usr/bin/env python3

import serial
import time
import threading
import queue
import logging
from contextlib import contextmanager
from targettest.uart_packet import UARTHeader
from targettest.rpc_packet import RPCPacket, RPCPacketType
from targettest.cbor import CBORPayload

LOGGER = logging.getLogger(__name__)

class UARTChannel(threading.Thread):
    DEFAULT_TIMEOUT = 0.001
    DEFAULT_WRITE_TIMEOUT = 5
    MAX_RECV_BYTE_COUNT = 256
    RPC_HEADER_LENGTH = 7

    def __init__(self,
                 port=None,
                 baudrate=1000000,
                 rtscts=True,
                 rx_handler=None):
        # TODO: Maybe serial.threaded could be used
        threading.Thread.__init__(self, daemon=True)
        self.port = port

        self._stop_rx_flag = threading.Event() # Used to cleanly stop the RX thread
        self._rx_handler = rx_handler # Mandatory, called for each RX packet/unit

        self._max_recv_byte_count = self.MAX_RECV_BYTE_COUNT

        self._serial = serial.Serial(port=port, baudrate=baudrate, rtscts=rtscts,
                                     timeout=UARTChannel.DEFAULT_TIMEOUT,
                                     write_timeout=UARTChannel.DEFAULT_WRITE_TIMEOUT)

    def clear_buffers(self):
        self._serial.reset_input_buffer()
        self._serial.reset_output_buffer()

    def send(self, data, timeout=15):
        data = bytearray(data)

        byte_count = 0
        start_time = time.monotonic()

        LOGGER.debug(f'TX [{self.port}] {data.hex(" ")}')
        while data:
            data = data[byte_count:]

            byte_count += self._serial.write(data)

            if time.monotonic() - start_time > timeout:
                LOGGER.error(f'Message not sent during required time: {timeout}')
                raise TimeoutError

        return byte_count

    def run(self):
        LOGGER.debug(f'Start RX [{self.port}]')
        self._stop_rx_flag.clear()

        while not self._stop_rx_flag.isSet():
            recv = self._serial.read(self.MAX_RECV_BYTE_COUNT)

            # Yield to other threads
            if recv == b'':
                time.sleep(0.0001)
                continue

            LOGGER.debug(f'RX [{self.port}] {recv.hex(" ")}')

            self._rx_handler(recv)

    def stop(self):
        self._stop_rx_flag.set()
        self.join()
        self._serial.close()


class UARTDecodingState():
    def __init__(self):
        self.reset()

    def reset(self):
        self.rx_buf = b''
        self.header = None

    def __repr__(self):
        return f'{self.header} buf {self.rx_buf.hex(" ")}'


class UARTRPCChannel(UARTChannel):
    def __init__(self,
                 port=None,
                 baudrate=1000000,
                 rtscts=True,
                 default_packet_handler=None,
                 group_name=None):

        super().__init__(port, baudrate, rtscts, rx_handler=self.handle_rx)

        LOGGER.debug(f'rpc channel init: {port}')
        self.group_name = group_name
        self.remote_gid = 0
        self.default_packet_handler = default_packet_handler
        self.state = UARTDecodingState()

        self.handler_lut = {item.value: {} for item in RPCPacketType}
        self.established = False
        self.events = queue.Queue()

    def handle_rx(self, data: bytes):
        # Prepend the (just received) data with the remains of the last RX
        data = self.state.rx_buf + data
        # Save the current data in case decoding is not complete
        self.state.rx_buf = data

        if len(data) >= UARTHeader._size:
            if self.state.header is None:
                # Attempt to decode the header
                self.state.header = UARTHeader.unpack(data)

            if self.state.header is None:
                # Header failed to decode, eat one byte and try again
                self.state.rx_buf = self.state.rx_buf[1:]
                if len(data) >= UARTHeader._size:
                    self.handle_rx(b'')

        if self.state.header is not None:
            # Header has been decoded
            # Try to decode the packet
            if len(data[self.state.header._size:]) >= self.state.header.length:
                packet = RPCPacket.unpack(data)
                self.handler(packet)

                # Consume the data in the RX buffer
                data = data[self.state.header._size + self.state.header.length:]
                self.state.reset()

                if len(data) > 0:
                    self.handle_rx(data)

    def handler_exists(self, packet: RPCPacket):
        return packet.opcode in self.handler_lut[packet.packet_type]

    def lookup(self, packet: RPCPacket):
        return self.handler_lut[packet.packet_type][packet.opcode]

    def handler(self, packet: RPCPacket):
        LOGGER.debug(f'Handling {packet}')
        # TODO: terminate session on ERR packets
        # Call opcode handler if registered, else call default handler
        if packet.packet_type == RPCPacketType.INIT:
            # Check the INIT packet is for the test system
            assert packet.payload == b'\x00' + self.group_name.encode()
            self.remote_gid = packet.gid_src

            self.clear_buffers()
            self.clear_events()

            # Mark channel as usable and send INIT response
            self.send_init()
            self.established = True
            LOGGER.debug(f'[{self.port}] channel established')

        elif packet.packet_type == RPCPacketType.EVT:
            self.events.put(packet)
            self.ack(packet.opcode)

        elif packet.packet_type == RPCPacketType.ACK:
            (_, sent_opcode) = self._ack
            assert packet.opcode == sent_opcode
            self._ack = (packet, packet.opcode)

        elif packet.packet_type == RPCPacketType.RSP:
            # We just assume only one command can be in-flight at a time
            # Should be enough for testing, can be extended later.
            self._rsp = packet

        elif self.handler_exists(packet):
            self.lookup(packet)(self, packet)

        elif self.default_packet_handler is not None:
            self.default_packet_handler(self, packet)

        else:
            LOGGER.error(f'[{self.port}] unhandled packet {packet}')

    def register_packet(self, packet_type: RPCPacketType, opcode: int, packet_handler):
        self.handler_lut[packet_type][opcode] = packet_handler

    def ack(self, opcode: int):
        packet = RPCPacket(RPCPacketType.ACK, opcode,
                           src=0, dst=0xFF,
                           gid_src=self.remote_gid, gid_dst=self.remote_gid,
                           payload=b'')

        super().send(packet.raw)

    def evt(self, opcode: int, data: bytes=b'', timeout=5):
        packet = RPCPacket(RPCPacketType.EVT, opcode,
                           src=0, dst=0xFF,
                           gid_src=self.remote_gid, gid_dst=self.remote_gid,
                           payload=data)
        self._ack = (None, opcode)

        super().send(packet.raw)

        end_time = time.monotonic() + timeout
        while self._ack[0] is None:
            time.sleep(.01)
            if time.monotonic() > end_time:
                raise Exception('Async command timeout')

        # Return packet containing the ACK
        return self._ack[1]

    def evt_cbor(self, opcode: int, data=None, timeout=5):
        if data is not None:
            payload = CBORPayload(data).encoded
            LOGGER.debug(f'encoded payload: {payload.hex(" ")}')
            self.evt(opcode, payload, timeout=timeout)
        else:
            self.evt(opcode, timeout=timeout)

    def cmd(self, opcode: int, data: bytes=b'', timeout=5):
        # WARNING:
        #
        # Only use EVENTS (async) when calling APIs that make use of nRF RPC on
        # the device (e.g., if using BT_RPC and calling bt_enable() in the
        # handler).
        #
        # If commands (sync) are used, nRF RPC will get confused, being called
        # from an existing RPC context (UART in this case) and will try to send
        # the command over IPC, but using the wrong IDs, resulting in a deadlock.
        packet = RPCPacket(RPCPacketType.CMD, opcode,
                           src=0, dst=0xFF,
                           gid_src=self.remote_gid, gid_dst=self.remote_gid,
                           payload=data)
        self._rsp = None

        super().send(packet.raw)

        end_time = time.monotonic() + timeout
        while self._rsp is None:
            time.sleep(.01)
            if time.monotonic() > end_time:
                raise Exception('Command timeout')

        return self._rsp

    def cmd_cbor(self, opcode: int, data=None, timeout=5):
        if data is not None:
            payload = CBORPayload(data).encoded
            LOGGER.debug(f'encoded payload: {payload.hex(" ")}')
            rsp = self.cmd(opcode, payload, timeout=timeout)
        else:
            rsp = self.cmd(opcode, timeout=timeout)

        LOGGER.debug(f'decoded payload: {rsp.payload.hex(" ")}')
        return CBORPayload.read(rsp.payload).objects

    def clear_events(self):
        while not self.events.empty():
            self.events.get()

    def get_evt(self, opcode=None, timeout=5):
        if opcode is None:
            return self.events.get(timeout=timeout)

        # TODO: add filtering by opcode
        return None

    def send_init(self):
        # Isn't encoded with CBOR
        # Protocol version + RPC group name
        version = b'\x00'
        payload = self.group_name.encode()
        packet = RPCPacket(RPCPacketType.INIT,
                           0, 0, 0xFF, self.remote_gid, self.remote_gid,
                           version + payload)

        LOGGER.debug(f'Send handshake {packet}')
        super().send(packet.raw)
