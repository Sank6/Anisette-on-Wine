from __future__ import annotations

import json
import socket
import struct
from typing import Any


class WebSocketError(RuntimeError):
    pass


class WebSocket:
    """Small RFC 6455 text-frame implementation for the single v3 exchange."""

    MAX_MESSAGE = 16 * 1024

    def __init__(self, connection: socket.socket):
        self.connection = connection

    def _read_exact(self, count: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < count:
            part = self.connection.recv(count - len(chunks))
            if not part:
                raise WebSocketError("client disconnected")
            chunks.extend(part)
        return bytes(chunks)

    def _send_frame(self, opcode: int, payload: bytes = b"") -> None:
        if len(payload) > self.MAX_MESSAGE:
            raise WebSocketError("outgoing message is too large")
        header = bytearray([0x80 | opcode])
        if len(payload) < 126:
            header.append(len(payload))
        else:
            header.append(126)
            header.extend(struct.pack("!H", len(payload)))
        self.connection.sendall(bytes(header) + payload)

    def send_json(self, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self._send_frame(0x1, encoded)

    def close(self, code: int = 1000) -> None:
        try:
            self._send_frame(0x8, struct.pack("!H", code))
        except (OSError, WebSocketError):
            pass

    def receive_json(self) -> dict[str, Any]:
        while True:
            first, second = self._read_exact(2)
            final = bool(first & 0x80)
            opcode = first & 0x0F
            masked = bool(second & 0x80)
            length = second & 0x7F
            if not final:
                raise WebSocketError("fragmented messages are not supported")
            if not masked:
                raise WebSocketError("client frames must be masked")
            if length == 126:
                length = struct.unpack("!H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exact(8))[0]
            if length > self.MAX_MESSAGE:
                raise WebSocketError("incoming message is too large")
            mask = self._read_exact(4)
            data = bytearray(self._read_exact(length))
            for index in range(length):
                data[index] ^= mask[index % 4]
            if opcode == 0x8:
                raise WebSocketError("client closed the connection")
            if opcode == 0x9:
                self._send_frame(0xA, bytes(data))
                continue
            if opcode != 0x1:
                raise WebSocketError("only text messages are supported")
            try:
                payload = json.loads(bytes(data).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise WebSocketError("message is not valid JSON") from exc
            if not isinstance(payload, dict):
                raise WebSocketError("message root must be an object")
            return payload
