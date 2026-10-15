"""TLS record layer encode/decode and handshake message reassembly."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

MAX_RECORD_LEN = 2**14 + 2048


class WireFormatError(ValueError):
    """Bytes from the server do not follow the TLS record/handshake format."""


@dataclass(frozen=True)
class Record:
    content_type: int
    version: int
    payload: bytes


@dataclass(frozen=True)
class HandshakeMessage:
    msg_type: int
    body: bytes


def u8(value: int) -> bytes:
    return struct.pack("!B", value)


def u16(value: int) -> bytes:
    return struct.pack("!H", value)


def u24(value: int) -> bytes:
    return struct.pack("!I", value)[1:]


def vec8(data: bytes) -> bytes:
    return u8(len(data)) + data


def vec16(data: bytes) -> bytes:
    return u16(len(data)) + data


def vec24(data: bytes) -> bytes:
    return u24(len(data)) + data


def encode_record(content_type: int, version: int, payload: bytes) -> bytes:
    return u8(content_type) + u16(version) + vec16(payload)


def encode_handshake(msg_type: int, body: bytes) -> bytes:
    return u8(msg_type) + vec24(body)


def looks_like_tls_record(data: bytes) -> bool:
    """True if the first bytes could start a TLS record (type 20-24, major version 3)."""
    return len(data) >= 3 and 20 <= data[0] <= 24 and data[1] == 3


def split_records(data: bytes) -> tuple[list[Record], bytes]:
    """Split as many complete records as possible; return (records, unconsumed tail)."""
    records: list[Record] = []
    offset = 0
    while len(data) - offset >= 5:
        ctype, version, length = struct.unpack_from("!BHH", data, offset)
        if not (20 <= ctype <= 24) or (version >> 8) != 3:
            raise WireFormatError(f"not a TLS record header at offset {offset}: {data[offset:offset + 5].hex()}")
        if length > MAX_RECORD_LEN:
            raise WireFormatError(f"record length {length} exceeds maximum")
        if len(data) - offset - 5 < length:
            break
        records.append(Record(ctype, version, data[offset + 5:offset + 5 + length]))
        offset += 5 + length
    return records, data[offset:]


@dataclass
class HandshakeBuffer:
    """Reassembles handshake messages that may be split across or packed into records."""

    _pending: bytearray = field(default_factory=bytearray)

    def feed(self, payload: bytes) -> list[HandshakeMessage]:
        self._pending.extend(payload)
        messages: list[HandshakeMessage] = []
        while len(self._pending) >= 4:
            msg_type = self._pending[0]
            length = int.from_bytes(self._pending[1:4], "big")
            if len(self._pending) < 4 + length:
                break
            messages.append(HandshakeMessage(msg_type, bytes(self._pending[4:4 + length])))
            del self._pending[:4 + length]
        return messages


class Reader:
    """Bounds-checked sequential reader over bytes; raises WireFormatError on overrun."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos

    def take(self, n: int) -> bytes:
        if n < 0 or self._pos + n > len(self._data):
            raise WireFormatError(f"need {n} bytes, have {self.remaining}")
        chunk = self._data[self._pos:self._pos + n]
        self._pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def vec8(self) -> bytes:
        return self.take(self.u8())

    def vec16(self) -> bytes:
        return self.take(self.u16())

    def vec24(self) -> bytes:
        return self.take(self.u24())

    def rest(self) -> bytes:
        return self.take(self.remaining)
