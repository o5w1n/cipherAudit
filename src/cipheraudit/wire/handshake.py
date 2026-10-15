"""Send one ClientHello, read the server's response, classify it.

We never complete a key exchange or encrypt anything: reading stops as soon as the
requested information is available (TRD §4.1).
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from cipheraudit.wire.client_hello import HelloParams, build_client_hello, build_sslv2_client_hello
from cipheraudit.wire.constants import ContentType, HandshakeType, ProtocolVersion
from cipheraudit.wire.records import (
    HandshakeBuffer,
    HandshakeMessage,
    WireFormatError,
    looks_like_tls_record,
    split_records,
)
from cipheraudit.wire.server_msgs import (
    Alert,
    ServerHello,
    SSLv2ServerHello,
    parse_alert,
    parse_certificate,
    parse_certificate_status,
    parse_server_hello,
    parse_sslv2_server_hello,
)

ConnFactory = Callable[[], socket.socket]

_RECV_SIZE = 16384


class ReadUntil(Enum):
    SERVER_HELLO = "server_hello"
    HELLO_DONE = "hello_done"  # TLS <= 1.2: also collect Certificate, ServerKeyExchange, CertificateStatus


@dataclass(frozen=True)
class Accepted:
    server_hello: ServerHello
    messages: list[HandshakeMessage] = field(default_factory=list)
    complete: bool = True  # False if the connection ended before HELLO_DONE was reached

    def _first(self, msg_type: int) -> bytes | None:
        return next((m.body for m in self.messages if m.msg_type == msg_type), None)

    @property
    def certificates(self) -> list[bytes]:
        body = self._first(HandshakeType.CERTIFICATE)
        return parse_certificate(body) if body is not None else []

    @property
    def server_key_exchange(self) -> bytes | None:
        return self._first(HandshakeType.SERVER_KEY_EXCHANGE)

    @property
    def ocsp_response(self) -> bytes | None:
        body = self._first(HandshakeType.CERTIFICATE_STATUS)
        return parse_certificate_status(body) if body is not None else None


@dataclass(frozen=True)
class HelloRetry:
    hrr: ServerHello


@dataclass(frozen=True)
class Rejected:
    alert: Alert


@dataclass(frozen=True)
class Closed:
    reset: bool = False


@dataclass(frozen=True)
class Timeout:
    pass


@dataclass(frozen=True)
class ConnectFailed:
    reason: str


@dataclass(frozen=True)
class ProtocolError:
    reason: str
    raw: bytes = b""


@dataclass(frozen=True)
class SSLv2Accepted:
    server_hello: SSLv2ServerHello


ProbeOutcome = Accepted | HelloRetry | Rejected | Closed | Timeout | ConnectFailed | ProtocolError
SSLv2Outcome = SSLv2Accepted | Rejected | Closed | Timeout | ConnectFailed | ProtocolError


@dataclass
class _ReadState:
    read_until: ReadUntil
    buffer: bytes = b""
    handshake: HandshakeBuffer = field(default_factory=HandshakeBuffer)
    messages: list[HandshakeMessage] = field(default_factory=list)
    server_hello: ServerHello | None = None
    hello_done: bool = False

    def finished(self) -> bool:
        if self.server_hello is None:
            return False
        if self.read_until is ReadUntil.SERVER_HELLO:
            return True
        return self.hello_done or self.server_hello.version == ProtocolVersion.TLS13

    def partial(self) -> ProbeOutcome | None:
        if self.server_hello is None:
            return None
        return Accepted(self.server_hello, self.messages, complete=False)


def _consume(state: _ReadState) -> ProbeOutcome | None:
    """Process buffered bytes. Returns a final outcome, or None if more data is needed."""
    try:
        records, state.buffer = split_records(state.buffer)
    except WireFormatError as exc:
        return state.partial() or ProtocolError(str(exc), state.buffer[:64])
    for record in records:
        if record.content_type == ContentType.ALERT:
            alert = parse_alert(record.payload)
            return state.partial() or Rejected(alert)
        if record.content_type != ContentType.HANDSHAKE:
            if state.server_hello is not None:  # TLS 1.3: CCS / encrypted records follow
                return Accepted(state.server_hello, state.messages)
            return ProtocolError(f"unexpected record type {record.content_type} before ServerHello")
        for message in state.handshake.feed(record.payload):
            state.messages.append(message)
            if message.msg_type == HandshakeType.SERVER_HELLO and state.server_hello is None:
                try:
                    state.server_hello = parse_server_hello(message.body)
                except WireFormatError as exc:
                    return ProtocolError(f"malformed ServerHello: {exc}", message.body[:64])
                if state.server_hello.is_hello_retry:
                    return HelloRetry(state.server_hello)
            elif message.msg_type == HandshakeType.SERVER_HELLO_DONE:
                state.hello_done = True
        if state.finished():
            return Accepted(state.server_hello, state.messages) if state.server_hello else None
    return None


def exchange(sock: socket.socket, data: bytes, read_until: ReadUntil = ReadUntil.SERVER_HELLO) -> ProbeOutcome:
    """Send `data` (a ClientHello record) on an open socket and read the response."""
    try:
        sock.sendall(data)
    except OSError as exc:
        return Closed(reset=True) if isinstance(exc, ConnectionError) else ProtocolError(f"send failed: {exc}")

    state = _ReadState(read_until)
    verified_tls = False
    while True:
        try:
            chunk = sock.recv(_RECV_SIZE)
        except TimeoutError:
            return state.partial() or Timeout()
        except OSError:
            return state.partial() or Closed(reset=True)
        if not chunk:
            return state.partial() or Closed()
        state.buffer += chunk
        if not verified_tls:
            if len(state.buffer) < 3:
                continue
            if not looks_like_tls_record(state.buffer):
                return ProtocolError("response is not TLS", state.buffer[:64])
            verified_tls = True
        outcome = _consume(state)
        if outcome is not None:
            return outcome


def probe(conn_factory: ConnFactory, params: HelloParams,
          read_until: ReadUntil = ReadUntil.SERVER_HELLO) -> ProbeOutcome:
    """Open a connection, send one ClientHello, read and parse the response."""
    try:
        sock = conn_factory()
    except Exception as exc:  # noqa: BLE001 - connector errors are reported, not raised
        return ConnectFailed(str(exc))
    with sock:
        return exchange(sock, build_client_hello(params), read_until)


def probe_sslv2(conn_factory: ConnFactory, cipher_specs: list[int]) -> SSLv2Outcome:
    try:
        sock = conn_factory()
    except Exception as exc:  # noqa: BLE001
        return ConnectFailed(str(exc))
    with sock:
        try:
            sock.sendall(build_sslv2_client_hello(cipher_specs))
        except OSError:
            return Closed(reset=True)
        data = b""
        while True:
            try:
                chunk = sock.recv(_RECV_SIZE)
            except TimeoutError:
                break
            except OSError:
                return Closed(reset=True) if not data else ProtocolError("reset mid-reply", data[:64])
            if not chunk:
                break
            data += chunk
            if _sslv2_complete(data):
                break
        if not data:
            return Closed()
        if looks_like_tls_record(data) and data[0] == ContentType.ALERT and len(data) >= 7:
            return Rejected(parse_alert(data[5:7]))
        if not data[0] & 0x80:
            return ProtocolError("not an SSLv2 reply", data[:64])
        try:
            return SSLv2Accepted(parse_sslv2_server_hello(data))
        except WireFormatError as exc:
            return ProtocolError(str(exc), data[:64])


def _sslv2_complete(data: bytes) -> bool:
    if len(data) < 2:
        return False
    if looks_like_tls_record(data):
        return len(data) >= 7
    if data[0] & 0x80:
        return len(data) >= 2 + (((data[0] & 0x7F) << 8) | data[1])
    return True
