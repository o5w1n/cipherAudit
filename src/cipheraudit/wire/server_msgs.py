"""Parse server handshake messages and alerts. Facts only; no judgments."""

from __future__ import annotations

from dataclasses import dataclass, field

from cipheraudit.wire.constants import (
    ALERT_DESCRIPTIONS,
    HELLO_RETRY_REQUEST_RANDOM,
    SSL2_MSG_SERVER_HELLO,
    ExtensionType,
    ProtocolVersion,
)
from cipheraudit.wire.extensions import parse_alpn_selected, parse_extensions
from cipheraudit.wire.records import Reader, WireFormatError


@dataclass(frozen=True)
class Alert:
    level: int
    description: int

    @property
    def name(self) -> str:
        return ALERT_DESCRIPTIONS.get(self.description, f"alert_{self.description}")


def parse_alert(payload: bytes) -> Alert:
    if len(payload) < 2:
        raise WireFormatError(f"alert too short: {payload.hex()}")
    return Alert(payload[0], payload[1])


def _negotiated(raw: int) -> ProtocolVersion | None:
    if raw >> 8 == 0x7F:  # TLS 1.3 drafts
        return ProtocolVersion.TLS13
    return ProtocolVersion.from_wire(raw)


@dataclass(frozen=True)
class ServerHello:
    legacy_version: int
    random: bytes
    session_id: bytes
    cipher_suite: int
    compression_method: int
    extensions: dict[int, bytes] = field(default_factory=dict)

    @property
    def is_hello_retry(self) -> bool:
        return self.random == HELLO_RETRY_REQUEST_RANDOM

    @property
    def version_raw(self) -> int:
        sv = self.extensions.get(ExtensionType.SUPPORTED_VERSIONS)
        if sv is not None and len(sv) == 2:
            return int.from_bytes(sv, "big")
        return self.legacy_version

    @property
    def version(self) -> ProtocolVersion | None:
        return _negotiated(self.version_raw)

    @property
    def selected_group(self) -> int | None:
        """Group from key_share (TLS 1.3 ServerHello or HelloRetryRequest)."""
        ks = self.extensions.get(ExtensionType.KEY_SHARE)
        if ks is None or len(ks) < 2:
            return None
        return int.from_bytes(ks[:2], "big")

    @property
    def alpn(self) -> str | None:
        data = self.extensions.get(ExtensionType.ALPN)
        return parse_alpn_selected(data) if data else None

    def has_extension(self, ext_type: int) -> bool:
        return ext_type in self.extensions


def parse_server_hello(body: bytes) -> ServerHello:
    reader = Reader(body)
    legacy_version = reader.u16()
    random = reader.take(32)
    session_id = reader.vec8()
    cipher_suite = reader.u16()
    compression = reader.u8()
    extensions = parse_extensions(reader.vec16()) if reader.remaining >= 2 else {}
    return ServerHello(legacy_version, random, session_id, cipher_suite, compression, extensions)


def parse_certificate(body: bytes, tls13: bool = False) -> list[bytes]:
    """Return DER certificates in the order the server sent them."""
    reader = Reader(body)
    if tls13:
        reader.vec8()  # certificate_request_context
    certs_reader = Reader(reader.vec24())
    certs: list[bytes] = []
    while certs_reader.remaining:
        certs.append(certs_reader.vec24())
        if tls13:
            certs_reader.vec16()  # per-certificate extensions
    return certs


@dataclass(frozen=True)
class DHParams:
    prime: bytes
    generator: bytes
    public: bytes

    @property
    def prime_bits(self) -> int:
        return int.from_bytes(self.prime, "big").bit_length()


def parse_dhe_params(body: bytes) -> DHParams:
    reader = Reader(body)
    return DHParams(reader.vec16(), reader.vec16(), reader.vec16())


def parse_ecdhe_named_curve(body: bytes) -> int | None:
    """Named group from an ECDHE ServerKeyExchange; None for explicit curves."""
    reader = Reader(body)
    curve_type = reader.u8()
    if curve_type != 3:  # named_curve
        return None
    return reader.u16()


def parse_certificate_status(body: bytes) -> bytes:
    reader = Reader(body)
    reader.u8()  # status_type (1 = ocsp)
    return reader.vec24()


@dataclass(frozen=True)
class SSLv2ServerHello:
    version: int
    certificate: bytes
    cipher_specs: list[int]


def parse_sslv2_server_hello(data: bytes) -> SSLv2ServerHello:
    if len(data) < 2:
        raise WireFormatError("SSLv2 reply too short")
    if data[0] & 0x80:
        length = ((data[0] & 0x7F) << 8) | data[1]
        reader = Reader(data[2:2 + length])
    else:
        length = ((data[0] & 0x3F) << 8) | data[1]
        reader = Reader(data[3:3 + length])
    if reader.u8() != SSL2_MSG_SERVER_HELLO:
        raise WireFormatError("not an SSLv2 SERVER-HELLO")
    reader.u8()  # session_id_hit
    reader.u8()  # certificate_type
    version = reader.u16()
    cert_len, specs_len, conn_id_len = reader.u16(), reader.u16(), reader.u16()
    certificate = reader.take(cert_len)
    specs_raw = reader.take(specs_len)
    reader.take(conn_id_len)
    specs = [int.from_bytes(specs_raw[i:i + 3], "big") for i in range(0, len(specs_raw) - 2, 3)]
    return SSLv2ServerHello(version, certificate, specs)
