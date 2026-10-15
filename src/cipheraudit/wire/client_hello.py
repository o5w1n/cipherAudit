"""Build TLS ClientHello messages (SSLv3 - TLS 1.3) and the SSLv2 CLIENT-HELLO."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from cipheraudit.wire import extensions as ext
from cipheraudit.wire.constants import (
    DEFAULT_GROUPS,
    DEFAULT_SIGNATURE_ALGORITHMS,
    GROUP_X25519,
    SSL2_MSG_CLIENT_HELLO,
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
    ContentType,
    HandshakeType,
    ProtocolVersion,
)
from cipheraudit.wire.records import encode_handshake, encode_record, u16, u24, vec8, vec16

# Some TLS stacks (notably F5 BIG-IP) hang on ClientHellos of 256-511 bytes (RFC 7685 §1).
_PAD_LOWER, _PAD_UPPER = 256, 512


@dataclass(frozen=True)
class HelloParams:
    version: ProtocolVersion
    cipher_suites: list[int]
    sni: str | None = None
    supported_versions: list[ProtocolVersion] | None = None
    supported_groups: list[int] | None = None
    signature_algorithms: list[int] | None = None
    key_shares: list[int] | None = None
    alpn: list[str] | None = None
    compression_methods: list[int] = field(default_factory=lambda: [0])
    extra_extensions: list[ext.Extension] = field(default_factory=list)
    renegotiation_scsv: bool = True


def _is_tls13(params: HelloParams) -> bool:
    return params.version == ProtocolVersion.TLS13


def _cipher_bytes(params: HelloParams) -> bytes:
    suites = list(params.cipher_suites)
    if params.renegotiation_scsv and not _is_tls13(params) and TLS_EMPTY_RENEGOTIATION_INFO_SCSV not in suites:
        suites.append(TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    return b"".join(u16(s) for s in suites)


def _extensions(params: HelloParams) -> list[ext.Extension]:
    if params.version == ProtocolVersion.SSL3:
        return list(params.extra_extensions)

    groups = params.supported_groups if params.supported_groups is not None else DEFAULT_GROUPS
    sigalgs = (params.signature_algorithms if params.signature_algorithms is not None
               else DEFAULT_SIGNATURE_ALGORITHMS)
    exts: list[ext.Extension] = []
    if params.sni:
        exts.append(ext.server_name(params.sni))
    if groups:
        exts.append(ext.supported_groups(groups))
    exts.append(ext.ec_point_formats())
    if params.version in (ProtocolVersion.TLS12, ProtocolVersion.TLS13) and sigalgs:
        exts.append(ext.signature_algorithms(sigalgs))
    if params.alpn:
        exts.append(ext.alpn(params.alpn))
    exts.append(ext.session_ticket())

    versions = params.supported_versions
    if _is_tls13(params) and versions is None:
        versions = [ProtocolVersion.TLS13]
    if versions:
        exts.append(ext.supported_versions(versions))
    if versions and ProtocolVersion.TLS13 in versions:
        shares = params.key_shares
        if shares is None:
            shares = [GROUP_X25519] if GROUP_X25519 in groups else []
        exts.append(ext.key_share([ext.random_key_share(g) for g in shares]))
        exts.append(ext.psk_key_exchange_modes())
    exts.extend(params.extra_extensions)
    return exts


def build_client_hello_body(params: HelloParams) -> bytes:
    legacy_version = ProtocolVersion.TLS12.wire if _is_tls13(params) else params.version.wire
    session_id = os.urandom(32) if _is_tls13(params) else b""
    head = (
        u16(legacy_version)
        + os.urandom(32)
        + vec8(session_id)
        + vec16(_cipher_bytes(params))
        + vec8(bytes(params.compression_methods))
    )
    exts = _extensions(params)
    if not exts and params.version == ProtocolVersion.SSL3:
        return head

    ext_bytes = b"".join(e.encode() for e in exts)
    hello_len = 4 + len(head) + 2 + len(ext_bytes)
    if _PAD_LOWER <= hello_len < _PAD_UPPER:
        pad_len = max(_PAD_UPPER - hello_len - 4, 0)
        ext_bytes += ext.padding(pad_len).encode()
    return head + vec16(ext_bytes)


def build_client_hello(params: HelloParams) -> bytes:
    """Return the ClientHello wrapped in a TLS record, ready to send."""
    record_version = ProtocolVersion.SSL3.wire if params.version == ProtocolVersion.SSL3 else 0x0301
    handshake = encode_handshake(HandshakeType.CLIENT_HELLO, build_client_hello_body(params))
    return encode_record(ContentType.HANDSHAKE, record_version, handshake)


def build_sslv2_client_hello(cipher_specs: list[int]) -> bytes:
    """SSLv2 CLIENT-HELLO (2-byte record header, high bit set)."""
    specs = b"".join(u24(c) for c in cipher_specs)
    challenge = os.urandom(16)
    body = (
        bytes([SSL2_MSG_CLIENT_HELLO])
        + u16(ProtocolVersion.SSL2.wire)
        + u16(len(specs))
        + u16(0)  # session id length
        + u16(len(challenge))
        + specs
        + challenge
    )
    return u16(0x8000 | len(body)) + body
