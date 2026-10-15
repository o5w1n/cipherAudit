"""ClientHello extension encoders and ServerHello extension decoders."""

from __future__ import annotations

import os
from dataclasses import dataclass

from cipheraudit.wire.constants import ExtensionType, ProtocolVersion
from cipheraudit.wire.records import Reader, u8, u16, vec8, vec16


@dataclass(frozen=True)
class Extension:
    ext_type: int
    data: bytes

    def encode(self) -> bytes:
        return u16(self.ext_type) + vec16(self.data)


def server_name(host: str) -> Extension:
    name = host.encode("idna")
    entry = u8(0) + vec16(name)
    return Extension(ExtensionType.SERVER_NAME, vec16(entry))


def supported_groups(groups: list[int]) -> Extension:
    return Extension(ExtensionType.SUPPORTED_GROUPS, vec16(b"".join(u16(g) for g in groups)))


def ec_point_formats() -> Extension:
    # uncompressed, ansiX962_compressed_prime, ansiX962_compressed_char2
    return Extension(ExtensionType.EC_POINT_FORMATS, vec8(b"\x00\x01\x02"))


def signature_algorithms(algs: list[int]) -> Extension:
    return Extension(ExtensionType.SIGNATURE_ALGORITHMS, vec16(b"".join(u16(a) for a in algs)))


def supported_versions(versions: list[ProtocolVersion]) -> Extension:
    return Extension(ExtensionType.SUPPORTED_VERSIONS, vec8(b"".join(u16(v.wire) for v in versions)))


def key_share(shares: list[tuple[int, bytes]]) -> Extension:
    entries = b"".join(u16(group) + vec16(key) for group, key in shares)
    return Extension(ExtensionType.KEY_SHARE, vec16(entries))


# Public key lengths for groups we can send a share for without owning a private key.
# We never complete the handshake, so random bytes of the right length are sufficient.
KEY_SHARE_LENGTHS = {0x001D: 32, 0x001E: 56}


def random_key_share(group: int) -> tuple[int, bytes]:
    return group, os.urandom(KEY_SHARE_LENGTHS[group])


def psk_key_exchange_modes() -> Extension:
    return Extension(ExtensionType.PSK_KEY_EXCHANGE_MODES, vec8(b"\x01"))  # psk_dhe_ke


def alpn(protocols: list[str]) -> Extension:
    names = b"".join(vec8(p.encode("ascii")) for p in protocols)
    return Extension(ExtensionType.ALPN, vec16(names))


def status_request() -> Extension:
    # status_type ocsp(1), empty responder_id_list, empty request_extensions
    return Extension(ExtensionType.STATUS_REQUEST, b"\x01\x00\x00\x00\x00")


def heartbeat() -> Extension:
    return Extension(ExtensionType.HEARTBEAT, b"\x01")  # peer_allowed_to_send


def renegotiation_info() -> Extension:
    return Extension(ExtensionType.RENEGOTIATION_INFO, b"\x00")


def session_ticket() -> Extension:
    return Extension(ExtensionType.SESSION_TICKET, b"")


def extended_master_secret() -> Extension:
    return Extension(ExtensionType.EXTENDED_MASTER_SECRET, b"")


def signed_certificate_timestamp() -> Extension:
    return Extension(ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP, b"")


def padding(length: int) -> Extension:
    return Extension(ExtensionType.PADDING, b"\x00" * length)


def parse_extensions(data: bytes) -> dict[int, bytes]:
    """Parse a server extension block (without its outer length) into {type: data}."""
    reader = Reader(data)
    result: dict[int, bytes] = {}
    while reader.remaining:
        ext_type = reader.u16()
        result[ext_type] = reader.vec16()
    return result


def parse_alpn_selected(data: bytes) -> str:
    names = Reader(Reader(data).vec16())
    return names.vec8().decode("ascii", errors="replace")
