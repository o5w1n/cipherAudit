"""TLS protocol constants (RFC 5246, RFC 8446, IANA TLS parameters)."""

from __future__ import annotations

from enum import IntEnum, StrEnum


class ProtocolVersion(StrEnum):
    SSL2 = "SSLv2"
    SSL3 = "SSLv3"
    TLS10 = "TLS1.0"
    TLS11 = "TLS1.1"
    TLS12 = "TLS1.2"
    TLS13 = "TLS1.3"

    @property
    def wire(self) -> int:
        return _WIRE[self]

    @classmethod
    def from_wire(cls, value: int) -> ProtocolVersion | None:
        return _FROM_WIRE.get(value)


_WIRE = {
    ProtocolVersion.SSL2: 0x0002,
    ProtocolVersion.SSL3: 0x0300,
    ProtocolVersion.TLS10: 0x0301,
    ProtocolVersion.TLS11: 0x0302,
    ProtocolVersion.TLS12: 0x0303,
    ProtocolVersion.TLS13: 0x0304,
}
_FROM_WIRE = {v: k for k, v in _WIRE.items()}

ALL_VERSIONS = list(ProtocolVersion)
RECORD_VERSIONS = [ProtocolVersion.SSL3, ProtocolVersion.TLS10, ProtocolVersion.TLS11, ProtocolVersion.TLS12]


class ContentType(IntEnum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    HEARTBEAT = 24


class HandshakeType(IntEnum):
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    CERTIFICATE_STATUS = 22


class ExtensionType(IntEnum):
    SERVER_NAME = 0
    STATUS_REQUEST = 5
    SUPPORTED_GROUPS = 10
    EC_POINT_FORMATS = 11
    SIGNATURE_ALGORITHMS = 13
    HEARTBEAT = 15
    ALPN = 16
    SIGNED_CERTIFICATE_TIMESTAMP = 18
    PADDING = 21
    ENCRYPT_THEN_MAC = 22
    EXTENDED_MASTER_SECRET = 23
    SESSION_TICKET = 35
    SUPPORTED_VERSIONS = 43
    COOKIE = 44
    PSK_KEY_EXCHANGE_MODES = 45
    KEY_SHARE = 51
    RENEGOTIATION_INFO = 0xFF01


class AlertLevel(IntEnum):
    WARNING = 1
    FATAL = 2


ALERT_DESCRIPTIONS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    21: "decryption_failed",
    22: "record_overflow",
    30: "decompression_failure",
    40: "handshake_failure",
    41: "no_certificate",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    60: "export_restriction",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_canceled",
    100: "no_renegotiation",
    109: "missing_extension",
    110: "unsupported_extension",
    112: "unrecognized_name",
    113: "bad_certificate_status_response",
    115: "unknown_psk_identity",
    116: "certificate_required",
    120: "no_application_protocol",
}

# SHA-256 of "HelloRetryRequest" (RFC 8446 §4.1.3)
HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
)

TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF
TLS_FALLBACK_SCSV = 0x5600

COMPRESSION_NULL = 0
COMPRESSION_DEFLATE = 1

GROUP_X25519 = 0x001D
GROUP_SECP256R1 = 0x0017
GROUP_SECP384R1 = 0x0018
GROUP_SECP521R1 = 0x0019
GROUP_X448 = 0x001E

DEFAULT_GROUPS = [
    GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1, GROUP_SECP521R1, GROUP_X448,
    0x0100, 0x0101, 0x0102, 0x0103, 0x0104,  # ffdhe2048..8192
    0x0016, 0x0015, 0x0014, 0x0013, 0x0012, 0x0011, 0x0010, 0x000F, 0x000E,  # legacy NIST/SECG curves
    0x000D, 0x000C, 0x000B, 0x000A, 0x0009, 0x0008, 0x0007, 0x0006, 0x0005, 0x0004, 0x0003, 0x0002, 0x0001,
    0x001A, 0x001B, 0x001C,  # brainpool
]

DEFAULT_SIGNATURE_ALGORITHMS = [
    0x0403, 0x0503, 0x0603,  # ecdsa_secp{256,384,521}r1 + sha{256,384,512}
    0x0807, 0x0808,  # ed25519, ed448
    0x0804, 0x0805, 0x0806,  # rsa_pss_rsae
    0x0809, 0x080A, 0x080B,  # rsa_pss_pss
    0x0401, 0x0501, 0x0601,  # rsa_pkcs1
    0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602, 0x0203, 0x0201, 0x0202,  # sha224 / sha1 / dsa
    0x0904, 0x0905, 0x0906,  # ML-DSA
]

SSL2_MSG_CLIENT_HELLO = 1
SSL2_MSG_ERROR = 0
SSL2_MSG_SERVER_HELLO = 4
