import socket
from typing import cast

from cipheraudit.wire.client_hello import HelloParams, build_client_hello, build_sslv2_client_hello
from cipheraudit.wire.constants import (
    HELLO_RETRY_REQUEST_RANDOM,
    ContentType,
    ExtensionType,
    HandshakeType,
    ProtocolVersion,
)
from cipheraudit.wire.extensions import parse_extensions
from cipheraudit.wire.handshake import Accepted, HelloRetry, ProbeOutcome, ProtocolError, ReadUntil, Rejected, exchange
from cipheraudit.wire.records import HandshakeBuffer, Reader, encode_handshake, encode_record, split_records, vec16
from cipheraudit.wire.server_msgs import parse_dhe_params, parse_ecdhe_named_curve, parse_sslv2_server_hello


def _parse_hello(record: bytes) -> tuple[int, Reader]:
    records, tail = split_records(record)
    assert tail == b"" and len(records) == 1
    msg = HandshakeBuffer().feed(records[0].payload)[0]
    assert msg.msg_type == HandshakeType.CLIENT_HELLO
    return records[0].version, Reader(msg.body)


def _hello_fields(record: bytes) -> dict[str, object]:
    record_version, r = _parse_hello(record)
    legacy = r.u16()
    r.take(32)
    session_id = r.vec8()
    suites_raw = r.vec16()
    compression = r.vec8()
    exts = parse_extensions(r.vec16()) if r.remaining else {}
    suites = [int.from_bytes(suites_raw[i:i + 2], "big") for i in range(0, len(suites_raw), 2)]
    return {"record_version": record_version, "legacy": legacy, "session_id": session_id, "suites": suites,
            "compression": compression, "exts": exts}


def test_tls12_hello_layout() -> None:
    f = _hello_fields(build_client_hello(HelloParams(ProtocolVersion.TLS12, [0xC02F, 0x009C], sni="example.com")))
    assert f["record_version"] == 0x0301
    assert f["legacy"] == 0x0303
    assert f["suites"] == [0xC02F, 0x009C, 0x00FF]  # renegotiation SCSV appended
    assert f["compression"] == b"\x00"
    exts = f["exts"]
    assert isinstance(exts, dict)
    assert b"example.com" in exts[ExtensionType.SERVER_NAME]
    assert ExtensionType.SIGNATURE_ALGORITHMS in exts
    assert ExtensionType.SUPPORTED_VERSIONS not in exts


def test_tls13_hello_uses_supported_versions_and_key_share() -> None:
    f = _hello_fields(build_client_hello(HelloParams(ProtocolVersion.TLS13, [0x1301])))
    assert f["legacy"] == 0x0303
    session_id = f["session_id"]
    assert isinstance(session_id, bytes) and len(session_id) == 32
    exts = f["exts"]
    assert isinstance(exts, dict)
    assert exts[ExtensionType.SUPPORTED_VERSIONS] == b"\x02\x03\x04"
    key_share = Reader(exts[ExtensionType.KEY_SHARE])
    entries = Reader(key_share.vec16())
    assert entries.u16() == 0x001D and len(entries.vec16()) == 32
    suites = f["suites"]
    assert isinstance(suites, list) and 0x00FF not in suites


def test_sslv3_hello_has_no_extensions() -> None:
    f = _hello_fields(build_client_hello(HelloParams(ProtocolVersion.SSL3, [0x000A])))
    assert f["record_version"] == 0x0300
    assert f["exts"] == {}


def test_hello_padded_out_of_f5_range() -> None:
    record = build_client_hello(HelloParams(ProtocolVersion.TLS12, list(range(0x0001, 0x0060))))
    handshake_len = len(record) - 5
    assert not 256 <= handshake_len < 512


def test_empty_key_share_for_group_probing() -> None:
    f = _hello_fields(build_client_hello(HelloParams(ProtocolVersion.TLS13, [0x1301], key_shares=[])))
    exts = f["exts"]
    assert isinstance(exts, dict)
    assert exts[ExtensionType.KEY_SHARE] == b"\x00\x00"


def test_sslv2_client_hello_format() -> None:
    data = build_sslv2_client_hello([0x0700C0, 0x010080])
    assert data[0] & 0x80
    assert ((data[0] & 0x7F) << 8 | data[1]) == len(data) - 2
    assert data[2] == 1 and data[3:5] == b"\x00\x02"


def _server_hello(version: int = 0x0303, suite: int = 0xC02F, random: bytes = b"\x11" * 32,
                  exts: bytes = b"") -> bytes:
    body = version.to_bytes(2, "big") + random + b"\x00" + suite.to_bytes(2, "big") + b"\x00"
    if exts:
        body += vec16(exts)
    return encode_handshake(HandshakeType.SERVER_HELLO, body)


class FakeSocket:
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = list(chunks)
        self.sent = b""

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, _n: int) -> bytes:
        return self.chunks.pop(0) if self.chunks else b""


def run(*chunks: bytes, read_until: ReadUntil = ReadUntil.SERVER_HELLO) -> ProbeOutcome:
    return exchange(cast(socket.socket, FakeSocket(*chunks)), b"hello", read_until)


def test_exchange_accepts_server_hello_split_across_reads() -> None:
    record = encode_record(ContentType.HANDSHAKE, 0x0303, _server_hello())
    outcome = run(record[:3], record[3:20], record[20:])
    assert isinstance(outcome, Accepted)
    assert outcome.server_hello.cipher_suite == 0xC02F
    assert outcome.server_hello.version == ProtocolVersion.TLS12


def test_exchange_reads_until_hello_done_across_records() -> None:
    certs = vec16(b"")  # placeholder body; parsed lazily
    msgs = _server_hello() + encode_handshake(HandshakeType.CERTIFICATE, b"\x00" + certs)
    done = encode_handshake(HandshakeType.SERVER_HELLO_DONE, b"")
    outcome = run(encode_record(22, 0x0303, msgs), encode_record(22, 0x0303, done), read_until=ReadUntil.HELLO_DONE)
    assert isinstance(outcome, Accepted) and outcome.complete
    assert [m.msg_type for m in outcome.messages] == [2, 11, 14]


def test_exchange_alert_is_rejected() -> None:
    outcome = run(encode_record(ContentType.ALERT, 0x0303, b"\x02\x28"))
    assert isinstance(outcome, Rejected) and outcome.alert.name == "handshake_failure"


def test_exchange_hello_retry() -> None:
    exts = (ExtensionType.SUPPORTED_VERSIONS.to_bytes(2, "big") + vec16(b"\x03\x04")
            + ExtensionType.KEY_SHARE.to_bytes(2, "big") + vec16(b"\x11\xec"))
    hrr = _server_hello(suite=0x1301, random=HELLO_RETRY_REQUEST_RANDOM, exts=exts)
    outcome = run(encode_record(22, 0x0303, hrr))
    assert isinstance(outcome, HelloRetry)
    assert outcome.hrr.selected_group == 0x11EC and outcome.hrr.version == ProtocolVersion.TLS13


def test_exchange_non_tls_reply_is_protocol_error() -> None:
    outcome = run(b"HTTP/1.1 400 Bad Request\r\n")
    assert isinstance(outcome, ProtocolError)


def test_tls13_version_from_supported_versions() -> None:
    exts = ExtensionType.SUPPORTED_VERSIONS.to_bytes(2, "big") + vec16(b"\x03\x04")
    record = encode_record(22, 0x0303, _server_hello(suite=0x1301, exts=exts))
    outcome = run(record)
    assert isinstance(outcome, Accepted) and outcome.server_hello.version == ProtocolVersion.TLS13


def test_parse_server_key_exchange() -> None:
    assert parse_ecdhe_named_curve(b"\x03\x00\x1d\x20" + b"\x00" * 32) == 0x001D
    prime = (2**1023 + 1).to_bytes(128, "big")
    dh = parse_dhe_params(vec16(prime) + vec16(b"\x02") + vec16(b"\x05"))
    assert dh.prime_bits == 1024


def test_parse_sslv2_server_hello() -> None:
    cert = b"\x30\x00"
    specs = b"\x07\x00\xc0\x01\x00\x80"
    body = b"\x04\x00\x01\x00\x02" + len(cert).to_bytes(2, "big") + len(specs).to_bytes(2, "big") + b"\x00\x10"
    body += cert + specs + b"\xaa" * 16
    hello = parse_sslv2_server_hello((0x8000 | len(body)).to_bytes(2, "big") + body)
    assert hello.cipher_specs == [0x0700C0, 0x010080]
