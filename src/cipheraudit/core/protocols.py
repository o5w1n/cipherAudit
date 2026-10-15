"""Core 1 - protocol probing (PRD PR-1..PR-5). One raw probe per protocol version."""

from __future__ import annotations

import ssl

from cipheraudit.data import cipher_suites, sslv2_ciphers, suites_for
from cipheraudit.models.results import ProtocolResult
from cipheraudit.net.connection import ConnectError
from cipheraudit.wire.client_hello import HelloParams
from cipheraudit.wire.constants import RECORD_VERSIONS, ProtocolVersion
from cipheraudit.wire.handshake import (
    Accepted,
    Closed,
    ConnFactory,
    HelloRetry,
    ProbeOutcome,
    Rejected,
    SSLv2Accepted,
    probe,
    probe_sslv2,
)

# Servers that cap ClientHello size reject more than this many suites.
MAX_SUITES_PER_HELLO = 127
ALPN_OFFER = ["h2", "http/1.1"]


def hello_for(version: ProtocolVersion, sni: str | None, alpn: list[str] | None = None) -> HelloParams:
    """A broad ClientHello for `version`: the strongest suites valid for it, capped at 127."""
    suites = [s.code for s in suites_for(version)][:MAX_SUITES_PER_HELLO]
    return HelloParams(version=version, cipher_suites=suites, sni=sni, alpn=alpn)


def _classify(version: ProtocolVersion, outcome: ProbeOutcome, result: ProtocolResult) -> bool | None:
    if isinstance(outcome, Accepted):
        answered = outcome.server_hello.version
        if answered == version:
            return True
        label = answered.value if answered else f"0x{outcome.server_hello.version_raw:04X}"
        result.downgrades[version] = label
        if answered is not None and answered.wire > version.wire:
            result.notes.append(f"{version.value} probe answered with higher version {label}")
        return False
    if isinstance(outcome, HelloRetry):
        return version == ProtocolVersion.TLS13 and outcome.hrr.version == ProtocolVersion.TLS13
    if isinstance(outcome, Rejected | Closed):
        return False
    result.notes.append(f"{version.value}: inconclusive ({type(outcome).__name__})")
    return None


def _probe_sslv2(conn: ConnFactory, result: ProtocolResult) -> bool | None:
    outcome = probe_sslv2(conn, list(sslv2_ciphers()))
    if isinstance(outcome, SSLv2Accepted):
        result.sslv2_cipher_count = len(outcome.server_hello.cipher_specs)
        if not outcome.server_hello.cipher_specs:
            result.notes.append("SSLv2 handshake accepted with no ciphers (CVE-2015-3197 behaviour)")
        return True
    if isinstance(outcome, Rejected | Closed):
        return False
    # A server that does not speak SSLv2 often answers with garbage or waits; that is not SSLv2 support.
    result.notes.append(f"SSLv2: no SSLv2 reply ({type(outcome).__name__})")
    return False


def probe_protocols(conn: ConnFactory, sni: str | None) -> ProtocolResult:
    result = ProtocolResult(supported={})
    result.supported[ProtocolVersion.SSL2] = _probe_sslv2(conn, result)

    for version in RECORD_VERSIONS:
        result.supported[version] = _classify(version, probe(conn, hello_for(version, sni)), result)

    tls13_suites = [s.code for s in cipher_suites().values() if s.protocols == (ProtocolVersion.TLS13,)]
    tls13 = HelloParams(version=ProtocolVersion.TLS13, cipher_suites=tls13_suites, sni=sni)
    result.supported[ProtocolVersion.TLS13] = _classify(ProtocolVersion.TLS13, probe(conn, tls13), result)

    _probe_alpn(conn, sni, result)
    return result


def _probe_alpn(conn: ConnFactory, sni: str | None, result: ProtocolResult) -> None:
    """ALPN is in the plaintext ServerHello only up to TLS 1.2; TLS 1.3 encrypts it (EncryptedExtensions)."""
    legacy = [ProtocolVersion.TLS12, ProtocolVersion.TLS11, ProtocolVersion.TLS10]
    best = next((v for v in legacy if result.supported.get(v)), None)
    if best is not None:
        result.alpn_offered = list(ALPN_OFFER)
        outcome = probe(conn, hello_for(best, sni, alpn=ALPN_OFFER))
        if isinstance(outcome, Accepted):
            result.alpn_selected = outcome.server_hello.alpn
    elif result.supported.get(ProtocolVersion.TLS13):
        result.alpn_offered = list(ALPN_OFFER)
        result.alpn_selected = _alpn_via_ssl(conn, sni)


def _alpn_via_ssl(conn: ConnFactory, sni: str | None) -> str | None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(ALPN_OFFER)
    try:
        with ctx.wrap_socket(conn(), server_hostname=sni) as tls:
            return tls.selected_alpn_protocol()
    except (OSError, ConnectError):
        return None
