"""TLS compression check for CRIME (PRD VU-4): offer DEFLATE and see whether the server selects it."""

from __future__ import annotations

from cipheraudit.core.protocols import hello_for
from cipheraudit.models.results import VulnResult
from cipheraudit.wire.client_hello import HelloParams
from cipheraudit.wire.constants import COMPRESSION_DEFLATE, COMPRESSION_NULL, ProtocolVersion
from cipheraudit.wire.handshake import Accepted, Closed, ConnFactory, Rejected, probe

LEGACY_ORDER = [ProtocolVersion.SSL3, ProtocolVersion.TLS10, ProtocolVersion.TLS11, ProtocolVersion.TLS12]


def check_compression(conn: ConnFactory, sni: str | None, offered: list[ProtocolVersion]) -> VulnResult:
    legacy = [v for v in LEGACY_ORDER if v in offered]
    if not legacy:
        return VulnResult(id="crime", status="not_vulnerable", evidence="TLS 1.3 forbids compression; no older version")
    version = legacy[-1]
    base = hello_for(version, sni)
    params = HelloParams(version=version, cipher_suites=base.cipher_suites, sni=sni,
                         compression_methods=[COMPRESSION_DEFLATE, COMPRESSION_NULL])
    outcome = probe(conn, params)
    if isinstance(outcome, Accepted):
        if outcome.server_hello.compression_method == COMPRESSION_DEFLATE:
            return VulnResult(id="crime", status="vulnerable", evidence=f"server selected DEFLATE on {version.value}")
        evidence = f"server selected no compression on {version.value}"
        return VulnResult(id="crime", status="not_vulnerable", evidence=evidence)
    if isinstance(outcome, Rejected | Closed):
        return VulnResult(id="crime", status="inconclusive", evidence="server refused a hello offering compression")
    return VulnResult(id="crime", status="inconclusive", evidence=type(outcome).__name__)
