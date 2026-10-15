"""Derived vulnerability checks (PRD VU-1): pure functions over Core 1-3 facts, no network."""

from __future__ import annotations

from collections.abc import Callable

from cipheraudit.models.results import CipherInfo, CipherResult, ProtocolResult, VulnResult
from cipheraudit.wire.constants import ProtocolVersion

LEGACY_TLS = (ProtocolVersion.SSL3, ProtocolVersion.TLS10, ProtocolVersion.TLS11, ProtocolVersion.TLS12)


def _ciphers_known(ciphers: CipherResult | None, protocols: tuple[ProtocolVersion, ...]) -> bool:
    if ciphers is None:
        return False
    relevant = [pc for pc in ciphers.per_protocol if pc.protocol in protocols]
    return all(pc.complete for pc in relevant)


def _matching(ciphers: CipherResult, protocols: tuple[ProtocolVersion, ...],
              predicate: Callable[[CipherInfo], bool]) -> list[str]:
    hits: list[str] = []
    for pc in ciphers.per_protocol:
        if pc.protocol in protocols:
            hits.extend(f"{c.iana} ({pc.protocol.value})" for c in pc.ciphers if predicate(c))
    return hits


def _cipher_check(vuln_id: str, protocols: ProtocolResult, ciphers: CipherResult | None,
                  versions: tuple[ProtocolVersion, ...], predicate: Callable[[CipherInfo], bool],
                  condition: str) -> VulnResult:
    if not any(protocols.supported.get(v) for v in versions):
        if any(protocols.supported.get(v) is None for v in versions):
            return VulnResult(id=vuln_id, status="inconclusive", evidence="protocol support inconclusive")
        return VulnResult(id=vuln_id, status="not_vulnerable", evidence="affected protocol versions not offered")
    if ciphers is None:
        return VulnResult(id=vuln_id, status="inconclusive", evidence="cipher enumeration did not run")
    hits = _matching(ciphers, versions, predicate)
    if hits:
        return VulnResult(id=vuln_id, status="vulnerable", evidence=f"{condition}: " + ", ".join(hits[:6]))
    if not _ciphers_known(ciphers, versions):
        return VulnResult(id=vuln_id, status="inconclusive", evidence="cipher enumeration incomplete")
    return VulnResult(id=vuln_id, status="not_vulnerable", evidence=f"no {condition}")


def drown(protocols: ProtocolResult) -> VulnResult:
    sslv2 = protocols.supported.get(ProtocolVersion.SSL2)
    if sslv2 is None:
        return VulnResult(id="drown", status="inconclusive", evidence="SSLv2 support inconclusive")
    if sslv2:
        return VulnResult(id="drown", status="vulnerable", evidence="SSLv2 offered on this endpoint")
    return VulnResult(id="drown", status="not_vulnerable",
                      evidence="SSLv2 not offered here (other servers sharing the key are not checked)")


def _is_cbc(c: CipherInfo) -> bool:
    return c.mode == "CBC"


def derived_checks(protocols: ProtocolResult, ciphers: CipherResult | None) -> list[VulnResult]:
    dh_bits = ciphers.dh_prime_bits if ciphers else None
    logjam = _cipher_check(
        "logjam", protocols, ciphers, LEGACY_TLS, lambda c: c.kx in ("DHE_EXPORT", "DH_EXPORT"),
        "DH export suites accepted",
    )
    if logjam.status != "vulnerable" and dh_bits is not None and dh_bits < 1024:
        logjam = VulnResult(id="logjam", status="vulnerable", evidence=f"DH prime is {dh_bits} bits")
    return [
        drown(protocols),
        _cipher_check("poodle_ssl", protocols, ciphers, (ProtocolVersion.SSL3,), _is_cbc,
                      "CBC suites accepted on SSLv3"),
        _cipher_check("beast", protocols, ciphers, (ProtocolVersion.SSL3, ProtocolVersion.TLS10), _is_cbc,
                      "CBC suites accepted on SSLv3/TLS 1.0"),
        _cipher_check("sweet32", protocols, ciphers, LEGACY_TLS, lambda c: c.block_bits == 64,
                      "64-bit block cipher suites accepted"),
        _cipher_check("rc4", protocols, ciphers, LEGACY_TLS, lambda c: c.enc == "RC4", "RC4 suites accepted"),
        _cipher_check("freak", protocols, ciphers, LEGACY_TLS, lambda c: c.kx == "RSA_EXPORT",
                      "RSA export suites accepted"),
        logjam,
        _cipher_check("lucky13", protocols, ciphers, LEGACY_TLS, lambda c: c.mode == "CBC" and c.mac != "AEAD",
                      "CBC-mode suites with HMAC accepted"),
    ]
