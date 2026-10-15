"""Hand-built ScanResult fixtures for rules and scoring tests (no network)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cipheraudit.core.ciphers import cipher_info
from cipheraudit.data import cipher_suites
from cipheraudit.models.results import (
    CertificateChainResult,
    CertificateInfo,
    CertificateResult,
    CipherResult,
    GroupResult,
    HstsInfo,
    HttpHeadersResult,
    ProtocolCiphers,
    ProtocolResult,
    ScanResult,
    ScanTarget,
    ServerConfigResult,
    TrustResult,
)
from cipheraudit.wire.constants import ProtocolVersion as P

NOW = datetime(2026, 10, 15, tzinfo=UTC)


def protocols(*offered: P) -> ProtocolResult:
    return ProtocolResult(supported={v: v in offered for v in P})


def per_protocol(version: P, codes: list[int], server_order: bool | None = True) -> ProtocolCiphers:
    suites = cipher_suites()
    return ProtocolCiphers(protocol=version, ciphers=[cipher_info(suites[c]) for c in codes],
                           server_order=server_order)


def leaf(days: int = 300, key_type: str = "EC", bits: int = 256, sig_hash: str = "sha256") -> CertificateInfo:
    return CertificateInfo(
        subject="CN=example.com", issuer="CN=Example CA", serial_hex="01", san_dns=["example.com"], san_ip=[],
        key_type=key_type, key_bits=bits, signature_algorithm=f"ecdsa-with-{sig_hash.upper()}",
        signature_hash=sig_hash, not_before=NOW - timedelta(days=30), not_after=NOW + timedelta(days=days),
        days_until_expiry=days, is_self_signed=False, is_ca=False, fingerprint_sha256="00",
    )


def certificate(cert: CertificateInfo | None = None, trust: TrustResult | None = None,
                stapled: bool = True) -> CertificateResult:
    return CertificateResult(chains=[CertificateChainResult(
        source="raw_handshake", key_family="ECDSA", chain=[cert or leaf()],
        trust=trust or TrustResult(trusted=True, hostname_match=True), chain_order_ok=True, ocsp_stapled=stapled,
    )])


def modern_scan() -> ScanResult:
    """A configuration that should score 100: TLS 1.2+1.3, ECDHE+AEAD, PQ group, trusted cert, HSTS."""
    return ScanResult(
        target=ScanTarget(host="example.com", ip="192.0.2.1", sni="example.com"),
        started_at=NOW, finished_at=NOW,
        protocols=protocols(P.TLS12, P.TLS13),
        ciphers=CipherResult(
            per_protocol=[per_protocol(P.TLS12, [0xC02B, 0xC02C]), per_protocol(P.TLS13, [0x1301, 0x1302])],
            groups=[GroupResult(protocol=P.TLS13, groups=[0x11EC, 0x001D], names=["X25519MLKEM768", "x25519"])],
        ),
        certificate=certificate(),
        server_config=ServerConfigResult(
            secure_renegotiation=True, extended_master_secret=True, fallback_scsv=True,
            http=HttpHeadersResult(url="https://example.com/", status=200,
                                   hsts=HstsInfo(present=True, max_age=31536000, include_subdomains=True),
                                   x_content_type_options="nosniff", x_frame_options="DENY",
                                   content_security_policy=True),
        ),
    )
