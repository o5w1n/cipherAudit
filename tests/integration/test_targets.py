"""Integration tests against the local Docker targets (tests/targets/docker-compose.yml).

Run: docker compose -f tests/targets/docker-compose.yml up -d --build
     docker cp targets-modern-1:/etc/nginx/certs/ca.pem tests/targets/certs/modern-ca.pem
     pytest -m network
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cipheraudit.config import ScanOptions
from cipheraudit.models.findings import Authorization
from cipheraudit.models.results import ScanResult
from cipheraudit.orchestrator import build_report, run_scan
from cipheraudit.wire.constants import ProtocolVersion as P

pytestmark = pytest.mark.network

MODERN, TLS13_ONLY, PQ = 8443, 8445, 8446
MODERN_CA = Path(__file__).resolve().parent.parent / "targets" / "certs" / "modern-ca.pem"
AUTH = Authorization(method="flag", confirmed_at=datetime.now(UTC).isoformat())


def _up(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def _scan(port: int, extra_ca: Path | None = None) -> ScanResult:
    if not _up(port):
        pytest.skip(f"target on port {port} is not running")
    return run_scan(ScanOptions(host="localhost", port=port, rate=20, timeout=3, extra_ca=extra_ca))


def test_modern_target_grades_a_with_test_ca() -> None:
    if not MODERN_CA.exists():
        pytest.skip("copy the modern target's CA to tests/targets/certs/modern-ca.pem first")
    scan = _scan(MODERN, extra_ca=MODERN_CA)
    assert scan.protocols is not None
    assert scan.protocols.offered() == [P.TLS12, P.TLS13]
    report = build_report(scan, AUTH)
    assert report.grade == "A", [f.id for f in report.findings]
    assert scan.errors == []


def test_modern_target_enforces_cipher_order() -> None:
    scan = _scan(MODERN)
    assert scan.ciphers is not None
    tls12 = next(pc for pc in scan.ciphers.per_protocol if pc.protocol == P.TLS12)
    assert tls12.server_order is True
    assert [c.openssl for c in tls12.ciphers] == [
        "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305",
    ]


def test_tls13_only_target_uses_ssl_module_certificate_path() -> None:
    scan = _scan(TLS13_ONLY)
    assert scan.protocols is not None and scan.protocols.offered() == [P.TLS13]
    assert scan.certificate is not None
    assert scan.certificate.chains[0].source == "ssl_module"


def test_pq_target_is_pq_ready() -> None:
    report = build_report(_scan(PQ), AUTH)
    assert report.pq_ready is True
