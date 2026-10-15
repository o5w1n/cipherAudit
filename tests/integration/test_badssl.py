"""Integration tests against badssl.com's deliberately weak endpoints (hostnames checked 2026-10-15).

Run: pytest -m network tests/integration/test_badssl.py
"""

from __future__ import annotations

from datetime import UTC, datetime
from functools import cache

import pytest

from cipheraudit.config import ScanOptions
from cipheraudit.models.findings import Authorization, Report
from cipheraudit.orchestrator import NoTLS, TargetUnreachable, build_report, run_scan

pytestmark = pytest.mark.network

AUTH = Authorization(method="flag", confirmed_at=datetime.now(UTC).isoformat())


@cache
def _report(host: str, port: int = 443, cert_only: bool = False) -> Report:
    options = ScanOptions(host=host, port=port, timeout=10, run_ciphers=not cert_only, run_vulns=not cert_only)
    try:
        return build_report(run_scan(options), AUTH)
    except (TargetUnreachable, NoTLS) as exc:
        pytest.skip(f"{host}:{port} unavailable: {exc}")


def _ids(report: Report) -> set[str]:
    return {f.id for f in report.findings}


@pytest.mark.parametrize(("host", "expected", "absent"), [
    ("expired.badssl.com", "CERT_EXPIRED", {"CERT_HOSTNAME_MISMATCH"}),
    ("self-signed.badssl.com", "CERT_UNTRUSTED", {"CERT_HOSTNAME_MISMATCH"}),
    ("untrusted-root.badssl.com", "CERT_UNTRUSTED", {"CERT_HOSTNAME_MISMATCH"}),
    # Same trusted chain as badssl.com: a name mismatch must not be reported as a chain problem too.
    ("wrong.host.badssl.com", "CERT_HOSTNAME_MISMATCH", {"CERT_INCOMPLETE_CHAIN", "CERT_UNTRUSTED"}),
])
def test_certificate_problems(host: str, expected: str, absent: set[str]) -> None:
    ids = _ids(_report(host, cert_only=True))
    assert expected in ids
    assert not ids & absent


def test_valid_certificate_has_no_trust_findings() -> None:
    ids = _ids(_report("badssl.com", cert_only=True))
    assert not ids & {"CERT_EXPIRED", "CERT_UNTRUSTED", "CERT_INCOMPLETE_CHAIN", "CERT_HOSTNAME_MISMATCH"}


@pytest.mark.parametrize(("host", "expected"), [
    ("3des.badssl.com", {"CIPHER_3DES", "VULN_SWEET32"}),
    ("rc4.badssl.com", {"CIPHER_RC4", "VULN_RC4"}),
    ("dh1024.badssl.com", {"DH_WEAK"}),
])
def test_weak_cipher_configs(host: str, expected: set[str]) -> None:
    report = _report(host)
    assert expected <= _ids(report)
    assert report.grade in {"E", "F"}


@pytest.mark.parametrize(("port", "version", "finding"), [
    (1010, "TLS1.0", "PROTO_TLS10_ENABLED"),
    (1011, "TLS1.1", "PROTO_TLS11_ENABLED"),
])
def test_legacy_protocol_only(port: int, version: str, finding: str) -> None:
    report = _report(f"tls-v1-{version[-1]}.badssl.com", port)
    assert report.scan.protocols is not None
    assert [v.value for v in report.scan.protocols.offered()] == [version]
    assert {finding, "PROTO_NO_MODERN_TLS"} <= _ids(report)
