"""Runs the cores in order and builds the ScanResult (facts), then the Report (judgments)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from cipheraudit import __version__
from cipheraudit.config import ScanOptions
from cipheraudit.core.certificate import retrieve_certificates
from cipheraudit.core.ciphers import enumerate_ciphers
from cipheraudit.core.protocols import probe_protocols
from cipheraudit.core.server_config import probe_server_config
from cipheraudit.core.vulns import run_vulns
from cipheraudit.evaluation.rules import evaluate, pq_status
from cipheraudit.evaluation.scoring import score
from cipheraudit.models.findings import Authorization, Report
from cipheraudit.models.results import ScanResult, ScanTarget
from cipheraudit.net.connection import ConnectError, Connector, resolve
from cipheraudit.net.ratelimit import RateLimiter

Progress = Callable[[str], None]
STEPS = ["Protocols", "Cipher suites", "Certificate", "Vulnerabilities", "Evaluating"]


class TargetUnreachable(Exception):
    pass


class NoTLS(Exception):
    pass


def run_scan(options: ScanOptions, progress: Progress = lambda _step: None) -> ScanResult:
    try:
        endpoint = resolve(options.host, options.port)
    except ConnectError as exc:
        raise TargetUnreachable(str(exc)) from exc
    limiter = RateLimiter(options.rate)
    conn = Connector(endpoint, limiter, options.timeout, options.timeout)
    try:
        conn().close()  # PR-5: fail early and clearly if the port is not reachable
    except ConnectError as exc:
        raise TargetUnreachable(str(exc)) from exc

    sni = options.server_name
    scan = ScanResult(
        target=ScanTarget(host=options.host, port=options.port, ip=endpoint.ip, sni=sni),
        started_at=datetime.now(UTC), finished_at=datetime.now(UTC),
    )

    progress(STEPS[0])
    scan.protocols = probe_protocols(conn, sni)
    offered = scan.protocols.offered()
    if not offered:
        if any(v is None for v in scan.protocols.supported.values()):
            detail = "; ".join(scan.protocols.notes) or "handshakes were inconclusive"
            raise NoTLS(f"{options.host}:{options.port}: no version confirmed and some probes timed out ({detail}). "
                        "The server may be busy; retry, or raise --timeout.")
        raise NoTLS(f"{options.host}:{options.port} did not complete a TLS or SSL handshake on any version")

    if options.run_ciphers or options.run_vulns:
        progress(STEPS[1])
        scan.ciphers = _guard(scan, "ciphers", lambda: enumerate_ciphers(conn, sni, offered))

    if options.run_cert:
        progress(STEPS[2])
        scan.certificate = _guard(scan, "certificate", lambda: retrieve_certificates(
            conn, sni or options.host, sni, offered, options.extra_ca))
        scan.server_config = _guard(scan, "server_config", lambda: probe_server_config(
            conn, options.host, options.port, sni, offered, options.timeout, limiter.acquire))

    if options.run_vulns:
        progress(STEPS[3])
        protocols = scan.protocols
        vulns = _guard(scan, "vulns", lambda: run_vulns(conn, sni, protocols, scan.ciphers, options.active_vulns))
        scan.vulns = vulns or []

    scan.finished_at = datetime.now(UTC)
    return scan


def _guard[T](scan: ScanResult, core: str, fn: Callable[[], T]) -> T | None:
    """Each core records its own failure; one failing core never aborts the others (TRD §8)."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - recorded in the report, never swallowed silently
        scan.errors.append(f"{core}: {type(exc).__name__}: {exc}")
        return None


def build_report(scan: ScanResult, authorization: Authorization) -> Report:
    findings = evaluate(scan)
    breakdown = score(findings)
    pq_ready, pq_explanation = pq_status(scan)
    return Report(
        tool_version=__version__, authorization=authorization, scan=scan, findings=findings,
        score=breakdown.score, grade=breakdown.grade, scoring=breakdown,
        pq_ready=pq_ready, pq_explanation=pq_explanation,
    )
