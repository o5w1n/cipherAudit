"""Rules engine (TRD §5b): ScanResult -> list[Finding]. Pure functions; wording comes from findings.yaml."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from functools import cache
from importlib import resources
from typing import Any

import yaml

from cipheraudit.data import named_groups
from cipheraudit.models.findings import Finding, Severity
from cipheraudit.models.results import CertificateInfo, ScanResult
from cipheraudit.wire.constants import ProtocolVersion

SEVERITY_DEFAULTS: dict[Severity, tuple[int, int | None]] = {
    Severity.CRITICAL: (40, 39),
    Severity.HIGH: (20, 64),
    Severity.MEDIUM: (10, None),
    Severity.LOW: (3, None),
    Severity.INFO: (0, None),
}
EXPIRY_WARNING_DAYS = 30
HSTS_MIN_SECONDS = 180 * 24 * 3600
WEAK_HASHES = {"sha1", "md5", "md2"}

Hit = tuple[str, dict[str, Any]]


class _SafeDict(dict[str, Any]):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


@cache
def catalog() -> dict[str, dict[str, Any]]:
    text = resources.files("cipheraudit.data").joinpath("findings.yaml").read_text(encoding="utf-8")
    entries: list[dict[str, Any]] = yaml.safe_load(text)
    return {e["id"]: e for e in entries}


def make_finding(finding_id: str, evidence: dict[str, Any]) -> Finding:
    entry = catalog()[finding_id]
    severity = Severity(entry["severity"])
    deduct, cap = SEVERITY_DEFAULTS[severity]
    impact = entry.get("score_impact") or {}
    return Finding(
        id=finding_id,
        title=entry["title"],
        severity=severity,
        plain=" ".join(entry["plain"].split()),
        technical=entry["technical"].format_map(_SafeDict(evidence)),
        nist=list(entry["nist"]),
        remediation=entry["remediation"],
        evidence=evidence,
        deduct=impact.get("deduct", deduct),
        cap=impact.get("cap", cap),
    )


# --- Protocols ---------------------------------------------------------------

def protocol_rules(scan: ScanResult) -> Iterator[Hit]:
    p = scan.protocols
    if p is None:
        return
    s = p.supported
    if s.get(ProtocolVersion.SSL2):
        yield "PROTO_SSL2_ENABLED", {"sslv2_ciphers": p.sslv2_cipher_count}
    if s.get(ProtocolVersion.SSL3):
        yield "PROTO_SSL3_ENABLED", {}
    if s.get(ProtocolVersion.TLS10):
        yield "PROTO_TLS10_ENABLED", {}
    if s.get(ProtocolVersion.TLS11):
        yield "PROTO_TLS11_ENABLED", {}
    if s.get(ProtocolVersion.TLS12) is False and s.get(ProtocolVersion.TLS13) is False:
        yield "PROTO_NO_MODERN_TLS", {}
    elif s.get(ProtocolVersion.TLS12) and s.get(ProtocolVersion.TLS13) is False:
        yield "PROTO_TLS13_MISSING", {}


# --- Ciphers -----------------------------------------------------------------

def _names(codes: list[str]) -> str:
    return ", ".join(codes[:8]) + (f" (+{len(codes) - 8} more)" if len(codes) > 8 else "")


def cipher_rules(scan: ScanResult) -> Iterator[Hit]:
    c = scan.ciphers
    if c is None:
        return
    accepted = c.all_ciphers()
    by_category: dict[str, list[str]] = {}
    for cipher in accepted:
        by_category.setdefault(cipher.category, []).append(cipher.iana)
    for category, finding_id in (("NULL", "CIPHER_NULL"), ("ANON", "CIPHER_ANON"), ("EXPORT", "CIPHER_EXPORT"),
                                 ("RC4", "CIPHER_RC4"), ("DES", "CIPHER_DES"), ("3DES", "CIPHER_3DES")):
        if by_category.get(category):
            yield finding_id, {"ciphers": _names(by_category[category]), "count": len(by_category[category])}
    if by_category.get("CBC"):
        yield "CIPHER_CBC", {"count": len(by_category["CBC"]), "ciphers": _names(by_category["CBC"])}

    no_fs = [x.iana for x in accepted if x.kx in ("RSA", "DH", "ECDH") and x.auth != "anon"]
    if no_fs:
        yield "CIPHER_NO_FORWARD_SECRECY", {"count": len(no_fs), "ciphers": _names(no_fs)}

    client_order = [pc.protocol.value for pc in c.per_protocol if pc.server_order is False]
    if client_order:
        yield "CIPHER_NO_SERVER_ORDER", {"protocols": ", ".join(client_order)}

    if c.dh_prime_bits is not None:
        if c.dh_prime_bits < 1024:
            yield "DH_BROKEN", {"bits": c.dh_prime_bits}
        elif c.dh_prime_bits < 2048:
            yield "DH_WEAK", {"bits": c.dh_prime_bits}

    if pq_status(scan)[0] is False:
        yield "PQ_NOT_READY", {}


def pq_status(scan: ScanResult) -> tuple[bool | None, str]:
    """RE-7: ready if any hybrid ML-KEM group is accepted on TLS 1.3."""
    p, c = scan.protocols, scan.ciphers
    if p is None or c is None:
        return None, "Not determined: protocol or cipher checks did not run."
    if not p.supported.get(ProtocolVersion.TLS13):
        return False, "Not ready: TLS 1.3 is required for post-quantum key exchange and is not enabled."
    groups = named_groups()
    tls13 = next((g for g in c.groups if g.protocol == ProtocolVersion.TLS13), None)
    if tls13 is None:
        return None, "Not determined: TLS 1.3 key exchange groups were not tested."
    hybrid = [g for g in tls13.groups if g in groups and groups[g].kind == "pq_hybrid"]
    if hybrid:
        names = ", ".join(groups[g].name for g in hybrid)
        return True, f"Ready: the server accepts hybrid post-quantum key exchange ({names})."
    if not tls13.complete:
        return None, "Not determined: group testing was incomplete."
    return False, "Not ready: no hybrid ML-KEM key exchange group is accepted."


# --- Certificate ---------------------------------------------------------------

def _weak_key(cert: CertificateInfo) -> bool:
    if cert.key_type in ("RSA", "DSA"):
        return cert.key_bits < 2048
    if cert.key_type == "EC":
        return cert.key_bits < 224
    return False


def certificate_rules(scan: ScanResult) -> Iterator[Hit]:
    if scan.certificate is None:
        return
    for chain in scan.certificate.chains:
        if not chain.chain:
            continue
        leaf = chain.chain[0]
        trust = chain.trust
        base = {"subject": leaf.subject, "key_family": chain.key_family}
        reason_map = {
            "expired": "CERT_EXPIRED", "not_yet_valid": "CERT_NOT_YET_VALID", "self_signed": "CERT_UNTRUSTED",
            "untrusted_root": "CERT_UNTRUSTED", "incomplete_chain_or_untrusted": "CERT_INCOMPLETE_CHAIN",
        }
        if trust.trusted is False and trust.reason in reason_map:
            yield reason_map[trust.reason], {
                **base, "reason": trust.reason, "store": trust.store, "detail": trust.detail or "",
                "not_after": leaf.not_after.date().isoformat(), "not_before": leaf.not_before.date().isoformat(),
            }
        if trust.hostname_match is False:
            yield "CERT_HOSTNAME_MISMATCH", {**base, "host": scan.target.sni or scan.target.host,
                                             "san": ", ".join(leaf.san_dns + leaf.san_ip) or "(none)"}
        if 0 <= leaf.days_until_expiry < EXPIRY_WARNING_DAYS:
            yield "CERT_EXPIRING_SOON", {**base, "days": leaf.days_until_expiry,
                                         "not_after": leaf.not_after.date().isoformat()}
        relevant = [c for c in chain.chain if not (c.is_self_signed and c.is_ca and c is not leaf)]
        weak_key = next((c for c in relevant if _weak_key(c)), None)
        if weak_key:
            yield "CERT_WEAK_KEY", {"subject": weak_key.subject, "key_type": weak_key.key_type,
                                    "bits": weak_key.key_bits}
        weak_sig = next((c for c in relevant if (c.signature_hash or "").lower() in WEAK_HASHES), None)
        if weak_sig:
            yield "CERT_WEAK_SIGNATURE", {"subject": weak_sig.subject, "algorithm": weak_sig.signature_algorithm}
        if chain.chain_order_ok is False:
            yield "CERT_CHAIN_ORDER", base
        if chain.ocsp_stapled is False:
            yield "CERT_NO_OCSP_STAPLING", base


# --- Server configuration ----------------------------------------------------

def config_rules(scan: ScanResult) -> Iterator[Hit]:
    cfg = scan.server_config
    if cfg is None:
        return
    if cfg.secure_renegotiation is False:
        yield "CONFIG_NO_SECURE_RENEGOTIATION", {}
    if cfg.fallback_scsv is False:
        yield "CONFIG_NO_FALLBACK_SCSV", {}
    tls12 = scan.protocols is not None and scan.protocols.supported.get(ProtocolVersion.TLS12)
    if cfg.extended_master_secret is False and tls12:
        yield "CONFIG_NO_EXTENDED_MASTER_SECRET", {}
    http = cfg.http
    if http is None or http.error is not None:
        return
    if not http.hsts.present:
        yield "HSTS_MISSING", {"url": http.url}
    elif http.hsts.max_age is not None and http.hsts.max_age < HSTS_MIN_SECONDS:
        yield "HSTS_SHORT", {"max_age": http.hsts.max_age}
    missing = [name for name, present in (
        ("X-Content-Type-Options", http.x_content_type_options is not None),
        ("X-Frame-Options", http.x_frame_options is not None or http.content_security_policy),
        ("Content-Security-Policy", http.content_security_policy),
    ) if not present]
    if missing:
        yield "HEADER_SECURITY_MISSING", {"missing": ", ".join(missing)}


# --- Vulnerabilities ---------------------------------------------------------

def vuln_rules(scan: ScanResult) -> Iterator[Hit]:
    known = catalog()
    for vuln in scan.vulns:
        finding_id = f"VULN_{vuln.id.upper()}"
        if vuln.status == "vulnerable" and finding_id in known:
            yield finding_id, {"evidence": vuln.evidence}


RULES: list[Callable[[ScanResult], Iterator[Hit]]] = [
    protocol_rules, cipher_rules, certificate_rules, config_rules, vuln_rules,
]


def evaluate(scan: ScanResult) -> list[Finding]:
    findings: dict[str, Finding] = {}
    for rule in RULES:
        for finding_id, evidence in rule(scan):
            findings.setdefault(finding_id, make_finding(finding_id, evidence))
    return sorted(findings.values(), key=lambda f: (f.severity.rank, f.id))
