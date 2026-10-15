from cipheraudit.core.certificate import hostname_matches
from cipheraudit.core.server_config import _parse_hsts
from cipheraudit.core.vulns.derived import derived_checks
from cipheraudit.evaluation.rules import evaluate, make_finding, pq_status
from cipheraudit.evaluation.scoring import grade_for, score
from cipheraudit.models.results import CipherResult, GroupResult, ScanResult, TrustResult
from cipheraudit.wire.constants import ProtocolVersion as P

from .factories import certificate, leaf, modern_scan, per_protocol, protocols


def finding_ids(scan: ScanResult) -> set[str]:
    return {f.id for f in evaluate(scan)}


# --- rules ---------------------------------------------------------------------

def test_modern_config_has_no_findings_and_scores_100() -> None:
    scan = modern_scan()
    findings = evaluate(scan)
    assert findings == []
    assert score(findings).score == 100 and score(findings).grade == "A"
    assert pq_status(scan)[0] is True


def test_old_protocols_flagged() -> None:
    scan = modern_scan()
    scan.protocols = protocols(P.TLS10, P.TLS11, P.TLS12)
    assert {"PROTO_TLS10_ENABLED", "PROTO_TLS11_ENABLED", "PROTO_TLS13_MISSING"} <= finding_ids(scan)


def test_no_modern_tls_is_critical() -> None:
    scan = modern_scan()
    scan.protocols = protocols(P.SSL3, P.TLS10)
    assert "PROTO_NO_MODERN_TLS" in finding_ids(scan)


def test_weak_cipher_categories() -> None:
    scan = modern_scan()
    scan.ciphers = CipherResult(per_protocol=[
        per_protocol(P.TLS12, [0xC02F, 0x000A, 0x0005, 0x0003, 0x002F], server_order=False),
    ])
    found = finding_ids(scan)
    assert {"CIPHER_3DES", "CIPHER_RC4", "CIPHER_EXPORT", "CIPHER_CBC", "CIPHER_NO_FORWARD_SECRECY",
            "CIPHER_NO_SERVER_ORDER"} <= found


def test_dh_thresholds() -> None:
    scan = modern_scan()
    assert scan.ciphers is not None
    scan.ciphers.dh_prime_bits = 1024
    assert "DH_WEAK" in finding_ids(scan)
    scan.ciphers.dh_prime_bits = 512
    assert "DH_BROKEN" in finding_ids(scan)


def test_certificate_problems() -> None:
    scan = modern_scan()
    scan.certificate = certificate(
        cert=leaf(days=10, key_type="RSA", bits=1024, sig_hash="sha1"),
        trust=TrustResult(trusted=False, hostname_match=False, reason="self_signed"),
        stapled=False,
    )
    assert {"CERT_UNTRUSTED", "CERT_HOSTNAME_MISMATCH", "CERT_EXPIRING_SOON", "CERT_WEAK_KEY",
            "CERT_WEAK_SIGNATURE", "CERT_NO_OCSP_STAPLING"} <= finding_ids(scan)


def test_expired_certificate() -> None:
    scan = modern_scan()
    scan.certificate = certificate(cert=leaf(days=-3), trust=TrustResult(trusted=False, hostname_match=True,
                                                                         reason="expired"))
    found = finding_ids(scan)
    assert "CERT_EXPIRED" in found and "CERT_EXPIRING_SOON" not in found


def test_pq_not_ready_without_hybrid_group() -> None:
    scan = modern_scan()
    assert scan.ciphers is not None
    scan.ciphers.groups = [GroupResult(protocol=P.TLS13, groups=[0x001D], names=["x25519"])]
    assert pq_status(scan)[0] is False
    assert "PQ_NOT_READY" in finding_ids(scan)


def test_pq_unknown_when_group_probe_incomplete() -> None:
    scan = modern_scan()
    assert scan.ciphers is not None
    scan.ciphers.groups = [GroupResult(protocol=P.TLS13, groups=[0x001D], names=["x25519"], complete=False)]
    assert pq_status(scan)[0] is None


def test_hsts_parsing_and_rules() -> None:
    hsts = _parse_hsts('max-age="600"; includeSubDomains; preload')
    assert hsts.max_age == 600 and hsts.include_subdomains and hsts.preload
    scan = modern_scan()
    assert scan.server_config is not None and scan.server_config.http is not None
    scan.server_config.http.hsts = hsts
    assert "HSTS_SHORT" in finding_ids(scan)


# --- derived vulnerability checks ------------------------------------------------

def test_derived_checks_on_legacy_facts() -> None:
    p = protocols(P.SSL2, P.SSL3, P.TLS10, P.TLS12)
    c = CipherResult(per_protocol=[
        per_protocol(P.SSL3, [0x000A, 0x0005, 0x0003]),
        per_protocol(P.TLS10, [0x002F]),
        per_protocol(P.TLS12, [0xC02F, 0x0014]),
    ])
    status = {v.id: v.status for v in derived_checks(p, c)}
    assert status == {
        "drown": "vulnerable", "poodle_ssl": "vulnerable", "beast": "vulnerable", "sweet32": "vulnerable",
        "rc4": "vulnerable", "freak": "vulnerable", "logjam": "vulnerable", "lucky13": "vulnerable",
    }


def test_derived_checks_on_modern_facts() -> None:
    scan = modern_scan()
    assert scan.protocols is not None
    results = derived_checks(scan.protocols, scan.ciphers)
    assert all(v.status == "not_vulnerable" for v in results), results


def test_incomplete_enumeration_is_inconclusive_not_safe() -> None:
    pc = per_protocol(P.TLS12, [0xC02F])
    pc.complete = False
    status = {v.id: v.status for v in derived_checks(protocols(P.TLS12), CipherResult(per_protocol=[pc]))}
    assert status["sweet32"] == "inconclusive"


def test_logjam_from_small_dh_prime() -> None:
    c = CipherResult(per_protocol=[per_protocol(P.TLS12, [0x009E])], dh_prime_bits=768)
    logjam = next(v for v in derived_checks(protocols(P.TLS12), c) if v.id == "logjam")
    assert logjam.status == "vulnerable"


# --- scoring -----------------------------------------------------------------------

def test_scoring_deductions_and_caps() -> None:
    high = make_finding("PROTO_TLS10_ENABLED", {})
    low = make_finding("HSTS_MISSING", {"url": "u"})
    result = score([high, low])
    assert result.total_deductions == 23
    assert result.score == 64 and result.cap_reason == high.title  # 77 capped at 64
    assert result.grade == "D"


def test_critical_caps_at_39() -> None:
    result = score([make_finding("CIPHER_NULL", {"ciphers": "x"})])
    assert result.score == 39 and result.grade == "F"


def test_score_floor_zero() -> None:
    findings = [make_finding(i, {}) for i in ("PROTO_SSL2_ENABLED", "PROTO_SSL3_ENABLED", "PROTO_NO_MODERN_TLS")]
    assert score(findings).score == 0


def test_grade_boundaries() -> None:
    assert [grade_for(s) for s in (100, 90, 89, 80, 65, 50, 40, 39, 0)] == ["A", "A", "B", "B", "C", "D", "E", "F", "F"]


def test_technical_text_filled_from_evidence() -> None:
    f = make_finding("DH_WEAK", {"bits": 1024})
    assert f.technical == "DHE prime is 1024 bits."


# --- hostname matching -----------------------------------------------------------

def test_hostname_matching_rules() -> None:
    assert hostname_matches("www.example.com", ["*.example.com"], [], None)
    assert not hostname_matches("a.b.example.com", ["*.example.com"], [], None)
    assert not hostname_matches("example.com", ["*.example.com"], [], None)
    assert hostname_matches("Example.COM.", ["example.com"], [], None)
    assert not hostname_matches("example.com", ["other.com"], [], "example.com")  # SAN wins over CN
    assert hostname_matches("example.com", [], [], "example.com")
    assert hostname_matches("127.0.0.1", ["localhost"], ["127.0.0.1"], None)
    assert not hostname_matches("10.0.0.1", ["10.0.0.1"], [], None)  # IPs only match IP SANs
