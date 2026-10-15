from cipheraudit.data import cipher_suites, named_groups, suites_for
from cipheraudit.evaluation.rules import catalog
from cipheraudit.models.findings import Severity
from cipheraudit.wire.constants import ProtocolVersion

CATEGORIES = {"NULL", "ANON", "EXPORT", "RC4", "DES", "3DES", "CBC", "AEAD", "OTHER"}


def test_cipher_registry_integrity() -> None:
    suites = cipher_suites()
    assert len(suites) > 300
    for code, s in suites.items():
        assert code == s.code and 0 <= code <= 0xFFFF
        assert s.category in CATEGORIES
        assert s.protocols, s.iana
        assert s.iana.startswith("TLS_")


def test_known_suites_classified() -> None:
    s = cipher_suites()
    assert s[0x000A].category == "3DES" and s[0x000A].block_bits == 64 and not s[0x000A].fs
    assert s[0xC02F].category == "AEAD" and s[0xC02F].fs and s[0xC02F].openssl == "ECDHE-RSA-AES128-GCM-SHA256"
    assert s[0x0005].category == "RC4"
    assert s[0x0003].category == "EXPORT" and s[0x0003].kx == "RSA_EXPORT"
    assert s[0x1301].protocols == (ProtocolVersion.TLS13,)
    assert s[0xC013].category == "CBC" and ProtocolVersion.SSL3 in s[0xC013].protocols
    assert s[0x0034].category == "ANON"


def test_suites_for_excludes_tls12_only_on_older_versions() -> None:
    tls10 = {s.code for s in suites_for(ProtocolVersion.TLS10)}
    assert 0xC02F not in tls10 and 0xC013 in tls10


def test_groups_include_hybrid_pq() -> None:
    groups = named_groups()
    assert groups[0x11EC].name == "X25519MLKEM768" and groups[0x11EC].kind == "pq_hybrid"
    assert groups[0x001D].kind == "ec"


def test_finding_catalog_complete() -> None:
    for entry in catalog().values():
        for key in ("id", "title", "severity", "plain", "technical", "nist", "remediation"):
            assert entry.get(key), f"{entry.get('id')} missing {key}"
        Severity(entry["severity"])
