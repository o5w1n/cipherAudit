import json
from pathlib import Path

from tests.compare_testssl import compare, load_testssl

FIXTURE = Path(__file__).parent.parent / "fixtures" / "testssl-modern.json"


def test_parses_real_testssl_output() -> None:
    protocols, ciphers = load_testssl(FIXTURE)
    assert protocols == {"SSLv2": False, "SSLv3": False, "TLS1.0": False, "TLS1.1": False, "TLS1.2": True,
                         "TLS1.3": True}
    assert ciphers == {"TLS1.2": {0xC02C, 0xCCA9, 0xC02B}, "TLS1.3": {0x1301, 0x1302, 0x1303}}


def test_empty_testssl_file_is_a_mismatch(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text("[]", encoding="utf-8")
    assert compare(empty, empty) != []


def test_reports_cipher_differences(tmp_path: Path) -> None:
    ours = tmp_path / "ours.json"
    tls13 = [{"code": c} for c in (0x1301, 0x1302, 0x1303)]
    ours.write_text(json.dumps({"scan": {
        "protocols": {"supported": {"TLS1.2": True, "TLS1.3": True}},
        "ciphers": {"per_protocol": [{"protocol": "TLS1.2", "ciphers": [{"code": 0xC02C}, {"code": 0xC030}]},
                                     {"protocol": "TLS1.3", "ciphers": tls13}]},
    }}), encoding="utf-8")
    assert compare(FIXTURE, ours) == ["TLS1.2: only testssl.sh found 0xC02B", "TLS1.2: only testssl.sh found 0xCCA9",
                                      "TLS1.2: only cipheraudit found 0xC030"]
