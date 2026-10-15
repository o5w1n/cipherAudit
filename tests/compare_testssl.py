"""Accuracy check (PRD §7): diff protocols and accepted ciphers against testssl.sh.

    testssl.sh -p -E --jsonfile testssl.json <host:port>
    cipheraudit scan <host:port> --i-have-permission --json ours.json
    python tests/compare_testssl.py testssl.json ours.json

Exit code 0 when there are no mismatches, 1 otherwise.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

PROTOCOL_IDS = {"SSLv2": "SSLv2", "SSLv3": "SSLv3", "TLS1": "TLS1.0", "TLS1_1": "TLS1.1", "TLS1_2": "TLS1.2",
                "TLS1_3": "TLS1.3"}
CIPHER_PROTO = {"ssl2": "SSLv2", "ssl3": "SSLv3", "tls1": "TLS1.0", "tls1_1": "TLS1.1", "tls1_2": "TLS1.2",
                "tls1_3": "TLS1.3"}
CIPHER_ID = re.compile(r"^cipher-(ssl2|ssl3|tls1(?:_[123])?)_x([0-9a-f]+)$")


def _testssl_findings(path: Path) -> list[dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    findings: list[dict[str, str]] = []
    for result in data.get("scanResult", []):  # --jsonfile-pretty layout
        for section in result.values():
            if isinstance(section, list):
                findings.extend(f for f in section if isinstance(f, dict))
    return findings


def load_testssl(path: Path) -> tuple[dict[str, bool], dict[str, set[int]]]:
    protocols: dict[str, bool] = {}
    ciphers: dict[str, set[int]] = {}
    for f in _testssl_findings(path):
        fid, finding = f.get("id", ""), f.get("finding", "").lower()
        if fid in PROTOCOL_IDS:
            protocols[PROTOCOL_IDS[fid]] = "not offered" not in finding and "offered" in finding
        match = CIPHER_ID.match(fid)
        if match:
            ciphers.setdefault(CIPHER_PROTO[match[1]], set()).add(int(match[2], 16))
    return protocols, ciphers


def load_ours(path: Path) -> tuple[dict[str, bool], dict[str, set[int]]]:
    scan = json.loads(path.read_text(encoding="utf-8"))["scan"]
    protocols = {k: bool(v) for k, v in scan["protocols"]["supported"].items()}
    ciphers = {pc["protocol"]: {c["code"] for c in pc["ciphers"]} for pc in (scan.get("ciphers") or {}).get(
        "per_protocol", [])}
    return protocols, ciphers


def compare(testssl: Path, ours: Path) -> list[str]:
    t_proto, t_ciph = load_testssl(testssl)
    if not t_proto:
        return [f"no protocol results in {testssl}; not testssl.sh -p JSON output?"]
    o_proto, o_ciph = load_ours(ours)
    problems = [f"protocol {v}: testssl={t_proto[v]} cipheraudit={o_proto.get(v)}"
                for v in t_proto if t_proto[v] != o_proto.get(v, False)]
    for version in sorted(set(t_ciph) | set(o_ciph)):
        if version == "SSLv2":
            continue  # cipheraudit reports SSLv2 cipher kinds as a count only
        only_t = t_ciph.get(version, set()) - o_ciph.get(version, set())
        only_o = o_ciph.get(version, set()) - t_ciph.get(version, set())
        problems += [f"{version}: only testssl.sh found 0x{c:04X}" for c in sorted(only_t)]
        problems += [f"{version}: only cipheraudit found 0x{c:04X}" for c in sorted(only_o)]
    return problems


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    problems = compare(Path(sys.argv[1]), Path(sys.argv[2]))
    for line in problems:
        print(line)
    print(f"{len(problems)} mismatch(es)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
