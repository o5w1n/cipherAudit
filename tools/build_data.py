"""Regenerate src/cipheraudit/data/ciphers.json and groups.json from primary sources.

Sources:
  - IANA TLS Cipher Suites registry (tls-parameters-4.csv)
  - IANA TLS Supported Groups registry (tls-parameters-8.csv)
  - OpenSSL include/openssl/tls1.h and ssl3.h (Apache-2.0) for OpenSSL cipher names

Usage: python tools/build_data.py <dir-with-downloaded-files>
The generated JSON is committed; this script only needs re-running when the registries change.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "src" / "cipheraudit" / "data"

PRE_TLS12 = ["SSLv3", "TLS1.0", "TLS1.1", "TLS1.2"]

# Non-IANA suites still found on legacy servers (published drafts / vendor codepoints).
EXTRA_SUITES = [
    (0x0060, "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5", "EXP1024-RC4-MD5"),
    (0x0061, "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5", "EXP1024-RC2-CBC-MD5"),
    (0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", "EXP1024-DES-CBC-SHA"),
    (0x0063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA", "EXP1024-DHE-DSS-DES-CBC-SHA"),
    (0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", "EXP1024-RC4-SHA"),
    (0x0065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA", "EXP1024-DHE-DSS-RC4-SHA"),
    (0xCC13, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD", "ECDHE-RSA-CHACHA20-POLY1305-OLD"),
    (0xCC14, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD", "ECDHE-ECDSA-CHACHA20-POLY1305-OLD"),
    (0xCC15, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD", "DHE-RSA-CHACHA20-POLY1305-OLD"),
]

# Legacy OpenSSL names for suites dropped from current OpenSSL headers.
LEGACY_OPENSSL_NAMES = {
    0x0003: "EXP-RC4-MD5",
    0x0006: "EXP-RC2-CBC-MD5",
    0x0008: "EXP-DES-CBC-SHA",
    0x0009: "DES-CBC-SHA",
    0x000B: "EXP-DH-DSS-DES-CBC-SHA",
    0x000C: "DH-DSS-DES-CBC-SHA",
    0x000E: "EXP-DH-RSA-DES-CBC-SHA",
    0x000F: "DH-RSA-DES-CBC-SHA",
    0x0011: "EXP-EDH-DSS-DES-CBC-SHA",
    0x0012: "EDH-DSS-DES-CBC-SHA",
    0x0014: "EXP-EDH-RSA-DES-CBC-SHA",
    0x0015: "EDH-RSA-DES-CBC-SHA",
    0x0017: "EXP-ADH-RC4-MD5",
    0x0019: "EXP-ADH-DES-CBC-SHA",
    0x001A: "ADH-DES-CBC-SHA",
}

SSLV2_CIPHERS = [
    (0x010080, "SSL_CK_RC4_128_WITH_MD5", "RC4-MD5", "RC4", 128, False),
    (0x020080, "SSL_CK_RC4_128_EXPORT40_WITH_MD5", "EXP-RC4-MD5", "RC4", 40, True),
    (0x030080, "SSL_CK_RC2_128_CBC_WITH_MD5", "RC2-CBC-MD5", "RC2", 128, False),
    (0x040080, "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5", "EXP-RC2-CBC-MD5", "RC2", 40, True),
    (0x050080, "SSL_CK_IDEA_128_CBC_WITH_MD5", "IDEA-CBC-MD5", "IDEA", 128, False),
    (0x060040, "SSL_CK_DES_64_CBC_WITH_MD5", "DES-CBC-MD5", "DES", 56, False),
    (0x0700C0, "SSL_CK_DES_192_EDE3_CBC_WITH_MD5", "DES-CBC3-MD5", "3DES", 112, False),
    (0x080080, "SSL_CK_RC4_64_WITH_MD5", "RC4-64-MD5", "RC4", 64, False),
]

MAC_TOKENS = {"MD5", "SHA", "SHA256", "SHA384", "SM3"}

# (prefix in IANA name, kx, auth); longest prefixes first.
KX_TABLE = [
    ("DHE_DSS_EXPORT1024", "DHE_EXPORT", "DSS"),
    ("RSA_EXPORT1024", "RSA_EXPORT", "RSA"),
    ("DH_anon_EXPORT", "DH_EXPORT", "anon"),
    ("DH_DSS_EXPORT", "DH_EXPORT", "DSS"),
    ("DH_RSA_EXPORT", "DH_EXPORT", "RSA"),
    ("DHE_DSS_EXPORT", "DHE_EXPORT", "DSS"),
    ("DHE_RSA_EXPORT", "DHE_EXPORT", "RSA"),
    ("KRB5_EXPORT", "KRB5_EXPORT", "KRB5"),
    ("RSA_EXPORT", "RSA_EXPORT", "RSA"),
    ("ECDHE_ECDSA", "ECDHE", "ECDSA"),
    ("ECDHE_RSA", "ECDHE", "RSA"),
    ("ECDHE_PSK", "ECDHE", "PSK"),
    ("ECDH_ECDSA", "ECDH", "ECDSA"),
    ("ECDH_RSA", "ECDH", "RSA"),
    ("ECDH_anon", "ECDH", "anon"),
    ("DHE_DSS", "DHE", "DSS"),
    ("DHE_RSA", "DHE", "RSA"),
    ("DHE_PSK", "DHE", "PSK"),
    ("DH_DSS", "DH", "DSS"),
    ("DH_RSA", "DH", "RSA"),
    ("DH_anon", "DH", "anon"),
    ("RSA_PSK", "RSA", "PSK"),
    ("SRP_SHA_RSA", "SRP", "RSA"),
    ("SRP_SHA_DSS", "SRP", "DSS"),
    ("SRP_SHA", "SRP", "SRP"),
    ("ECCPWD", "ECCPWD", "ECCPWD"),
    ("KRB5", "KRB5", "KRB5"),
    ("PSK", "PSK", "PSK"),
    ("RSA", "RSA", "RSA"),
    ("NULL", "NULL", "NULL"),
    ("GOSTR341112_256", "GOST", "GOST"),
]

# (enc token prefix, algorithm, bits, block_bits, mode)
ENC_TABLE = [
    ("NULL", "NULL", 0, 0, "NULL"),
    ("RC4_40", "RC4", 40, 0, "STREAM"),
    ("RC4_56", "RC4", 56, 0, "STREAM"),
    ("RC4_128", "RC4", 128, 0, "STREAM"),
    ("RC2_CBC_40", "RC2", 40, 64, "CBC"),
    ("RC2_CBC_56", "RC2", 56, 64, "CBC"),
    ("IDEA_CBC", "IDEA", 128, 64, "CBC"),
    ("DES40_CBC", "DES", 40, 64, "CBC"),
    ("DES_CBC_40", "DES", 40, 64, "CBC"),
    ("DES_CBC", "DES", 56, 64, "CBC"),
    ("3DES_EDE_CBC", "3DES", 112, 64, "CBC"),
    ("AES_128_CBC", "AES", 128, 128, "CBC"),
    ("AES_256_CBC", "AES", 256, 128, "CBC"),
    ("AES_128_GCM", "AES", 128, 128, "GCM"),
    ("AES_256_GCM", "AES", 256, 128, "GCM"),
    ("AES_128_CCM_8", "AES", 128, 128, "CCM_8"),
    ("AES_256_CCM_8", "AES", 256, 128, "CCM_8"),
    ("AES_128_CCM", "AES", 128, 128, "CCM"),
    ("AES_256_CCM", "AES", 256, 128, "CCM"),
    ("CAMELLIA_128_CBC", "CAMELLIA", 128, 128, "CBC"),
    ("CAMELLIA_256_CBC", "CAMELLIA", 256, 128, "CBC"),
    ("CAMELLIA_128_GCM", "CAMELLIA", 128, 128, "GCM"),
    ("CAMELLIA_256_GCM", "CAMELLIA", 256, 128, "GCM"),
    ("SEED_CBC", "SEED", 128, 128, "CBC"),
    ("ARIA_128_CBC", "ARIA", 128, 128, "CBC"),
    ("ARIA_256_CBC", "ARIA", 256, 128, "CBC"),
    ("ARIA_128_GCM", "ARIA", 128, 128, "GCM"),
    ("ARIA_256_GCM", "ARIA", 256, 128, "GCM"),
    ("CHACHA20_POLY1305", "CHACHA20", 256, 0, "POLY1305"),
    ("KUZNYECHIK_CTR_OMAC", "KUZNYECHIK", 256, 128, "CTR_OMAC"),
    ("MAGMA_CTR_OMAC", "MAGMA", 256, 64, "CTR_OMAC"),
    ("KUZNYECHIK_MGM", "KUZNYECHIK", 256, 128, "MGM"),
    ("MAGMA_MGM", "MAGMA", 256, 64, "MGM"),
    ("SM4_GCM", "SM4", 128, 128, "GCM"),
    ("SM4_CCM", "SM4", 128, 128, "CCM"),
]

TLS13_ENC = {
    "TLS_AES_128_GCM_SHA256": ("AES", 128, 128, "GCM", "SHA256"),
    "TLS_AES_256_GCM_SHA384": ("AES", 256, 128, "GCM", "SHA384"),
    "TLS_CHACHA20_POLY1305_SHA256": ("CHACHA20", 256, 0, "POLY1305", "SHA256"),
    "TLS_AES_128_CCM_SHA256": ("AES", 128, 128, "CCM", "SHA256"),
    "TLS_AES_128_CCM_8_SHA256": ("AES", 128, 128, "CCM_8", "SHA256"),
    "TLS_SM4_GCM_SM3": ("SM4", 128, 128, "GCM", "SM3"),
    "TLS_SM4_CCM_SM3": ("SM4", 128, 128, "CCM", "SM3"),
    "TLS_SHA256_SHA256": ("NULL", 0, 0, "NULL", "SHA256"),
    "TLS_SHA384_SHA384": ("NULL", 0, 0, "NULL", "SHA384"),
}

AEAD_MODES = {"GCM", "CCM", "CCM_8", "POLY1305", "MGM"}


def openssl_names(header_dir: Path) -> dict[int, str]:
    names: dict[int, str] = {}
    for header in ("tls1.h", "ssl3.h"):
        text = (header_dir / header).read_text()
        codes: dict[str, int] = {}
        for m in re.finditer(r"#\s*define\s+(?:TLS1|SSL3)_CK_(\w+)\s+0x([0-9A-Fa-f]+)", text):
            codes[m[1]] = int(m[2], 16) & 0xFFFF
        for m in re.finditer(r"#\s*define\s+(?:TLS1|SSL3)_TXT_(\w+)\s+\"([^\"]+)\"", text):
            code = codes.get(m[1])
            if code is not None:
                names.setdefault(code, m[2])
    return names


def category(enc: str, auth: str, kx: str, export: bool, mode: str) -> str:
    if enc == "NULL":
        return "NULL"
    if auth == "anon":
        return "ANON"
    if export:
        return "EXPORT"
    if enc == "RC4":
        return "RC4"
    if enc in ("DES", "RC2"):
        return "DES"
    if enc in ("3DES", "IDEA", "MAGMA"):
        return "3DES"
    if mode in AEAD_MODES:
        return "AEAD"
    if mode == "CBC":
        return "CBC"
    return "OTHER"


def parse_suite(code: int, iana: str) -> dict[str, object] | None:
    if iana in TLS13_ENC:
        enc, bits, block, mode, mac = TLS13_ENC[iana]
        return {
            "code": code, "iana": iana, "protocols": ["TLS1.3"], "kx": "ANY", "auth": "ANY",
            "enc": enc, "bits": bits, "block_bits": block, "mode": mode, "mac": "AEAD" if mode != "NULL" else mac,
            "fs": True, "aead": mode in AEAD_MODES, "export": False,
            "category": "NULL" if enc == "NULL" else "AEAD",
        }
    m = re.fullmatch(r"TLS_(.+)_WITH_(.+)", iana)
    if not m:
        return None
    kx_part, rest = m[1], m[2]
    kx_auth = next(((kx, auth) for prefix, kx, auth in KX_TABLE if kx_part == prefix), None)
    if kx_auth is None:
        return None
    kx, auth = kx_auth
    tokens = rest.split("_")
    mac = "AEAD"
    if tokens[-1] in MAC_TOKENS or tokens[-1] == "OLD":
        if tokens[-1] == "OLD":
            tokens = tokens[:-1]
        mac = tokens[-1]
        tokens = tokens[:-1]
    enc_str = "_".join(tokens)
    enc_row = next((row for row in ENC_TABLE if enc_str == row[0] or enc_str.startswith(row[0] + "_")), None)
    if enc_row is None:
        return None
    _, enc, bits, block, mode = enc_row
    if mode in AEAD_MODES:
        mac = "AEAD"
    export = "EXPORT" in iana or bits == 40
    fs = kx in ("DHE", "ECDHE", "DHE_EXPORT")
    tls12_only = mode in AEAD_MODES or mac in ("SHA256", "SHA384") or enc in ("ARIA", "KUZNYECHIK", "MAGMA")
    protocols = ["TLS1.2"] if tls12_only else list(PRE_TLS12)
    return {
        "code": code, "iana": iana, "protocols": protocols, "kx": kx, "auth": auth,
        "enc": enc, "bits": bits, "block_bits": block, "mode": mode, "mac": mac,
        "fs": fs, "aead": mode in AEAD_MODES, "export": export,
        "category": category(enc, auth, kx, export, mode),
    }


def build_ciphers(src: Path) -> None:
    ossl = openssl_names(src)
    ossl.update({k: v for k, v in LEGACY_OPENSSL_NAMES.items() if k not in ossl})
    suites: list[dict[str, object]] = []
    skipped: list[str] = []
    with (src / "iana-ciphers.csv").open(newline="") as fh:
        for row in csv.DictReader(fh):
            value, name = row["Value"], row["Description"]
            if not re.fullmatch(r"0x[0-9A-F]{2},0x[0-9A-F]{2}", value):
                continue
            if name.startswith(("Unassigned", "Reserved")) or "SCSV" in name or name == "TLS_NULL_WITH_NULL_NULL":
                continue
            code = int(value[2:4], 16) << 8 | int(value[7:9], 16)
            suite = parse_suite(code, name)
            if suite is None:
                skipped.append(name)
                continue
            # OpenSSL uses the IANA names for TLS 1.3 suites
            suite["openssl"] = ossl.get(code) or (name if suite["protocols"] == ["TLS1.3"] else None)
            suite["recommended"] = row["Recommended"] == "Y"
            suites.append(suite)
    for code, iana, openssl in EXTRA_SUITES:
        suite = parse_suite(code, iana)
        if suite is None:
            skipped.append(iana)
            continue
        suite["openssl"] = openssl
        suite["recommended"] = False
        suites.append(suite)
    suites.sort(key=lambda s: int(str(s["code"])))
    sslv2 = [
        {"code": code, "name": name, "openssl": openssl, "enc": enc, "bits": bits, "export": export}
        for code, name, openssl, enc, bits, export in SSLV2_CIPHERS
    ]
    out = {"source": "IANA tls-parameters-4 + OpenSSL headers", "suites": suites, "sslv2": sslv2}
    (DATA_DIR / "ciphers.json").write_text(json.dumps(out, indent=1) + "\n")
    print(f"ciphers.json: {len(suites)} suites, {len(sslv2)} SSLv2 kinds; skipped {len(skipped)}: {skipped}")


def group_kind(gid: int, name: str) -> str:
    if "MLKEM" in name or "Kyber" in name:
        return "pq_hybrid" if any(x in name for x in ("X25519", "SecP", "SM2")) else "pq"
    if name.startswith("ffdhe"):
        return "ffdhe"
    return "ec"


def build_groups(src: Path) -> None:
    groups = []
    with (src / "groups.csv").open(newline="") as fh:
        for row in csv.DictReader(fh):
            if not row["Value"].isdigit():
                continue
            name = row["Description"].replace(" (OBSOLETE)", "")
            if name.startswith(("Unassigned", "Reserved", "arbitrary")):
                continue
            gid = int(row["Value"])
            groups.append({
                "id": gid, "name": name, "kind": group_kind(gid, name),
                "recommended": row["Recommended"] == "Y", "obsolete": "OBSOLETE" in row["Description"],
            })
    (DATA_DIR / "groups.json").write_text(json.dumps({"source": "IANA tls-parameters-8", "groups": groups},
                                                     indent=1) + "\n")
    print(f"groups.json: {len(groups)} groups")


if __name__ == "__main__":
    source_dir = Path(sys.argv[1])
    build_ciphers(source_dir)
    build_groups(source_dir)
