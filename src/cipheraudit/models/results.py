"""Scan facts (what the server does). No severities or judgments here (TRD §2)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from cipheraudit.wire.constants import ProtocolVersion


class ScanTarget(BaseModel):
    host: str
    port: int = 443
    ip: str
    sni: str | None


class ProtocolResult(BaseModel):
    supported: dict[ProtocolVersion, bool | None]  # None = inconclusive
    alpn_selected: str | None = None
    alpn_offered: list[str] = Field(default_factory=list)
    downgrades: dict[ProtocolVersion, str] = Field(default_factory=dict)  # offered -> version the server answered
    sslv2_cipher_count: int | None = None
    notes: list[str] = Field(default_factory=list)

    def offered(self) -> list[ProtocolVersion]:
        return [v for v, ok in self.supported.items() if ok]


class CipherInfo(BaseModel):
    code: int
    iana: str
    openssl: str | None
    category: str
    kx: str
    auth: str
    enc: str
    bits: int
    block_bits: int
    mode: str
    mac: str
    fs: bool
    aead: bool
    export: bool


class ProtocolCiphers(BaseModel):
    protocol: ProtocolVersion
    ciphers: list[CipherInfo]  # server preference order when server_order is True
    server_order: bool | None  # None = could not determine (fewer than 2 ciphers, or inconclusive)
    complete: bool = True  # False if enumeration stopped on an error
    chacha_priority: bool | None = None  # server prefers ChaCha20 when the client lists it first


class GroupResult(BaseModel):
    protocol: ProtocolVersion
    groups: list[int]
    names: list[str]
    complete: bool = True


class CipherResult(BaseModel):
    per_protocol: list[ProtocolCiphers]
    groups: list[GroupResult] = Field(default_factory=list)
    dh_prime_bits: int | None = None
    dh_prime_sha256: str | None = None

    def all_ciphers(self) -> list[CipherInfo]:
        seen: dict[int, CipherInfo] = {}
        for pc in self.per_protocol:
            for c in pc.ciphers:
                seen.setdefault(c.code, c)
        return list(seen.values())

    def ciphers_for(self, protocol: ProtocolVersion) -> list[CipherInfo]:
        return next((pc.ciphers for pc in self.per_protocol if pc.protocol == protocol), [])


class CertificateInfo(BaseModel):
    subject: str
    issuer: str
    serial_hex: str
    san_dns: list[str]
    san_ip: list[str]
    key_type: str  # RSA | EC | Ed25519 | Ed448 | DSA | other
    key_bits: int
    key_curve: str | None = None
    rsa_exponent: int | None = None
    signature_algorithm: str
    signature_hash: str | None
    not_before: datetime
    not_after: datetime
    days_until_expiry: int
    is_self_signed: bool
    is_ca: bool
    ocsp_urls: list[str] = Field(default_factory=list)
    crl_urls: list[str] = Field(default_factory=list)
    sct_count: int = 0
    must_staple: bool = False
    fingerprint_sha256: str


class TrustResult(BaseModel):
    trusted: bool | None
    hostname_match: bool | None
    reason: str | None = None  # expired | not_yet_valid | untrusted_root | incomplete_chain | self_signed | ...
    detail: str | None = None
    store: str = "certifi (Mozilla)"


class CertificateChainResult(BaseModel):
    source: Literal["raw_handshake", "ssl_module"]
    key_family: str  # RSA | ECDSA | ... (which auth family was offered to obtain this chain)
    chain: list[CertificateInfo]
    trust: TrustResult
    chain_order_ok: bool | None = None
    ocsp_stapled: bool | None = None


class CertificateResult(BaseModel):
    chains: list[CertificateChainResult]


class HstsInfo(BaseModel):
    present: bool
    max_age: int | None = None
    include_subdomains: bool = False
    preload: bool = False
    raw: str | None = None


class HttpHeadersResult(BaseModel):
    url: str
    status: int | None
    hsts: HstsInfo
    x_content_type_options: str | None = None
    x_frame_options: str | None = None
    content_security_policy: bool = False
    server_banner: str | None = None
    error: str | None = None


class ServerConfigResult(BaseModel):
    secure_renegotiation: bool | None = None
    session_resumption_id: bool | None = None
    session_resumption_ticket: bool | None = None
    extended_master_secret: bool | None = None
    fallback_scsv: bool | None = None  # True = server rejects downgraded hello with inappropriate_fallback
    http: HttpHeadersResult | None = None


VulnStatus = Literal["vulnerable", "not_vulnerable", "inconclusive", "not_tested"]


class VulnResult(BaseModel):
    id: str
    status: VulnStatus
    evidence: str


class ScanResult(BaseModel):
    target: ScanTarget
    started_at: datetime
    finished_at: datetime
    protocols: ProtocolResult | None = None
    ciphers: CipherResult | None = None
    certificate: CertificateResult | None = None
    server_config: ServerConfigResult | None = None
    vulns: list[VulnResult] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
