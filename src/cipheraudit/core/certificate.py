"""Core 3 - certificate chain retrieval and assessment facts (PRD CE-1..CE-5)."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import warnings
from datetime import UTC, datetime
from functools import cache
from pathlib import Path

import certifi
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from cipheraudit.data import suites_for
from cipheraudit.models.results import (
    CertificateChainResult,
    CertificateInfo,
    CertificateResult,
    TrustResult,
)
from cipheraudit.wire import extensions as ext
from cipheraudit.wire.client_hello import HelloParams
from cipheraudit.wire.constants import ProtocolVersion
from cipheraudit.wire.handshake import Accepted, ConnFactory, ReadUntil, probe

# Auth families probed separately: a server can hold an RSA and an ECDSA certificate side by side.
KEY_FAMILIES = {"RSA": ("RSA",), "ECDSA": ("ECDSA",), "DSA": ("DSS",)}
MAX_SUITES_PER_HELLO = 127


def _key_facts(cert: x509.Certificate) -> tuple[str, int, str | None, int | None]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size, None, key.public_numbers().e
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC", key.key_size, key.curve.name, None
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, None, None
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456, None, None
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size, None, None
    return type(key).__name__, 0, None, None


def _ext[T: x509.ExtensionType](cert: x509.Certificate, ext_type: type[T]) -> T | None:
    try:
        return cert.extensions.get_extension_for_class(ext_type).value
    except x509.ExtensionNotFound:
        return None
    except ValueError:  # malformed extension
        return None


def describe(der: bytes, now: datetime) -> CertificateInfo:
    cert = x509.load_der_x509_certificate(der)
    key_type, key_bits, curve, exponent = _key_facts(cert)
    san = _ext(cert, x509.SubjectAlternativeName)
    aia = _ext(cert, x509.AuthorityInformationAccess)
    crl = _ext(cert, x509.CRLDistributionPoints)
    scts = _ext(cert, x509.PrecertificateSignedCertificateTimestamps)
    basic = _ext(cert, x509.BasicConstraints)
    features = _ext(cert, x509.TLSFeature)
    try:
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except UnsupportedAlgorithm:
        sig_hash = None
    sig_name = getattr(cert.signature_algorithm_oid, "_name", cert.signature_algorithm_oid.dotted_string)
    return CertificateInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial_hex=f"{cert.serial_number:X}",
        san_dns=san.get_values_for_type(x509.DNSName) if san else [],
        san_ip=[str(ip) for ip in san.get_values_for_type(x509.IPAddress)] if san else [],
        key_type=key_type,
        key_bits=key_bits,
        key_curve=curve,
        rsa_exponent=exponent,
        signature_algorithm=sig_name,
        signature_hash=sig_hash,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        days_until_expiry=(cert.not_valid_after_utc - now).days,
        is_self_signed=cert.issuer == cert.subject,
        is_ca=bool(basic and basic.ca),
        ocsp_urls=[d.access_location.value for d in aia or []
                   if d.access_method == AuthorityInformationAccessOID.OCSP],
        crl_urls=[n.value for dp in crl or [] for n in dp.full_name or []
                  if isinstance(n, x509.UniformResourceIdentifier)],
        sct_count=len(list(scts)) if scts else 0,
        must_staple=bool(features and x509.TLSFeatureType.status_request in features),
        fingerprint_sha256=hashlib.sha256(der).hexdigest(),
    )


def _common_name(cert: x509.Certificate) -> str | None:
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    value = attrs[0].value if attrs else None
    return value if isinstance(value, str) else None


def hostname_matches(host: str, san_dns: list[str], san_ip: list[str], common_name: str | None) -> bool:
    """RFC 6125 matching: SAN takes precedence over CN; wildcard covers exactly one left-most label."""
    try:
        ip = ipaddress.ip_address(host)
        return any(ipaddress.ip_address(s) == ip for s in san_ip)
    except ValueError:
        pass
    target = host.lower().rstrip(".")
    names = san_dns or ([common_name] if common_name else [])
    for name in names:
        pattern = name.lower().rstrip(".")
        if pattern == target:
            return True
        if pattern.startswith("*.") and "." in target:
            label, rest = target.split(".", 1)
            if label and rest == pattern[2:] and "." in rest:
                return True
    return False


@cache
def _store(extra_ca: Path | None) -> Store:
    pem = Path(certifi.where()).read_bytes()
    if extra_ca:
        pem += b"\n" + extra_ca.read_bytes()
    with warnings.catch_warnings():
        # certifi ships a legacy root with a non-positive serial number; it is still a valid trust anchor.
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        return Store(x509.load_pem_x509_certificates(pem))


def assess_trust(chain_der: list[bytes], host: str, now: datetime, extra_ca: Path | None = None) -> TrustResult:
    if not chain_der:
        return TrustResult(trusted=None, hostname_match=None, reason="no_certificate")
    certs = [x509.load_der_x509_certificate(d) for d in chain_der]
    leaf = certs[0]
    leaf_info = describe(chain_der[0], now)
    name_ok = hostname_matches(host, leaf_info.san_dns, leaf_info.san_ip, _common_name(leaf))

    if any(c.not_valid_after_utc < now for c in certs):
        return TrustResult(trusted=False, hostname_match=name_ok, reason="expired")
    if any(c.not_valid_before_utc > now for c in certs):
        return TrustResult(trusted=False, hostname_match=name_ok, reason="not_yet_valid")

    # Verify the chain against a name the certificate does carry, so a hostname mismatch is reported
    # separately from chain trust.
    subject: x509.GeneralName
    try:
        subject = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        subject = x509.DNSName(host)
    if not name_ok and leaf_info.san_dns:
        alts = sorted(leaf_info.san_dns, key=lambda n: n.startswith("*."))
        subject = x509.DNSName(alts[0].replace("*.", "a.", 1))
    try:
        verifier = PolicyBuilder().store(_store(extra_ca)).time(now).build_server_verifier(subject)
        verifier.verify(leaf, certs[1:])
        return TrustResult(trusted=True, hostname_match=name_ok)
    except VerificationError as exc:
        if len(certs) == 1 and leaf.issuer == leaf.subject:
            reason = "self_signed"
        elif certs[-1].issuer != certs[-1].subject:
            reason = "incomplete_chain_or_untrusted"
        else:
            reason = "untrusted_root"
        return TrustResult(trusted=False, hostname_match=name_ok, reason=reason, detail=str(exc))
    except ValueError as exc:  # unsupported name type / malformed certificate
        return TrustResult(trusted=None, hostname_match=name_ok, reason="verification_error", detail=str(exc))


def _family(key_type: str) -> str:
    return {"EC": "ECDSA", "Ed25519": "EdDSA", "Ed448": "EdDSA"}.get(key_type, key_type)


def _chain_order_ok(chain_der: list[bytes]) -> bool:
    certs = [x509.load_der_x509_certificate(d) for d in chain_der]
    return all(certs[i].issuer == certs[i + 1].subject for i in range(len(certs) - 1))


def _raw_chain(conn: ConnFactory, sni: str | None, version: ProtocolVersion,
               auths: tuple[str, ...]) -> Accepted | None:
    suites = [s.code for s in suites_for(version) if s.auth in auths][:MAX_SUITES_PER_HELLO]
    if not suites:
        return None
    params = HelloParams(version=version, cipher_suites=suites, sni=sni,
                         extra_extensions=[ext.status_request(), ext.signed_certificate_timestamp()])
    outcome = probe(conn, params, ReadUntil.HELLO_DONE)
    if isinstance(outcome, Accepted) and outcome.certificates:
        return outcome
    return None


def _ssl_chain(conn: ConnFactory, sni: str | None) -> list[bytes]:
    """TLS 1.3-only servers encrypt the Certificate message: use a real handshake (verification off)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock: socket.socket = conn()
    with ctx.wrap_socket(sock, server_hostname=sni) as tls:
        return list(tls.get_unverified_chain())


def retrieve_certificates(conn: ConnFactory, host: str, sni: str | None, offered: list[ProtocolVersion],
                          extra_ca: Path | None = None) -> CertificateResult:
    now = datetime.now(UTC)
    legacy = [v for v in offered if v in (ProtocolVersion.TLS10, ProtocolVersion.TLS11, ProtocolVersion.TLS12,
                                          ProtocolVersion.SSL3)]
    chains: list[CertificateChainResult] = []
    seen: set[str] = set()
    if legacy:
        version = legacy[-1]
        for family, auths in KEY_FAMILIES.items():
            accepted = _raw_chain(conn, sni, version, auths)
            if accepted is None:
                continue
            der = accepted.certificates
            fingerprint = hashlib.sha256(der[0]).hexdigest()
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            chains.append(CertificateChainResult(
                source="raw_handshake", key_family=family,
                chain=[describe(d, now) for d in der],
                trust=assess_trust(der, host, now, extra_ca),
                chain_order_ok=_chain_order_ok(der),
                ocsp_stapled=accepted.ocsp_response is not None,
            ))
    elif ProtocolVersion.TLS13 in offered:
        der = _ssl_chain(conn, sni)
        if der:
            chains.append(CertificateChainResult(
                source="ssl_module", key_family=_family(describe(der[0], now).key_type),
                chain=[describe(d, now) for d in der],
                trust=assess_trust(der, host, now, extra_ca),
                chain_order_ok=_chain_order_ok(der),
            ))
    return CertificateResult(chains=chains)
