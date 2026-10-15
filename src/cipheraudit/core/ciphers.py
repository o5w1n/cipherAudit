"""Core 2 - cipher suite enumeration (PRD CI-1..CI-6).

Elimination loop: offer every remaining suite, record the server's pick, remove it, repeat until
the server refuses. One probe per accepted suite instead of one per candidate.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from cipheraudit.data import CipherSuite, cipher_suites, named_groups, suites_for
from cipheraudit.models.results import CipherInfo, CipherResult, GroupResult, ProtocolCiphers
from cipheraudit.wire.client_hello import HelloParams
from cipheraudit.wire.constants import ProtocolVersion
from cipheraudit.wire.handshake import (
    Accepted,
    Closed,
    ConnFactory,
    HelloRetry,
    ProbeOutcome,
    ReadUntil,
    Rejected,
    probe,
)
from cipheraudit.wire.records import WireFormatError
from cipheraudit.wire.server_msgs import parse_dhe_params, parse_ecdhe_named_curve

MAX_SUITES_PER_HELLO = 127


def cipher_info(suite: CipherSuite) -> CipherInfo:
    return CipherInfo(
        code=suite.code, iana=suite.iana, openssl=suite.openssl, category=suite.category, kx=suite.kx,
        auth=suite.auth, enc=suite.enc, bits=suite.bits, block_bits=suite.block_bits, mode=suite.mode,
        mac=suite.mac, fs=suite.fs, aead=suite.aead, export=suite.export,
    )


def _is_chacha(code: int) -> bool:
    suite = cipher_suites().get(code)
    return suite is not None and suite.enc == "CHACHA20"


def _chacha_last(codes: Sequence[int]) -> list[int]:
    """Listing ChaCha20 first can trigger a server's prioritize-ChaCha rule and distort its order."""
    return [c for c in codes if not _is_chacha(c)] + [c for c in codes if _is_chacha(c)]


@dataclass
class _Selection:
    code: int | None
    conclusive: bool


def _selected(outcome: ProbeOutcome, version: ProtocolVersion) -> _Selection:
    if isinstance(outcome, Accepted):
        if outcome.server_hello.version != version:
            return _Selection(None, True)
        return _Selection(outcome.server_hello.cipher_suite, True)
    if isinstance(outcome, HelloRetry):
        return _Selection(outcome.hrr.cipher_suite if version == ProtocolVersion.TLS13 else None, True)
    return _Selection(None, isinstance(outcome, Rejected | Closed))


class CipherProber:
    def __init__(self, conn: ConnFactory, sni: str | None) -> None:
        self._conn = conn
        self._sni = sni

    def pick(self, version: ProtocolVersion, codes: Sequence[int],
             groups: list[int] | None = None) -> _Selection:
        params = HelloParams(version=version, cipher_suites=list(codes), sni=self._sni, supported_groups=groups)
        return _selected(probe(self._conn, params), version)

    def eliminate(self, version: ProtocolVersion, codes: Sequence[int]) -> tuple[list[int], bool]:
        """Return (accepted codes in pick order, complete)."""
        remaining = _chacha_last(codes)
        accepted: list[int] = []
        while remaining:
            sel = self.pick(version, remaining)
            if sel.code is None:
                return accepted, sel.conclusive
            if sel.code not in remaining:  # server chose something we did not offer
                return accepted, False
            accepted.append(sel.code)
            remaining.remove(sel.code)
        return accepted, True

    def enumerate(self, version: ProtocolVersion) -> ProtocolCiphers:
        candidates = [s.code for s in suites_for(version, include_special=True)]
        chunks = [candidates[i:i + MAX_SUITES_PER_HELLO] for i in range(0, len(candidates), MAX_SUITES_PER_HELLO)]
        accepted: list[int] = []
        complete = True
        for chunk in chunks:
            found, ok = self.eliminate(version, chunk)
            accepted.extend(found)
            complete = complete and ok

        server_order = self._server_order(version, accepted)
        if server_order and len(chunks) > 1 and len(accepted) <= MAX_SUITES_PER_HELLO:
            # Picks from separate chunks are not comparable; re-run over the accepted set for the true order.
            reordered, ok = self.eliminate(version, accepted)
            if ok and set(reordered) == set(accepted):
                accepted = reordered

        suites = cipher_suites()
        return ProtocolCiphers(
            protocol=version,
            ciphers=[cipher_info(suites[c]) for c in accepted],
            server_order=server_order,
            complete=complete,
            chacha_priority=self._chacha_priority(version, accepted) if server_order else None,
        )

    def _server_order(self, version: ProtocolVersion, accepted: list[int]) -> bool | None:
        if len(accepted) < 2:
            return None
        offer = _chacha_last(accepted)
        forward = self.pick(version, offer)
        reverse = self.pick(version, list(reversed(offer)))
        if forward.code is None or reverse.code is None:
            return None
        return forward.code == reverse.code

    def _chacha_priority(self, version: ProtocolVersion, accepted: list[int]) -> bool | None:
        if not accepted or _is_chacha(accepted[0]):
            return None
        chacha = next((c for c in accepted if _is_chacha(c)), None)
        if chacha is None:
            return None
        sel = self.pick(version, [chacha, accepted[0]])
        return None if sel.code is None else sel.code == chacha


def _group_names(ids: list[int]) -> list[str]:
    groups = named_groups()
    return [groups[g].name if g in groups else f"0x{g:04X}" for g in ids]


def probe_tls13_groups(conn: ConnFactory, sni: str | None, tls13_suites: list[int]) -> GroupResult:
    """Offer supported_groups with an empty key_share; the server must HelloRetry naming a group it supports."""
    remaining = [g.id for g in named_groups().values() if not g.obsolete]
    found: list[int] = []
    complete = True
    while remaining:
        params = HelloParams(version=ProtocolVersion.TLS13, cipher_suites=tls13_suites, sni=sni,
                             supported_groups=remaining, key_shares=[])
        outcome = probe(conn, params)
        group = outcome.hrr.selected_group if isinstance(outcome, HelloRetry) else None
        if group is None or group not in remaining:
            complete = isinstance(outcome, Rejected | Closed)
            break
        found.append(group)
        remaining.remove(group)
    return GroupResult(protocol=ProtocolVersion.TLS13, groups=found, names=_group_names(found), complete=complete)


def probe_tls12_curves(conn: ConnFactory, sni: str | None, version: ProtocolVersion,
                       ecdhe_suites: list[int]) -> GroupResult:
    """Offer ECDHE suites with a shrinking supported_groups list; read each curve from ServerKeyExchange.

    With an ECDSA certificate, TLS 1.2 servers refuse a hello whose groups omit the certificate's curve.
    That curve is pinned at the end of every offer once it has been found. If the server then falls back
    to the pin, curves it ranks below the pin cannot be distinguished, and the result is marked incomplete.
    """
    remaining = [g.id for g in named_groups().values() if g.kind == "ec" and not g.obsolete]
    found: list[int] = []
    pin: int | None = None
    complete = True
    while remaining:
        offer = remaining + ([pin] if pin is not None and pin not in remaining else [])
        params = HelloParams(version=version, cipher_suites=ecdhe_suites, sni=sni, supported_groups=offer)
        outcome = probe(conn, params, ReadUntil.HELLO_DONE)
        curve: int | None = None
        if isinstance(outcome, Accepted) and outcome.server_key_exchange is not None:
            if pin is None:
                pin = _cert_curve(outcome.certificates)
            try:
                curve = parse_ecdhe_named_curve(outcome.server_key_exchange)
            except WireFormatError:
                complete = False
                break
        elif not isinstance(outcome, Rejected | Closed):
            complete = False
            break
        if curve is not None and curve in remaining:
            found.append(curve)
            remaining.remove(curve)
            continue
        if curve is not None and curve == pin:
            complete = False
        break
    return GroupResult(protocol=version, groups=found, names=_group_names(found), complete=complete)


_CURVE_IDS = {"secp256r1": 23, "secp384r1": 24, "secp521r1": 25}


def _cert_curve(certificates: list[bytes]) -> int | None:
    if not certificates:
        return None
    try:
        key = x509.load_der_x509_certificate(certificates[0]).public_key()
    except ValueError:
        return None
    return _CURVE_IDS.get(key.curve.name) if isinstance(key, ec.EllipticCurvePublicKey) else None


def probe_dh_params(conn: ConnFactory, sni: str | None, version: ProtocolVersion,
                    dhe_suites: list[int]) -> tuple[int, str] | None:
    params = HelloParams(version=version, cipher_suites=dhe_suites, sni=sni)
    outcome = probe(conn, params, ReadUntil.HELLO_DONE)
    if not isinstance(outcome, Accepted) or outcome.server_key_exchange is None:
        return None
    try:
        dh = parse_dhe_params(outcome.server_key_exchange)
    except WireFormatError:
        return None
    return dh.prime_bits, hashlib.sha256(dh.prime).hexdigest()


def enumerate_ciphers(conn: ConnFactory, sni: str | None, offered: list[ProtocolVersion]) -> CipherResult:
    prober = CipherProber(conn, sni)
    tls_versions = [v for v in offered if v != ProtocolVersion.SSL2]
    per_protocol = [prober.enumerate(v) for v in tls_versions]
    result = CipherResult(per_protocol=per_protocol)

    tls13 = next((pc for pc in per_protocol if pc.protocol == ProtocolVersion.TLS13), None)
    if tls13 and tls13.ciphers:
        result.groups.append(probe_tls13_groups(conn, sni, [c.code for c in tls13.ciphers]))

    legacy = [pc for pc in per_protocol if pc.protocol != ProtocolVersion.TLS13 and pc.ciphers]
    if legacy:
        best = legacy[-1]
        ecdhe = [c.code for c in best.ciphers if c.kx == "ECDHE"]
        if ecdhe:
            result.groups.append(probe_tls12_curves(conn, sni, best.protocol, ecdhe))
        dhe = [c.code for c in best.ciphers if c.kx in ("DHE", "DHE_EXPORT") and not c.export]
        dh = probe_dh_params(conn, sni, best.protocol, dhe) if dhe else None
        if dh:
            result.dh_prime_bits, result.dh_prime_sha256 = dh
    return result
