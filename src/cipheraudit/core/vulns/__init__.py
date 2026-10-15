"""Core 4 - vulnerability testing (PRD VU-1..VU-6)."""

from __future__ import annotations

from cipheraudit.core.vulns.compression import check_compression
from cipheraudit.core.vulns.derived import derived_checks
from cipheraudit.models.results import CipherResult, ProtocolResult, VulnResult
from cipheraudit.wire.handshake import ConnFactory

# Active checks for Heartbleed (VU-2), CCS injection (VU-3) and ROBOT (VU-5) are not in this build.
NOT_IMPLEMENTED = ("heartbleed", "ccs_injection", "robot")


def run_vulns(conn: ConnFactory, sni: str | None, protocols: ProtocolResult, ciphers: CipherResult | None,
              active: bool) -> list[VulnResult]:
    results = derived_checks(protocols, ciphers)
    if active:
        results.append(check_compression(conn, sni, protocols.offered()))
    else:
        results.append(VulnResult(id="crime", status="not_tested", evidence="active checks disabled"))
    results.extend(VulnResult(id=v, status="not_tested", evidence="check not implemented in this version")
                   for v in NOT_IMPLEMENTED)
    return results
