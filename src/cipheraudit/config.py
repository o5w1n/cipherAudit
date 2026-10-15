"""Scan options (TRD §7)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScanOptions:
    host: str
    port: int = 443
    sni: str | None = None
    timeout: float = 5.0
    rate: float = 4.0
    run_ciphers: bool = True
    run_cert: bool = True
    run_vulns: bool = True
    active_vulns: bool = True
    extra_ca: Path | None = None

    @property
    def server_name(self) -> str | None:
        """SNI to send: explicit override, else the host name (never an IP literal)."""
        if self.sni:
            return self.sni
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            return self.host
        return None
