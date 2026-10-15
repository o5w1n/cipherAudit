"""TCP connections to the scan target, with timeouts and rate limiting."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

from cipheraudit.net.ratelimit import RateLimiter


class ConnectError(Exception):
    """The target could not be reached (DNS failure, refused, unreachable, timeout)."""


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    ip: str


def resolve(host: str, port: int) -> Endpoint:
    try:
        ipaddress.ip_address(host)
        return Endpoint(host, port, host)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ConnectError(f"cannot resolve {host}: {exc.strerror}") from exc
    # Prefer IPv4: some hosts publish AAAA records they do not serve TLS on.
    infos.sort(key=lambda info: info[0] != socket.AF_INET)
    return Endpoint(host, port, str(infos[0][4][0]))


class Connector:
    """Opens rate-limited TCP sockets to one endpoint. Use as the wire layer's conn_factory."""

    def __init__(self, endpoint: Endpoint, limiter: RateLimiter,
                 connect_timeout: float = 5.0, read_timeout: float = 5.0) -> None:
        self.endpoint = endpoint
        self.read_timeout = read_timeout
        self._limiter = limiter
        self._connect_timeout = connect_timeout

    def __call__(self) -> socket.socket:
        self._limiter.acquire()
        try:
            sock = socket.create_connection((self.endpoint.ip, self.endpoint.port), timeout=self._connect_timeout)
        except TimeoutError as exc:
            raise ConnectError(f"connection to {self.endpoint.ip}:{self.endpoint.port} timed out") from exc
        except OSError as exc:
            raise ConnectError(f"cannot connect to {self.endpoint.ip}:{self.endpoint.port}: {exc}") from exc
        sock.settimeout(self.read_timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock
