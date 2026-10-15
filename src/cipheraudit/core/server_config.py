"""Core 3 - server configuration facts (PRD CE-6, CE-7) plus TLS_FALLBACK_SCSV."""

from __future__ import annotations

import contextlib
import ssl
from collections.abc import Callable
from urllib.parse import urlsplit

import httpx

from cipheraudit.core.protocols import hello_for
from cipheraudit.models.results import HstsInfo, HttpHeadersResult, ServerConfigResult
from cipheraudit.net.connection import ConnectError
from cipheraudit.wire import extensions as ext
from cipheraudit.wire.client_hello import HelloParams
from cipheraudit.wire.constants import TLS_FALLBACK_SCSV, ExtensionType, ProtocolVersion
from cipheraudit.wire.handshake import Accepted, ConnFactory, Rejected, probe

LEGACY_ORDER = [ProtocolVersion.SSL3, ProtocolVersion.TLS10, ProtocolVersion.TLS11, ProtocolVersion.TLS12]
INAPPROPRIATE_FALLBACK = 86
MAX_REDIRECTS = 3


def _extension_echo(conn: ConnFactory, sni: str | None, version: ProtocolVersion, result: ServerConfigResult) -> None:
    base = hello_for(version, sni)
    params = HelloParams(version=version, cipher_suites=base.cipher_suites, sni=sni, renegotiation_scsv=False,
                         extra_extensions=[ext.renegotiation_info(), ext.extended_master_secret()])
    outcome = probe(conn, params)
    if isinstance(outcome, Accepted):
        hello = outcome.server_hello
        result.secure_renegotiation = hello.has_extension(ExtensionType.RENEGOTIATION_INFO)
        result.extended_master_secret = hello.has_extension(ExtensionType.EXTENDED_MASTER_SECRET)


def _fallback_scsv(conn: ConnFactory, sni: str | None, offered: list[ProtocolVersion]) -> bool | None:
    """Send a hello one version below the server's best with TLS_FALLBACK_SCSV (RFC 7507)."""
    legacy = [v for v in LEGACY_ORDER if v in offered]
    if ProtocolVersion.TLS13 in offered:
        lower = legacy[-1] if legacy else None
    else:
        lower = legacy[-2] if len(legacy) >= 2 else None
    if lower is None:
        return None
    base = hello_for(lower, sni)
    params = HelloParams(version=lower, cipher_suites=[*base.cipher_suites, TLS_FALLBACK_SCSV], sni=sni)
    outcome = probe(conn, params)
    if isinstance(outcome, Rejected):
        return outcome.alert.description == INAPPROPRIATE_FALLBACK
    if isinstance(outcome, Accepted):
        return False
    return None


def _ssl_context(tickets: bool) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if not tickets:
        ctx.options |= ssl.OP_NO_TICKET
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2  # TLS 1.3 resumption is ticket-only
    return ctx


def _drain(tls: ssl.SSLSocket) -> None:
    """TLS 1.3 tickets arrive after the handshake; a short read lets the client process them."""
    tls.settimeout(1.0)
    with contextlib.suppress(TimeoutError, ssl.SSLError, OSError):
        tls.recv(1)


def _resumes(conn: ConnFactory, sni: str | None, tickets: bool) -> bool | None:
    ctx = _ssl_context(tickets)
    try:
        with ctx.wrap_socket(conn(), server_hostname=sni) as first:
            _drain(first)
            session = first.session
        if session is None:
            return False
        if not tickets and not session.id:
            return False
        if tickets and not session.has_ticket:
            return False
        with ctx.wrap_socket(conn(), server_hostname=sni, session=session) as second:
            return second.session_reused
    except (OSError, ssl.SSLError, ConnectError):
        return None


def _parse_hsts(value: str | None) -> HstsInfo:
    if value is None:
        return HstsInfo(present=False)
    max_age: int | None = None
    directives = [d.strip() for d in value.split(";") if d.strip()]
    for directive in directives:
        name, _, arg = directive.partition("=")
        if name.strip().lower() == "max-age":
            try:
                max_age = int(arg.strip().strip('"'))
            except ValueError:
                max_age = None
    lowered = {d.lower() for d in directives}
    return HstsInfo(present=True, max_age=max_age, include_subdomains="includesubdomains" in lowered,
                    preload="preload" in lowered, raw=value)


def fetch_http_headers(host: str, port: int, timeout: float,
                       before_request: Callable[[], None] = lambda: None) -> HttpHeadersResult:
    """One GET /, following up to 3 redirects on the same host only (PRD CE-7)."""
    url = f"https://{host}/" if port == 443 else f"https://{host}:{port}/"
    try:
        with httpx.Client(verify=False, timeout=timeout, follow_redirects=False) as client:
            before_request()
            response = client.get(url, headers={"User-Agent": "cipheraudit"})
            for _ in range(MAX_REDIRECTS):
                location = response.headers.get("location")
                if not response.is_redirect or not location:
                    break
                target = response.url.join(location)
                if urlsplit(str(target)).hostname != urlsplit(url).hostname or target.scheme != "https":
                    break
                before_request()
                response = client.get(target)
    except httpx.HTTPError as exc:
        error = str(exc) or type(exc).__name__
        return HttpHeadersResult(url=url, status=None, hsts=HstsInfo(present=False), error=error)
    headers = response.headers
    return HttpHeadersResult(
        url=str(response.url),
        status=response.status_code,
        hsts=_parse_hsts(headers.get("strict-transport-security")),
        x_content_type_options=headers.get("x-content-type-options"),
        x_frame_options=headers.get("x-frame-options"),
        content_security_policy="content-security-policy" in headers,
        server_banner=headers.get("server"),
    )


def probe_server_config(conn: ConnFactory, host: str, port: int, sni: str | None,
                        offered: list[ProtocolVersion], timeout: float,
                        before_http: Callable[[], None] | None = None) -> ServerConfigResult:
    result = ServerConfigResult()
    legacy = [v for v in LEGACY_ORDER if v in offered and v != ProtocolVersion.SSL3]
    if legacy:
        _extension_echo(conn, sni, legacy[-1], result)
        result.session_resumption_id = _resumes(conn, sni, tickets=False)
    if legacy or ProtocolVersion.TLS13 in offered:
        result.session_resumption_ticket = _resumes(conn, sni, tickets=True)
    result.fallback_scsv = _fallback_scsv(conn, sni, offered)
    if before_http is not None:
        result.http = fetch_http_headers(host, port, timeout, before_http)
    return result

