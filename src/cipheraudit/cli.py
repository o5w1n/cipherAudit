"""Command-line interface (TRD §7). Exit codes: 0 done, 1 scan error, 2 not authorized, 3 unreachable."""

from __future__ import annotations

import io
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from cipheraudit import __version__
from cipheraudit.config import ScanOptions
from cipheraudit.models.findings import Authorization
from cipheraudit.orchestrator import STEPS, NoTLS, TargetUnreachable, build_report, run_scan
from cipheraudit.report.html.render import write_html
from cipheraudit.report.json_out import write_json
from cipheraudit.report.terminal import render

EXIT_OK, EXIT_ERROR, EXIT_UNAUTHORIZED, EXIT_UNREACHABLE = 0, 1, 2, 3

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Audit the TLS configuration of a server.")
# A cp1252 stream (Windows NUL, legacy console) cannot encode the spinner or box glyphs; a crash there
# would abort the scan before the JSON/HTML report is written.
for _stream in (sys.stdout, sys.stderr):
    if isinstance(_stream, io.TextIOWrapper):
        _stream.reconfigure(errors="replace")
console = Console()
err = Console(stderr=True)


def parse_target(target: str) -> tuple[str, int]:
    """host, host:port, [v6]:port. Bare IPv6 addresses take the default port."""
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else 443
    if target.count(":") == 1:
        host, port = target.split(":")
        return host, int(port)
    return target, 443


def authorize(host: str, flag: bool) -> Authorization:
    """PRD X-1: no scan without explicit confirmation of permission."""
    now = datetime.now(UTC).isoformat(timespec="seconds")
    if flag:
        return Authorization(method="flag", confirmed_at=now)
    console.print("\n  [bold yellow]Only scan systems you own or have written permission to test.[/bold yellow]")
    answer = typer.prompt(f"  Do you have permission to scan {host}? [y/N]", default="", show_default=False)
    if answer.strip().lower() != "y":
        err.print("Not authorized; nothing was scanned.")
        raise typer.Exit(EXIT_UNAUTHORIZED)
    return Authorization(method="interactive_prompt", confirmed_at=now)


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="host or host:port")],
    i_have_permission: Annotated[bool, typer.Option(
        "--i-have-permission", help="Confirm authorization non-interactively (recorded in the report).")] = False,
    protocols: Annotated[bool, typer.Option("--protocols", help="Run protocol probing only.")] = False,
    ciphers: Annotated[bool, typer.Option("--ciphers", help="Run cipher enumeration.")] = False,
    cert: Annotated[bool, typer.Option("--cert", help="Run certificate and server configuration checks.")] = False,
    vulns: Annotated[bool, typer.Option("--vulns", help="Run vulnerability checks.")] = False,
    no_active_vulns: Annotated[bool, typer.Option(
        "--no-active-vulns", help="Derived vulnerability checks only; no extra probes.")] = False,
    sni: Annotated[str | None, typer.Option(help="Override the server name sent in SNI.")] = None,
    timeout: Annotated[float, typer.Option(help="Connect/read timeout in seconds.")] = 5.0,
    rate: Annotated[float, typer.Option(help="Max new connections per second.")] = 4.0,
    ca_file: Annotated[Path | None, typer.Option(
        help="Extra trusted CA certificates (PEM), e.g. for an internal CA.", exists=True, dir_okay=False)] = None,
    json_path: Annotated[Path | None, typer.Option("--json", help="Write the JSON report here.")] = None,
    html_path: Annotated[Path | None, typer.Option("--html", help="Write the HTML report here.")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show technical detail.")] = False,
) -> None:
    """Scan one TLS server. Protocol probing always runs; the other cores build on it."""
    try:
        host, port = parse_target(target)
    except ValueError:
        err.print(f"Invalid target: {target}")
        raise typer.Exit(EXIT_ERROR) from None
    if rate <= 0 or timeout <= 0:
        err.print("--rate and --timeout must be positive")
        raise typer.Exit(EXIT_ERROR)

    authorization = authorize(host, i_have_permission)
    selected = protocols or ciphers or cert or vulns
    options = ScanOptions(
        host=host, port=port, sni=sni, timeout=timeout, rate=rate,
        run_ciphers=ciphers or not selected, run_cert=cert or not selected, run_vulns=vulns or not selected,
        active_vulns=not no_active_vulns, extra_ca=ca_file,
    )

    console.print(f"\n  Scanning {host}:{port} ...")
    step_numbers = {name: i + 1 for i, name in enumerate(STEPS)}
    try:
        with console.status("") as status:
            def progress(step: str) -> None:
                status.update(f"  [{step_numbers[step]}/{len(STEPS)}] {step}")
            scan_result = run_scan(options, progress)
            progress(STEPS[-1])
            report = build_report(scan_result, authorization)
    except TargetUnreachable as exc:
        err.print(f"Target unreachable: {exc}")
        raise typer.Exit(EXIT_UNREACHABLE) from None
    except NoTLS as exc:
        err.print(f"No TLS service found: {exc}")
        raise typer.Exit(EXIT_ERROR) from None

    console.print()
    render(report, console, verbose)
    if json_path:
        write_json(report, json_path)
        console.print(f"\n  JSON report: {json_path}")
    if html_path:
        write_html(report, html_path)
        console.print(f"  HTML report: {html_path}")
    raise typer.Exit(EXIT_OK)


@app.command()
def version() -> None:
    """Print the cipherAudit version."""
    console.print(__version__)


if __name__ == "__main__":
    app()
