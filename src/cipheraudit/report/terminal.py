"""Terminal summary (PRD RE-4): score banner, then findings sorted by severity, plain language first."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cipheraudit.models.findings import Report, Severity

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
GRADE_STYLE = {"A": "bold green", "B": "green", "C": "yellow", "D": "yellow", "E": "red", "F": "bold red"}


def render(report: Report, console: Console, verbose: bool = False) -> None:
    scan = report.scan
    banner = Text.assemble(
        ("Overall: ", "bold"), (f"{report.score}/100 ", "bold"),
        (f"(Grade {report.grade})", GRADE_STYLE.get(report.grade, "bold")),
    )
    if report.scoring.cap_reason:
        banner.append(f"\nCapped at {report.scoring.cap} by: {report.scoring.cap_reason}", style="dim")
    pq = {True: "ready", False: "not ready", None: "unknown"}[report.pq_ready]
    banner.append(f"\nPost-quantum key exchange: {pq}", style="dim")
    console.print(Panel(banner, title=f"{scan.target.host}:{scan.target.port} ({scan.target.ip})", expand=False))

    if scan.protocols:
        offered = ", ".join(v.value for v in scan.protocols.offered()) or "none"
        console.print(f"[bold]Protocols:[/bold] {offered}")
        if scan.protocols.alpn_selected:
            console.print(f"[bold]ALPN:[/bold] {scan.protocols.alpn_selected}")

    if not report.findings:
        console.print("\n[green]No issues found.[/green]")
    for finding in report.findings:
        console.print()
        label = Text(f" {finding.severity.value.upper():<8}", style=SEVERITY_STYLE[finding.severity])
        console.print(Text.assemble(label, " ", (finding.title, "bold")))
        console.print(f"   {finding.plain}", highlight=False)
        console.print(f"   [dim]{'; '.join(finding.nist)}[/dim]", highlight=False)
        console.print(f"   [bold]Fix:[/bold] {finding.remediation}", highlight=False)
        if verbose:
            console.print(f"   [dim]Detail: {finding.technical}[/dim]", highlight=False)

    if verbose:
        _render_details(report, console)
    if scan.errors:
        console.print()
        for error in scan.errors:
            console.print(f"[yellow]Scan error:[/yellow] {error}", highlight=False)


def _render_details(report: Report, console: Console) -> None:
    scan = report.scan
    if scan.ciphers:
        for pc in scan.ciphers.per_protocol:
            order = {True: "server order", False: "client order", None: "order unknown"}[pc.server_order]
            table = Table(title=f"{pc.protocol.value} cipher suites ({order})", title_justify="left")
            table.add_column("IANA name", overflow="fold")
            table.add_column("OpenSSL name", overflow="fold")
            table.add_column("Category")
            table.add_column("Bits", justify="right")
            for c in pc.ciphers:
                table.add_row(c.iana, c.openssl or "-", c.category, str(c.bits))
            console.print(table)
        for g in scan.ciphers.groups:
            note = "" if g.complete else " (may be incomplete)"
            console.print(f"[bold]{g.protocol.value} groups{note}:[/bold] {', '.join(g.names) or 'none'}")
    if scan.vulns:
        table = Table(title="Vulnerability checks", title_justify="left")
        table.add_column("Check")
        table.add_column("Result")
        table.add_column("Evidence")
        for v in scan.vulns:
            table.add_row(v.id, v.status, v.evidence)
        console.print(table)
