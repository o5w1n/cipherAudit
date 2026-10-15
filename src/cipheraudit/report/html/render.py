"""Standalone HTML report (PRD RE-5): one file, inline CSS, no external assets."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from cipheraudit.evaluation.scoring import METHOD
from cipheraudit.models.findings import Report, Severity

TOP_ISSUES = 3


def render_html(report: Report) -> str:
    env = Environment(loader=PackageLoader("cipheraudit.report", "html"), autoescape=select_autoescape(["j2"]))
    top = [f for f in report.findings if f.severity != Severity.INFO][:TOP_ISSUES]
    return env.get_template("report.html.j2").render(report=report, scan=report.scan, top=top, method=METHOD)


def write_html(report: Report, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report), encoding="utf-8")
