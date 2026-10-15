"""Judgments: findings, score and the final report (TRD §6)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from cipheraudit.models.results import ScanResult


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    plain: str
    technical: str
    nist: list[str]
    remediation: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    deduct: int
    cap: int | None = None


class ScoreBreakdown(BaseModel):
    base: int = 100
    total_deductions: int
    cap: int | None
    cap_reason: str | None
    score: int
    grade: str


class Authorization(BaseModel):
    method: Literal["interactive_prompt", "flag"]
    confirmed_at: str


class Report(BaseModel):
    schema_version: str = "0.1"
    tool_version: str
    authorization: Authorization
    scan: ScanResult
    findings: list[Finding]
    score: int
    grade: str
    scoring: ScoreBreakdown
    pq_ready: bool | None
    pq_explanation: str
