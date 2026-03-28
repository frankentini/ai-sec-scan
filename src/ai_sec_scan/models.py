"""Data models for scan findings and results."""

from __future__ import annotations

import enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting (higher is more severe)."""
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]

    @property
    def sarif_level(self) -> str:
        """Map to SARIF result level."""
        return {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "warning",
            Severity.INFO: "note",
        }[self]

    @property
    def color(self) -> str:
        """Rich color for terminal display."""
        return {
            Severity.CRITICAL: "bright_red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim",
        }[self]


class Finding(BaseModel):
    """A single security finding."""

    file_path: str = Field(description="Path to the file containing the finding")
    line_start: int = Field(ge=1, description="Starting line number")
    line_end: Optional[int] = Field(default=None, ge=1, description="Ending line number")
    severity: Severity = Field(description="Severity level")
    title: str = Field(description="Short title of the finding")
    description: str = Field(description="Detailed description of the vulnerability")
    recommendation: str = Field(description="How to fix the vulnerability")
    cwe_id: Optional[str] = Field(default=None, description="CWE identifier (e.g. CWE-89)")
    owasp_category: Optional[str] = Field(
        default=None, description="OWASP Top 10 category (e.g. A03:2021)"
    )

    def __str__(self) -> str:
        """Human-readable one-line summary for logging and debugging."""
        location = f"{self.file_path}:{self.line_start}"
        if self.line_end is not None:
            location += f"-{self.line_end}"
        return f"[{self.severity.value.upper()}] {self.title} ({location})"


class ScanResult(BaseModel):
    """Aggregated result of a security scan."""

    findings: list[Finding] = Field(default_factory=list)
    files_scanned: int = Field(default=0, ge=0)
    scan_duration: float = Field(default=0.0, ge=0.0)
    provider: str = Field(description="LLM provider used")
    model: str = Field(description="Model name used")

    @property
    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        """Group findings by severity level."""
        grouped: dict[Severity, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.severity, []).append(finding)
        return grouped

    @property
    def sorted_findings(self) -> list[Finding]:
        """Findings sorted by severity (most severe first)."""
        return sorted(self.findings, key=lambda f: f.severity.rank, reverse=True)

    def filter_by_severity(self, min_severity: str) -> "ScanResult":
        """Return a new ScanResult with only findings at or above *min_severity*.

        Args:
            min_severity: Minimum severity string (e.g. ``"high"``).

        Returns:
            A new ``ScanResult`` containing only the matching findings.
        """
        min_rank = Severity(min_severity).rank
        filtered = [f for f in self.findings if f.severity.rank >= min_rank]
        return self.model_copy(update={"findings": filtered})
