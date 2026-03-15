"""Tests for output rendering helpers."""

from __future__ import annotations

from ai_sec_scan.models import Finding, ScanResult, Severity
from ai_sec_scan.output import render_github_annotations


def _make_result(findings: list[Finding]) -> ScanResult:
    return ScanResult(
        findings=findings,
        files_scanned=1,
        scan_duration=0.1,
        provider="test",
        model="test-model",
    )


def test_render_github_annotations_levels() -> None:
    findings = [
        Finding(
            file_path="src/app.py",
            line_start=10,
            severity=Severity.HIGH,
            title="High issue",
            description="Description",
            recommendation="Fix it",
        ),
        Finding(
            file_path="src/lib.py",
            line_start=20,
            severity=Severity.LOW,
            title="Low issue",
            description="Description",
            recommendation="Fix it",
        ),
    ]
    output = render_github_annotations(_make_result(findings))
    lines = output.splitlines()
    assert lines[0].startswith("::error ")
    assert lines[1].startswith("::warning ")


def test_render_github_annotations_escape_values() -> None:
    finding = Finding(
        file_path="src/a,b:c.py",
        line_start=3,
        line_end=5,
        severity=Severity.MEDIUM,
        title="Issue",
        description="bad\nnewline",
        recommendation="fix",
    )
    output = render_github_annotations(_make_result([finding]))
    assert "file=src/a%2Cb%3Ac.py" in output
    assert "line=3" in output
    assert "endLine=5" in output
    assert "%0A" in output
