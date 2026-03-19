"""Tests for output rendering helpers."""

from __future__ import annotations

import json

from ai_sec_scan.models import Finding, ScanResult, Severity
from ai_sec_scan.output import render_github_annotations, render_json


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


class TestRenderJson:
    def test_empty_result(self) -> None:
        result = _make_result([])
        output = render_json(result)
        data = json.loads(output)
        assert data["findings"] == []
        assert data["files_scanned"] == 1
        assert data["provider"] == "test"

    def test_findings_included(self) -> None:
        finding = Finding(
            file_path="app.py",
            line_start=42,
            line_end=44,
            severity=Severity.CRITICAL,
            title="RCE",
            description="Remote code execution via eval()",
            recommendation="Remove eval()",
            cwe_id="CWE-94",
            owasp_category="A03:2021",
        )
        output = render_json(_make_result([finding]))
        data = json.loads(output)
        assert len(data["findings"]) == 1
        f = data["findings"][0]
        assert f["file_path"] == "app.py"
        assert f["line_start"] == 42
        assert f["line_end"] == 44
        assert f["severity"] == "critical"
        assert f["cwe_id"] == "CWE-94"
        assert f["owasp_category"] == "A03:2021"

    def test_output_is_valid_json(self) -> None:
        findings = [
            Finding(
                file_path="a.py",
                line_start=1,
                severity=Severity.HIGH,
                title="Issue A",
                description="desc",
                recommendation="fix",
            ),
            Finding(
                file_path="b.py",
                line_start=5,
                severity=Severity.LOW,
                title="Issue B",
                description="desc",
                recommendation="fix",
            ),
        ]
        output = render_json(_make_result(findings))
        data = json.loads(output)
        assert isinstance(data, dict)
        assert data["scan_duration"] == 0.1
        assert data["model"] == "test-model"

    def test_optional_fields_null_when_absent(self) -> None:
        finding = Finding(
            file_path="x.py",
            line_start=1,
            severity=Severity.INFO,
            title="Tip",
            description="Consider logging",
            recommendation="Add logging",
        )
        output = render_json(_make_result([finding]))
        data = json.loads(output)
        f = data["findings"][0]
        assert f["line_end"] is None
        assert f["cwe_id"] is None
        assert f["owasp_category"] is None


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
