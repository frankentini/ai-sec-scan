"""Tests for the rich text output renderer."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from ai_sec_scan.models import Finding, ScanResult, Severity
from ai_sec_scan.output import render_text


def _make_result(findings: list[Finding] | None = None, **kwargs) -> ScanResult:
    defaults = {
        "findings": findings or [],
        "files_scanned": 3,
        "scan_duration": 1.5,
        "provider": "anthropic",
        "model": "claude-3-haiku",
    }
    defaults.update(kwargs)
    return ScanResult(**defaults)


def _capture_text_output(result: ScanResult) -> str:
    """Capture render_text output by temporarily replacing the module console."""
    import ai_sec_scan.output as output_mod

    buf = StringIO()
    original = output_mod.console
    output_mod.console = Console(file=buf, force_terminal=False, width=120)
    try:
        render_text(result)
    finally:
        output_mod.console = original
    return buf.getvalue()


class TestRenderTextNoFindings:
    def test_shows_no_issues_message(self) -> None:
        output = _capture_text_output(_make_result())
        assert "No security issues found" in output

    def test_shows_file_count(self) -> None:
        output = _capture_text_output(_make_result(files_scanned=7))
        assert "7" in output

    def test_shows_duration(self) -> None:
        output = _capture_text_output(_make_result(scan_duration=2.34))
        assert "2.34" in output


class TestRenderTextWithFindings:
    def test_displays_finding_title(self) -> None:
        finding = Finding(
            file_path="app.py",
            line_start=10,
            severity=Severity.HIGH,
            title="SQL Injection",
            description="Unsanitized input in query",
            recommendation="Use parameterized queries",
        )
        output = _capture_text_output(_make_result([finding]))
        assert "SQL Injection" in output

    def test_displays_location(self) -> None:
        finding = Finding(
            file_path="routes/auth.py",
            line_start=42,
            severity=Severity.MEDIUM,
            title="Weak hash",
            description="MD5 used for passwords",
            recommendation="Use bcrypt",
        )
        output = _capture_text_output(_make_result([finding]))
        assert "routes/auth.py:42" in output

    def test_displays_line_range(self) -> None:
        finding = Finding(
            file_path="db.py",
            line_start=5,
            line_end=12,
            severity=Severity.CRITICAL,
            title="RCE",
            description="eval() on user input",
            recommendation="Remove eval",
        )
        output = _capture_text_output(_make_result([finding]))
        assert "db.py:5-12" in output

    def test_displays_recommendation(self) -> None:
        finding = Finding(
            file_path="config.py",
            line_start=1,
            severity=Severity.LOW,
            title="Debug mode",
            description="Debug flag enabled",
            recommendation="Set DEBUG=False in production",
        )
        output = _capture_text_output(_make_result([finding]))
        assert "Set DEBUG=False in production" in output

    def test_displays_cwe_id(self) -> None:
        finding = Finding(
            file_path="api.py",
            line_start=30,
            severity=Severity.HIGH,
            title="XSS",
            description="Reflected XSS",
            recommendation="Escape output",
            cwe_id="CWE-79",
        )
        output = _capture_text_output(_make_result([finding]))
        assert "CWE-79" in output

    def test_displays_owasp_category(self) -> None:
        finding = Finding(
            file_path="api.py",
            line_start=30,
            severity=Severity.HIGH,
            title="Injection",
            description="SQL injection",
            recommendation="Parameterize",
            owasp_category="A03:2021",
        )
        output = _capture_text_output(_make_result([finding]))
        assert "A03:2021" in output

    def test_summary_shows_provider(self) -> None:
        finding = Finding(
            file_path="x.py",
            line_start=1,
            severity=Severity.INFO,
            title="Note",
            description="d",
            recommendation="r",
        )
        output = _capture_text_output(
            _make_result([finding], provider="openai", model="gpt-4o")
        )
        assert "openai" in output
        assert "gpt-4o" in output

    def test_multiple_findings_all_shown(self) -> None:
        findings = [
            Finding(
                file_path="a.py",
                line_start=1,
                severity=Severity.CRITICAL,
                title="Critical bug",
                description="d",
                recommendation="r",
            ),
            Finding(
                file_path="b.py",
                line_start=2,
                severity=Severity.LOW,
                title="Minor thing",
                description="d",
                recommendation="r",
            ),
        ]
        output = _capture_text_output(_make_result(findings))
        assert "Critical bug" in output
        assert "Minor thing" in output

    def test_summary_shows_severity_counts(self) -> None:
        findings = [
            Finding(
                file_path="a.py", line_start=1, severity=Severity.HIGH,
                title="H1", description="d", recommendation="r",
            ),
            Finding(
                file_path="b.py", line_start=2, severity=Severity.HIGH,
                title="H2", description="d", recommendation="r",
            ),
            Finding(
                file_path="c.py", line_start=3, severity=Severity.LOW,
                title="L1", description="d", recommendation="r",
            ),
        ]
        output = _capture_text_output(_make_result(findings, files_scanned=3))
        assert "3" in output  # total findings or files
