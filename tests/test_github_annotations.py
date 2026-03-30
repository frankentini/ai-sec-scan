"""Tests for GitHub Actions annotation output helpers."""

from __future__ import annotations

from ai_sec_scan.models import Finding, ScanResult, Severity
from ai_sec_scan.output import (
    _annotation_level,
    _escape_command_message,
    _escape_command_property,
    _to_github_annotation,
    render_github_annotations,
)


def _result_with(findings: list[Finding]) -> ScanResult:
    return ScanResult(
        findings=findings,
        files_scanned=len(findings),
        scan_duration=0.05,
        provider="test",
        model="test-model",
    )


class TestAnnotationLevel:
    def test_critical_maps_to_error(self) -> None:
        assert _annotation_level(Severity.CRITICAL) == "error"

    def test_high_maps_to_error(self) -> None:
        assert _annotation_level(Severity.HIGH) == "error"

    def test_medium_maps_to_warning(self) -> None:
        assert _annotation_level(Severity.MEDIUM) == "warning"

    def test_low_maps_to_warning(self) -> None:
        assert _annotation_level(Severity.LOW) == "warning"

    def test_info_maps_to_warning(self) -> None:
        assert _annotation_level(Severity.INFO) == "warning"


class TestEscapeCommandProperty:
    def test_colons_escaped(self) -> None:
        assert _escape_command_property("src:main.py") == "src%3Amain.py"

    def test_commas_escaped(self) -> None:
        assert _escape_command_property("a,b") == "a%2Cb"

    def test_percent_escaped(self) -> None:
        assert _escape_command_property("100%") == "100%25"

    def test_newlines_escaped(self) -> None:
        assert _escape_command_property("line1\nline2") == "line1%0Aline2"

    def test_carriage_return_escaped(self) -> None:
        assert _escape_command_property("a\rb") == "a%0Db"

    def test_plain_string_unchanged(self) -> None:
        assert _escape_command_property("src/app.py") == "src/app.py"


class TestEscapeCommandMessage:
    def test_percent_escaped(self) -> None:
        assert _escape_command_message("80% done") == "80%25 done"

    def test_newline_escaped(self) -> None:
        assert _escape_command_message("first\nsecond") == "first%0Asecond"

    def test_carriage_return_escaped(self) -> None:
        assert _escape_command_message("a\rb") == "a%0Db"

    def test_colons_not_escaped(self) -> None:
        # Colons are only escaped in properties, not messages
        assert _escape_command_message("key: value") == "key: value"


class TestToGithubAnnotation:
    def test_basic_format(self) -> None:
        finding = Finding(
            file_path="app.py",
            line_start=42,
            severity=Severity.HIGH,
            title="SQL Injection",
            description="Unsafe query",
            recommendation="Use parameterized queries",
        )
        line = _to_github_annotation(finding)
        assert line.startswith("::error ")
        assert "file=app.py" in line
        assert "line=42" in line
        assert "SQL Injection" in line

    def test_includes_end_line(self) -> None:
        finding = Finding(
            file_path="app.py",
            line_start=10,
            line_end=15,
            severity=Severity.MEDIUM,
            title="Hardcoded secret",
            description="API key in source",
            recommendation="Use env vars",
        )
        line = _to_github_annotation(finding)
        assert "endLine=15" in line
        assert line.startswith("::warning ")

    def test_no_end_line_omitted(self) -> None:
        finding = Finding(
            file_path="main.py",
            line_start=1,
            severity=Severity.LOW,
            title="Weak hash",
            description="MD5 used",
            recommendation="Use SHA-256",
        )
        line = _to_github_annotation(finding)
        assert "endLine" not in line


class TestRenderGithubAnnotations:
    def test_empty_findings(self) -> None:
        output = render_github_annotations(_result_with([]))
        assert output == ""

    def test_sorted_by_severity(self) -> None:
        low = Finding(
            file_path="a.py",
            line_start=1,
            severity=Severity.LOW,
            title="Low",
            description="d",
            recommendation="r",
        )
        critical = Finding(
            file_path="b.py",
            line_start=2,
            severity=Severity.CRITICAL,
            title="Critical",
            description="d",
            recommendation="r",
        )
        output = render_github_annotations(_result_with([low, critical]))
        lines = output.splitlines()
        assert len(lines) == 2
        # Critical should come first
        assert "Critical" in lines[0]
        assert "Low" in lines[1]

    def test_multiple_findings_one_per_line(self) -> None:
        findings = [
            Finding(
                file_path=f"file{i}.py",
                line_start=i,
                severity=Severity.MEDIUM,
                title=f"Issue {i}",
                description="d",
                recommendation="r",
            )
            for i in range(1, 4)
        ]
        output = render_github_annotations(_result_with(findings))
        assert len(output.splitlines()) == 3
