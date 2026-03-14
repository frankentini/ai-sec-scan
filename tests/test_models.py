"""Tests for data models."""

from __future__ import annotations

import pytest

from ai_sec_scan.models import Finding, ScanResult, Severity


class TestSeverity:
    def test_rank_ordering(self) -> None:
        assert Severity.CRITICAL.rank > Severity.HIGH.rank
        assert Severity.HIGH.rank > Severity.MEDIUM.rank
        assert Severity.MEDIUM.rank > Severity.LOW.rank
        assert Severity.LOW.rank > Severity.INFO.rank

    def test_sarif_level_mapping(self) -> None:
        assert Severity.CRITICAL.sarif_level == "error"
        assert Severity.HIGH.sarif_level == "error"
        assert Severity.MEDIUM.sarif_level == "warning"
        assert Severity.LOW.sarif_level == "warning"
        assert Severity.INFO.sarif_level == "note"

    def test_color_mapping(self) -> None:
        for sev in Severity:
            assert isinstance(sev.color, str)
            assert len(sev.color) > 0

    def test_from_string(self) -> None:
        assert Severity("critical") == Severity.CRITICAL
        assert Severity("info") == Severity.INFO

    def test_all_values_present(self) -> None:
        expected = {"critical", "high", "medium", "low", "info"}
        actual = {s.value for s in Severity}
        assert actual == expected


class TestFinding:
    def test_create_minimal(self) -> None:
        f = Finding(
            file_path="test.py",
            line_start=1,
            severity=Severity.HIGH,
            title="Test finding",
            description="A test",
            recommendation="Fix it",
        )
        assert f.file_path == "test.py"
        assert f.line_end is None
        assert f.cwe_id is None
        assert f.owasp_category is None

    def test_create_full(self) -> None:
        f = Finding(
            file_path="app.py",
            line_start=10,
            line_end=15,
            severity=Severity.CRITICAL,
            title="SQL Injection",
            description="User input in SQL query",
            recommendation="Use parameterized queries",
            cwe_id="CWE-89",
            owasp_category="A03:2021",
        )
        assert f.line_end == 15
        assert f.cwe_id == "CWE-89"
        assert f.owasp_category == "A03:2021"

    def test_line_start_must_be_positive(self) -> None:
        with pytest.raises(Exception):
            Finding(
                file_path="test.py",
                line_start=0,
                severity=Severity.LOW,
                title="Bad",
                description="Bad",
                recommendation="Fix",
            )

    def test_model_validate_from_dict(self) -> None:
        data = {
            "file_path": "x.py",
            "line_start": 5,
            "severity": "high",
            "title": "Issue",
            "description": "Desc",
            "recommendation": "Rec",
        }
        f = Finding.model_validate(data)
        assert f.severity == Severity.HIGH
        assert f.line_start == 5


class TestScanResult:
    @pytest.fixture()
    def sample_result(self) -> ScanResult:
        return ScanResult(
            findings=[
                Finding(
                    file_path="a.py",
                    line_start=1,
                    severity=Severity.LOW,
                    title="Low issue",
                    description="desc",
                    recommendation="fix",
                ),
                Finding(
                    file_path="b.py",
                    line_start=5,
                    severity=Severity.CRITICAL,
                    title="Critical issue",
                    description="desc",
                    recommendation="fix",
                ),
                Finding(
                    file_path="c.py",
                    line_start=10,
                    severity=Severity.LOW,
                    title="Another low",
                    description="desc",
                    recommendation="fix",
                ),
            ],
            files_scanned=3,
            scan_duration=1.5,
            provider="test",
            model="test-model",
        )

    def test_sorted_findings(self, sample_result: ScanResult) -> None:
        sorted_f = sample_result.sorted_findings
        assert sorted_f[0].severity == Severity.CRITICAL
        assert sorted_f[1].severity == Severity.LOW
        assert sorted_f[2].severity == Severity.LOW

    def test_findings_by_severity(self, sample_result: ScanResult) -> None:
        grouped = sample_result.findings_by_severity
        assert len(grouped[Severity.CRITICAL]) == 1
        assert len(grouped[Severity.LOW]) == 2
        assert Severity.HIGH not in grouped

    def test_empty_result(self) -> None:
        r = ScanResult(
            findings=[],
            files_scanned=0,
            scan_duration=0.0,
            provider="test",
            model="test",
        )
        assert r.sorted_findings == []
        assert r.findings_by_severity == {}

    def test_model_dump(self, sample_result: ScanResult) -> None:
        data = sample_result.model_dump(mode="json")
        assert data["files_scanned"] == 3
        assert len(data["findings"]) == 3
        assert data["provider"] == "test"
