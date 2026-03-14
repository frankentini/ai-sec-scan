"""Tests for SARIF output."""

from __future__ import annotations

import json

from ai_sec_scan.models import Finding, ScanResult, Severity
from ai_sec_scan.sarif import to_sarif, to_sarif_json


def _make_result(findings: list[Finding] | None = None) -> ScanResult:
    return ScanResult(
        findings=findings or [],
        files_scanned=1,
        scan_duration=0.5,
        provider="test",
        model="test-model",
    )


def _make_finding(**kwargs) -> Finding:  # type: ignore[no-untyped-def]
    defaults = {
        "file_path": "app.py",
        "line_start": 1,
        "severity": Severity.HIGH,
        "title": "Test Issue",
        "description": "Test description",
        "recommendation": "Test fix",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


class TestSarif:
    def test_empty_sarif_structure(self) -> None:
        sarif = to_sarif(_make_result())
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["results"] == []

    def test_sarif_tool_info(self) -> None:
        sarif = to_sarif(_make_result())
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "ai-sec-scan"
        assert "frankentini" in driver["informationUri"]

    def test_sarif_with_finding(self) -> None:
        finding = _make_finding(
            line_start=42,
            cwe_id="CWE-798",
            owasp_category="A07:2021",
        )
        sarif = to_sarif(_make_result([finding]))
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "CWE-798"
        assert results[0]["level"] == "error"
        loc = results[0]["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] == 42
        assert loc["artifactLocation"]["uri"] == "app.py"

    def test_sarif_properties(self) -> None:
        finding = _make_finding(cwe_id="CWE-89", owasp_category="A03:2021")
        sarif = to_sarif(_make_result([finding]))
        props = sarif["runs"][0]["results"][0]["properties"]
        assert props["cwe"] == "CWE-89"
        assert props["owasp"] == "A03:2021"

    def test_sarif_no_properties_without_metadata(self) -> None:
        finding = _make_finding(cwe_id=None, owasp_category=None)
        sarif = to_sarif(_make_result([finding]))
        assert "properties" not in sarif["runs"][0]["results"][0]

    def test_sarif_level_mapping(self) -> None:
        for sev, expected in [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "warning"),
            (Severity.INFO, "note"),
        ]:
            finding = _make_finding(severity=sev)
            sarif = to_sarif(_make_result([finding]))
            assert sarif["runs"][0]["results"][0]["level"] == expected

    def test_sarif_json_is_valid(self) -> None:
        finding = _make_finding()
        output = to_sarif_json(_make_result([finding]))
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"

    def test_sarif_line_range(self) -> None:
        finding = _make_finding(line_start=10, line_end=20)
        sarif = to_sarif(_make_result([finding]))
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 10
        assert region["endLine"] == 20

    def test_sarif_no_end_line(self) -> None:
        finding = _make_finding(line_start=5)
        sarif = to_sarif(_make_result([finding]))
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 5
        assert "endLine" not in region

    def test_sarif_rule_dedup(self) -> None:
        findings = [
            _make_finding(file_path="a.py", line_start=1, cwe_id="CWE-89"),
            _make_finding(file_path="b.py", line_start=5, cwe_id="CWE-89"),
        ]
        sarif = to_sarif(_make_result(findings))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "CWE-89"
        # But still two results
        assert len(sarif["runs"][0]["results"]) == 2

    def test_sarif_rule_help_uri(self) -> None:
        finding = _make_finding(cwe_id="CWE-89")
        sarif = to_sarif(_make_result([finding]))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "cwe.mitre.org" in rule["helpUri"]
        assert "89" in rule["helpUri"]

    def test_sarif_invocations(self) -> None:
        sarif = to_sarif(_make_result())
        invocations = sarif["runs"][0]["invocations"]
        assert len(invocations) == 1
        assert invocations[0]["executionSuccessful"] is True
