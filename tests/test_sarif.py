"""Tests for SARIF 2.1.0 output formatting."""

from __future__ import annotations

import json

import pytest

from ai_sec_scan import __version__
from ai_sec_scan.models import Finding, ScanResult, Severity
from ai_sec_scan.sarif import finding_to_sarif_result, to_sarif, to_sarif_json, _build_rules


def _finding(**overrides) -> Finding:
    defaults = dict(
        file_path="src/app.py",
        line_start=42,
        severity=Severity.HIGH,
        title="Hardcoded Secret",
        description="API key found in source",
        recommendation="Store secrets in environment variables",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _result(findings: list[Finding] | None = None) -> ScanResult:
    return ScanResult(
        findings=findings or [],
        files_scanned=2,
        scan_duration=0.5,
        provider="anthropic",
        model="claude-3.5-sonnet",
    )


class TestFindingToSarifResult:
    def test_basic_finding_maps_correctly(self) -> None:
        f = _finding(cwe_id="CWE-798")
        result = finding_to_sarif_result(f)

        assert result["ruleId"] == "CWE-798"
        assert result["level"] == "error"
        assert "Hardcoded Secret" in result["message"]["text"]
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/app.py"
        assert loc["region"]["startLine"] == 42

    def test_line_end_included_when_set(self) -> None:
        f = _finding(line_end=50)
        result = finding_to_sarif_result(f)
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["endLine"] == 50

    def test_line_end_absent_when_none(self) -> None:
        f = _finding(line_end=None)
        result = finding_to_sarif_result(f)
        region = result["locations"][0]["physicalLocation"]["region"]
        assert "endLine" not in region

    def test_rule_id_falls_back_to_title(self) -> None:
        f = _finding(cwe_id=None)
        result = finding_to_sarif_result(f)
        assert result["ruleId"] == "hardcoded-secret"

    def test_severity_level_mapping(self) -> None:
        for sev, expected_level in [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "warning"),
            (Severity.INFO, "note"),
        ]:
            f = _finding(severity=sev)
            result = finding_to_sarif_result(f)
            assert result["level"] == expected_level

    def test_properties_include_cwe_and_owasp(self) -> None:
        f = _finding(cwe_id="CWE-89", owasp_category="A03:2021")
        result = finding_to_sarif_result(f)
        assert result["properties"]["cwe"] == "CWE-89"
        assert result["properties"]["owasp"] == "A03:2021"

    def test_properties_omitted_when_no_extras(self) -> None:
        f = _finding(cwe_id=None, owasp_category=None)
        result = finding_to_sarif_result(f)
        assert "properties" not in result

    def test_recommendation_in_message(self) -> None:
        f = _finding(recommendation="Use parameterized queries")
        result = finding_to_sarif_result(f)
        assert "Use parameterized queries" in result["message"]["text"]


class TestToSarif:
    def test_schema_and_version(self) -> None:
        doc = to_sarif(_result())
        assert doc["version"] == "2.1.0"
        assert "$schema" in doc

    def test_tool_info(self) -> None:
        doc = to_sarif(_result())
        driver = doc["runs"][0]["tool"]["driver"]
        assert driver["name"] == "ai-sec-scan"
        assert driver["version"] == __version__
        assert "github.com" in driver["informationUri"]

    def test_empty_findings_produce_empty_results(self) -> None:
        doc = to_sarif(_result([]))
        assert doc["runs"][0]["results"] == []
        assert doc["runs"][0]["tool"]["driver"]["rules"] == []

    def test_findings_ordered_by_severity(self) -> None:
        findings = [
            _finding(severity=Severity.LOW, title="Low thing"),
            _finding(severity=Severity.CRITICAL, title="Critical thing"),
        ]
        doc = to_sarif(_result(findings))
        results = doc["runs"][0]["results"]
        assert results[0]["level"] == "error"
        assert results[1]["level"] == "warning"

    def test_invocation_marked_successful(self) -> None:
        doc = to_sarif(_result())
        invocations = doc["runs"][0]["invocations"]
        assert len(invocations) == 1
        assert invocations[0]["executionSuccessful"] is True


class TestToSarifJson:
    def test_output_is_valid_json(self) -> None:
        findings = [_finding(cwe_id="CWE-79")]
        output = to_sarif_json(_result(findings))
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"

    def test_custom_indent(self) -> None:
        output_2 = to_sarif_json(_result(), indent=2)
        output_4 = to_sarif_json(_result(), indent=4)
        # 4-space indent produces longer output
        assert len(output_4) > len(output_2)


class TestBuildRules:
    def test_deduplicates_by_rule_id(self) -> None:
        findings = [
            _finding(cwe_id="CWE-89", title="SQL Injection A"),
            _finding(cwe_id="CWE-89", title="SQL Injection B"),
        ]
        rules = _build_rules(findings)
        assert len(rules) == 1
        assert rules[0]["id"] == "CWE-89"

    def test_different_cwe_ids_produce_separate_rules(self) -> None:
        findings = [
            _finding(cwe_id="CWE-89", title="SQLi"),
            _finding(cwe_id="CWE-79", title="XSS"),
        ]
        rules = _build_rules(findings)
        ids = {r["id"] for r in rules}
        assert ids == {"CWE-89", "CWE-79"}

    def test_help_uri_generated_for_cwe(self) -> None:
        findings = [_finding(cwe_id="CWE-89")]
        rules = _build_rules(findings)
        assert rules[0]["helpUri"] == "https://cwe.mitre.org/data/definitions/89.html"

    def test_no_help_uri_without_cwe(self) -> None:
        findings = [_finding(cwe_id=None)]
        rules = _build_rules(findings)
        assert "helpUri" not in rules[0]

    def test_rule_descriptions(self) -> None:
        findings = [_finding(title="XSS", description="Cross-site scripting found")]
        rules = _build_rules(findings)
        assert rules[0]["shortDescription"]["text"] == "XSS"
        assert rules[0]["fullDescription"]["text"] == "Cross-site scripting found"
