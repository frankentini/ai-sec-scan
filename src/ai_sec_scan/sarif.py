"""SARIF 2.1.0 output formatter for scan results."""

from __future__ import annotations

import json
from typing import Any

from ai_sec_scan import __version__
from ai_sec_scan.models import Finding, ScanResult


def finding_to_sarif_result(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to a SARIF result object."""
    region: dict[str, Any] = {"startLine": finding.line_start}
    if finding.line_end is not None:
        region["endLine"] = finding.line_end

    rule_id = finding.cwe_id or finding.title.lower().replace(" ", "-")[:64]

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": finding.severity.sarif_level,
        "message": {
            "text": f"{finding.title}: {finding.description}\n\nRecommendation: {finding.recommendation}",
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": region,
                }
            }
        ],
    }

    properties: dict[str, str] = {}
    if finding.cwe_id:
        properties["cwe"] = finding.cwe_id
    if finding.owasp_category:
        properties["owasp"] = finding.owasp_category
    if properties:
        result["properties"] = properties

    return result


def to_sarif(result: ScanResult) -> dict[str, Any]:
    """Convert a ScanResult to a SARIF 2.1.0 document.

    Args:
        result: The scan result to convert.

    Returns:
        A SARIF 2.1.0 compliant dictionary.
    """
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ai-sec-scan",
                        "version": __version__,
                        "informationUri": "https://github.com/frankentini/ai-sec-scan",
                        "rules": _build_rules(result.findings),
                    }
                },
                "results": [finding_to_sarif_result(f) for f in result.sorted_findings],
                "invocations": [
                    {
                        "executionSuccessful": True,
                    }
                ],
            }
        ],
    }


def to_sarif_json(result: ScanResult, indent: int = 2) -> str:
    """Convert a ScanResult to a SARIF 2.1.0 JSON string."""
    return json.dumps(to_sarif(result), indent=indent)


def _build_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    """Build SARIF rule descriptors from findings, deduplicating by rule ID."""
    seen: set[str] = set()
    rules: list[dict[str, Any]] = []

    for finding in findings:
        rule_id = finding.cwe_id or finding.title.lower().replace(" ", "-")[:64]
        if rule_id in seen:
            continue
        seen.add(rule_id)

        rule: dict[str, Any] = {
            "id": rule_id,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "help": {"text": finding.recommendation},
        }

        if finding.cwe_id:
            cwe_num = finding.cwe_id.split("-")[1] if "-" in finding.cwe_id else finding.cwe_id
            rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"

        rules.append(rule)

    return rules
