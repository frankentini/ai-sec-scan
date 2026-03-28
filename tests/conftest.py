"""Shared test fixtures."""

from __future__ import annotations

import pytest

from ai_sec_scan.models import Finding, ScanResult, Severity


@pytest.fixture()
def sample_finding() -> Finding:
    """A reusable high-severity finding for tests."""
    return Finding(
        file_path="app.py",
        line_start=10,
        severity=Severity.HIGH,
        title="SQL Injection",
        description="User input used directly in query",
        recommendation="Use parameterized queries",
        cwe_id="CWE-89",
    )


@pytest.fixture()
def empty_result() -> ScanResult:
    return ScanResult(
        findings=[],
        files_scanned=0,
        scan_duration=0.0,
        provider="test",
        model="test-model",
    )
