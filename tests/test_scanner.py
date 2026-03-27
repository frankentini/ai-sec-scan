"""Tests for the file collection and scanning logic."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ai_sec_scan.models import Finding, Severity
from ai_sec_scan.providers.base import BaseProvider
from ai_sec_scan.scanner import collect_files, scan


class MockProvider(BaseProvider):
    """Mock provider that returns predefined findings."""

    def __init__(self, findings: list[Finding] | None = None) -> None:
        super().__init__("mock-model")
        self._findings = findings or []

    @property
    def name(self) -> str:
        return "mock"

    async def analyze(self, code: str, filename: str) -> list[Finding]:
        return self._findings


class ErrorProvider(BaseProvider):
    """Mock provider that raises errors."""

    def __init__(self) -> None:
        super().__init__("error-model")

    @property
    def name(self) -> str:
        return "error"

    async def analyze(self, code: str, filename: str) -> list[Finding]:
        raise RuntimeError("Provider error")


class TestCollectFiles:
    def test_single_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.py"
        f.write_text("print('hello')")
        files = collect_files(f)
        assert len(files) == 1
        assert files[0] == f

    def test_directory_walk(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1")
        (tmp_path / "lib.py").write_text("y = 2")
        (tmp_path / "readme.txt").write_text("not code")
        files = collect_files(tmp_path)
        names = {f.name for f in files}
        assert "app.py" in names
        assert "lib.py" in names
        assert "readme.txt" not in names

    def test_exclude_patterns(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1")
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "dep.js").write_text("var x")
        files = collect_files(tmp_path)
        assert len(files) == 1
        assert files[0].name == "app.py"

    def test_custom_exclude(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1")
        vendor = tmp_path / "vendor"
        vendor.mkdir()
        (vendor / "lib.py").write_text("y = 2")
        files = collect_files(tmp_path, exclude=["vendor"])
        assert len(files) == 1

    def test_include_filter(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1")
        (tmp_path / "app.js").write_text("var x")
        files = collect_files(tmp_path, include=["*.py"])
        assert len(files) == 1
        assert files[0].suffix == ".py"

    def test_max_file_size(self, tmp_path: Path) -> None:
        f = tmp_path / "big.py"
        f.write_text("x" * 200_000)
        files = collect_files(tmp_path, max_file_size_kb=100)
        assert len(files) == 0

    def test_empty_directory(self, tmp_path: Path) -> None:
        files = collect_files(tmp_path)
        assert files == []

    def test_nested_exclude(self, tmp_path: Path) -> None:
        sub = tmp_path / "src" / "__pycache__"
        sub.mkdir(parents=True)
        (sub / "mod.cpython-310.pyc").write_text("bytes")
        (tmp_path / "src" / "main.py").write_text("code")
        files = collect_files(tmp_path)
        assert len(files) == 1
        assert files[0].name == "main.py"

    def test_source_extensions(self, tmp_path: Path) -> None:
        for ext in [".py", ".js", ".ts", ".go", ".rs", ".java"]:
            (tmp_path / f"file{ext}").write_text("code")
        (tmp_path / "data.csv").write_text("a,b,c")
        (tmp_path / "image.png").write_bytes(b"\x89PNG")
        files = collect_files(tmp_path)
        extensions = {f.suffix for f in files}
        assert ".csv" not in extensions
        assert ".png" not in extensions
        assert ".py" in extensions

    def test_single_large_file_skipped(self, tmp_path: Path) -> None:
        f = tmp_path / "big.py"
        f.write_text("x" * 200_000)
        files = collect_files(f, max_file_size_kb=100)
        assert files == []


class TestScan:
    def test_scan_empty_dir(self, tmp_path: Path) -> None:
        provider = MockProvider()
        result = asyncio.run(scan(tmp_path, provider))
        assert result.files_scanned == 0
        assert result.findings == []
        assert result.provider == "mock"
        assert result.model == "mock-model"

    def test_scan_with_findings(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("password = 'secret123'")
        findings = [
            Finding(
                file_path="app.py",
                line_start=1,
                severity=Severity.HIGH,
                title="Hardcoded Secret",
                description="Password in source",
                recommendation="Use env vars",
                cwe_id="CWE-798",
            )
        ]
        provider = MockProvider(findings=findings)
        result = asyncio.run(scan(tmp_path, provider))
        assert result.files_scanned == 1
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH

    def test_scan_severity_filter(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("code")
        findings = [
            Finding(
                file_path="app.py",
                line_start=1,
                severity=Severity.INFO,
                title="Info",
                description="d",
                recommendation="r",
            ),
            Finding(
                file_path="app.py",
                line_start=2,
                severity=Severity.HIGH,
                title="High",
                description="d",
                recommendation="r",
            ),
        ]
        provider = MockProvider(findings=findings)
        result = asyncio.run(scan(tmp_path, provider, min_severity="high"))
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH

    def test_scan_duration_recorded(self, tmp_path: Path) -> None:
        (tmp_path / "test.py").write_text("x = 1")
        provider = MockProvider()
        result = asyncio.run(scan(tmp_path, provider))
        assert result.scan_duration >= 0.0

    def test_scan_handles_provider_error(self, tmp_path: Path) -> None:
        (tmp_path / "test.py").write_text("x = 1")
        provider = ErrorProvider()
        result = asyncio.run(scan(tmp_path, provider))
        assert result.files_scanned == 1
        assert result.findings == []

    def test_scan_quiet_mode(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1")
        provider = MockProvider()
        result = asyncio.run(scan(tmp_path, provider, quiet=True))
        assert result.files_scanned == 1
        assert result.findings == []

    def test_parallel_scan_collects_all_findings(self, tmp_path: Path) -> None:
        for i in range(5):
            (tmp_path / f"mod{i}.py").write_text(f"x = {i}")
        finding = Finding(
            file_path="placeholder",
            line_start=1,
            severity=Severity.MEDIUM,
            title="Test finding",
            description="d",
            recommendation="r",
        )
        provider = MockProvider(findings=[finding])
        result = asyncio.run(scan(tmp_path, provider, quiet=True, parallel=3))
        assert result.files_scanned == 5
        assert len(result.findings) == 5

    def test_parallel_scan_with_error_provider(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x = 1")
        (tmp_path / "b.py").write_text("y = 2")
        provider = ErrorProvider()
        result = asyncio.run(scan(tmp_path, provider, quiet=True, parallel=2))
        assert result.files_scanned == 2
        assert result.findings == []

    def test_parallel_scan_severity_filter(self, tmp_path: Path) -> None:
        for name in ("a.py", "b.py", "c.py"):
            (tmp_path / name).write_text("code")
        findings = [
            Finding(
                file_path="x",
                line_start=1,
                severity=Severity.LOW,
                title="Low",
                description="d",
                recommendation="r",
            ),
        ]
        provider = MockProvider(findings=findings)
        result = asyncio.run(
            scan(tmp_path, provider, quiet=True, parallel=2, min_severity="high")
        )
        assert result.findings == []
