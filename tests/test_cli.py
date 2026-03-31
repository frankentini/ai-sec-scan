"""Tests for CLI behavior."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from ai_sec_scan.cli import main
from ai_sec_scan.models import Finding, ScanResult
from ai_sec_scan.providers.base import BaseProvider


class _DummyProvider(BaseProvider):
    """Provider stub for CLI tests."""

    def __init__(self) -> None:
        super().__init__("dummy-model")

    @property
    def name(self) -> str:
        return "dummy"

    async def analyze(self, code: str, filename: str) -> list[Finding]:
        return []


def test_scan_loads_defaults_from_target_config(  # type: ignore[no-untyped-def]
    monkeypatch,
) -> None:
    runner = CliRunner()
    captured: dict[str, object] = {}

    def fake_get_provider(provider_name: str, model: str | None) -> BaseProvider:
        captured["provider_name"] = provider_name
        captured["model"] = model
        return _DummyProvider()

    def fake_run_scan_sync(  # type: ignore[no-untyped-def]
        path: Path,
        provider: BaseProvider,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        max_file_size_kb: int = 100,
        min_severity: str | None = None,
        quiet: bool = False,
        cache_dir: Path | None = None,
        no_cache: bool = False,
        parallel: int = 1,
    ) -> ScanResult:
        captured["include"] = include
        captured["exclude"] = exclude
        captured["max_file_size_kb"] = max_file_size_kb
        captured["min_severity"] = min_severity
        return ScanResult(
            findings=[],
            files_scanned=1,
            scan_duration=0.01,
            provider=provider.name,
            model=provider.model,
        )

    monkeypatch.setattr("ai_sec_scan.cli._get_provider", fake_get_provider)
    monkeypatch.setattr("ai_sec_scan.scanner.run_scan_sync", fake_run_scan_sync)

    with runner.isolated_filesystem():
        project_dir = Path("project")
        project_dir.mkdir()
        (project_dir / "app.py").write_text("print('ok')", encoding="utf-8")
        (project_dir / ".ai-sec-scan.yaml").write_text(
            "\n".join(
                [
                    "provider: openai",
                    "model: gpt-4o",
                    "severity: high",
                    "output: json",
                    "max_file_size: 42",
                    "include:",
                    "  - \"**/*.py\"",
                    "exclude:",
                    "  - \"tests/**\"",
                ]
            ),
            encoding="utf-8",
        )

        result = runner.invoke(main, ["scan", "project"])

    assert result.exit_code == 0
    assert captured["provider_name"] == "openai"
    assert captured["model"] == "gpt-4o"
    assert captured["include"] == ["**/*.py"]
    assert captured["exclude"] == ["tests/**"]
    assert captured["max_file_size_kb"] == 42
    assert captured["min_severity"] == "high"


def test_dry_run_lists_files(tmp_path: Path) -> None:
    """--dry-run should list matching files without invoking any provider."""
    (tmp_path / "app.py").write_text("x = 1", encoding="utf-8")
    (tmp_path / "lib.js").write_text("var y", encoding="utf-8")
    (tmp_path / "readme.txt").write_text("not code", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--dry-run"])

    assert result.exit_code == 0
    assert "app.py" in result.output
    assert "lib.js" in result.output
    assert "readme.txt" not in result.output
    assert "file(s) would be scanned" in result.output


def test_dry_run_respects_include(tmp_path: Path) -> None:
    """--dry-run should honour --include filters."""
    (tmp_path / "app.py").write_text("x = 1", encoding="utf-8")
    (tmp_path / "lib.js").write_text("var y", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--dry-run", "-i", "*.py"])

    assert result.exit_code == 0
    assert "app.py" in result.output
    assert "lib.js" not in result.output


def test_dry_run_empty(tmp_path: Path) -> None:
    """--dry-run on an empty directory should report no files."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--dry-run"])

    assert result.exit_code == 0
    assert "No files match" in result.output


def test_quiet_flag_suppresses_progress(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """--quiet should suppress the banner and progress output."""
    runner = CliRunner()
    captured: dict[str, object] = {}

    def fake_get_provider(provider_name: str, model: str | None) -> BaseProvider:
        return _DummyProvider()

    def fake_run_scan_sync(  # type: ignore[no-untyped-def]
        path: Path,
        provider: BaseProvider,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        max_file_size_kb: int = 100,
        min_severity: str | None = None,
        quiet: bool = False,
        cache_dir: Path | None = None,
        no_cache: bool = False,
        parallel: int = 1,
    ) -> ScanResult:
        captured["quiet"] = quiet
        return ScanResult(
            findings=[],
            files_scanned=1,
            scan_duration=0.01,
            provider=provider.name,
            model=provider.model,
        )

    monkeypatch.setattr("ai_sec_scan.cli._get_provider", fake_get_provider)
    monkeypatch.setattr("ai_sec_scan.scanner.run_scan_sync", fake_run_scan_sync)

    with runner.isolated_filesystem():
        project_dir = Path("project")
        project_dir.mkdir()
        (project_dir / "app.py").write_text("print('ok')", encoding="utf-8")

        result = runner.invoke(main, ["scan", "project", "--quiet"])

    assert result.exit_code == 0
    assert captured["quiet"] is True
    # Banner should not appear in stderr-captured output
    assert "ai-sec-scan" not in result.output


def test_cli_flags_override_config(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    runner = CliRunner()
    captured: dict[str, object] = {}

    def fake_get_provider(provider_name: str, model: str | None) -> BaseProvider:
        captured["provider_name"] = provider_name
        captured["model"] = model
        return _DummyProvider()

    def fake_run_scan_sync(  # type: ignore[no-untyped-def]
        path: Path,
        provider: BaseProvider,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        max_file_size_kb: int = 100,
        min_severity: str | None = None,
        quiet: bool = False,
        cache_dir: Path | None = None,
        no_cache: bool = False,
        parallel: int = 1,
    ) -> ScanResult:
        captured["include"] = include
        captured["max_file_size_kb"] = max_file_size_kb
        captured["min_severity"] = min_severity
        return ScanResult(
            findings=[],
            files_scanned=1,
            scan_duration=0.01,
            provider=provider.name,
            model=provider.model,
        )

    monkeypatch.setattr("ai_sec_scan.cli._get_provider", fake_get_provider)
    monkeypatch.setattr("ai_sec_scan.scanner.run_scan_sync", fake_run_scan_sync)

    with runner.isolated_filesystem():
        project_dir = Path("project")
        project_dir.mkdir()
        (project_dir / "app.py").write_text("print('ok')", encoding="utf-8")
        (project_dir / ".ai-sec-scan.yaml").write_text(
            "\n".join(
                [
                    "provider: openai",
                    "model: config-model",
                    "severity: low",
                    "max_file_size: 12",
                    "include:",
                    "  - \"**/*.py\"",
                ]
            ),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            [
                "scan",
                "project",
                "--provider",
                "anthropic",
                "--model",
                "override-model",
                "--severity",
                "critical",
                "--max-file-size",
                "88",
                "--include",
                "*.txt",
            ],
        )

    assert result.exit_code == 0
    assert captured["provider_name"] == "anthropic"
    assert captured["model"] == "override-model"
    assert captured["min_severity"] == "critical"
    assert captured["max_file_size_kb"] == 88
    assert captured["include"] == ["*.txt"]


class TestBaselineFlag:
    def test_baseline_suppresses_known_findings(self, monkeypatch, tmp_path: Path) -> None:
        """--baseline should filter out findings that match the baseline."""
        from ai_sec_scan.baseline import Baseline, _fingerprint
        from ai_sec_scan.models import Finding, Severity

        finding_suppressed = Finding(
            file_path="app.py",
            line_start=5,
            severity=Severity.HIGH,
            title="SQL Injection",
            description="desc",
            recommendation="fix",
            cwe_id="CWE-89",
        )
        finding_kept = Finding(
            file_path="app.py",
            line_start=20,
            severity=Severity.MEDIUM,
            title="XSS",
            description="desc",
            recommendation="fix",
            cwe_id="CWE-79",
        )

        # Write baseline file that suppresses only the first finding
        baseline_doc = Baseline.generate([finding_suppressed])
        baseline_path = tmp_path / "baseline.json"
        import json
        baseline_path.write_text(json.dumps(baseline_doc))

        def fake_get_provider(provider_name: str, model: str | None) -> BaseProvider:
            return _DummyProvider()

        def fake_run_scan_sync(
            path,
            provider,
            include=None,
            exclude=None,
            max_file_size_kb=100,
            min_severity=None,
            quiet=False,
            cache_dir=None,
            no_cache=False,
            parallel=1,
        ):
            return ScanResult(
                findings=[finding_suppressed, finding_kept],
                files_scanned=1,
                scan_duration=0.01,
                provider=provider.name,
                model=provider.model,
            )

        monkeypatch.setattr("ai_sec_scan.cli._get_provider", fake_get_provider)
        monkeypatch.setattr("ai_sec_scan.scanner.run_scan_sync", fake_run_scan_sync)

        runner = CliRunner()
        with runner.isolated_filesystem():
            project_dir = Path("project")
            project_dir.mkdir()
            (project_dir / "app.py").write_text("print('ok')", encoding="utf-8")

            result = runner.invoke(
                main,
                ["scan", "project", "-o", "json", "-q", "--baseline", str(baseline_path)],
            )

        # Should still exit 1 because one finding remains
        assert result.exit_code == 1
        output = json.loads(result.output)
        assert len(output["findings"]) == 1
        assert output["findings"][0]["title"] == "XSS"


class TestCacheStatsCommand:
    def test_stats_empty_cache(self, tmp_path: Path) -> None:
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        runner = CliRunner()
        result = runner.invoke(
            main, ["cache", "stats", "--cache-dir", str(cache_dir)]
        )

        assert result.exit_code == 0
        assert "empty" in result.output.lower()

    def test_stats_with_entries(self, tmp_path: Path) -> None:
        import json
        import time

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        entry = {
            "version": 1,
            "file_path": "app.py",
            "content_hash": "abc123",
            "provider": "anthropic",
            "model": "claude-3",
            "timestamp": time.time(),
            "findings": [],
        }
        (cache_dir / "entry1.json").write_text(json.dumps(entry))
        (cache_dir / "entry2.json").write_text(json.dumps(entry))

        runner = CliRunner()
        result = runner.invoke(
            main, ["cache", "stats", "--cache-dir", str(cache_dir)]
        )

        assert result.exit_code == 0
        assert "2" in result.output  # 2 entries


class TestCacheEvictCommand:
    def test_evict_removes_expired(self, tmp_path: Path) -> None:
        """cache evict should remove expired entries."""
        import json
        import time

        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        # Create an expired entry (timestamp 2 hours ago)
        entry = {
            "version": 1,
            "file_path": "old.py",
            "content_hash": "abc",
            "provider": "anthropic",
            "model": "claude-3",
            "timestamp": time.time() - 7200,
            "findings": [],
        }
        (cache_dir / "expired.json").write_text(json.dumps(entry))

        runner = CliRunner()
        result = runner.invoke(
            main, ["cache", "evict", "--cache-dir", str(cache_dir), "--max-age", "3600"]
        )

        assert result.exit_code == 0
        assert "Evicted 1" in result.output

    def test_evict_nothing_expired(self, tmp_path: Path) -> None:
        """cache evict with no expired entries reports accordingly."""
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        runner = CliRunner()
        result = runner.invoke(
            main, ["cache", "evict", "--cache-dir", str(cache_dir)]
        )

        assert result.exit_code == 0
        assert "No expired entries" in result.output
