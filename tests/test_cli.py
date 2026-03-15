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
