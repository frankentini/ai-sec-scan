"""Tests for custom rules file support (--rules-file)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner

from ai_sec_scan.cli import main
from ai_sec_scan.models import Finding, Severity
from ai_sec_scan.providers.base import BaseProvider
from ai_sec_scan.rules import ANALYSIS_PROMPT
from tests.helpers import MockProvider


# ---------------------------------------------------------------------------
# BaseProvider system_prompt inheritance
# ---------------------------------------------------------------------------

class TestBaseProviderSystemPrompt:
    def test_default_prompt_is_analysis_prompt(self) -> None:
        p = MockProvider()
        assert p.system_prompt == ANALYSIS_PROMPT

    def test_custom_prompt_stored(self) -> None:
        custom = "You are a specialized Ruby security reviewer."
        p = MockProvider()
        # Rebuild with system_prompt kwarg via BaseProvider directly
        p2 = BaseProvider.__new__(MockProvider)
        BaseProvider.__init__(p2, "mock-model", system_prompt=custom)
        p2._findings = []
        assert p2.system_prompt == custom

    def test_none_prompt_falls_back_to_default(self) -> None:
        p = BaseProvider.__new__(MockProvider)
        BaseProvider.__init__(p, "mock-model", system_prompt=None)
        p._findings = []
        assert p.system_prompt == ANALYSIS_PROMPT


# ---------------------------------------------------------------------------
# AnthropicProvider picks up custom prompt
# ---------------------------------------------------------------------------

class TestAnthropicProviderCustomPrompt:
    def test_system_prompt_forwarded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr("anthropic.AsyncAnthropic", MagicMock)

        from ai_sec_scan.providers.anthropic import AnthropicProvider

        custom = "Check only for hardcoded credentials."
        provider = AnthropicProvider(system_prompt=custom)
        assert provider.system_prompt == custom

    def test_default_prompt_when_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.setattr("anthropic.AsyncAnthropic", MagicMock)

        from ai_sec_scan.providers.anthropic import AnthropicProvider

        provider = AnthropicProvider()
        assert provider.system_prompt == ANALYSIS_PROMPT


# ---------------------------------------------------------------------------
# OpenAIProvider picks up custom prompt
# ---------------------------------------------------------------------------

class TestOpenAIProviderCustomPrompt:
    def test_system_prompt_forwarded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setattr("openai.AsyncOpenAI", MagicMock)

        from ai_sec_scan.providers.openai import OpenAIProvider

        custom = "Focus only on SQL injection vulnerabilities."
        provider = OpenAIProvider(system_prompt=custom)
        assert provider.system_prompt == custom

    def test_default_prompt_when_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setattr("openai.AsyncOpenAI", MagicMock)

        from ai_sec_scan.providers.openai import OpenAIProvider

        provider = OpenAIProvider()
        assert provider.system_prompt == ANALYSIS_PROMPT


# ---------------------------------------------------------------------------
# CLI --rules-file option
# ---------------------------------------------------------------------------

class TestRulesFileCLI:
    def _fake_get_provider(
        self,
        provider_name: str,
        model: str | None,
        system_prompt: str | None = None,
    ) -> MockProvider:
        p = MockProvider()
        p._last_system_prompt = system_prompt  # type: ignore[attr-defined]
        return p

    def test_rules_file_loaded_and_passed(self, tmp_path: Path) -> None:
        """--rules-file contents should reach _get_provider as system_prompt."""
        rules = tmp_path / "rules.txt"
        rules.write_text("Only check for SQL injection.\n")

        target = tmp_path / "app.py"
        target.write_text("x = 1\n")

        captured: dict = {}

        def fake_get_provider(
            provider_name: str,
            model: str | None,
            system_prompt: str | None = None,
        ) -> MockProvider:
            captured["system_prompt"] = system_prompt
            return MockProvider()

        runner = CliRunner()
        with patch("ai_sec_scan.cli._get_provider", side_effect=fake_get_provider):
            result = runner.invoke(
                main,
                ["scan", str(target), "--rules-file", str(rules), "--quiet"],
            )

        assert result.exit_code == 0
        assert captured["system_prompt"] == "Only check for SQL injection.\n"

    def test_missing_rules_file_rejected(self, tmp_path: Path) -> None:
        """Passing a non-existent path should be caught by click."""
        target = tmp_path / "app.py"
        target.write_text("x = 1\n")

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", str(target), "--rules-file", str(tmp_path / "nope.txt")],
        )
        # click.Path(exists=True) exits with code 2 for missing files
        assert result.exit_code == 2
        assert "nope.txt" in result.output

    def test_no_rules_file_passes_none(self, tmp_path: Path) -> None:
        """Without --rules-file, system_prompt should be None."""
        target = tmp_path / "app.py"
        target.write_text("x = 1\n")

        captured: dict = {}

        def fake_get_provider(
            provider_name: str,
            model: str | None,
            system_prompt: str | None = None,
        ) -> MockProvider:
            captured["system_prompt"] = system_prompt
            return MockProvider()

        runner = CliRunner()
        with patch("ai_sec_scan.cli._get_provider", side_effect=fake_get_provider):
            result = runner.invoke(main, ["scan", str(target), "--quiet"])

        assert result.exit_code == 0
        assert captured["system_prompt"] is None

    def test_rules_file_shown_in_banner(self, tmp_path: Path) -> None:
        """The provider banner should mention the custom rules file path."""
        rules = tmp_path / "my_rules.txt"
        rules.write_text("Custom prompt.\n")

        target = tmp_path / "app.py"
        target.write_text("x = 1\n")

        def fake_get_provider(
            provider_name: str,
            model: str | None,
            system_prompt: str | None = None,
        ) -> MockProvider:
            return MockProvider()

        runner = CliRunner()
        with patch("ai_sec_scan.cli._get_provider", side_effect=fake_get_provider):
            result = runner.invoke(
                main,
                ["scan", str(target), "--rules-file", str(rules)],
            )

        assert "my_rules.txt" in result.output
