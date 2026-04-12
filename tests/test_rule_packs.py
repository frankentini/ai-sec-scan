"""Tests for built-in framework rule packs."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from ai_sec_scan.cli import main
from ai_sec_scan.rules import (
    ANALYSIS_PROMPT,
    DJANGO_PROMPT,
    FASTAPI_PROMPT,
    get_pack_prompt,
    list_packs,
)


class TestListPacks:
    def test_returns_list(self) -> None:
        packs = list_packs()
        assert isinstance(packs, list)

    def test_contains_django_and_fastapi(self) -> None:
        names = {p["name"] for p in list_packs()}
        assert "django" in names
        assert "fastapi" in names

    def test_each_pack_has_required_keys(self) -> None:
        for p in list_packs():
            assert "name" in p
            assert "description" in p
            assert "prompt" in p

    def test_packs_sorted_by_name(self) -> None:
        names = [p["name"] for p in list_packs()]
        assert names == sorted(names)

    def test_prompt_strings_are_nonempty(self) -> None:
        for p in list_packs():
            assert len(p["prompt"]) > 100


class TestGetPackPrompt:
    def test_django_prompt_returned(self) -> None:
        prompt = get_pack_prompt("django")
        assert prompt == DJANGO_PROMPT

    def test_fastapi_prompt_returned(self) -> None:
        prompt = get_pack_prompt("fastapi")
        assert prompt == FASTAPI_PROMPT

    def test_unknown_pack_returns_none(self) -> None:
        assert get_pack_prompt("rails") is None
        assert get_pack_prompt("") is None
        assert get_pack_prompt("DJANGO") is None  # case-sensitive

    def test_pack_prompt_differs_from_default(self) -> None:
        django_prompt = get_pack_prompt("django")
        fastapi_prompt = get_pack_prompt("fastapi")
        assert django_prompt != ANALYSIS_PROMPT
        assert fastapi_prompt != ANALYSIS_PROMPT
        assert django_prompt != fastapi_prompt


class TestDjangoPrompt:
    def test_contains_django_specific_terms(self) -> None:
        for term in ("CSRF", "QuerySet", "mark_safe", "SECRET_KEY"):
            assert term in DJANGO_PROMPT, f"Expected '{term}' in Django prompt"

    def test_contains_json_format_instructions(self) -> None:
        assert "JSON array" in DJANGO_PROMPT
        assert "line_start" in DJANGO_PROMPT
        assert "severity" in DJANGO_PROMPT

    def test_contains_cwe_instructions(self) -> None:
        assert "cwe_id" in DJANGO_PROMPT


class TestFastAPIPrompt:
    def test_contains_fastapi_specific_terms(self) -> None:
        for term in ("JWT", "CORS", "Pydantic", "Depends"):
            assert term in FASTAPI_PROMPT, f"Expected '{term}' in FastAPI prompt"

    def test_contains_json_format_instructions(self) -> None:
        assert "JSON array" in FASTAPI_PROMPT
        assert "line_start" in FASTAPI_PROMPT
        assert "severity" in FASTAPI_PROMPT

    def test_contains_cwe_instructions(self) -> None:
        assert "cwe_id" in FASTAPI_PROMPT


class TestRulesListPacksCLI:
    def test_list_packs_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["rules", "list-packs"])
        assert result.exit_code == 0

    def test_list_packs_shows_django_and_fastapi(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["rules", "list-packs"])
        assert "django" in result.output
        assert "fastapi" in result.output

    def test_list_packs_json_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["rules", "list-packs", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        names = {item["name"] for item in data}
        assert "django" in names
        assert "fastapi" in names
        for item in data:
            assert "name" in item
            assert "description" in item


class TestScanPackOption:
    def test_unknown_pack_exits_nonzero(self, tmp_path) -> None:
        target = tmp_path / "app.py"
        target.write_text("x = 1\n")

        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(target), "--pack", "rails", "--quiet"])
        assert result.exit_code != 0
        assert "rails" in result.output

    def test_pack_option_accepted_for_known_pack(self, tmp_path) -> None:
        """--pack with a valid name should not error before calling the provider."""
        from unittest.mock import patch

        from tests.helpers import MockProvider

        target = tmp_path / "app.py"
        target.write_text("x = 1\n")

        captured: dict = {}

        def fake_get_provider(provider_name, model, system_prompt=None):
            captured["system_prompt"] = system_prompt
            return MockProvider()

        runner = CliRunner()
        with patch("ai_sec_scan.cli._get_provider", side_effect=fake_get_provider):
            result = runner.invoke(
                main, ["scan", str(target), "--pack", "django", "--quiet"]
            )

        assert result.exit_code == 0
        assert captured.get("system_prompt") == DJANGO_PROMPT

    def test_rules_file_takes_precedence_over_pack(self, tmp_path) -> None:
        """--rules-file should win over --pack when both are supplied."""
        from unittest.mock import patch

        from tests.helpers import MockProvider

        target = tmp_path / "app.py"
        target.write_text("x = 1\n")
        rules = tmp_path / "custom.txt"
        rules.write_text("Custom prompt.\n")

        captured: dict = {}

        def fake_get_provider(provider_name, model, system_prompt=None):
            captured["system_prompt"] = system_prompt
            return MockProvider()

        runner = CliRunner()
        with patch("ai_sec_scan.cli._get_provider", side_effect=fake_get_provider):
            result = runner.invoke(
                main,
                [
                    "scan", str(target),
                    "--rules-file", str(rules),
                    "--pack", "django",
                    "--quiet",
                ],
            )

        assert result.exit_code == 0
        assert captured.get("system_prompt") == "Custom prompt.\n"
