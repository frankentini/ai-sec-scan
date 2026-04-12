"""Tests for built-in framework rule packs."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from ai_sec_scan.cli import main
from ai_sec_scan.rules import (
    ANALYSIS_PROMPT,
    DJANGO_PROMPT,
    EXPRESS_PROMPT,
    FASTAPI_PROMPT,
    SPRING_PROMPT,
    get_pack_prompt,
    list_packs,
)


class TestListPacks:
    def test_returns_list(self) -> None:
        packs = list_packs()
        assert isinstance(packs, list)

    def test_contains_all_framework_packs(self) -> None:
        names = {p["name"] for p in list_packs()}
        assert "django" in names
        assert "express" in names
        assert "fastapi" in names
        assert "spring" in names

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

    def test_express_prompt_returned(self) -> None:
        prompt = get_pack_prompt("express")
        assert prompt == EXPRESS_PROMPT

    def test_spring_prompt_returned(self) -> None:
        prompt = get_pack_prompt("spring")
        assert prompt == SPRING_PROMPT

    def test_unknown_pack_returns_none(self) -> None:
        assert get_pack_prompt("rails") is None
        assert get_pack_prompt("") is None
        assert get_pack_prompt("DJANGO") is None  # case-sensitive

    def test_pack_prompt_differs_from_default(self) -> None:
        django_prompt = get_pack_prompt("django")
        fastapi_prompt = get_pack_prompt("fastapi")
        express_prompt = get_pack_prompt("express")
        spring_prompt = get_pack_prompt("spring")
        prompts = [django_prompt, fastapi_prompt, express_prompt, spring_prompt]
        for p in prompts:
            assert p != ANALYSIS_PROMPT
        # all four prompts are distinct
        assert len(set(id(p) for p in prompts)) == 4


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


class TestExpressPrompt:
    def test_contains_express_specific_terms(self) -> None:
        for term in ("helmet", "Prototype pollution", "CORS", "CSRF", "child_process"):
            assert term in EXPRESS_PROMPT, f"Expected '{term}' in Express prompt"

    def test_contains_json_format_instructions(self) -> None:
        assert "JSON array" in EXPRESS_PROMPT
        assert "line_start" in EXPRESS_PROMPT
        assert "severity" in EXPRESS_PROMPT

    def test_contains_cwe_instructions(self) -> None:
        assert "cwe_id" in EXPRESS_PROMPT


class TestSpringPrompt:
    def test_contains_spring_specific_terms(self) -> None:
        for term in ("SpEL", "actuator", "deserialization", "JdbcTemplate", "@PreAuthorize"):
            assert term in SPRING_PROMPT, f"Expected '{term}' in Spring prompt"

    def test_contains_json_format_instructions(self) -> None:
        assert "JSON array" in SPRING_PROMPT
        assert "line_start" in SPRING_PROMPT
        assert "severity" in SPRING_PROMPT

    def test_contains_cwe_instructions(self) -> None:
        assert "cwe_id" in SPRING_PROMPT


class TestRulesListPacksCLI:
    def test_list_packs_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["rules", "list-packs"])
        assert result.exit_code == 0

    def test_list_packs_shows_all_packs(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["rules", "list-packs"])
        assert "django" in result.output
        assert "express" in result.output
        assert "fastapi" in result.output
        assert "spring" in result.output

    def test_list_packs_json_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["rules", "list-packs", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        names = {item["name"] for item in data}
        assert "django" in names
        assert "express" in names
        assert "fastapi" in names
        assert "spring" in names
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
