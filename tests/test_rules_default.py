"""Tests for the default security analysis prompt builder."""

from __future__ import annotations

from ai_sec_scan.rules.default import ANALYSIS_PROMPT, build_prompt


class TestBuildPrompt:
    def test_contains_filename(self) -> None:
        result = build_prompt("x = 1", "app.py")
        assert "Filename: app.py" in result

    def test_contains_code(self) -> None:
        code = "import os\nos.system('rm -rf /')"
        result = build_prompt(code, "bad.py")
        assert code in result

    def test_code_wrapped_in_fences(self) -> None:
        result = build_prompt("print(1)", "demo.py")
        assert "```\nprint(1)\n```" in result

    def test_starts_with_system_prompt(self) -> None:
        result = build_prompt("pass", "noop.py")
        assert result.startswith(ANALYSIS_PROMPT)

    def test_empty_code(self) -> None:
        result = build_prompt("", "empty.py")
        assert "Filename: empty.py" in result
        assert "```\n\n```" in result


class TestAnalysisPrompt:
    def test_mentions_json_array(self) -> None:
        assert "JSON array" in ANALYSIS_PROMPT

    def test_severity_levels_documented(self) -> None:
        for level in ("critical", "high", "medium", "low", "info"):
            assert level in ANALYSIS_PROMPT

    def test_required_fields_listed(self) -> None:
        for field in (
            "file_path",
            "line_start",
            "line_end",
            "severity",
            "title",
            "description",
            "recommendation",
            "cwe_id",
            "owasp_category",
        ):
            assert f'"{field}"' in ANALYSIS_PROMPT
