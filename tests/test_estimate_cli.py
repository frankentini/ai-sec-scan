"""Tests for the estimate CLI subcommand."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from ai_sec_scan.cli import main


class TestEstimateCommand:
    def test_estimate_single_file(self, tmp_path: Path) -> None:
        f = tmp_path / "app.py"
        f.write_text("print('hello world')\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(main, ["estimate", str(f)])

        assert result.exit_code == 0
        assert "1 file(s)" in result.output

    def test_estimate_directory(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("y = 2\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(main, ["estimate", str(tmp_path)])

        assert result.exit_code == 0
        assert "2 file(s)" in result.output

    def test_estimate_json_output(self, tmp_path: Path) -> None:
        f = tmp_path / "app.py"
        f.write_text("import os\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(main, ["estimate", str(f), "--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["file_count"] == 1
        assert data["total_input_tokens"] > 0
        assert data["estimated_output_tokens"] > 0
        assert "total_cost_usd" in data

    def test_estimate_empty_directory(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["estimate", str(tmp_path)])

        assert result.exit_code == 0
        assert "0 file(s)" in result.output

    def test_estimate_respects_include(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1", encoding="utf-8")
        (tmp_path / "style.css").write_text("body {}", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main, ["estimate", str(tmp_path), "--json", "-i", "*.py"]
        )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["file_count"] == 1

    def test_estimate_json_has_model(self, tmp_path: Path) -> None:
        f = tmp_path / "test.py"
        f.write_text("pass\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(main, ["estimate", str(f), "--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "model" in data
        assert isinstance(data["model"], str)
