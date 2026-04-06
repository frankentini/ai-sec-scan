"""Tests for the cost estimation module."""

from __future__ import annotations

from pathlib import Path

from ai_sec_scan.cost import (
    CostEstimate,
    _OUTPUT_RATIO,
    _PRICING,
    estimate_scan_cost,
    estimate_tokens,
    model_price,
)


class TestEstimateTokens:
    def test_empty_string_returns_zero(self) -> None:
        assert estimate_tokens("") == 0

    def test_short_string(self) -> None:
        tokens = estimate_tokens("hello")
        assert tokens >= 1

    def test_longer_text_scales(self) -> None:
        short = estimate_tokens("x" * 10)
        long = estimate_tokens("x" * 1000)
        assert long > short

    def test_minimum_is_one(self) -> None:
        assert estimate_tokens("a") >= 1

    def test_returns_integer(self) -> None:
        result = estimate_tokens("some code here")
        assert isinstance(result, int)


class TestModelPrice:
    def test_known_model(self) -> None:
        price = model_price("gpt-4o")
        assert price is not None
        assert len(price) == 2
        assert price[0] > 0
        assert price[1] > 0

    def test_unknown_model_returns_none(self) -> None:
        assert model_price("nonexistent-model-xyz") is None

    def test_all_pricing_entries_have_two_values(self) -> None:
        for model, (inp, out) in _PRICING.items():
            assert inp > 0, f"{model} input price should be positive"
            assert out > 0, f"{model} output price should be positive"


class TestCostEstimate:
    def _make(self, **overrides) -> CostEstimate:
        defaults = {
            "file_count": 5,
            "total_input_tokens": 10_000,
            "estimated_output_tokens": 2_500,
            "model": "gpt-4o",
            "input_cost_usd": 0.025,
            "output_cost_usd": 0.025,
        }
        defaults.update(overrides)
        return CostEstimate(**defaults)

    def test_total_tokens(self) -> None:
        est = self._make(total_input_tokens=8000, estimated_output_tokens=2000)
        assert est.total_tokens == 10_000

    def test_total_cost_usd(self) -> None:
        est = self._make(input_cost_usd=0.01, output_cost_usd=0.02)
        assert est.total_cost_usd == 0.03

    def test_total_cost_none_when_pricing_unavailable(self) -> None:
        est = self._make(input_cost_usd=None, output_cost_usd=None)
        assert est.total_cost_usd is None

    def test_summary_with_cost(self) -> None:
        est = self._make()
        summary = est.summary()
        assert "5 file(s)" in summary
        assert "$" in summary

    def test_summary_without_cost(self) -> None:
        est = self._make(input_cost_usd=None, output_cost_usd=None)
        summary = est.summary()
        assert "unknown" in summary

    def test_frozen(self) -> None:
        est = self._make()
        try:
            est.file_count = 99  # type: ignore[misc]
            raise AssertionError("Should not allow mutation")
        except AttributeError:
            pass


class TestEstimateScanCost:
    def test_single_file(self, tmp_path: Path) -> None:
        f = tmp_path / "app.py"
        f.write_text("print('hello world')\n")
        result = estimate_scan_cost(f, model="gpt-4o")
        assert result.file_count == 1
        assert result.total_input_tokens > 0
        assert result.estimated_output_tokens > 0
        assert result.total_cost_usd is not None
        assert result.total_cost_usd > 0

    def test_directory_with_multiple_files(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\n")
        result = estimate_scan_cost(tmp_path, model="gpt-4o")
        assert result.file_count == 2

    def test_unknown_model_has_none_cost(self, tmp_path: Path) -> None:
        f = tmp_path / "test.py"
        f.write_text("pass\n")
        result = estimate_scan_cost(f, model="made-up-model")
        assert result.total_cost_usd is None
        assert result.total_input_tokens > 0

    def test_empty_directory(self, tmp_path: Path) -> None:
        result = estimate_scan_cost(tmp_path, model="gpt-4o")
        assert result.file_count == 0
        assert result.total_input_tokens == 0
        assert result.total_cost_usd is not None
        assert result.total_cost_usd == 0.0

    def test_respects_include_filter(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 1")
        (tmp_path / "readme.md").write_text("# Hello")
        result = estimate_scan_cost(tmp_path, model="gpt-4o", include=["*.py"])
        assert result.file_count == 1

    def test_output_ratio_applied(self, tmp_path: Path) -> None:
        f = tmp_path / "code.py"
        f.write_text("import os\n" * 50)
        result = estimate_scan_cost(f, model="gpt-4o")
        expected_output = int(result.total_input_tokens * _OUTPUT_RATIO) + 1  # ceil
        # Allow for rounding
        assert abs(result.estimated_output_tokens - expected_output) <= 1
