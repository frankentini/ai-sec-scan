"""Tests for the Google Gemini provider."""

from __future__ import annotations

import importlib
import json
import sys
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

from ai_sec_scan.models import Severity
from ai_sec_scan.rules import ANALYSIS_PROMPT


SAMPLE_FINDING = {
    "file_path": "app.py",
    "line_start": 12,
    "line_end": None,
    "severity": "high",
    "title": "Hardcoded API Key",
    "description": "An API key is stored directly in the source code.",
    "recommendation": "Move secrets to environment variables.",
    "cwe_id": "CWE-798",
    "owasp_category": "A02:2021",
}


def _make_genai_mock(findings: list | dict) -> MagicMock:
    """Return a mock google.generativeai module."""
    mock_genai = MagicMock()

    response = MagicMock()
    response.text = json.dumps(findings)

    genai_model = MagicMock()
    genai_model.generate_content.return_value = response
    mock_genai.GenerativeModel.return_value = genai_model
    mock_genai.types = MagicMock()
    mock_genai.types.GenerationConfig.return_value = MagicMock()

    return mock_genai


def _make_google_namespace(genai_mock: MagicMock) -> MagicMock:
    """Return a minimal 'google' namespace package mock."""
    google_ns = MagicMock()
    google_ns.generativeai = genai_mock
    return google_ns


def _patched_modules(genai_mock: MagicMock) -> dict:
    return {
        "google": _make_google_namespace(genai_mock),
        "google.generativeai": genai_mock,
    }


class TestGeminiProviderInit:
    def test_missing_api_key_raises_value_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

        mock_genai = _make_genai_mock([])
        with patch.dict(sys.modules, _patched_modules(mock_genai)):
            import ai_sec_scan.providers.gemini as gemini_mod

            importlib.reload(gemini_mod)

            with pytest.raises(ValueError, match="GEMINI_API_KEY"):
                gemini_mod.GeminiProvider()

    def test_gemini_api_key_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "my-key")
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

        mock_genai = _make_genai_mock([])
        with patch.dict(sys.modules, _patched_modules(mock_genai)):
            import ai_sec_scan.providers.gemini as gemini_mod

            importlib.reload(gemini_mod)
            provider = gemini_mod.GeminiProvider()

        assert provider.name == "gemini"
        assert provider.model == gemini_mod.GeminiProvider.DEFAULT_MODEL

    def test_google_api_key_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("GOOGLE_API_KEY", "fallback-key")

        mock_genai = _make_genai_mock([])
        with patch.dict(sys.modules, _patched_modules(mock_genai)):
            import ai_sec_scan.providers.gemini as gemini_mod

            importlib.reload(gemini_mod)
            provider = gemini_mod.GeminiProvider()

        assert provider.name == "gemini"

    def test_custom_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "key")

        mock_genai = _make_genai_mock([])
        with patch.dict(sys.modules, _patched_modules(mock_genai)):
            import ai_sec_scan.providers.gemini as gemini_mod

            importlib.reload(gemini_mod)
            provider = gemini_mod.GeminiProvider(model="gemini-1.5-pro")

        assert provider.model == "gemini-1.5-pro"

    def test_default_system_prompt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "key")

        mock_genai = _make_genai_mock([])
        with patch.dict(sys.modules, _patched_modules(mock_genai)):
            import ai_sec_scan.providers.gemini as gemini_mod

            importlib.reload(gemini_mod)
            provider = gemini_mod.GeminiProvider()

        assert provider.system_prompt == ANALYSIS_PROMPT

    def test_custom_system_prompt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "key")
        custom = "Only report critical SQL injection issues."

        mock_genai = _make_genai_mock([])
        with patch.dict(sys.modules, _patched_modules(mock_genai)):
            import ai_sec_scan.providers.gemini as gemini_mod

            importlib.reload(gemini_mod)
            provider = gemini_mod.GeminiProvider(system_prompt=custom)

        assert provider.system_prompt == custom


class TestGeminiProviderAnalyze:
    @pytest.mark.asyncio
    async def test_returns_findings_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "key")

        mock_genai = _make_genai_mock([SAMPLE_FINDING])
        with patch.dict(sys.modules, _patched_modules(mock_genai)):
            import ai_sec_scan.providers.gemini as gemini_mod

            importlib.reload(gemini_mod)
            provider = gemini_mod.GeminiProvider()
            findings = await provider.analyze("secret = 'abc123'", "app.py")

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].cwe_id == "CWE-798"

    @pytest.mark.asyncio
    async def test_empty_response(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "key")

        mock_genai = _make_genai_mock([])
        with patch.dict(sys.modules, _patched_modules(mock_genai)):
            import ai_sec_scan.providers.gemini as gemini_mod

            importlib.reload(gemini_mod)
            provider = gemini_mod.GeminiProvider()
            findings = await provider.analyze("x = 1", "clean.py")

        assert findings == []

    @pytest.mark.asyncio
    async def test_wrapped_findings_object(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Gemini sometimes returns {"findings": [...]} instead of a bare array."""
        monkeypatch.setenv("GEMINI_API_KEY", "key")

        mock_genai = _make_genai_mock({"findings": [SAMPLE_FINDING]})
        with patch.dict(sys.modules, _patched_modules(mock_genai)):
            import ai_sec_scan.providers.gemini as gemini_mod

            importlib.reload(gemini_mod)
            provider = gemini_mod.GeminiProvider()
            findings = await provider.analyze("code", "app.py")

        assert len(findings) == 1


class TestGeminiPricing:
    def test_gemini_models_in_pricing_table(self) -> None:
        from ai_sec_scan.cost import model_price

        assert model_price("gemini-2.0-flash") is not None
        assert model_price("gemini-1.5-pro") is not None
        assert model_price("gemini-2.5-pro") is not None

    def test_gemini_prices_are_positive(self) -> None:
        from ai_sec_scan.cost import _PRICING

        gemini_models = [k for k in _PRICING if k.startswith("gemini")]
        assert len(gemini_models) >= 4
        for m in gemini_models:
            inp, out = _PRICING[m]
            assert inp > 0
            assert out > 0
