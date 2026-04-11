"""Google Gemini provider for security analysis."""

from __future__ import annotations

import asyncio
import json
import os

from ai_sec_scan.models import Finding
from ai_sec_scan.providers.base import BaseProvider


class GeminiProvider(BaseProvider):
    """Security analysis using Google's Gemini models.

    Requires the ``google-generativeai`` package::

        pip install ai-sec-scan[gemini]

    Authentication is read from the ``GEMINI_API_KEY`` environment variable
    (``GOOGLE_API_KEY`` is also accepted as a fallback).
    """

    DEFAULT_MODEL = "gemini-2.0-flash"

    def __init__(self, model: str | None = None, system_prompt: str | None = None) -> None:
        try:
            import google.generativeai as genai  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "google-generativeai is required for the Gemini provider. "
                "Install it with: pip install ai-sec-scan[gemini]"
            ) from exc

        super().__init__(model or self.DEFAULT_MODEL, system_prompt=system_prompt)

        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY (or GOOGLE_API_KEY) environment variable is required. "
                "Get your key at https://aistudio.google.com/app/apikey"
            )

        genai.configure(api_key=api_key)
        self._genai = genai

    @property
    def name(self) -> str:
        return "gemini"

    async def analyze(self, code: str, filename: str) -> list[Finding]:
        """Analyze code using Gemini.

        Runs the synchronous ``generate_content`` call in a thread-pool
        executor so it doesn't block the event loop.
        """
        generation_config = self._genai.types.GenerationConfig(
            temperature=0,
            response_mime_type="application/json",
        )
        genai_model = self._genai.GenerativeModel(
            model_name=self.model,
            system_instruction=self.system_prompt,
            generation_config=generation_config,
        )

        prompt = f"Filename: {filename}\n\n```\n{code}\n```"

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None, lambda: genai_model.generate_content(prompt)
        )

        text: str = response.text
        data = json.loads(text)

        # Normalise: some Gemini responses wrap the array in {"findings": [...]}
        if isinstance(data, dict):
            data = data.get("findings", [])

        if not isinstance(data, list):
            raise ValueError("Gemini response must be a JSON array of findings")

        return [Finding.model_validate(item) for item in data]
