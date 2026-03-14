"""OpenAI (GPT) provider for security analysis."""

from __future__ import annotations

import json
import os
from typing import Any

import openai

from ai_sec_scan.models import Finding
from ai_sec_scan.providers.base import BaseProvider
from ai_sec_scan.rules import ANALYSIS_PROMPT


class OpenAIProvider(BaseProvider):
    """Security analysis using OpenAI's GPT models."""

    DEFAULT_MODEL = "gpt-4o"

    def __init__(self, model: str | None = None) -> None:
        super().__init__(model or self.DEFAULT_MODEL)
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY environment variable is required. "
                "Get your key at https://platform.openai.com/api-keys"
            )
        self._client = openai.AsyncOpenAI(api_key=api_key)

    @property
    def name(self) -> str:
        return "openai"

    async def analyze(self, code: str, filename: str) -> list[Finding]:
        """Analyze code using GPT."""
        response = await self._client.chat.completions.create(
            model=self.model,
            temperature=0,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": ANALYSIS_PROMPT},
                {
                    "role": "user",
                    "content": f"Filename: {filename}\n\n```\n{code}\n```",
                },
            ],
        )

        text = response.choices[0].message.content or "[]"
        data: Any = json.loads(text)

        # OpenAI JSON mode may wrap in an object with a "findings" key
        findings_data = data if isinstance(data, list) else data.get("findings", [])

        if not isinstance(findings_data, list):
            raise ValueError("Provider response must contain a findings array")

        return [Finding.model_validate(item) for item in findings_data]
