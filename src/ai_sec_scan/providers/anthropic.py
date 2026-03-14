"""Anthropic (Claude) provider for security analysis."""

from __future__ import annotations

import json
import os

import anthropic

from ai_sec_scan.models import Finding
from ai_sec_scan.providers.base import BaseProvider
from ai_sec_scan.rules import ANALYSIS_PROMPT, build_prompt


class AnthropicProvider(BaseProvider):
    """Security analysis using Anthropic's Claude models."""

    DEFAULT_MODEL = "claude-sonnet-4-20250514"

    def __init__(self, model: str | None = None) -> None:
        super().__init__(model or self.DEFAULT_MODEL)
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY environment variable is required. "
                "Get your key at https://console.anthropic.com/"
            )
        self._client = anthropic.AsyncAnthropic(api_key=api_key)

    @property
    def name(self) -> str:
        return "anthropic"

    async def analyze(self, code: str, filename: str) -> list[Finding]:
        """Analyze code using Claude."""
        response = await self._client.messages.create(
            model=self.model,
            max_tokens=4096,
            temperature=0,
            system=ANALYSIS_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": f"Filename: {filename}\n\n```\n{code}\n```",
                }
            ],
        )

        text = "".join(
            block.text for block in response.content if getattr(block, "type", "") == "text"
        )
        findings_data = json.loads(text)

        if not isinstance(findings_data, list):
            raise ValueError("Provider response must be a JSON array")

        return [Finding.model_validate(item) for item in findings_data]
