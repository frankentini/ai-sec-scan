"""Abstract base class for LLM providers."""

from __future__ import annotations

import abc

from ai_sec_scan.models import Finding
from ai_sec_scan.rules import ANALYSIS_PROMPT


class BaseProvider(abc.ABC):
    """Base class for LLM security analysis providers."""

    def __init__(self, model: str, system_prompt: str | None = None) -> None:
        self.model = model
        self.system_prompt: str = system_prompt if system_prompt is not None else ANALYSIS_PROMPT

    @abc.abstractmethod
    async def analyze(self, code: str, filename: str) -> list[Finding]:
        """Analyze source code for security vulnerabilities.

        Args:
            code: The source code content to analyze.
            filename: Name of the file being analyzed.

        Returns:
            A list of security findings.
        """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Provider name identifier."""
