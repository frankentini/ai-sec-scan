"""Abstract base class for LLM providers."""

from __future__ import annotations

import abc

from ai_sec_scan.models import Finding


class BaseProvider(abc.ABC):
    """Base class for LLM security analysis providers."""

    def __init__(self, model: str) -> None:
        self.model = model

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
