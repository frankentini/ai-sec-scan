"""Shared mock providers and utilities for tests."""

from __future__ import annotations

from ai_sec_scan.models import Finding
from ai_sec_scan.providers.base import BaseProvider


class MockProvider(BaseProvider):
    """Mock provider that returns predefined findings."""

    def __init__(self, findings: list[Finding] | None = None) -> None:
        super().__init__("mock-model")
        self._findings = findings or []

    @property
    def name(self) -> str:
        return "mock"

    async def analyze(self, code: str, filename: str) -> list[Finding]:
        return self._findings


class ErrorProvider(BaseProvider):
    """Mock provider that always raises."""

    def __init__(self) -> None:
        super().__init__("error-model")

    @property
    def name(self) -> str:
        return "error"

    async def analyze(self, code: str, filename: str) -> list[Finding]:
        raise RuntimeError("Provider error")
