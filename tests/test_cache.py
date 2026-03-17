"""Tests for the result cache module."""

from __future__ import annotations

from pathlib import Path

import pytest

from ai_sec_scan.cache import ResultCache, file_hash
from ai_sec_scan.models import Finding, Severity


@pytest.fixture()
def cache(tmp_path: Path) -> ResultCache:
    return ResultCache(cache_dir=tmp_path / "cache")


@pytest.fixture()
def sample_finding() -> Finding:
    return Finding(
        file_path="app.py",
        line_start=10,
        severity=Severity.HIGH,
        title="SQL Injection",
        description="User input used directly in query",
        recommendation="Use parameterized queries",
        cwe_id="CWE-89",
    )


class TestFileHash:
    def test_consistent_hash(self, tmp_path: Path) -> None:
        f = tmp_path / "test.py"
        f.write_text("print('hello')")
        h1 = file_hash(f)
        h2 = file_hash(f)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex length

    def test_different_content_different_hash(self, tmp_path: Path) -> None:
        f1 = tmp_path / "a.py"
        f2 = tmp_path / "b.py"
        f1.write_text("x = 1")
        f2.write_text("x = 2")
        assert file_hash(f1) != file_hash(f2)

    def test_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.py"
        f.write_text("")
        h = file_hash(f)
        assert isinstance(h, str)
        assert len(h) == 64


class TestResultCache:
    def test_miss_on_empty_cache(self, cache: ResultCache) -> None:
        result = cache.get("app.py", "abc123", "anthropic", "claude-3")
        assert result is None

    def test_put_and_get(self, cache: ResultCache, sample_finding: Finding) -> None:
        cache.put("app.py", "hash1", "anthropic", "claude-3", [sample_finding])
        findings = cache.get("app.py", "hash1", "anthropic", "claude-3")
        assert findings is not None
        assert len(findings) == 1
        assert findings[0].title == "SQL Injection"
        assert findings[0].cwe_id == "CWE-89"

    def test_invalidated_by_hash_change(
        self, cache: ResultCache, sample_finding: Finding
    ) -> None:
        cache.put("app.py", "hash1", "anthropic", "claude-3", [sample_finding])
        result = cache.get("app.py", "hash2", "anthropic", "claude-3")
        assert result is None

    def test_different_provider_is_separate(
        self, cache: ResultCache, sample_finding: Finding
    ) -> None:
        cache.put("app.py", "hash1", "anthropic", "claude-3", [sample_finding])
        result = cache.get("app.py", "hash1", "openai", "gpt-4")
        assert result is None

    def test_empty_findings_cached(self, cache: ResultCache) -> None:
        cache.put("clean.py", "hash1", "anthropic", "claude-3", [])
        findings = cache.get("clean.py", "hash1", "anthropic", "claude-3")
        assert findings is not None
        assert findings == []

    def test_clear(self, cache: ResultCache, sample_finding: Finding) -> None:
        cache.put("a.py", "h1", "anthropic", "claude-3", [sample_finding])
        cache.put("b.py", "h2", "anthropic", "claude-3", [])
        removed = cache.clear()
        assert removed == 2
        assert cache.get("a.py", "h1", "anthropic", "claude-3") is None

    def test_corrupted_json_returns_none(self, cache: ResultCache) -> None:
        cache.put("app.py", "hash1", "anthropic", "claude-3", [])
        # corrupt the file
        for entry in cache.cache_dir.glob("*.json"):
            entry.write_text("{invalid json", encoding="utf-8")
        result = cache.get("app.py", "hash1", "anthropic", "claude-3")
        assert result is None

    def test_cache_dir_created(self, tmp_path: Path) -> None:
        cache_dir = tmp_path / "deep" / "nested" / "cache"
        cache = ResultCache(cache_dir=cache_dir)
        assert cache_dir.exists()
