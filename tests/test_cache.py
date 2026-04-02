"""Tests for the result cache module."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from ai_sec_scan.cache import ResultCache, file_hash
from ai_sec_scan.models import Finding, Severity


@pytest.fixture()
def cache(tmp_path: Path) -> ResultCache:
    return ResultCache(cache_dir=tmp_path / "cache")


# sample_finding fixture is inherited from conftest.py


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

    def test_expired_entry_returns_none(
        self, tmp_path: Path, sample_finding: Finding
    ) -> None:
        cache = ResultCache(cache_dir=tmp_path / "cache", max_age_seconds=60)
        cache.put("app.py", "hash1", "anthropic", "claude-3", [sample_finding])

        # Simulate passage of time by patching time.time
        with patch("ai_sec_scan.cache.time") as mock_time:
            mock_time.time.return_value = time.time() + 120
            result = cache.get("app.py", "hash1", "anthropic", "claude-3")
        assert result is None

    def test_non_expired_entry_returned(
        self, tmp_path: Path, sample_finding: Finding
    ) -> None:
        cache = ResultCache(cache_dir=tmp_path / "cache", max_age_seconds=300)
        cache.put("app.py", "hash1", "anthropic", "claude-3", [sample_finding])
        result = cache.get("app.py", "hash1", "anthropic", "claude-3")
        assert result is not None
        assert len(result) == 1

    def test_evict_expired(self, tmp_path: Path, sample_finding: Finding) -> None:
        cache = ResultCache(cache_dir=tmp_path / "cache", max_age_seconds=60)
        cache.put("old.py", "h1", "anthropic", "claude-3", [sample_finding])

        # Manually backdate the timestamp
        for entry in cache.cache_dir.glob("*.json"):
            data = json.loads(entry.read_text())
            data["timestamp"] = time.time() - 120
            entry.write_text(json.dumps(data))

        cache.put("new.py", "h2", "anthropic", "claude-3", [])
        evicted = cache.evict_expired()
        assert evicted == 1
        # The fresh entry should still exist
        assert cache.get("new.py", "h2", "anthropic", "claude-3") is not None

    def test_stats(self, tmp_path: Path, sample_finding: Finding) -> None:
        cache = ResultCache(cache_dir=tmp_path / "cache")
        assert cache.stats()["total_entries"] == 0

        cache.put("a.py", "h1", "anthropic", "claude-3", [sample_finding])
        cache.put("b.py", "h2", "anthropic", "claude-3", [])
        stats = cache.stats()
        assert stats["total_entries"] == 2
        assert stats["total_bytes"] > 0
        assert stats["oldest_timestamp"] is not None

    def test_repr(self, cache: ResultCache) -> None:
        r = repr(cache)
        assert "ResultCache" in r
        assert "cache_dir=" in r
        assert "max_age_seconds=" in r

    def test_len_empty(self, cache: ResultCache) -> None:
        assert len(cache) == 0

    def test_entries_empty(self, cache: ResultCache) -> None:
        assert cache.entries() == []

    def test_entries_returns_metadata(
        self, cache: ResultCache, sample_finding: Finding
    ) -> None:
        cache.put("a.py", "h1", "anthropic", "claude-3", [sample_finding])
        cache.put("b.py", "h2", "openai", "gpt-4", [])
        items = cache.entries()
        assert len(items) == 2
        paths = {e["file_path"] for e in items}
        assert paths == {"a.py", "b.py"}
        for item in items:
            assert "provider" in item
            assert "model" in item
            assert "timestamp" in item
            assert "num_findings" in item

    def test_len_with_entries(
        self, cache: ResultCache, sample_finding: Finding
    ) -> None:
        cache.put("a.py", "h1", "anthropic", "claude-3", [sample_finding])
        cache.put("b.py", "h2", "anthropic", "claude-3", [])
        assert len(cache) == 2
        cache.clear()
        assert len(cache) == 0
