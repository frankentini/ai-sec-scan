"""File-level result cache for skipping unchanged files on re-scan."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from ai_sec_scan.models import Finding

CACHE_VERSION = 1
DEFAULT_CACHE_DIR = ".ai-sec-scan-cache"
DEFAULT_MAX_AGE = 7 * 24 * 3600  # 7 days


def file_hash(path: Path) -> str:
    """Compute a SHA-256 hash of a file's contents.

    Args:
        path: Path to the file.

    Returns:
        Hex-encoded SHA-256 digest.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _cache_key(file_path: str, provider: str, model: str) -> str:
    """Build a deterministic cache key from scan parameters."""
    raw = f"{file_path}:{provider}:{model}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class ResultCache:
    """Disk-backed cache that maps (file, provider, model) to findings.

    Cache entries are invalidated when the file content hash changes or
    when they exceed ``max_age_seconds`` (default 7 days).
    """

    def __init__(
        self,
        cache_dir: Path | None = None,
        max_age_seconds: int | None = None,
    ) -> None:
        self._dir = cache_dir or Path(DEFAULT_CACHE_DIR)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._max_age = max_age_seconds if max_age_seconds is not None else DEFAULT_MAX_AGE

    @property
    def cache_dir(self) -> Path:
        return self._dir

    def _entry_path(self, key: str) -> Path:
        return self._dir / f"{key}.json"

    def get(
        self, file_path: str, content_hash: str, provider: str, model: str
    ) -> list[Finding] | None:
        """Look up cached findings for a file.

        Returns None on cache miss or if the content hash doesn't match.
        """
        key = _cache_key(file_path, provider, model)
        entry_path = self._entry_path(key)

        if not entry_path.exists():
            return None

        try:
            data = json.loads(entry_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

        if data.get("version") != CACHE_VERSION:
            return None
        if data.get("content_hash") != content_hash:
            return None

        # Check expiration
        ts = data.get("timestamp")
        if self._max_age > 0 and isinstance(ts, (int, float)):
            if time.time() - ts > self._max_age:
                entry_path.unlink(missing_ok=True)
                return None

        try:
            return [Finding.model_validate(f) for f in data.get("findings", [])]
        except Exception:
            return None

    def put(
        self,
        file_path: str,
        content_hash: str,
        provider: str,
        model: str,
        findings: list[Finding],
    ) -> None:
        """Store findings in the cache."""
        key = _cache_key(file_path, provider, model)
        entry: dict[str, Any] = {
            "version": CACHE_VERSION,
            "file_path": file_path,
            "content_hash": content_hash,
            "provider": provider,
            "model": model,
            "timestamp": time.time(),
            "findings": [f.model_dump(mode="json") for f in findings],
        }
        self._entry_path(key).write_text(
            json.dumps(entry, indent=2), encoding="utf-8"
        )

    def clear(self) -> int:
        """Remove all cache entries. Returns the number of entries removed."""
        count = 0
        for entry in self._dir.glob("*.json"):
            entry.unlink()
            count += 1
        return count

    def evict_expired(self) -> int:
        """Remove cache entries older than max_age_seconds.

        Returns:
            Number of entries evicted.
        """
        if self._max_age <= 0:
            return 0

        now = time.time()
        evicted = 0
        for entry_path in self._dir.glob("*.json"):
            try:
                data = json.loads(entry_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                entry_path.unlink(missing_ok=True)
                evicted += 1
                continue

            ts = data.get("timestamp")
            if isinstance(ts, (int, float)) and now - ts > self._max_age:
                entry_path.unlink(missing_ok=True)
                evicted += 1

        return evicted

    def stats(self) -> dict[str, Any]:
        """Return cache statistics.

        Returns:
            Dict with ``total_entries``, ``total_bytes``, and ``oldest_timestamp``.
        """
        total_entries = 0
        total_bytes = 0
        oldest: float | None = None

        for entry_path in self._dir.glob("*.json"):
            total_entries += 1
            try:
                total_bytes += entry_path.stat().st_size
            except OSError:
                continue
            try:
                data = json.loads(entry_path.read_text(encoding="utf-8"))
                ts = data.get("timestamp")
                if isinstance(ts, (int, float)):
                    if oldest is None or ts < oldest:
                        oldest = ts
            except (json.JSONDecodeError, OSError):
                continue

        return {
            "total_entries": total_entries,
            "total_bytes": total_bytes,
            "oldest_timestamp": oldest,
        }
