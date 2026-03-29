"""Baseline file support for suppressing known findings."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ai_sec_scan.models import Finding


def _fingerprint(finding: Finding) -> str:
    """Compute a stable fingerprint for a finding.

    The fingerprint is based on file path, title, and CWE ID (if present),
    making it resilient to minor line number changes across edits.
    """
    parts = [finding.file_path, finding.title]
    if finding.cwe_id:
        parts.append(finding.cwe_id)
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class Baseline:
    """A set of known finding fingerprints to suppress from results."""

    def __init__(self, fingerprints: set[str]) -> None:
        self._fingerprints = fingerprints

    def __len__(self) -> int:
        return len(self._fingerprints)

    def __contains__(self, finding: Finding) -> bool:
        return _fingerprint(finding) in self._fingerprints

    def filter(self, findings: list[Finding]) -> tuple[list[Finding], int]:
        """Remove baselined findings.

        Returns:
            A tuple of (remaining findings, number suppressed).
        """
        remaining: list[Finding] = []
        suppressed = 0
        for f in findings:
            if f in self:
                suppressed += 1
            else:
                remaining.append(f)
        return remaining, suppressed

    @classmethod
    def load(cls, path: Path) -> "Baseline":
        """Load a baseline from a JSON file.

        The file should contain a JSON object with a ``"fingerprints"`` key
        mapping to a list of hex strings.

        Raises:
            FileNotFoundError: If the baseline file does not exist.
            ValueError: If the file format is invalid.
        """
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in baseline file: {exc}") from exc

        if not isinstance(data, dict) or "fingerprints" not in data:
            raise ValueError(
                "Baseline file must be a JSON object with a 'fingerprints' key"
            )

        fps = data["fingerprints"]
        if not isinstance(fps, list) or not all(isinstance(fp, str) for fp in fps):
            raise ValueError("'fingerprints' must be a list of strings")

        return cls(set(fps))

    @staticmethod
    def generate(findings: list[Finding]) -> dict[str, Any]:
        """Generate a baseline document from a list of findings.

        Returns:
            A dict suitable for writing as JSON.
        """
        entries: list[dict[str, str]] = []
        seen: set[str] = set()

        for f in findings:
            fp = _fingerprint(f)
            if fp in seen:
                continue
            seen.add(fp)
            entry: dict[str, str] = {
                "fingerprint": fp,
                "file_path": f.file_path,
                "title": f.title,
            }
            if f.cwe_id:
                entry["cwe_id"] = f.cwe_id
            entries.append(entry)

        return {
            "version": 1,
            "fingerprints": [e["fingerprint"] for e in entries],
            "entries": entries,
        }
