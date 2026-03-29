"""Tests for baseline suppression."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_sec_scan.baseline import Baseline, _fingerprint
from ai_sec_scan.models import Finding, Severity


def _make_finding(
    file_path: str = "app.py",
    title: str = "SQL Injection",
    cwe_id: str | None = "CWE-89",
    line_start: int = 10,
) -> Finding:
    return Finding(
        file_path=file_path,
        line_start=line_start,
        severity=Severity.HIGH,
        title=title,
        description="desc",
        recommendation="fix",
        cwe_id=cwe_id,
    )


class TestFingerprint:
    def test_stable_across_calls(self) -> None:
        f = _make_finding()
        assert _fingerprint(f) == _fingerprint(f)

    def test_line_change_does_not_affect_fingerprint(self) -> None:
        f1 = _make_finding(line_start=10)
        f2 = _make_finding(line_start=25)
        assert _fingerprint(f1) == _fingerprint(f2)

    def test_different_title_different_fingerprint(self) -> None:
        f1 = _make_finding(title="SQL Injection")
        f2 = _make_finding(title="XSS")
        assert _fingerprint(f1) != _fingerprint(f2)

    def test_different_file_different_fingerprint(self) -> None:
        f1 = _make_finding(file_path="a.py")
        f2 = _make_finding(file_path="b.py")
        assert _fingerprint(f1) != _fingerprint(f2)

    def test_cwe_included_when_present(self) -> None:
        f_with = _make_finding(cwe_id="CWE-89")
        f_without = _make_finding(cwe_id=None)
        assert _fingerprint(f_with) != _fingerprint(f_without)


class TestBaseline:
    def test_contains(self) -> None:
        f = _make_finding()
        fp = _fingerprint(f)
        baseline = Baseline({fp})
        assert f in baseline

    def test_not_contains(self) -> None:
        baseline = Baseline(set())
        assert _make_finding() not in baseline

    def test_len(self) -> None:
        baseline = Baseline({"a", "b", "c"})
        assert len(baseline) == 3

    def test_filter_removes_baselined(self) -> None:
        f1 = _make_finding(title="SQL Injection")
        f2 = _make_finding(title="XSS", cwe_id="CWE-79")
        fp1 = _fingerprint(f1)
        baseline = Baseline({fp1})

        remaining, suppressed = baseline.filter([f1, f2])
        assert suppressed == 1
        assert len(remaining) == 1
        assert remaining[0].title == "XSS"

    def test_filter_all_suppressed(self) -> None:
        f = _make_finding()
        baseline = Baseline({_fingerprint(f)})
        remaining, suppressed = baseline.filter([f])
        assert remaining == []
        assert suppressed == 1

    def test_filter_none_suppressed(self) -> None:
        f = _make_finding()
        baseline = Baseline(set())
        remaining, suppressed = baseline.filter([f])
        assert remaining == [f]
        assert suppressed == 0


class TestBaselineLoad:
    def test_load_valid(self, tmp_path: Path) -> None:
        f = _make_finding()
        fp = _fingerprint(f)
        data = {"version": 1, "fingerprints": [fp], "entries": []}
        path = tmp_path / "baseline.json"
        path.write_text(json.dumps(data))

        baseline = Baseline.load(path)
        assert len(baseline) == 1
        assert f in baseline

    def test_load_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            Baseline.load(tmp_path / "nope.json")

    def test_load_invalid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{not valid")
        with pytest.raises(ValueError, match="Invalid JSON"):
            Baseline.load(path)

    def test_load_missing_fingerprints_key(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text(json.dumps({"version": 1}))
        with pytest.raises(ValueError, match="fingerprints"):
            Baseline.load(path)

    def test_load_bad_fingerprints_type(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text(json.dumps({"fingerprints": "not-a-list"}))
        with pytest.raises(ValueError, match="list of strings"):
            Baseline.load(path)


class TestBaselineGenerate:
    def test_generate_from_findings(self) -> None:
        f1 = _make_finding(title="SQL Injection")
        f2 = _make_finding(title="XSS", cwe_id="CWE-79")
        doc = Baseline.generate([f1, f2])

        assert doc["version"] == 1
        assert len(doc["fingerprints"]) == 2
        assert len(doc["entries"]) == 2
        titles = {e["title"] for e in doc["entries"]}
        assert titles == {"SQL Injection", "XSS"}

    def test_generate_deduplicates(self) -> None:
        f = _make_finding()
        doc = Baseline.generate([f, f])
        assert len(doc["fingerprints"]) == 1

    def test_generate_empty(self) -> None:
        doc = Baseline.generate([])
        assert doc["fingerprints"] == []
        assert doc["entries"] == []

    def test_roundtrip(self, tmp_path: Path) -> None:
        f = _make_finding()
        doc = Baseline.generate([f])

        path = tmp_path / "baseline.json"
        path.write_text(json.dumps(doc))
        baseline = Baseline.load(path)

        assert f in baseline
