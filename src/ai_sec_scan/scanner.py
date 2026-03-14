"""Core scanning logic for walking directories and analyzing files."""

from __future__ import annotations

import asyncio
import fnmatch
import time
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ai_sec_scan.models import Finding, ScanResult, Severity
from ai_sec_scan.providers.base import BaseProvider

DEFAULT_EXCLUDES = [
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".eggs",
    "*.egg-info",
    ".tox",
    ".nox",
]

SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".rs", ".swift", ".kt", ".scala",
    ".sql", ".sh", ".bash", ".yaml", ".yml", ".toml", ".json", ".xml",
    ".html", ".css", ".vue", ".svelte",
}

console = Console(stderr=True)


def collect_files(
    path: Path,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_file_size_kb: int = 100,
) -> list[Path]:
    """Collect files to scan from a path.

    Args:
        path: File or directory to scan.
        include: Glob patterns to include (if set, only matching files).
        exclude: Glob patterns to exclude.
        max_file_size_kb: Maximum file size in KB.

    Returns:
        List of file paths to scan.
    """
    exclude_patterns = exclude or DEFAULT_EXCLUDES
    max_bytes = max_file_size_kb * 1024

    if path.is_file():
        if path.stat().st_size <= max_bytes:
            return [path]
        return []

    files: list[Path] = []
    for file_path in sorted(path.rglob("*")):
        if not file_path.is_file():
            continue

        # Check exclude patterns against all path parts
        rel = str(file_path.relative_to(path))
        if any(
            fnmatch.fnmatch(part, pat)
            for part in Path(rel).parts
            for pat in exclude_patterns
        ):
            continue

        # Check include patterns
        if include and not any(fnmatch.fnmatch(file_path.name, pat) for pat in include):
            continue

        # Filter by extension if no include patterns specified
        if not include and file_path.suffix not in SOURCE_EXTENSIONS:
            continue

        # Check file size
        try:
            if file_path.stat().st_size > max_bytes:
                continue
        except OSError:
            continue

        files.append(file_path)

    return files


async def scan(
    path: Path,
    provider: BaseProvider,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_file_size_kb: int = 100,
    min_severity: str | None = None,
) -> ScanResult:
    """Run a security scan on a file or directory.

    Args:
        path: File or directory to scan.
        provider: LLM provider to use for analysis.
        include: Glob patterns to include.
        exclude: Glob patterns to exclude.
        max_file_size_kb: Maximum file size in KB.
        min_severity: Minimum severity to include in results.

    Returns:
        ScanResult with all findings.
    """
    files = collect_files(path, include, exclude, max_file_size_kb)

    if not files:
        console.print("[yellow]No files found to scan.[/yellow]")
        return ScanResult(
            findings=[],
            files_scanned=0,
            scan_duration=0.0,
            provider=provider.name,
            model=provider.model,
        )

    all_findings: list[Finding] = []
    start_time = time.monotonic()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=len(files))

        for file_path in files:
            rel_path = str(file_path.relative_to(path)) if path.is_dir() else file_path.name
            progress.update(task, description=f"Scanning {rel_path}")

            try:
                code = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                console.print(f"[red]Error reading {rel_path}: {e}[/red]")
                progress.advance(task)
                continue

            try:
                findings = await provider.analyze(code, rel_path)
                all_findings.extend(findings)
            except Exception as e:
                console.print(f"[red]Error analyzing {rel_path}: {e}[/red]")

            progress.advance(task)

    duration = time.monotonic() - start_time

    # Apply severity filter
    if min_severity:
        min_rank = Severity(min_severity).rank
        all_findings = [f for f in all_findings if f.severity.rank >= min_rank]

    return ScanResult(
        findings=all_findings,
        files_scanned=len(files),
        scan_duration=round(duration, 2),
        provider=provider.name,
        model=provider.model,
    )


def run_scan_sync(
    path: Path,
    provider: BaseProvider,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_file_size_kb: int = 100,
    min_severity: str | None = None,
) -> ScanResult:
    """Synchronous wrapper for the async scan function."""
    return asyncio.run(
        scan(path, provider, include, exclude, max_file_size_kb, min_severity)
    )
