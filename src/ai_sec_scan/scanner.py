"""Core scanning logic for walking directories and analyzing files."""

from __future__ import annotations

import asyncio
import fnmatch
import time
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ai_sec_scan.cache import ResultCache, file_hash
from ai_sec_scan.models import Finding, ScanResult
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


async def _analyze_file(
    file_path: Path,
    rel_path: str,
    provider: BaseProvider,
    cache: ResultCache | None,
) -> list[Finding]:
    """Analyze a single file, using cache when available.

    Returns the findings for the file. On cache hit the provider is
    skipped entirely. On cache miss the result is stored for future runs.
    """
    try:
        code = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    content_hash = file_hash(file_path) if cache else ""

    if cache:
        cached = cache.get(rel_path, content_hash, provider.name, provider.model)
        if cached is not None:
            return cached

    try:
        findings = await provider.analyze(code, rel_path)
    except Exception:
        return []

    if cache:
        cache.put(rel_path, content_hash, provider.name, provider.model, findings)

    return findings


async def scan(
    path: Path,
    provider: BaseProvider,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_file_size_kb: int = 100,
    min_severity: str | None = None,
    quiet: bool = False,
    cache_dir: Path | None = None,
    no_cache: bool = False,
    parallel: int = 1,
    timeout: float | None = None,
) -> ScanResult:
    """Run a security scan on a file or directory.

    Args:
        path: File or directory to scan.
        provider: LLM provider to use for analysis.
        include: Glob patterns to include.
        exclude: Glob patterns to exclude.
        max_file_size_kb: Maximum file size in KB.
        min_severity: Minimum severity to include in results.
        quiet: Suppress progress output.
        cache_dir: Directory for the result cache. ``None`` uses the default.
        no_cache: Disable caching entirely when ``True``.
        parallel: Maximum number of files to analyze concurrently. Defaults
            to ``1`` (sequential). Values above 1 enable parallel analysis
            using an ``asyncio.Semaphore``.
        timeout: Maximum wall-clock seconds for the entire scan. When
            exceeded the scan stops early and returns partial results.
            ``None`` means no limit.

    Returns:
        ScanResult with all findings.
    """
    files = collect_files(path, include, exclude, max_file_size_kb)

    if not files:
        if not quiet:
            console.print("[yellow]No files found to scan.[/yellow]")
        return ScanResult(
            findings=[],
            files_scanned=0,
            scan_duration=0.0,
            provider=provider.name,
            model=provider.model,
        )

    cache = None if no_cache else ResultCache(cache_dir=cache_dir)
    concurrency = max(1, parallel)

    all_findings: list[Finding] = []
    files_analyzed = 0
    start_time = time.monotonic()
    deadline = (start_time + timeout) if timeout else None

    def _timed_out() -> bool:
        return deadline is not None and time.monotonic() >= deadline

    if concurrency == 1:
        # Sequential path (original behaviour)
        if quiet:
            for fp in files:
                if _timed_out():
                    break
                rel_path = str(fp.relative_to(path)) if path.is_dir() else fp.name
                findings = await _analyze_file(fp, rel_path, provider, cache)
                all_findings.extend(findings)
                files_analyzed += 1
        else:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Scanning...", total=len(files))

                for fp in files:
                    if _timed_out():
                        break
                    rel_path = str(fp.relative_to(path)) if path.is_dir() else fp.name
                    progress.update(task, description=f"Scanning {rel_path}")

                    findings = await _analyze_file(fp, rel_path, provider, cache)
                    all_findings.extend(findings)
                    files_analyzed += 1

                    progress.advance(task)

            if _timed_out() and not quiet:
                console.print(
                    f"[yellow]Timeout reached after {timeout}s — "
                    f"scanned {files_analyzed}/{len(files)} file(s).[/yellow]"
                )
    else:
        # Parallel path
        semaphore = asyncio.Semaphore(concurrency)
        results_lock = asyncio.Lock()

        progress_ctx = (
            None
            if quiet
            else Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            )
        )

        task_id = None
        if progress_ctx is not None:
            progress_ctx.start()
            task_id = progress_ctx.add_task("Scanning...", total=len(files))

        timed_out_flag = False

        async def _process(fp: Path) -> None:
            nonlocal timed_out_flag, files_analyzed
            if timed_out_flag or _timed_out():
                timed_out_flag = True
                return
            rel_path = str(fp.relative_to(path)) if path.is_dir() else fp.name
            async with semaphore:
                if _timed_out():
                    timed_out_flag = True
                    return
                findings = await _analyze_file(fp, rel_path, provider, cache)
            async with results_lock:
                all_findings.extend(findings)
                files_analyzed += 1
            if progress_ctx is not None and task_id is not None:
                progress_ctx.advance(task_id)

        await asyncio.gather(*[_process(fp) for fp in files])

        if progress_ctx is not None:
            progress_ctx.stop()

    duration = time.monotonic() - start_time

    result = ScanResult(
        findings=all_findings,
        files_scanned=files_analyzed,
        scan_duration=round(duration, 2),
        provider=provider.name,
        model=provider.model,
    )

    # Apply severity filter
    if min_severity:
        result = result.filter_by_severity(min_severity)

    return result


def run_scan_sync(
    path: Path,
    provider: BaseProvider,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_file_size_kb: int = 100,
    min_severity: str | None = None,
    quiet: bool = False,
    cache_dir: Path | None = None,
    no_cache: bool = False,
    parallel: int = 1,
    timeout: float | None = None,
) -> ScanResult:
    """Synchronous wrapper for the async scan function."""
    return asyncio.run(
        scan(
            path, provider, include, exclude, max_file_size_kb,
            min_severity, quiet, cache_dir, no_cache, parallel, timeout,
        )
    )
