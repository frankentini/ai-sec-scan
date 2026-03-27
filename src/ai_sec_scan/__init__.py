"""AI-powered security scanner for source code."""

from ai_sec_scan.models import Finding, ScanResult, Severity
from ai_sec_scan.providers.base import BaseProvider
from ai_sec_scan.scanner import collect_files, run_scan_sync, scan

__version__ = "0.2.0"

__all__ = [
    "BaseProvider",
    "Finding",
    "ScanResult",
    "Severity",
    "__version__",
    "collect_files",
    "run_scan_sync",
    "scan",
]
