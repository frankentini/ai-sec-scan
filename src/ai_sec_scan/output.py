"""Output formatting for scan results."""

from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ai_sec_scan.models import ScanResult, Severity
from ai_sec_scan.sarif import to_sarif_json

console = Console()


def render_text(result: ScanResult) -> None:
    """Render scan results as rich text to the console."""
    if not result.findings:
        console.print(
            Panel(
                "[green]No security issues found.[/green]",
                title="Scan Complete",
                subtitle=(
                    f"{result.files_scanned} files scanned in {result.scan_duration}s"
                ),
            )
        )
        return

    # Summary table
    summary = Table(title="Scan Summary", show_header=False, box=None, padding=(0, 2))
    summary.add_column("Label", style="bold")
    summary.add_column("Value")
    summary.add_row("Provider", f"{result.provider} ({result.model})")
    summary.add_row("Files scanned", str(result.files_scanned))
    summary.add_row("Duration", f"{result.scan_duration}s")
    summary.add_row("Total findings", str(len(result.findings)))

    by_severity = result.findings_by_severity
    for sev in Severity:
        count = len(by_severity.get(sev, []))
        if count > 0:
            label = Text(f"  {sev.value.upper()}", style=sev.color)
            summary.add_row(label, str(count))

    console.print(summary)
    console.print()

    # Individual findings
    for finding in result.sorted_findings:
        severity_badge = Text(
            f" {finding.severity.value.upper()} ", style=f"bold {finding.severity.color}"
        )
        title = Text(f"  {finding.title}")
        header = Text.assemble(severity_badge, title)

        location = f"{finding.file_path}:{finding.line_start}"
        if finding.line_end:
            location += f"-{finding.line_end}"

        body_parts = [
            f"[bold]Location:[/bold] {location}",
            f"\n{finding.description}",
            f"\n[bold]Recommendation:[/bold] {finding.recommendation}",
        ]

        if finding.cwe_id:
            body_parts.append(f"\n[dim]{finding.cwe_id}[/dim]")
        if finding.owasp_category:
            body_parts.append(f" [dim]{finding.owasp_category}[/dim]")

        console.print(
            Panel(
                "\n".join(body_parts),
                title=header,
                title_align="left",
                border_style=finding.severity.color,
            )
        )


def render_json(result: ScanResult) -> str:
    """Render scan results as JSON string."""
    return json.dumps(result.model_dump(mode="json"), indent=2)


def render_sarif(result: ScanResult) -> str:
    """Render scan results as SARIF 2.1.0 JSON string."""
    return to_sarif_json(result)
