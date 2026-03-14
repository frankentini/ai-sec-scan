"""CLI entry point for ai-sec-scan."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from ai_sec_scan import __version__
from ai_sec_scan.output import render_json, render_sarif, render_text
from ai_sec_scan.providers.base import BaseProvider

console = Console(stderr=True)


def _get_provider(provider_name: str, model: str | None) -> BaseProvider:
    """Instantiate the requested LLM provider."""
    if provider_name == "anthropic":
        from ai_sec_scan.providers.anthropic import AnthropicProvider
        return AnthropicProvider(model=model)
    elif provider_name == "openai":
        from ai_sec_scan.providers.openai import OpenAIProvider
        return OpenAIProvider(model=model)
    else:
        console.print(f"[red]Unknown provider: {provider_name}[/red]")
        sys.exit(1)


@click.group()
@click.version_option(version=__version__, prog_name="ai-sec-scan")
def main() -> None:
    """AI-powered security scanner for source code."""


@main.command()
def version() -> None:
    """Show the package version."""
    click.echo(__version__)


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "-p", "--provider",
    type=click.Choice(["anthropic", "openai"]),
    default="anthropic",
    show_default=True,
    help="LLM provider to use.",
)
@click.option("-m", "--model", default=None, help="Model name override.")
@click.option(
    "-o", "--output",
    "output_format",
    type=click.Choice(["text", "json", "sarif"]),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option(
    "-s", "--severity",
    type=click.Choice(["info", "low", "medium", "high", "critical"]),
    default=None,
    help="Minimum severity to report.",
)
@click.option("-f", "--output-file", default=None, help="Write output to file.")
@click.option(
    "--max-file-size", default=100, type=int, show_default=True,
    help="Max file size in KB.",
)
@click.option("-i", "--include", multiple=True, help="Glob patterns to include (repeatable).")
@click.option("-e", "--exclude", multiple=True, help="Glob patterns to exclude (repeatable).")
def scan(
    path: str,
    provider: str,
    model: str | None,
    output_format: str,
    severity: str | None,
    output_file: str | None,
    max_file_size: int,
    include: tuple[str, ...],
    exclude: tuple[str, ...],
) -> None:
    """Scan a file or directory for security vulnerabilities."""
    from ai_sec_scan.scanner import run_scan_sync

    target = Path(path)

    try:
        llm_provider = _get_provider(provider, model)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    console.print(
        f"[bold]ai-sec-scan[/bold] v{__version__} | "
        f"provider: {llm_provider.name} | model: {llm_provider.model}"
    )
    console.print(f"Scanning: {target.resolve()}\n")

    result = run_scan_sync(
        path=target,
        provider=llm_provider,
        include=list(include) if include else None,
        exclude=list(exclude) if exclude else None,
        max_file_size_kb=max_file_size,
        min_severity=severity,
    )

    # Render output
    if output_format == "text":
        render_text(result)
        text_output = None
    elif output_format == "json":
        text_output = render_json(result)
    elif output_format == "sarif":
        text_output = render_sarif(result)
    else:
        text_output = None

    if text_output:
        if output_file:
            Path(output_file).write_text(text_output, encoding="utf-8")
            console.print(f"\n[green]Results written to {output_file}[/green]")
        else:
            click.echo(text_output)

    # Exit with non-zero if findings exist
    if result.findings:
        sys.exit(1)
