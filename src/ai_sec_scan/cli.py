"""CLI entry point for ai-sec-scan."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import click
import yaml
from rich.console import Console

from ai_sec_scan import __version__
from ai_sec_scan.output import (
    render_github_annotations,
    render_json,
    render_sarif,
    render_text,
)
from ai_sec_scan.providers.base import BaseProvider

console = Console(stderr=True)
CONFIG_FILENAME = ".ai-sec-scan.yaml"

_LONG_OPTIONS_WITH_VALUE = {
    "--provider",
    "--model",
    "--output",
    "--severity",
    "--output-file",
    "--max-file-size",
    "--include",
    "--exclude",
}
_SHORT_OPTIONS_WITH_VALUE = {"-p", "-m", "-o", "-s", "-f", "-i", "-e"}
_CONFIG_KEY_MAP = {
    "provider": "provider",
    "model": "model",
    "severity": "severity",
    "output": "output_format",
    "output_file": "output_file",
    "max_file_size": "max_file_size",
    "include": "include",
    "exclude": "exclude",
    "github_annotations": "github_annotations",
}


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


def _extract_scan_target_arg(args: list[str]) -> str | None:
    """Extract the scan target positional argument from raw CLI args."""
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            return args[index + 1] if index + 1 < len(args) else None

        if token in _LONG_OPTIONS_WITH_VALUE or token in _SHORT_OPTIONS_WITH_VALUE:
            index += 2
            continue

        if token.startswith("--"):
            if any(token.startswith(f"{option}=") for option in _LONG_OPTIONS_WITH_VALUE):
                index += 1
                continue
            index += 1
            continue

        if token.startswith("-") and token != "-":
            index += 1
            continue

        return token

    return None


def _find_config_file(scan_target: Path) -> Path | None:
    """Resolve config file location based on scan target and cwd."""
    candidates: list[Path] = []
    if scan_target.exists():
        target_dir = scan_target if scan_target.is_dir() else scan_target.parent
        candidates.append(target_dir / CONFIG_FILENAME)

    cwd_candidate = Path.cwd() / CONFIG_FILENAME
    if cwd_candidate not in candidates:
        candidates.append(cwd_candidate)

    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _normalize_list_config_value(key: str, value: object) -> list[str]:
    """Normalize list config values into a list of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise click.ClickException(
        f"Invalid '{key}' in {CONFIG_FILENAME}: expected string or list[str]"
    )


def _load_config_defaults(scan_target_arg: str | None) -> dict[str, Any]:
    """Load CLI default values from .ai-sec-scan.yaml."""
    scan_target = Path(scan_target_arg) if scan_target_arg else Path.cwd()
    config_path = _find_config_file(scan_target)
    if config_path is None:
        return {}

    try:
        raw_data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise click.ClickException(f"Unable to read {config_path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise click.ClickException(f"Invalid YAML in {config_path}: {exc}") from exc

    if raw_data is None:
        return {}
    if not isinstance(raw_data, dict):
        raise click.ClickException(f"Invalid {config_path}: top-level content must be a mapping")

    defaults: dict[str, Any] = {}
    for raw_key, value in raw_data.items():
        if not isinstance(raw_key, str):
            continue
        key = _CONFIG_KEY_MAP.get(raw_key)
        if key is None:
            continue
        if key in {"include", "exclude"}:
            defaults[key] = _normalize_list_config_value(raw_key, value)
        else:
            defaults[key] = value

    return defaults


class ConfigAwareScanCommand(click.Command):
    """Click command that preloads defaults from .ai-sec-scan.yaml."""

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        config_defaults = _load_config_defaults(_extract_scan_target_arg(args))
        if config_defaults:
            merged_defaults = dict(config_defaults)
            if ctx.default_map:
                merged_defaults.update(ctx.default_map)
            ctx.default_map = merged_defaults
        return super().parse_args(ctx, args)


@click.group()
@click.version_option(version=__version__, prog_name="ai-sec-scan")
def main() -> None:
    """AI-powered security scanner for source code."""


@main.command()
def version() -> None:
    """Show the package version."""
    click.echo(__version__)


@main.command(cls=ConfigAwareScanCommand)
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
    type=click.Choice(["text", "json", "sarif", "github"]),
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
@click.option(
    "--github-annotations",
    is_flag=True,
    default=False,
    help="Emit GitHub Actions workflow command annotations to stdout.",
)
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
    github_annotations: bool,
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
    elif output_format == "github":
        text_output = render_github_annotations(result)
    else:
        text_output = None

    if text_output:
        if output_file:
            Path(output_file).write_text(text_output, encoding="utf-8")
            console.print(f"\n[green]Results written to {output_file}[/green]")
        else:
            click.echo(text_output)

    if github_annotations and output_format != "github":
        annotations_output = render_github_annotations(result)
        if annotations_output:
            click.echo(annotations_output)

    # Exit with non-zero if findings exist
    if result.findings:
        sys.exit(1)
