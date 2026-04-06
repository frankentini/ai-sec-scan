"""Token counting and cost estimation for scan operations."""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

from ai_sec_scan.rules.default import build_prompt
from ai_sec_scan.scanner import collect_files

# Approximate characters-per-token ratio for modern LLMs.
# OpenAI's tokenizer averages ~4 chars/token for English code;
# Anthropic is similar.  We use a conservative 3.5 to slightly
# over-estimate rather than under-estimate.
_CHARS_PER_TOKEN = 3.5

# Per-model pricing in USD per 1M tokens (input, output).
# Output tokens are estimated as a fixed ratio of input tokens
# since the actual response length depends on vulnerability density.
_PRICING: dict[str, tuple[float, float]] = {
    # Anthropic
    "claude-sonnet-4-20250514": (3.00, 15.00),
    "claude-3-5-sonnet-20241022": (3.00, 15.00),
    "claude-3-haiku-20240307": (0.25, 1.25),
    "claude-3-opus-20240229": (15.00, 75.00),
    # OpenAI
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4-turbo": (10.00, 30.00),
    "gpt-3.5-turbo": (0.50, 1.50),
}

# Estimated output tokens as a fraction of input tokens.
_OUTPUT_RATIO = 0.25


def estimate_tokens(text: str) -> int:
    """Estimate the number of tokens in a string.

    Uses a character-based heuristic that tends to slightly over-count,
    which is preferable for cost estimation.

    Args:
        text: The input text.

    Returns:
        Estimated token count.
    """
    if not text:
        return 0
    return max(1, math.ceil(len(text) / _CHARS_PER_TOKEN))


def model_price(model: str) -> tuple[float, float] | None:
    """Look up per-million-token pricing for a model.

    Args:
        model: Model identifier string.

    Returns:
        Tuple of (input_price, output_price) per 1M tokens, or None
        if the model is not in the pricing table.
    """
    return _PRICING.get(model)


@dataclass(frozen=True)
class CostEstimate:
    """Estimated cost for a scan operation."""

    file_count: int
    total_input_tokens: int
    estimated_output_tokens: int
    model: str
    input_cost_usd: float | None
    output_cost_usd: float | None

    @property
    def total_tokens(self) -> int:
        """Total estimated tokens (input + output)."""
        return self.total_input_tokens + self.estimated_output_tokens

    @property
    def total_cost_usd(self) -> float | None:
        """Total estimated cost in USD, or None if pricing unavailable."""
        if self.input_cost_usd is None or self.output_cost_usd is None:
            return None
        return round(self.input_cost_usd + self.output_cost_usd, 6)

    def summary(self) -> str:
        """Human-readable one-line summary."""
        cost = self.total_cost_usd
        cost_str = f"${cost:.4f}" if cost is not None else "unknown (model not in pricing table)"
        return (
            f"{self.file_count} file(s), ~{self.total_input_tokens:,} input tokens, "
            f"~{self.estimated_output_tokens:,} output tokens — estimated cost: {cost_str}"
        )


def estimate_scan_cost(
    path: Path,
    model: str,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_file_size_kb: int = 100,
) -> CostEstimate:
    """Estimate the token count and cost of scanning a path.

    Collects files the same way the scanner does, builds the analysis
    prompt for each file, and sums up token estimates.

    Args:
        path: File or directory to estimate.
        model: Model identifier for pricing lookup.
        include: Glob patterns to include.
        exclude: Glob patterns to exclude.
        max_file_size_kb: Maximum file size in KB.

    Returns:
        A ``CostEstimate`` with token counts and projected cost.
    """
    files = collect_files(path, include, exclude, max_file_size_kb)

    total_input = 0
    for file_path in files:
        try:
            code = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(file_path.relative_to(path)) if path.is_dir() else file_path.name
        prompt = build_prompt(code, rel)
        total_input += estimate_tokens(prompt)

    estimated_output = math.ceil(total_input * _OUTPUT_RATIO)

    pricing = model_price(model)
    if pricing is not None:
        input_cost = round(total_input / 1_000_000 * pricing[0], 6)
        output_cost = round(estimated_output / 1_000_000 * pricing[1], 6)
    else:
        input_cost = None
        output_cost = None

    return CostEstimate(
        file_count=len(files),
        total_input_tokens=total_input,
        estimated_output_tokens=estimated_output,
        model=model,
        input_cost_usd=input_cost,
        output_cost_usd=output_cost,
    )
