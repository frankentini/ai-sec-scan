"""Security analysis rules and prompts."""

from __future__ import annotations

from ai_sec_scan.rules.default import ANALYSIS_PROMPT, build_prompt
from ai_sec_scan.rules.django import DJANGO_PROMPT, build_django_prompt
from ai_sec_scan.rules.fastapi import FASTAPI_PROMPT, build_fastapi_prompt

#: Mapping of pack name → (prompt, build_fn description)
_PACKS: dict[str, tuple[str, str]] = {
    "django": (DJANGO_PROMPT, "Django web framework — ORM, CSRF, template injection, settings"),
    "fastapi": (FASTAPI_PROMPT, "FastAPI / Starlette — JWT, CORS, Pydantic, async routes"),
}


def list_packs() -> list[dict[str, str]]:
    """Return metadata for all built-in rule packs.

    Returns:
        List of dicts with ``name``, ``description``, and ``prompt`` keys.
    """
    return [
        {"name": name, "description": desc, "prompt": prompt}
        for name, (prompt, desc) in sorted(_PACKS.items())
    ]


def get_pack_prompt(name: str) -> str | None:
    """Return the system prompt for a named rule pack.

    Args:
        name: Pack identifier (e.g. ``"django"`` or ``"fastapi"``).

    Returns:
        The prompt string, or ``None`` if the pack is unknown.
    """
    entry = _PACKS.get(name)
    return entry[0] if entry is not None else None


__all__ = [
    "ANALYSIS_PROMPT",
    "DJANGO_PROMPT",
    "FASTAPI_PROMPT",
    "build_prompt",
    "build_django_prompt",
    "build_fastapi_prompt",
    "get_pack_prompt",
    "list_packs",
]
