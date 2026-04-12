"""Security analysis rules and prompts."""

from __future__ import annotations

from ai_sec_scan.rules.default import ANALYSIS_PROMPT, build_prompt
from ai_sec_scan.rules.django import DJANGO_PROMPT, build_django_prompt
from ai_sec_scan.rules.express import EXPRESS_PROMPT, build_express_prompt
from ai_sec_scan.rules.fastapi import FASTAPI_PROMPT, build_fastapi_prompt
from ai_sec_scan.rules.spring import SPRING_PROMPT, build_spring_prompt

#: Mapping of pack name → (prompt, description)
_PACKS: dict[str, tuple[str, str]] = {
    "django": (DJANGO_PROMPT, "Django web framework — ORM, CSRF, template injection, settings"),
    "express": (EXPRESS_PROMPT, "Express.js / Node.js — XSS, prototype pollution, JWT, CORS"),
    "fastapi": (FASTAPI_PROMPT, "FastAPI / Starlette — JWT, CORS, Pydantic, async routes"),
    "spring": (SPRING_PROMPT, "Spring Boot / Java — SpEL injection, deserialization, actuators"),
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
    "EXPRESS_PROMPT",
    "FASTAPI_PROMPT",
    "SPRING_PROMPT",
    "build_prompt",
    "build_django_prompt",
    "build_express_prompt",
    "build_fastapi_prompt",
    "build_spring_prompt",
    "get_pack_prompt",
    "list_packs",
]
