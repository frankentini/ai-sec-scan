"""Default security analysis prompt and rules."""

from __future__ import annotations

ANALYSIS_PROMPT = """\
You are a security code reviewer. Analyze the following source code for security \
vulnerabilities. Be precise and avoid false positives -- only report issues you are \
confident about.

For each vulnerability found, return a JSON object with these fields:
- "file_path": the filename provided below
- "line_start": integer, the line number where the vulnerability begins (1-indexed)
- "line_end": integer or null, the line number where it ends (null if single line)
- "severity": one of "critical", "high", "medium", "low", "info"
- "title": short descriptive title (under 80 chars)
- "description": detailed explanation of the vulnerability
- "recommendation": specific remediation guidance with code examples where helpful
- "cwe_id": CWE identifier if applicable (e.g. "CWE-89"), or null
- "owasp_category": OWASP Top 10 2021 category if applicable (e.g. "A03:2021"), or null

Return ONLY a JSON array of finding objects. If no vulnerabilities are found, return \
an empty array []. Do not include any text outside the JSON array.

Severity guidelines:
- critical: Remote code execution, authentication bypass, data exfiltration
- high: SQL injection, XSS, path traversal, command injection, hardcoded secrets
- medium: Missing input validation, insecure defaults, weak cryptography
- low: Information disclosure, verbose errors, missing security headers
- info: Best practice suggestions, code quality issues with security implications
"""


def build_prompt(code: str, filename: str) -> str:
    """Build the full analysis prompt for a given file.

    Args:
        code: The source code to analyze.
        filename: The name of the file.

    Returns:
        The complete prompt string.
    """
    return f"{ANALYSIS_PROMPT}\nFilename: {filename}\n\n```\n{code}\n```"
