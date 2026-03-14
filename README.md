# ai-sec-scan

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

AI-powered security scanner for source code. Uses LLMs to identify vulnerabilities, generate actionable recommendations, and output industry-standard SARIF reports.

## Features

- **Multi-provider** -- supports Anthropic (Claude) and OpenAI (GPT) backends
- **SARIF 2.1.0 output** -- integrates with GitHub Code Scanning and other SARIF-compatible tools
- **Rich terminal UI** -- color-coded severity badges, structured findings, progress indicators
- **Flexible filtering** -- include/exclude glob patterns, severity thresholds, file size limits
- **CI-ready** -- non-zero exit code when findings are detected

## Installation

```bash
pip install ai-sec-scan
```

Or install from source:

```bash
git clone https://github.com/frankentini/ai-sec-scan.git
cd ai-sec-scan
pip install -e .
```

## Quick Start

Set your API key:

```bash
export ANTHROPIC_API_KEY="your-key-here"
# or
export OPENAI_API_KEY="your-key-here"
```

Scan a file or directory:

```bash
# Scan a single file
ai-sec-scan scan app.py

# Scan a directory
ai-sec-scan scan ./src

# Use OpenAI instead of Anthropic
ai-sec-scan scan ./src -p openai

# Filter by minimum severity
ai-sec-scan scan ./src -s high

# Output as SARIF
ai-sec-scan scan ./src -o sarif -f results.sarif

# Include only Python files
ai-sec-scan scan ./src -i "*.py"
```

## Output Formats

### Text (default)

Rich terminal output with color-coded severity, file locations, descriptions, and fix recommendations.

### JSON

```bash
ai-sec-scan scan ./src -o json
```

Machine-readable JSON with all finding details, scan metadata, and timing.

### SARIF

```bash
ai-sec-scan scan ./src -o sarif -f results.sarif
```

[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) for integration with GitHub Code Scanning, VS Code SARIF Viewer, and other static analysis tools.

## GitHub Code Scanning

Add to your CI workflow to upload results:

```yaml
- name: Run ai-sec-scan
  run: ai-sec-scan scan ./src -o sarif -f results.sarif
  continue-on-error: true
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## CLI Reference

```
Usage: ai-sec-scan scan [OPTIONS] PATH

Options:
  -p, --provider [anthropic|openai]  LLM provider (default: anthropic)
  -m, --model TEXT                   Model name override
  -o, --output [text|json|sarif]     Output format (default: text)
  -s, --severity [info|low|medium|high|critical]
                                     Minimum severity to report
  -f, --output-file TEXT             Write output to file
  --max-file-size INTEGER            Max file size in KB (default: 100)
  -i, --include TEXT                 Glob patterns to include (repeatable)
  -e, --exclude TEXT                 Glob patterns to exclude (repeatable)
```

## Configuration

| Environment Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | For Anthropic provider | [console.anthropic.com](https://console.anthropic.com/) |
| `OPENAI_API_KEY` | For OpenAI provider | [platform.openai.com](https://platform.openai.com/api-keys) |

## Development

```bash
git clone https://github.com/frankentini/ai-sec-scan.git
cd ai-sec-scan
pip install -e ".[dev]"
pytest
ruff check src/ tests/
mypy src/
```

## License

[MIT](LICENSE)
