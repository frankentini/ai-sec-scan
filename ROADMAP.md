# Roadmap

## v0.1.0 (current)

- CLI scanner with `scan` and `version` commands
- Anthropic (Claude) and OpenAI (GPT) provider backends
- Text, JSON, and SARIF 2.1.0 output formats
- File filtering (include/exclude globs, size limits, severity threshold)
- Rich terminal UI with progress indicators
- GitHub Code Scanning integration via SARIF upload

## v0.2.0 (complete)

- [x] GitHub Action for drop-in CI integration
- [x] Pre-commit hook support
- [x] `.ai-sec-scan.yaml` config file for per-project defaults
- [x] Scan summary annotations on pull requests

## v0.3.0

- Multi-file context awareness (understand imports and call chains across files)
- Result caching to skip unchanged files on re-scan
- Parallel file analysis for faster scans

## v0.4.0

- Custom rules (bring your own prompts for domain-specific checks)
- Framework-specific rule packs (Django, FastAPI, Express, Spring)
- Baseline file to suppress known findings

## v1.0.0

- Stable Python API for programmatic use
- VS Code extension with inline findings
- Diff-only scanning (analyze changed lines only)
- Cost estimation before scan
- Plugin system for community providers
