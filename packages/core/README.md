# AISAST - AI-Native Static Application Security Testing

AI-powered security scanner that uses Claude's multi-agent architecture to find vulnerabilities in your code.

## Features

- **4-Phase Pipeline**: Assessment → Threat Modeling → Code Review → Report Generation
- **STRIDE + CWE methodology**: Structured threat analysis with evidence
- **PR Review**: Analyze git diffs for security regressions
- **Multiple output formats**: Markdown, JSON, table, text
- **11 languages**: Python, JS, TS, Go, Ruby, Java, PHP, C#, Rust, Kotlin, Swift
- **Agentic app detection**: Auto-applies OWASP ASI threats for LLM/agent codebases

## Installation

```bash
cd packages/core
pip install -e ".[dev]"
export ANTHROPIC_API_KEY="your-api-key"
```

## Usage

### Full Scan

```bash
aisast scan .
aisast scan /path/to/project --severity high
aisast scan . --format json --output results.json
aisast scan . --model haiku   # faster/cheaper
```

### Sub-Agent Mode

```bash
aisast scan . --subagent assessment        # Architecture analysis only
aisast scan . --subagent code-review       # Code review only
aisast scan . --resume-from threat-modeling  # Resume from phase 2
```

### PR Review

```bash
aisast pr-review . --base main --head feature-branch
aisast pr-review . --range abc123~1..abc123
aisast pr-review . --diff changes.patch
aisast pr-review . --last 3
```

## Artifacts (stored in `.aisast/`)

| File | Created By | Description |
|------|-----------|-------------|
| `SECURITY.md` | Assessment | Architecture documentation |
| `THREAT_MODEL.json` | Threat Modeling | STRIDE threats |
| `VULNERABILITIES.json` | Code Review | Confirmed vulnerabilities |
| `scan_results.json` | Report Generator | Final compiled report |
| `PR_VULNERABILITIES.json` | PR Review | PR-specific findings |

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `AISAST_ASSESSMENT_MODEL` | Override model for assessment agent |
| `AISAST_THREAT_MODELING_MODEL` | Override model for threat modeling agent |
| `AISAST_CODE_REVIEW_MODEL` | Override model for code review agent |
| `AISAST_PR_CODE_REVIEW_MODEL` | Override model for PR review agent |
| `AISAST_REPORT_GENERATOR_MODEL` | Override model for report generator |
| `AISAST_MAX_TURNS` | Max agent turns (default: 50) |
| `AISAST_PR_REVIEW_TIMEOUT_SECONDS` | PR review timeout (default: 240) |
| `AISAST_PR_REVIEW_ATTEMPTS` | PR review retry attempts (default: 4) |

## Exit Codes

- `0` — No issues or only low/medium severity
- `1` — High severity issues found
- `2` — Critical severity issues found
- `130` — Cancelled by user
