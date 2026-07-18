# AISAST — AI-Native Security Scanner

An AI-powered Static Application Security Testing (SAST) tool built on Claude's multi-agent architecture. It finds real security vulnerabilities in your code by **reasoning like a security expert**, not just pattern-matching.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation — Step by Step](#2-installation--step-by-step)
3. [Set Your API Key](#3-set-your-api-key)
4. [Running Your First Scan](#4-running-your-first-scan)
5. [All CLI Commands](#5-all-cli-commands)
6. [How It Works Internally](#6-how-it-works-internally)
7. [Understanding the Output](#7-understanding-the-output)
8. [PR Review Workflow](#8-pr-review-workflow)
9. [Advanced Options](#9-advanced-options)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Prerequisites

Before installing, make sure you have:

| Requirement | Version | Check Command |
|-------------|---------|---------------|
| Python | 3.10 or higher | `python --version` |
| pip | Latest | `pip --version` |
| git | Any | `git --version` (needed for PR review only) |
| Claude Auth | Session **or** API key | See [Authentication](#3-authentication) section |

---

## 2. Installation — Step by Step

### Step 1 — Open a terminal and go to the project folder

```bash
cd C:\Users\GauravBhosale\Documents\gauravAITestFolder\packages\core
```

### Step 2 — (Recommended) Create a virtual environment

```bash
# Create virtual environment
python -m venv venv

# Activate it — Windows Command Prompt
venv\Scripts\activate

# Activate it — Windows PowerShell
venv\Scripts\Activate.ps1

# Activate it — Git Bash / WSL
source venv/Scripts/activate
```

You should see `(venv)` appear in your terminal prompt.

### Step 3 — Install AISAST

```bash
pip install -e .
```

This installs the `aisast` command globally (within your venv).

### Step 4 — Verify installation

```bash
aisast --version
```

Expected output:
```
aisast, version 1.0.0
```

---

## 3. Authentication

AISAST uses Claude AI for analysis. You can authenticate using **either** of these methods:

---

### Method 1: Session-based (recommended — uses your Claude subscription)

If you have a Claude subscription (Claude.ai Pro/Max or are using Claude Code), you can use your existing session — no API key needed.

```bash
# Step 1: Open a terminal and run the Claude CLI
claude

# Step 2: Inside the Claude interactive prompt, type:
/login

# Step 3: Follow the prompts to log in with your Claude account
# Step 4: Exit the interactive prompt (Ctrl+C or /exit)
```

After logging in, AISAST will automatically use your Claude session token. Run scans as normal.

> **Note:** This works because the `claude-agent-sdk` checks for a saved session token from the `claude` CLI before requiring an API key.

---

### Method 2: API Key

If you have a direct Anthropic API key:

#### Windows Command Prompt (temporary — current session only)
```cmd
set ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxx
```

#### Windows PowerShell (temporary)
```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-xxxxxxxxxxxxxxxx"
```

#### Permanent — Windows Environment Variables
1. Press `Win + S` → search **"Environment Variables"**
2. Click **"Edit the system environment variables"**
3. Click **"Environment Variables..."**
4. Under **User variables**, click **New**
5. Variable name: `ANTHROPIC_API_KEY`
6. Variable value: `sk-ant-xxxxxxxxxxxxxxxx`
7. Click OK

### Using a `.env` file (alternative)
Create a file called `.env` in your project root:
```
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxx
```

---

## 4. Running Your First Scan

### Scan the current directory
```bash
aisast scan .
```

### Scan a specific project folder
```bash
aisast scan C:\path\to\your\project
```

### What you will see on screen

```
🛡️ AISAST Security Scanner
AI-Powered Vulnerability Detection

━━━ Phase 1/4: Architecture Assessment ━━━

  🔍 Searching: import flask
  📂 Listing directory
  ...

✅ Phase 1/4: Architecture Assessment Complete
   Duration: 45.2s | Tools: 38 | Files: 12 read, 1 written
   Created: SECURITY.md

━━━ Phase 2/4: Threat Modeling (STRIDE Analysis) ━━━

  ...

✅ Phase 2/4: Threat Modeling Complete
   Duration: 62.1s | Tools: 22 | Files: 3 read, 1 written
   Created: THREAT_MODEL.json

━━━ Phase 3/4: Code Review (Security Analysis) ━━━

  ...

✅ Phase 3/4: Code Review Complete
   Duration: 89.4s | Tools: 67 | Files: 18 read, 1 written
   Created: VULNERABILITIES.json

━━━ Phase 4/4: Report Generation ━━━

  ...

✅ Phase 4/4: Report Generation Complete

📄 Markdown report: .aisast/scan_report.md
```

### After the scan finishes

All results are saved in a `.aisast/` folder inside the scanned directory:

```
your-project/
└── .aisast/
    ├── SECURITY.md          ← Architecture map
    ├── THREAT_MODEL.json    ← All identified threats
    ├── VULNERABILITIES.json ← Confirmed vulnerabilities with evidence
    ├── scan_results.json    ← Final compiled report
    └── scan_report.md       ← Human-readable report (open this!)
```

**Open `scan_report.md`** in any Markdown viewer (VS Code, GitHub, Notepad++) to read the full report.

---

## 5. All CLI Commands

### `aisast scan` — Full Repository Scan

```bash
# Basic scan
aisast scan .
aisast scan /path/to/project

# Choose AI model (affects speed and cost)
aisast scan . --model sonnet      # Default — balanced
aisast scan . --model haiku       # Faster and cheaper
aisast scan . --model opus        # Most powerful

# Filter output by severity
aisast scan . --severity high     # Show only high + critical
aisast scan . --severity medium   # Show medium + high + critical

# Choose output format
aisast scan . --format markdown   # Default — saves .aisast/scan_report.md
aisast scan . --format json       # Prints JSON to terminal
aisast scan . --format table      # Prints summary table to terminal
aisast scan . --format text       # Plain text list

# Save output to a specific file
aisast scan . --format json --output results.json
aisast scan . --format markdown --output my_report.md

# Verbose mode (show agent thinking)
aisast scan . --debug

# Quiet mode (errors only)
aisast scan . --quiet

# Force agentic classification (for AI/LLM codebases)
aisast scan . --agentic
aisast scan . --no-agentic
```

### `aisast scan` — Sub-Agent / Phase Control

```bash
# Run only ONE specific phase
aisast scan . --subagent assessment        # Phase 1 only
aisast scan . --subagent threat-modeling   # Phase 2 only
aisast scan . --subagent code-review       # Phase 3 only
aisast scan . --subagent report-generator  # Phase 4 only

# Resume from a specific phase (skips earlier phases)
aisast scan . --resume-from threat-modeling   # Run phases 2, 3, 4
aisast scan . --resume-from code-review       # Run phases 3, 4

# Skip confirmation prompts when overwriting existing artifacts
aisast scan . --subagent code-review --force

# Skip prerequisite validation checks
aisast scan . --subagent code-review --skip-checks
```

### `aisast pr-review` — Pull Request Review

```bash
# Review diff between two branches
aisast pr-review . --base main --head feature-branch

# Review a specific commit range
aisast pr-review . --range abc1234~1..abc1234

# Review from a patch/diff file
aisast pr-review . --diff changes.patch

# Review the last N commits
aisast pr-review . --last 3

# Set minimum severity (default: medium)
aisast pr-review . --base main --head feature-branch --severity high

# Save PR report
aisast pr-review . --base main --head feature-branch --format markdown --output pr_report.md

# Update baseline VULNERABILITIES.json with PR findings
aisast pr-review . --base main --head feature-branch --update-artifacts
```

---

## 6. How It Works Internally

### The 4-Phase Pipeline

Every `aisast scan` runs these 4 phases **in sequence**. Each phase is a separate Claude AI agent with its own instructions and tool permissions.

```
┌─────────────────────────────────────────────────────────────────────┐
│  YOU run:  aisast scan .                                            │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  PYTHON (Scanner class)                                             │
│  • Creates .aisast/ directory                                       │
│  • Detects if codebase uses AI/LLM (agentic detection)              │
│  • Loads orchestration prompt                                       │
│  • Starts ClaudeSDKClient                                           │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  CLAUDE (Orchestrator)                                              │
│  • Reads orchestration/main.txt instructions                        │
│  • Decides to run agents one-by-one using the Task tool             │
│  • Waits for each agent to finish before starting next              │
└────┬────────────────────────────────────────────────────────────────┘
     │
     │  PHASE 1
     ▼
┌────────────────────────────────────┐
│  ASSESSMENT AGENT                  │
│  Tools: Read, Grep, Glob, LS, Write│
│                                    │
│  1. Explores your codebase         │
│  2. Skips node_modules, venv, etc. │
│  3. Maps architecture, entry       │
│     points, auth flows, data flows │
│                                    │
│  OUTPUT → .aisast/SECURITY.md      │
└────────────────────────────────────┘
     │
     │  PHASE 2
     ▼
┌────────────────────────────────────┐
│  THREAT MODELING AGENT             │
│  Tools: Read, Grep, Glob, Write    │
│                                    │
│  1. Reads SECURITY.md              │
│  2. Applies STRIDE methodology:    │
│     • Spoofing                     │
│     • Tampering                    │
│     • Repudiation                  │
│     • Information Disclosure       │
│     • Denial of Service            │
│     • Elevation of Privilege       │
│  3. If AI/LLM detected → adds      │
│     OWASP ASI01-ASI10 threats      │
│  4. Scores risk = Likelihood×Impact│
│                                    │
│  OUTPUT → .aisast/THREAT_MODEL.json│
└────────────────────────────────────┘
     │
     │  PHASE 3
     ▼
┌────────────────────────────────────┐
│  CODE REVIEW AGENT                 │
│  Tools: Read, Grep, Glob, Write    │
│                                    │
│  1. Reads THREAT_MODEL.json        │
│  2. For each threat, greps the     │
│     actual source code             │
│  3. Traces data from user input    │
│     → through code → to output     │
│  4. Only reports vulnerabilities   │
│     with REAL evidence:            │
│     • File path                    │
│     • Line number                  │
│     • Actual code snippet          │
│  5. Also finds NEW vulnerabilities │
│     not in the threat model        │
│                                    │
│  OUTPUT → .aisast/VULNERABILITIES  │
│           .json                    │
└────────────────────────────────────┘
     │
     │  PHASE 4
     ▼
┌────────────────────────────────────┐
│  REPORT GENERATOR AGENT            │
│  Tools: Read, Write (only)         │
│                                    │
│  1. Reads VULNERABILITIES.json     │
│  2. Counts by severity             │
│  3. Writes final scan_results.json │
│                                    │
│  OUTPUT → .aisast/scan_results.json│
└────────────────────────────────────┘
     │
     │
     ▼
┌────────────────────────────────────┐
│  PYTHON (Back in Scanner class)    │
│  • Parses scan_results.json        │
│  • Creates ScanResult object       │
│  • Formats output (Markdown/JSON)  │
│  • Saves .aisast/scan_report.md    │
│  • Sets exit code                  │
└────────────────────────────────────┘
```

### Why This Approach Is Different from Traditional SAST

| Traditional SAST | AISAST |
|-----------------|--------|
| Pattern matching (`grep for SQL + string concat`) | Reasons about data flow and trust boundaries |
| Many false positives | Only reports findings with concrete code evidence |
| Cannot understand context | Understands what the app does before looking for bugs |
| Generic rules | Generates threats specific to YOUR architecture |
| Fixed rule set | Uses STRIDE + OWASP + CWE frameworks dynamically |

### Tool Isolation — Each Agent Only Gets What It Needs

| Agent | Allowed Tools | Why |
|-------|--------------|-----|
| Assessment | Read, Grep, Glob, LS, Write | Needs to explore all files |
| Threat Modeling | Read, Grep, Glob, Write | Needs to look at code patterns |
| Code Review | Read, Grep, Glob, Write | Needs deep code search |
| Report Generator | Read, Write **only** | Just transforms JSON — no codebase access needed |
| PR Code Review | Read, Grep, Glob, Write | Needs to trace diff impact |

---

## 7. Understanding the Output

### scan_report.md structure

```
# Security Scan Report

Repository: /path/to/project
Scan Date: 2026-03-29 14:32:10
Files Scanned: 47
Scan Duration: 234.5s

---

## Executive Summary
🔴 3 security vulnerabilities found — CRITICAL

- 🔴 1 Critical
- 🟠 1 High
- 🟡 1 Medium

## Primary Exploit Chain
[The most severe finding with full attack scenario]

---

## Severity Distribution
| Severity   | Count | Percentage |
|------------|-------|------------|
| 🔴 Critical | 1    | 33%        |
| 🟠 High     | 1    | 33%        |
| 🟡 Medium   | 1    | 33%        |

---

## Vulnerability Overview
| # | Severity    | Title                    | Location              |
|---|-------------|--------------------------|----------------------|
| 1 | 🔴 CRITICAL | SQL Injection in login   | `app/auth.py:45`     |
| 2 | 🟠 HIGH     | Hardcoded secret key     | `config.py:12`       |
| 3 | 🟡 MEDIUM   | Missing CSRF protection  | `app/routes.py:89`   |

---

## Detailed Findings

### 1. SQL Injection in login [🔴 CRITICAL]
File: `app/auth.py:45`
CWE: CWE-89
...
```

### Exit Codes (useful for CI/CD)

```bash
aisast scan .
echo $?    # Check exit code

# 0 = no issues or only low/medium
# 1 = high severity issues found
# 2 = critical severity issues found
# 130 = cancelled with Ctrl+C
```

---

## 8. PR Review Workflow

Use PR review to check only the **code that changed** in a pull request, without re-scanning the whole codebase.

### Step 1 — Run a full scan first (one time)
```bash
cd your-project
aisast scan .
# This creates .aisast/SECURITY.md and .aisast/THREAT_MODEL.json
# which PR review uses as baseline context
```

### Step 2 — Before merging a PR, run pr-review
```bash
# If you're on the feature branch:
aisast pr-review . --base main --head HEAD

# Or compare two branches explicitly:
aisast pr-review . --base main --head feature/new-login

# Or check the last commit:
aisast pr-review . --last 1
```

### Step 3 — Read the PR report
Results saved to `.aisast/pr_review_report.md`

Each finding is classified as:
- `new_threat` — This change opened a new attack surface
- `threat_enabler` — Makes an already-known threat exploitable
- `mitigation_removal` — Removed a security control
- `regression` — Reintroduced a previously fixed vulnerability

---

## 9. Advanced Options

### Run Only One Phase (saves cost)

If you already have `SECURITY.md` and `THREAT_MODEL.json` and just want to re-run the code review:

```bash
aisast scan . --subagent code-review
```

If it asks about overwriting, choose option 1 (use existing) to keep your threat model.

### Resume a Failed Scan

If a scan failed partway through, resume it from where it stopped:

```bash
# If assessment and threat-modeling completed but code-review failed:
aisast scan . --resume-from code-review
```

### Use Different Models Per Phase

Set environment variables to use different models per agent (e.g., cheaper model for assessment, powerful model for code review):

```bash
# Windows CMD
set AISAST_ASSESSMENT_MODEL=haiku
set AISAST_THREAT_MODELING_MODEL=haiku
set AISAST_CODE_REVIEW_MODEL=sonnet
set AISAST_REPORT_GENERATOR_MODEL=haiku

aisast scan .
```

### Integrate into CI/CD (GitHub Actions example)

```yaml
- name: Security Scan
  run: |
    pip install -e packages/core
    aisast scan . --severity high --format json --output security-results.json
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

---

## 10. Troubleshooting

### "aisast: command not found"
Make sure your virtual environment is activated:
```bash
venv\Scripts\activate   # Windows
```
Then re-install:
```bash
pip install -e .
```

### "ANTHROPIC_API_KEY not set" or authentication error
Set your API key (see [Step 3](#3-set-your-api-key) above).

### "Repository path does not exist"
Use the full absolute path or make sure you're in the right directory:
```bash
aisast scan C:\Users\YourName\projects\my-app
```

### Scan is very slow
Use the faster/cheaper `haiku` model:
```bash
aisast scan . --model haiku
```

### "Cannot run 'code-review': Missing prerequisite"
You ran a sub-agent without the required artifacts. Either run a full scan first, or use `--skip-checks`:
```bash
aisast scan .              # Run full scan first
# OR
aisast scan . --subagent code-review --skip-checks
```

### Scan fails midway
Resume from the phase that failed:
```bash
aisast scan . --resume-from code-review
```

### Too many false positives
The code review agent is designed to only report findings with real evidence. If you're still seeing noise:
- Review `THREAT_MODEL.json` — delete irrelevant threats before running code-review
- Use `--severity high` to filter to only high/critical

---

## Project Structure

```
gauravAITestFolder/
├── README.md                          ← You are here
└── packages/
    └── core/
        ├── pyproject.toml             ← Package config, dependencies
        ├── README.md                  ← Short reference
        └── aisast/
            ├── __init__.py
            ├── config.py              ← Language detection, env vars, agent config
            ├── agents/
            │   └── definitions.py     ← 5 agent definitions with tools + prompts
            ├── cli/
            │   └── main.py            ← CLI commands (scan, pr-review)
            ├── models/
            │   ├── issue.py           ← SecurityIssue dataclass
            │   └── result.py          ← ScanResult dataclass
            ├── prompts/
            │   ├── loader.py          ← Loads .txt prompt files
            │   ├── agents/
            │   │   ├── _shared/
            │   │   │   └── security_rules.txt   ← Shared rules (no node_modules etc.)
            │   │   ├── assessment.txt           ← Phase 1 instructions
            │   │   ├── threat_modeling.txt      ← Phase 2 instructions (STRIDE)
            │   │   ├── code_review.txt          ← Phase 3 instructions
            │   │   ├── pr_code_review.txt       ← PR review instructions
            │   │   └── report_generator.txt     ← Phase 4 instructions
            │   └── orchestration/
            │       └── main.txt                 ← Top-level orchestration instructions
            ├── reporters/
            │   ├── markdown_reporter.py         ← Generates scan_report.md
            │   └── json_reporter.py             ← Saves/loads JSON results
            └── scanner/
                ├── scanner.py                   ← Core scanner class
                ├── progress.py                  ← Real-time terminal progress
                └── subagent_manager.py          ← Artifact dependency tracking
```

---

*Built with Claude AI — Anthropic's multi-agent SDK*
