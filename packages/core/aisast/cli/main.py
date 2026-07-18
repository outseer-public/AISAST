"""Main CLI entry point for AISAST"""

import asyncio
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List

import click
from rich.console import Console
from rich.table import Table
from rich import box

from aisast import __version__
from aisast.models.issue import SEVERITY_RANK, Severity
from aisast.models.result import ScanResult
from aisast.scanner.scanner import Scanner

console = Console()


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_AISAST_ART = [
    " █████╗ ██╗███████╗ █████╗ ███████╗████████╗",
    "██╔══██╗██║██╔════╝██╔══██╗██╔════╝╚══██╔══╝",
    "███████║██║███████╗███████║███████╗   ██║   ",
    "██╔══██║██║╚════██║██╔══██║╚════██║   ██║   ",
    "██║  ██║██║███████║██║  ██║███████║   ██║   ",
    "╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ",
]

_CAPABILITIES = [
    ("5-phase pipeline",  "Arch → Threat Model → Diagram → Code → Report"),
    ("Multi-methodology", "STRIDE · LINDDUN · Attack-trees threat modeling"),
    ("OWASP ASI10",       "Agentic-specific risk coverage"),
    ("Evidence-gated",    "Source-to-sink & sink-to-source tracing"),
    ("All languages",     "py js ts go java php rs c html yaml sql …"),
    ("LWRA",              "Auto risk-score findings for your environment"),
    ("Any LLM",            "claude · openai · gemini · ollama (local)"),
]


def _print_banner(version: str) -> None:
    """Print the AISAST startup banner."""
    from rich.panel import Panel
    from rich.table import Table as _Table
    from rich.text import Text

    art = Text()
    for line in _AISAST_ART:
        art.append(line + "\n", style="bold cyan")

    art.append(f"\n  AI-Native Static Application Security Testing", style="dim cyan")
    art.append(f"  ·  v{version}\n", style="dim cyan")

    cap_table = _Table(
        box=None, show_header=False, padding=(0, 2),
        show_edge=False, expand=False,
    )
    cap_table.add_column("bullet", width=2,  style="bold cyan", no_wrap=True)
    cap_table.add_column("cap",    width=18, style="bold cyan", no_wrap=True)
    cap_table.add_column("desc",   ratio=1,  style="dim cyan",  no_wrap=True)

    for cap, desc in _CAPABILITIES:
        cap_table.add_row("◆", cap, desc)

    outer = _Table(
        box=None, show_header=False, padding=(0, 0),
        show_edge=False, expand=True,
    )
    outer.add_column("content", ratio=1)
    outer.add_row(art)
    outer.add_row(cap_table)

    console.print(
        Panel(
            outer,
            border_style="cyan",
            padding=(0, 1),
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _command_console(quiet: bool) -> Console:
    return Console(stderr=True) if quiet else console


def _require_repo_scoped_path(repo_root: Path, candidate: Path, *, operation: str) -> Path:
    """Ensure a candidate path resolves inside the repository root."""
    repo_root_r = repo_root.resolve(strict=False)
    candidate_r = candidate.resolve(strict=False)
    if candidate_r == repo_root_r or repo_root_r in candidate_r.parents:
        return candidate
    raise RuntimeError(
        f"Refusing unsafe {operation}: {candidate} resolves outside repository root"
    )


def _repo_output_path(repo_root: Path, path: "Path | str", *, operation: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    return _require_repo_scoped_path(repo_root, candidate, operation=operation)


def _print_inline_summary(repo: Path, quiet: bool) -> None:
    """Print a combined threat + vulnerability summary table after the scan completes."""
    if quiet:
        return

    aisast_dir = repo / ".aisast"

    _SEV_ORDER  = ["critical", "high", "medium", "low", "info"]
    _SEV_ICONS  = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}
    _SEV_STYLES = {
        "critical": "bold red",
        "high":     "bold yellow",
        "medium":   "yellow",
        "low":      "green",
        "info":     "dim",
    }

    def _count_by_sev(items: list, key: str = "severity") -> dict:
        counts: dict = {}
        for item in items:
            s = item.get(key, "medium").lower()
            counts[s] = counts.get(s, 0) + 1
        return counts

    # ── Load artifacts ────────────────────────────────────────────────────────
    threats: list = []
    vulns: list = []

    threat_file = aisast_dir / "THREAT_MODEL.json"
    if threat_file.exists():
        try:
            data = json.loads(threat_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                threats = data
        except (json.JSONDecodeError, OSError):
            pass

    vuln_file = aisast_dir / "VULNERABILITIES.json"
    if vuln_file.exists():
        try:
            data = json.loads(vuln_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                vulns = data
        except (json.JSONDecodeError, OSError):
            pass

    # ── Combined severity count table ─────────────────────────────────────────
    if threats or vulns:
        console.print()
        console.print("[bold cyan]━━━ Scan Summary ━━━[/bold cyan]")
        console.print(
            f"  Threats identified: [bold]{len(threats)}[/bold]   "
            f"Vulnerabilities confirmed: [bold]{len(vulns)}[/bold]"
        )
        console.print()

        t_counts = _count_by_sev(threats)
        v_counts = _count_by_sev(vulns)

        summary_table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold dim",
            border_style="dim",
        )
        summary_table.add_column("Severity",         width=14)
        summary_table.add_column("Threats",          width=10, justify="center")
        summary_table.add_column("Vulnerabilities",  width=18, justify="center")

        for sev in _SEV_ORDER:
            tc = t_counts.get(sev, 0)
            vc = v_counts.get(sev, 0)
            if tc == 0 and vc == 0:
                continue
            icon  = _SEV_ICONS.get(sev, "⚪")
            style = _SEV_STYLES.get(sev, "")
            summary_table.add_row(
                f"{icon} {sev.upper()}",
                str(tc) if tc else "[dim]—[/dim]",
                str(vc) if vc else "[dim]—[/dim]",
                style=style,
            )

        console.print(summary_table)

    # ── Vulnerability detail table ────────────────────────────────────────────
    if vulns:
        def _sev_rank(v: dict) -> int:
            return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                v.get("severity", "medium").lower(), 5
            )

        sorted_vulns = sorted(vulns, key=_sev_rank)

        console.print()
        console.print("[bold cyan]━━━ Vulnerability Details ━━━[/bold cyan]")
        console.print()

        detail_table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold",
        )
        detail_table.add_column("#",             width=3,  style="dim")
        detail_table.add_column("Severity",      width=12)
        detail_table.add_column("Vulnerability", width=50)
        detail_table.add_column("Location",      width=30)
        detail_table.add_column("CWE",           width=10)

        for idx, v in enumerate(sorted_vulns, 1):
            sev   = v.get("severity", "medium").lower()
            icon  = _SEV_ICONS.get(sev, "⚪")
            style = _SEV_STYLES.get(sev, "")
            title = v.get("title", "Unknown")
            if len(title) > 48:
                title = title[:46] + ".."
            loc = f"{v.get('file_path', '')}:{v.get('line_number', '')}"
            if len(loc) > 30:
                loc = "..." + loc[-27:]
            detail_table.add_row(
                str(idx),
                f"{icon} {sev.upper()}",
                title,
                loc,
                v.get("cwe_id", ""),
                style=style,
            )

        console.print(detail_table)

    console.print()


def _get_cache_age(repo: Path) -> Optional[str]:
    """Return human-readable age of the last scan, or None if no previous scan."""
    import time as _time
    cache_file = repo / ".aisast" / "cache_state.json"
    if not cache_file.exists():
        return None
    age = _time.time() - cache_file.stat().st_mtime
    if age < 60:
        return "just now"
    if age < 3600:
        return f"{int(age / 60)}m ago"
    if age < 86400:
        return f"{int(age / 3600)}h ago"
    return f"{int(age / 86400)}d ago"


def _detect_changed_files_cli(repo: Path) -> List[str]:
    """Detect source files changed since the last scan."""
    from aisast.config import LanguageConfig, ScanConfig
    from aisast.scanner.delta import detect_changed_files
    aisast_dir = repo / ".aisast"
    extensions = LanguageConfig.get_all_extensions()
    languages = LanguageConfig.detect_languages(repo)
    excluded = ScanConfig.get_excluded_dirs(languages)
    return detect_changed_files(repo, aisast_dir, extensions, excluded)


_PII_SIGNAL_RE = None  # compiled lazily in _recommend_methodology


def _recommend_methodology(repo: Path) -> "tuple[str, str]":
    """
    Fast local heuristic to recommend a threat-modeling methodology — no LLM call.

    This is a proxy for "let the agent decide": a real per-codebase LLM judgment would
    require splitting Phase 1 into its own session before Phase 2 starts, which the
    current single continuous Claude Code session doesn't support without extra
    latency/cost. A keyword sweep over source files is a reasonable, cheap stand-in —
    the user can always override with --methodology or at the interactive prompt.

    Returns (methodology, reason).
    """
    import re
    from aisast.config import LanguageConfig, ScanConfig

    global _PII_SIGNAL_RE
    if _PII_SIGNAL_RE is None:
        _PII_SIGNAL_RE = re.compile(
            r"\b(ssn|social_security|passport|date_of_birth|dob|medical_record|health_record|"
            r"gdpr|ccpa|personal_data|pii|consent|data_subject|right_to_erasure|anonymiz)\b",
            re.IGNORECASE,
        )

    extensions = LanguageConfig.get_all_extensions()
    languages = LanguageConfig.detect_languages(repo)
    excluded = ScanConfig.get_excluded_dirs(languages)
    hits = 0
    try:
        for f in repo.rglob("*"):
            if not f.is_file() or f.suffix.lower() not in extensions:
                continue
            if any(part in excluded for part in f.parts):
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if _PII_SIGNAL_RE.search(text):
                hits += 1
                if hits >= 3:
                    break
    except (OSError, PermissionError):
        pass

    if hits >= 3:
        return "linddun", f"detected {hits}+ files referencing personal/regulated data (PII, GDPR/CCPA, consent, etc.)"
    return "stride", "no strong privacy-data signal detected"


def _prompt_scan_strategy(repo: Path) -> str:
    """
    Show a 3-option menu when a previous scan exists.
    Returns: 'cache' | 'delta' | 'versioned' | 'full'
    """
    cache_age = _get_cache_age(repo)
    if cache_age is None:
        return "full"

    changed_files = _detect_changed_files_cli(repo)

    console.print("\n[bold cyan]━━━ Previous Scan Found ━━━[/bold cyan]")
    console.print(f"  Last scanned: [dim]{cache_age}[/dim]")

    if changed_files:
        console.print(
            f"\n  [yellow]{len(changed_files)} file(s) changed since last scan:[/yellow]"
        )
        for f in changed_files[:5]:
            console.print(f"  [dim]  • {f}[/dim]")
        if len(changed_files) > 5:
            console.print(f"  [dim]  ... and {len(changed_files) - 5} more[/dim]")
    else:
        console.print("\n  [green]No code changes detected since last scan[/green]")

    console.print()
    console.print(
        "  [bold]1.[/bold]  Use cached results"
        "     [dim]— skip re-scan, show existing findings[/dim]"
    )
    console.print(
        "  [bold]2.[/bold]  Delta scan"
        "             [dim]— re-scan changed files only, update artifacts[/dim]"
    )
    console.print(
        "  [bold]3.[/bold]  Full re-scan"
        "           [dim]— fresh scan, archive previous as SECURITY2.md etc.[/dim]"
    )
    console.print()

    default_choice = 2 if changed_files else 1
    choice = click.prompt("  Choice", type=click.IntRange(1, 3), default=default_choice)
    console.print()
    return {1: "cache", 2: "delta", 3: "versioned"}[choice]


def _print_lwra_summary(repo: Path) -> None:
    """Print the risk-adjusted findings table from LWRA_REPORT.json."""
    lwra_path = repo / ".aisast" / "LWRA_REPORT.json"
    if not lwra_path.exists():
        return
    try:
        data = json.loads(lwra_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return

    issues = data.get("adjusted_issues", [])
    summary = data.get("summary", {})
    if not issues:
        return

    _SEV_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    _SEV_STYLES = {"critical": "bold red", "high": "bold yellow", "medium": "yellow", "low": "green"}

    console.print()
    console.print("[bold cyan]━━━ Risk Review (LWRA) ━━━[/bold cyan]")
    adjusted = summary.get("severity_reduced", 0)
    total = summary.get("issues_analyzed", len(issues))
    patches = summary.get("code_patches_total", 0)
    soft = summary.get("soft_fixes_total", 0)
    console.print(
        f"  [dim]{total} findings reviewed · "
        f"[bold]{adjusted} severity adjusted[/bold] · "
        f"{patches} code patches · {soft} soft fixes[/dim]"
    )
    console.print()

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
    t.add_column("#",        width=3,  style="dim")
    t.add_column("Original", width=12)
    t.add_column("→",        width=3,  justify="center", style="dim")
    t.add_column("Adjusted", width=12)
    t.add_column("Score",    width=6,  justify="right")
    t.add_column("Finding",  width=46)
    t.add_column("Reason",   ratio=1)

    _ADJ_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_issues = sorted(
        issues,
        key=lambda v: (_ADJ_RANK.get(v.get("adjusted_severity", "").lower(), 9), -v.get("risk_score", 0)),
    )

    last_adj_group = None
    for idx, issue in enumerate(sorted_issues, 1):
        orig = issue.get("original_severity", "").lower()
        adj  = issue.get("adjusted_severity", "").lower()
        score = issue.get("risk_score", 0)
        title = issue.get("title", "")[:44]
        reason = issue.get("adjustment_reason", "")
        reason_short = reason.split(".")[0] if "." in reason else reason[:80]

        if adj != last_adj_group:
            if last_adj_group is not None:
                t.add_row("", "", "", "", "", "", "", style="dim")
            last_adj_group = adj

        changed = orig != adj
        adj_style = _SEV_STYLES.get(adj, "")

        t.add_row(
            str(idx),
            f"{_SEV_ICONS.get(orig, '⚪')} {orig.upper()}",
            "[bold cyan]↓[/bold cyan]" if changed else "[dim]=[/dim]",
            f"[{adj_style}]{_SEV_ICONS.get(adj, '⚪')} {adj.upper()}[/{adj_style}]",
            f"{score:.1f}",
            title,
            f"[dim]{reason_short}[/dim]",
            style=_SEV_STYLES.get(adj, ""),
        )

    console.print(t)
    console.print(
        f"  [dim]Full report: [cyan]{repo / '.aisast' / 'LWRA_REPORT.json'}[/cyan]"
        f"  ·  Run [bold]aisast apply <patch-id>[/bold] for 1-click code fixes[/dim]"
    )
    console.print()


def _run_lwra_interactive(scanner: "Scanner", repo: Path) -> None:
    """Offer and run a risk review interactively after a scan completes."""
    from aisast.scanner.env_collector import (
        collect_deployment_context, save_context, load_context,
    )

    aisast_dir = repo / ".aisast"
    existing_ctx = load_context(aisast_dir)

    console.print()
    console.print("[bold cyan]━━━ Risk Review Available ━━━[/bold cyan]")
    console.print(
        "  The Risk Review Agent adjusts each vulnerability's severity based on your\n"
        "  actual environment — exploitability, reachability, and security controls.\n"
        "  It also generates soft-fixes (config patches) and 1-click code patches."
    )
    if existing_ctx:
        console.print(
            "  [dim cyan]✓ Existing environment context found — will reuse unless you reset it.[/dim cyan]"
        )

    console.print()
    if not click.confirm("  Run risk review now?", default=True):
        console.print("  [dim]Skipped. Run [bold]aisast lwra .[/bold] later to review.[/dim]\n")
        return

    if existing_ctx:
        reuse = click.confirm("  Reuse existing environment context?", default=True)
        if not reuse:
            existing_ctx = None

    if not existing_ctx:
        ctx = collect_deployment_context(console)
        save_context(ctx, aisast_dir)

    console.print("  [dim cyan]Running Risk Review Agent...[/dim cyan]\n")
    try:
        asyncio.run(scanner._run_lwra_phase(repo, aisast_dir))
        _print_lwra_summary(repo)
    except Exception as exc:
        console.print(f"  [bold red]❌ Risk review failed:[/bold red] {exc}")


def _print_repo_prereqs(
    repo: Path,
    strategy: str,
    changed_files: List[str],
    backup_version: Optional[int] = None,
) -> None:
    """Print a static repo-details + structure panel before the live scan panel starts."""
    from collections import defaultdict
    from aisast.config import LanguageConfig, ScanConfig
    from rich.panel import Panel
    from rich.table import Table
    from rich.tree import Tree

    languages = LanguageConfig.detect_languages(repo)
    extensions = LanguageConfig.get_all_extensions()
    excluded = ScanConfig.get_excluded_dirs(languages)

    # Single pass: total file count + per-directory breakdown
    dir_counts: dict = defaultdict(int)          # top_dir -> total source files
    subdir_counts: dict = defaultdict(lambda: defaultdict(int))  # top_dir -> subdir -> count
    file_count = 0
    try:
        for f in repo.rglob("*"):
            if not f.is_file():
                continue
            if f.suffix.lower() not in extensions:
                continue
            try:
                rel = f.relative_to(repo)
            except ValueError:
                continue
            parts = rel.parts
            if any(part in excluded for part in parts):
                continue
            file_count += 1
            if parts:
                dir_counts[parts[0]] += 1
                if len(parts) >= 2:
                    subdir_counts[parts[0]][parts[1]] += 1
    except (OSError, PermissionError):
        pass

    lang_display = ", ".join(sorted(languages)) if languages else "auto-detect"

    if strategy == "full":
        mode_text = "[cyan]Full scan[/cyan]  [dim](first scan — all phases)[/dim]"
    elif strategy == "cache":
        mode_text = "[dim]Using cached results — no re-scan[/dim]"
    elif strategy == "delta":
        mode_text = f"[cyan]Delta scan[/cyan]  [dim]({len(changed_files)} file(s) changed)[/dim]"
    elif strategy == "versioned" and backup_version:
        mode_text = (
            f"[cyan]Full re-scan[/cyan]  "
            f"[dim](previous archived → v{backup_version})[/dim]"
        )
    else:
        mode_text = strategy

    # ── Metadata table ───────────────────────────────────────────
    meta = Table(box=None, show_header=False, padding=(0, 2), show_edge=False, expand=True)
    meta.add_column("key",   width=16, style="bold dim")
    meta.add_column("value", ratio=1)

    meta.add_row("Repository",   f"[bold]{repo.name}[/bold]")
    meta.add_row("Path",         f"[dim]{repo}[/dim]")
    meta.add_row("Languages",    f"[cyan]{lang_display}[/cyan]")
    meta.add_row("Source Files", f"[bold]{file_count:,}[/bold]")
    meta.add_row("Scan Mode",    mode_text)

    if strategy == "delta" and changed_files:
        lines = [f"[dim]  • {f}[/dim]" for f in changed_files[:6]]
        if len(changed_files) > 6:
            lines.append(f"[dim]  ... and {len(changed_files) - 6} more[/dim]")
        meta.add_row("Changed Files", "\n".join(lines))

    # ── Repo structure tree ──────────────────────────────────────
    repo_tree = Tree(f"[bold cyan]{repo.name}/[/bold cyan]", guide_style="dim cyan")
    _MAX_TOP = 12
    _MAX_SUB = 6
    top_dirs = sorted(dir_counts.keys())
    shown_top = top_dirs[:_MAX_TOP]

    for top_dir in shown_top:
        count = dir_counts[top_dir]
        branch = repo_tree.add(
            f"[cyan]{top_dir}/[/cyan]  [dim]({count:,} file{'s' if count != 1 else ''})[/dim]"
        )
        subdirs = dict(sorted(subdir_counts[top_dir].items()))
        shown_sub = list(subdirs.keys())[:_MAX_SUB]
        for sd in shown_sub:
            sc = subdirs[sd]
            branch.add(
                f"[dim cyan]{sd}/[/dim cyan]  [dim]({sc:,})[/dim]"
            )
        if len(subdirs) > _MAX_SUB:
            branch.add(f"[dim]... {len(subdirs) - _MAX_SUB} more directories[/dim]")

    if len(top_dirs) > _MAX_TOP:
        repo_tree.add(f"[dim]... {len(top_dirs) - _MAX_TOP} more top-level directories[/dim]")

    # ── Compose panel ────────────────────────────────────────────
    outer = Table(box=None, show_header=False, padding=(0, 0), show_edge=False, expand=True)
    outer.add_column("content")
    outer.add_row(meta)
    if dir_counts:
        outer.add_row("")
        outer.add_row("  [bold dim]Repository Structure[/bold dim]")
        outer.add_row(repo_tree)

    console.print(
        Panel(
            outer,
            title="[bold]🔍  Repository Prerequisites[/bold]",
            border_style="dim cyan",
            padding=(0, 1),
        )
    )
    console.print()


def _filter_by_severity(result: ScanResult, min_severity: Optional[str]) -> None:
    if not min_severity:
        return
    threshold = Severity(min_severity)
    min_rank = SEVERITY_RANK[threshold.value]
    result.issues = [
        i for i in result.issues if SEVERITY_RANK.get(i.severity.value, 0) >= min_rank
    ]


def _resolve_markdown_output_path(
    repo_path: Path, output: Optional[str], default_filename: str
) -> Path:
    if output:
        p = Path(output)
        if p.is_absolute():
            return _repo_output_path(repo_path, p, operation="markdown output")
        return _repo_output_path(repo_path, Path(".aisast") / output, operation="markdown output")
    return _repo_output_path(repo_path, Path(".aisast") / default_filename, operation="markdown output")


def _write_output(
    result: ScanResult,
    output_format: str,
    output: Optional[str],
    repo_path: Path,
    markdown_default_filename: str,
    markdown_label: str,
    quiet: bool = False,
) -> None:
    if output_format == "markdown":
        from aisast.reporters.markdown_reporter import MarkdownReporter

        output_path = _resolve_markdown_output_path(repo_path, output, markdown_default_filename)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            MarkdownReporter.save(result, output_path)
            if output:
                console.print(f"\n✅ {markdown_label} saved to: {output_path}")
            else:
                console.print(f"\n📄 {markdown_label}: [cyan]{output_path}[/cyan]")
        except (IOError, OSError, PermissionError) as exc:
            console.print(f"[bold red]❌ Error writing output:[/bold red] {exc}")
            sys.exit(1)
        return

    if output_format == "json":
        output_data = result.to_dict()
        if output:
            try:
                output_path = _repo_output_path(repo_path, Path(output), operation="JSON output")
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(json.dumps(output_data, indent=2), encoding="utf-8")
                console.print(f"\n✅ Results saved to: {output_path}")
            except (IOError, OSError, PermissionError) as exc:
                console.print(f"[bold red]❌ Error writing output:[/bold red] {exc}")
                sys.exit(1)
        else:
            console.print_json(data=output_data)
        return

    if output_format == "table":
        _display_table_results(result)
        return

    _display_text_results(result)


def _display_text_results(result: ScanResult) -> None:
    if not result.issues:
        console.print("\n✅ [bold green]No security vulnerabilities found![/bold green]")
        return

    severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    console.print(f"\n[bold]Found {len(result.issues)} security issue(s):[/bold]")
    for i, issue in enumerate(result.issues, 1):
        icon = severity_icons.get(issue.severity.value, "⚪")
        console.print(
            f"\n{i}. {icon} [{issue.severity.value.upper()}] {issue.title}\n"
            f"   File: {issue.file_path}:{issue.line_number}\n"
            f"   {issue.description[:120]}"
        )


def _display_table_results(result: ScanResult) -> None:
    if not result.issues:
        console.print("\n✅ [bold green]No security vulnerabilities found![/bold green]")
        return

    table = Table(
        title=f"Security Scan Results - {len(result.issues)} issue(s)",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Title", width=45)
    table.add_column("Location", width=35)
    table.add_column("CWE", width=10)

    severity_styles = {
        "critical": "bold red",
        "high": "bold yellow",
        "medium": "yellow",
        "low": "green",
    }
    severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}

    for idx, issue in enumerate(result.issues, 1):
        style = severity_styles.get(issue.severity.value, "")
        icon = severity_icons.get(issue.severity.value, "⚪")
        sev_text = f"{icon} {issue.severity.value.upper()}"
        title = issue.title[:43] + ".." if len(issue.title) > 45 else issue.title
        location = f"{issue.file_path}:{issue.line_number}"
        if len(location) > 35:
            location = f"...{location[-32:]}"

        table.add_row(
            str(idx),
            sev_text,
            title,
            location,
            issue.cwe_id or "",
            style=style,
        )

    console.print(table)
    console.print(
        f"\nSummary: {result.critical_count} critical, {result.high_count} high, "
        f"{result.medium_count} medium, {result.low_count} low"
    )


# ---------------------------------------------------------------------------
# Diff utilities (git-based)
# ---------------------------------------------------------------------------

@dataclass
class SimpleDiffContext:
    """Lightweight diff context for PR review."""
    raw_diff: str
    changed_files: List[str] = field(default_factory=list)
    added_lines: int = 0
    removed_lines: int = 0

    def to_dict(self) -> dict:
        return {
            "changed_files": self.changed_files,
            "added_lines": self.added_lines,
            "removed_lines": self.removed_lines,
        }


def _get_diff_from_git(repo: Path, base: str, head: str) -> SimpleDiffContext:
    """Get diff between two git refs."""
    try:
        diff_result = subprocess.run(
            ["git", "diff", f"{base}...{head}"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=30,
        )
        raw_diff = diff_result.stdout

        # Get changed files
        files_result = subprocess.run(
            ["git", "diff", "--name-only", f"{base}...{head}"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=30,
        )
        changed_files = [f for f in files_result.stdout.strip().splitlines() if f]

        # Count lines
        added = sum(1 for line in raw_diff.splitlines() if line.startswith("+") and not line.startswith("+++"))
        removed = sum(1 for line in raw_diff.splitlines() if line.startswith("-") and not line.startswith("---"))

        return SimpleDiffContext(
            raw_diff=raw_diff,
            changed_files=changed_files,
            added_lines=added,
            removed_lines=removed,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Git diff timed out")
    except FileNotFoundError:
        raise RuntimeError("git not found. Ensure git is installed and in PATH.")


def _get_diff_from_range(repo: Path, commit_range: str) -> SimpleDiffContext:
    """Get diff from a commit range (e.g., abc123~1..abc123)."""
    try:
        diff_result = subprocess.run(
            ["git", "diff", commit_range],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=30,
        )
        raw_diff = diff_result.stdout

        files_result = subprocess.run(
            ["git", "diff", "--name-only", commit_range],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=30,
        )
        changed_files = [f for f in files_result.stdout.strip().splitlines() if f]
        added = sum(1 for line in raw_diff.splitlines() if line.startswith("+") and not line.startswith("+++"))
        removed = sum(1 for line in raw_diff.splitlines() if line.startswith("-") and not line.startswith("---"))

        return SimpleDiffContext(raw_diff=raw_diff, changed_files=changed_files, added_lines=added, removed_lines=removed)
    except subprocess.TimeoutExpired:
        raise RuntimeError("Git diff timed out")
    except FileNotFoundError:
        raise RuntimeError("git not found.")


def _get_diff_from_file(diff_path: Path) -> SimpleDiffContext:
    """Load diff from a patch file."""
    raw_diff = diff_path.read_text(encoding="utf-8", errors="replace")
    changed_files = []
    for line in raw_diff.splitlines():
        if line.startswith("+++ b/"):
            changed_files.append(line[6:])
    added = sum(1 for line in raw_diff.splitlines() if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in raw_diff.splitlines() if line.startswith("-") and not line.startswith("---"))
    return SimpleDiffContext(raw_diff=raw_diff, changed_files=changed_files, added_lines=added, removed_lines=removed)


def _get_diff_last_n_commits(repo: Path, n: int) -> SimpleDiffContext:
    """Get diff for the last N commits."""
    return _get_diff_from_range(repo, f"HEAD~{n}..HEAD")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version=__version__, prog_name="aisast")
def cli():
    """
    🛡️ AISAST - AI-Native Static Application Security Testing

    Detect security vulnerabilities in your code using Claude AI.
    """
    pass


@cli.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--model", "-m", default="sonnet", help="Claude model to use (e.g., sonnet, haiku, opus)")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["markdown", "json", "text", "table"]),
    default="markdown",
    help="Output format (default: markdown)",
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Minimum severity to report",
)
@click.option("--quiet", "-q", is_flag=True, help="Minimal output (errors only)")
@click.option("--debug", is_flag=True, help="Show verbose diagnostic output")
@click.option(
    "--subagent",
    type=click.Choice(["assessment", "threat-modeling", "threat-model-diagram", "code-review", "report-generator"]),
    help="Run specific sub-agent only",
)
@click.option(
    "--resume-from",
    type=click.Choice(["assessment", "threat-modeling", "threat-model-diagram", "code-review", "report-generator"]),
    help="Resume scan from specific sub-agent onwards",
)
@click.option("--force", is_flag=True, help="Skip confirmation prompts, overwrite existing artifacts")
@click.option("--skip-checks", is_flag=True, help="Bypass artifact validation checks")
@click.option("--agentic", is_flag=True, help="Force agentic classification (require ASI threats)")
@click.option("--no-agentic", "no_agentic", is_flag=True, help="Force non-agentic classification")
@click.option(
    "--workers",
    default=1,
    type=click.IntRange(1, 5),
    help="Parallel workers for Phase 3 code review (1=sequential, 2-5=parallel). Default: 1",
)
@click.option("--no-cache", "no_cache", is_flag=True, help="Ignore cached artifacts and re-run all phases")
@click.option("--lwra", "run_lwra", is_flag=True, help="Run LWRA risk adjustment after scan (interactive questionnaire)")
@click.option("--diagram", "diagram", is_flag=True, default=False, help="Include threat model diagram (Phase 2.5)")
@click.option("--no-diagram", "no_diagram", is_flag=True, default=False, help="Skip threat model diagram without asking")
@click.option(
    "--methodology",
    type=click.Choice(["stride", "linddun", "attack-trees"]),
    help="Threat modeling methodology for Phase 2 (default: auto-recommend, falls back to stride)",
)
@click.option(
    "--no-methodology-prompt", "no_methodology_prompt", is_flag=True, default=False,
    help="Skip the methodology recommendation prompt, use stride",
)
def scan(
    path: str,
    model: str,
    output: Optional[str],
    output_format: str,
    severity: Optional[str],
    quiet: bool,
    debug: bool,
    subagent: Optional[str],
    resume_from: Optional[str],
    force: bool,
    skip_checks: bool,
    agentic: bool,
    no_agentic: bool,
    workers: int,
    no_cache: bool,
    run_lwra: bool,
    diagram: bool,
    no_diagram: bool,
    methodology: Optional[str],
    no_methodology_prompt: bool,
):
    """
    Scan a repository for security vulnerabilities.

    Examples:

        aisast scan .

        aisast scan /path/to/project --severity high

        aisast scan . --format json --output results.json

        aisast scan . --subagent code-review

        aisast scan . --resume-from threat-modeling
    """
    cmd_console = _command_console(quiet)
    try:
        repo = Path(path).resolve()

        if quiet and debug:
            cmd_console.print("[yellow]⚠️  --quiet and --debug are contradictory. Using --debug.[/yellow]")
            quiet = False

        if subagent and resume_from:
            cmd_console.print("[bold red]❌ Error:[/bold red] --subagent and --resume-from are mutually exclusive")
            sys.exit(1)

        if agentic and no_agentic:
            cmd_console.print("[bold red]❌ Error:[/bold red] --agentic and --no-agentic are mutually exclusive")
            sys.exit(1)

        if not quiet:
            _print_banner(__version__)

        output_dir = _repo_output_path(repo, Path(".aisast"), operation="scan output directory")
        output_dir.mkdir(parents=True, exist_ok=True)

        agentic_override = True if agentic else (False if no_agentic else None)

        # Wipe cache if --no-cache flag is set
        if no_cache:
            from aisast.scanner.cache import invalidate_cache
            aisast_dir = repo / ".aisast"
            aisast_dir.mkdir(parents=True, exist_ok=True)
            invalidate_cache(aisast_dir)
            if not quiet:
                console.print("  [dim]Cache cleared — all phases will re-run.[/dim]")

        scanner = Scanner(model=model, debug=debug, quiet=quiet, workers=workers)
        scanner.configure_agentic_detection(agentic_override)

        # Collect deployment context before the scan if --lwra requested
        if run_lwra and not subagent and not resume_from:
            from aisast.scanner.env_collector import collect_deployment_context, save_context, load_context
            aisast_dir = repo / ".aisast"
            aisast_dir.mkdir(parents=True, exist_ok=True)
            existing_ctx = load_context(aisast_dir)
            if existing_ctx is not None:
                console.print(
                    "  [dim cyan]LWRA: using existing deployment context from .aisast/LWRA_CONTEXT.json\n"
                    "  (delete it to re-answer the questionnaire)[/dim cyan]\n"
                )
            else:
                ctx = collect_deployment_context(console)
                save_context(ctx, aisast_dir)

        # Determine scan strategy when a previous scan exists
        strategy = "full"
        delta_changed_files: List[str] = []
        backup_version: Optional[int] = None
        if not subagent and not resume_from and not no_cache and not quiet:
            strategy = _prompt_scan_strategy(repo)
            if strategy == "delta":
                delta_changed_files = _detect_changed_files_cli(repo)
            elif strategy == "versioned":
                backup_version = Scanner._backup_artifacts_versioned(repo / ".aisast")
                from aisast.scanner.cache import invalidate_cache
                invalidate_cache(repo / ".aisast")

        # Print repo details panel before the live scan panel starts
        if not quiet and not subagent and not resume_from:
            _print_repo_prereqs(repo, strategy, delta_changed_files, backup_version=backup_version)

        # Resolve diagram preference
        include_diagram = False
        if not subagent and not resume_from and strategy != "delta":
            if diagram:
                include_diagram = True
            elif not no_diagram and not quiet:
                console.print(
                    "  [bold]Threat model diagram?[/bold]  "
                    "[dim]Visual ASCII map of components + threat vectors "
                    "(adds ~1 min · saves to .aisast/THREAT_MODEL_DIAGRAM.md)[/dim]"
                )
                include_diagram = click.confirm("  Include diagram", default=False)
                console.print()

        # Resolve threat-modeling methodology preference
        resolved_methodology = "stride"
        if not subagent and not resume_from and strategy != "delta":
            if methodology:
                resolved_methodology = methodology
            elif not no_methodology_prompt and not quiet:
                rec_methodology, rec_reason = _recommend_methodology(repo)
                console.print(
                    f"  [bold]Threat modeling methodology?[/bold]  "
                    f"[dim]Recommended: {rec_methodology.upper()} — {rec_reason}[/dim]"
                )
                if click.confirm(f"  Use {rec_methodology.upper()}", default=True):
                    resolved_methodology = rec_methodology
                else:
                    resolved_methodology = click.prompt(
                        "  Choose methodology",
                        type=click.Choice(["stride", "linddun", "attack-trees"]),
                        default="stride",
                    )
                console.print()
        elif methodology:
            # Explicit --methodology still honored for --subagent/--resume-from runs
            resolved_methodology = methodology

        if subagent:
            result = asyncio.run(
                scanner.scan_subagent(
                    str(repo), subagent, force=force, skip_checks=skip_checks,
                    methodology=resolved_methodology,
                )
            )
        elif resume_from:
            result = asyncio.run(
                scanner.scan_resume_from(str(repo), resume_from, methodology=resolved_methodology)
            )
        elif strategy == "cache":
            # Load existing artifacts straight off disk — no agent session,
            # no repo-hash check, no network calls. Guaranteed instant,
            # unlike relying on the phase-level hash cache inside scan().
            result = scanner.load_cached_result(str(repo))
            if not quiet:
                console.print("  [dim cyan]✓ Using cached results — no re-scan.[/dim cyan]\n")
            if run_lwra:
                asyncio.run(scanner._run_lwra_phase(repo, repo / ".aisast"))
        elif strategy == "delta" and delta_changed_files:
            result = asyncio.run(scanner.scan_delta(str(repo), delta_changed_files))
        elif strategy == "delta" and not delta_changed_files:
            console.print("  [dim]No changes detected — using cached results.[/dim]\n")
            result = asyncio.run(scanner.scan(
                str(repo), run_lwra=run_lwra and True, include_diagram=include_diagram,
                methodology=resolved_methodology,
            ))
        else:
            result = asyncio.run(scanner.scan(
                str(repo), run_lwra=run_lwra and True, include_diagram=include_diagram,
                methodology=resolved_methodology,
            ))

        _print_inline_summary(repo, quiet)

        # LWRA — run, offer, or show existing results
        lwra_report = repo / ".aisast" / "LWRA_REPORT.json"
        if not quiet and not subagent and not resume_from:
            if run_lwra:
                # --lwra flag: scanner.scan() already ran the LWRA phase above
                # (using the context collected before the scan started) — just
                # show the summary rather than running it a second time.
                _print_lwra_summary(repo)
            elif not lwra_report.exists():
                # No LWRA yet: offer interactively
                _run_lwra_interactive(scanner, repo)
            else:
                # Already done: show existing summary
                _print_lwra_summary(repo)

        _filter_by_severity(result, severity)
        _write_output(
            result=result,
            output_format=output_format,
            output=output,
            repo_path=repo,
            markdown_default_filename="scan_report.md",
            markdown_label="Markdown report",
            quiet=quiet,
        )

        if result.critical_count > 0:
            sys.exit(2)
        elif result.high_count > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan cancelled by user[/yellow]")
        sys.exit(130)
    except Exception as exc:
        console.print(f"\n[bold red]❌ Error:[/bold red] {exc}", style="red")
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command("pr-review")
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--base", help="Base branch/commit (e.g., main)")
@click.option("--head", help="Head branch/commit (e.g., feature-branch)")
@click.option("--range", "commit_range", help="Commit range (e.g., abc123~1..abc123)")
@click.option("--diff", "diff_file", type=click.Path(exists=True), help="Path to diff/patch file")
@click.option("--last", "last_commits", type=click.IntRange(min=1), help="Review last N commits")
@click.option("--model", "-m", default="sonnet", help="Claude model to use")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["markdown", "json", "text", "table"]),
    default="markdown",
    help="Output format (default: markdown)",
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
@click.option("--debug", is_flag=True, help="Show verbose diagnostic output")
@click.option(
    "--severity", "-s",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default="medium",
    help="Minimum severity to report (default: medium)",
)
@click.option(
    "--update-artifacts", is_flag=True,
    help="Update THREAT_MODEL.json and VULNERABILITIES.json from PR findings",
)
def pr_review(
    path: str,
    base: Optional[str],
    head: Optional[str],
    commit_range: Optional[str],
    diff_file: Optional[str],
    last_commits: Optional[int],
    model: str,
    output_format: str,
    output: Optional[str],
    quiet: bool,
    debug: bool,
    severity: str,
    update_artifacts: bool,
):
    """
    Review a PR diff for security vulnerabilities.

    Examples:

        aisast pr-review . --base main --head feature-branch

        aisast pr-review . --range abc123~1..abc123

        aisast pr-review . --diff changes.patch

        aisast pr-review . --last 3
    """
    cmd_console = _command_console(quiet)
    try:
        repo = Path(path).resolve()
        aisast_dir = _repo_output_path(repo, Path(".aisast"), operation="PR review output directory")

        # Check that baseline scan artifacts exist
        security_md = aisast_dir / "SECURITY.md"
        if not security_md.exists():
            cmd_console.print(
                "[bold red]❌ Error:[/bold red] No baseline scan found.\n"
                "Run [bold]aisast scan .[/bold] first to create baseline artifacts, then run pr-review."
            )
            sys.exit(1)

        # Resolve diff context
        if sum(bool(x) for x in [base and head, commit_range, diff_file, last_commits]) > 1:
            cmd_console.print("[bold red]❌ Error:[/bold red] Specify only one of: --base/--head, --range, --diff, --last")
            sys.exit(1)

        if not any([base and head, commit_range, diff_file, last_commits]):
            cmd_console.print(
                "[bold red]❌ Error:[/bold red] Specify a diff source:\n"
                "  --base BRANCH --head BRANCH\n"
                "  --range COMMIT_RANGE\n"
                "  --diff PATCH_FILE\n"
                "  --last N"
            )
            sys.exit(1)

        try:
            if diff_file:
                diff_context = _get_diff_from_file(Path(diff_file))
            elif commit_range:
                diff_context = _get_diff_from_range(repo, commit_range)
            elif last_commits:
                diff_context = _get_diff_last_n_commits(repo, last_commits)
            else:
                diff_context = _get_diff_from_git(repo, base, head)
        except RuntimeError as exc:
            cmd_console.print(f"[bold red]❌ Error getting diff:[/bold red] {exc}")
            sys.exit(1)

        if not diff_context.raw_diff.strip():
            cmd_console.print("[yellow]⚠️  No changes found in diff. Nothing to review.[/yellow]")
            sys.exit(0)

        if not quiet:
            console.print("[bold cyan]🛡️ AISAST PR Review[/bold cyan]")
            console.print(f"[dim]Analyzing {len(diff_context.changed_files)} changed file(s)...[/dim]")
            console.print()

        # Save raw diff for agent reference
        aisast_dir.mkdir(parents=True, exist_ok=True)
        diff_raw_path = aisast_dir / "DIFF_RAW.patch"
        diff_raw_path.write_text(diff_context.raw_diff, encoding="utf-8")

        known_vulns_path = aisast_dir / "VULNERABILITIES.json"
        if not known_vulns_path.exists():
            known_vulns_path = None

        scanner = Scanner(model=model, debug=debug, quiet=quiet)
        result = asyncio.run(
            scanner.pr_review(
                str(repo),
                diff_context=diff_context,
                severity_threshold=severity,
                known_vulns_path=known_vulns_path,
            )
        )

        if update_artifacts and result.issues:
            _update_baseline_artifacts(aisast_dir, result)
            cmd_console.print(
                f"[green]✅ Updated baseline artifacts with {len(result.issues)} PR finding(s)[/green]"
            )

        _write_output(
            result=result,
            output_format=output_format,
            output=output,
            repo_path=repo,
            markdown_default_filename="pr_review_report.md",
            markdown_label="PR review report",
            quiet=quiet,
        )

        if result.critical_count > 0:
            sys.exit(2)
        elif result.high_count > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  PR review cancelled by user[/yellow]")
        sys.exit(130)
    except Exception as exc:
        console.print(f"\n[bold red]❌ Error:[/bold red] {exc}", style="red")
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command("lwra")
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--model", "-m", default="sonnet", help="Claude model to use")
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["markdown", "json"]),
    default="markdown",
    help="Output format (default: markdown)",
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
@click.option("--debug", is_flag=True, help="Verbose output")
@click.option(
    "--reset-context", is_flag=True,
    help="Re-ask deployment questions even if LWRA_CONTEXT.json already exists",
)
def lwra_cmd(
    path: str,
    model: str,
    output_format: str,
    output: Optional[str],
    quiet: bool,
    debug: bool,
    reset_context: bool,
):
    """
    Run the LWRA risk adjustment phase on existing scan results.

    Must have run 'aisast scan .' first.

    Examples:

        aisast lwra .

        aisast lwra . --format markdown --output lwra_report.md

        aisast lwra . --reset-context
    """
    from aisast.scanner.env_collector import collect_deployment_context, save_context, load_context
    from aisast.models.fix import LWRAResult
    from aisast.reporters.markdown_reporter import MarkdownReporter

    cmd_console = _command_console(quiet)
    try:
        repo = Path(path).resolve()
        aisast_dir = repo / ".aisast"

        scan_results = aisast_dir / "scan_results.json"
        if not scan_results.exists():
            cmd_console.print(
                "[bold red]❌ Error:[/bold red] No scan_results.json found.\n"
                "Run [bold]aisast scan .[/bold] first."
            )
            sys.exit(1)

        if not quiet:
            console.print("[bold cyan]🛡️ AISAST LWRA — Risk Adjustment[/bold cyan]")
            console.print()

        ctx = None if reset_context else load_context(aisast_dir)
        if ctx is None:
            ctx = collect_deployment_context(console)
            save_context(ctx, aisast_dir)
        else:
            console.print(
                "  [dim cyan]Using cached deployment context "
                "(use --reset-context to re-answer)[/dim cyan]\n"
            )

        scanner = Scanner(model=model, debug=debug, quiet=quiet)
        result = asyncio.run(scanner.lwra_scan(str(repo)))

        lwra_report_path = aisast_dir / "LWRA_REPORT.json"

        if output_format == "json":
            lwra_data = lwra_report_path.read_text(encoding="utf-8") if lwra_report_path.exists() else "{}"
            if output:
                out_path = _repo_output_path(repo, Path(output), operation="LWRA output")
                out_path.write_text(lwra_data, encoding="utf-8")
                if not quiet:
                    console.print(f"\n[dim]LWRA JSON saved to:[/dim] {out_path}")
            else:
                console.print(lwra_data)
        else:
            md = MarkdownReporter.generate_lwra_section(lwra_report_path)
            if not md:
                console.print("[yellow]No LWRA report generated.[/yellow]")
                sys.exit(0)
            out_filename = output or str(aisast_dir / "lwra_report.md")
            out_path = _repo_output_path(repo, Path(out_filename), operation="LWRA report")
            out_path.write_text(md, encoding="utf-8")
            if not quiet:
                console.print(f"\n[green]✅ LWRA report saved:[/green] {out_path}")

        # Surface patch IDs for convenience
        lwra = LWRAResult.from_file(lwra_report_path)
        if lwra and not quiet:
            patches = [i.code_patch.patch_id for i in lwra.adjusted_issues if i.code_patch]
            if patches:
                console.print("\n[bold]Available code patches (1-click fixes):[/bold]")
                for pid in patches:
                    console.print(f"  [cyan]aisast apply {pid}[/cyan]")

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  LWRA cancelled[/yellow]")
        sys.exit(130)
    except Exception as exc:
        console.print(f"\n[bold red]❌ Error:[/bold red] {exc}", style="red")
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command("apply")
@click.argument("patch_id", required=False)
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--all", "apply_all", is_flag=True, help="Apply all available code patches")
@click.option("--dry-run", is_flag=True, help="Show what would change without writing files")
@click.option("--no-backup", is_flag=True, help="Skip creating .bak backup files")
def apply_cmd(
    patch_id: Optional[str],
    path: str,
    apply_all: bool,
    dry_run: bool,
    no_backup: bool,
):
    """
    Apply a 1-click code patch from the LWRA report.

    Examples:

        aisast apply PATCH-001

        aisast apply --all

        aisast apply PATCH-001 --dry-run
    """
    from aisast.models.fix import LWRAResult, CodePatch

    repo = Path(path).resolve()
    aisast_dir = repo / ".aisast"
    lwra_report_path = aisast_dir / "LWRA_REPORT.json"

    if not lwra_report_path.exists():
        console.print(
            "[bold red]❌ Error:[/bold red] No LWRA_REPORT.json found.\n"
            "Run [bold]aisast lwra .[/bold] first."
        )
        sys.exit(1)

    lwra = LWRAResult.from_file(lwra_report_path)
    if lwra is None:
        console.print("[bold red]❌ Error:[/bold red] Failed to parse LWRA_REPORT.json")
        sys.exit(1)

    all_patches = [
        (issue.title, issue.code_patch)
        for issue in lwra.adjusted_issues
        if issue.code_patch is not None
    ]

    if not all_patches:
        console.print("[yellow]No code patches available in LWRA report.[/yellow]")
        sys.exit(0)

    if not patch_id and not apply_all:
        console.print("[bold]Available patches:[/bold]")
        for title, cp in all_patches:
            console.print(
                f"  [cyan]{cp.patch_id}[/cyan]  {cp.file_path}:{cp.line_number}  "
                f"[dim]{title[:60]}[/dim]"
            )
        console.print("\nUse [bold]aisast apply <PATCH_ID>[/bold] or [bold]aisast apply --all[/bold]")
        sys.exit(0)

    if apply_all:
        targets = all_patches
    else:
        targets = [(t, cp) for t, cp in all_patches if cp.patch_id == patch_id]
        if not targets:
            console.print(f"[bold red]❌ Patch not found:[/bold red] {patch_id}")
            console.print("Available: " + ", ".join(cp.patch_id for _, cp in all_patches))
            sys.exit(1)

    applied = 0
    for title, cp in targets:
        file_path = repo / cp.file_path
        if not file_path.exists():
            console.print(f"[yellow]⚠️  Skipping {cp.patch_id}: file not found: {cp.file_path}[/yellow]")
            continue

        source = file_path.read_text(encoding="utf-8")

        if cp.original_code not in source:
            console.print(
                f"[yellow]⚠️  Skipping {cp.patch_id}: original code not found in {cp.file_path}\n"
                f"   The file may have changed since the scan. Review manually.[/yellow]"
            )
            continue

        if dry_run:
            console.print(f"[dim cyan][dry-run][/dim cyan] [bold]{cp.patch_id}[/bold] — {cp.file_path}:{cp.line_number}")
            console.print(f"  [dim]{cp.explanation}[/dim]")
            console.print(f"  [red]- {cp.original_code.splitlines()[0][:80]}[/red]")
            console.print(f"  [green]+ {cp.patched_code.splitlines()[0][:80]}[/green]")
            console.print()
            continue

        # Create backup
        if not no_backup:
            backup_dir = aisast_dir / "patches"
            backup_dir.mkdir(parents=True, exist_ok=True)
            backup_path = backup_dir / f"{cp.patch_id}.bak"
            backup_path.write_text(source, encoding="utf-8")

        patched = source.replace(cp.original_code, cp.patched_code, 1)
        file_path.write_text(patched, encoding="utf-8")
        applied += 1

        console.print(f"[green]✅ Applied[/green] [bold]{cp.patch_id}[/bold] → {cp.file_path}:{cp.line_number}")
        console.print(f"   [dim]{cp.explanation}[/dim]")
        if not no_backup:
            console.print(f"   [dim]Backup saved to .aisast/patches/{cp.patch_id}.bak[/dim]")
        if cp.test_hint:
            console.print(f"   [yellow]Test: {cp.test_hint}[/yellow]")
        console.print()

    if not dry_run:
        console.print(f"[bold green]{applied} patch(es) applied.[/bold green]")


def _update_baseline_artifacts(aisast_dir: Path, result: ScanResult) -> None:
    """Merge PR findings into baseline VULNERABILITIES.json."""
    vulns_path = aisast_dir / "VULNERABILITIES.json"
    try:
        existing: list = []
        if vulns_path.exists():
            try:
                existing = json.loads(vulns_path.read_text(encoding="utf-8"))
                if not isinstance(existing, list):
                    existing = []
            except json.JSONDecodeError:
                existing = []

        existing_keys = {
            (str(v.get("file_path", "")), str(v.get("title", "")))
            for v in existing
            if isinstance(v, dict)
        }

        for issue in result.issues:
            key = (issue.file_path, issue.title)
            if key not in existing_keys:
                entry = issue.to_dict()
                entry["source"] = "pr_review"
                existing.append(entry)
                existing_keys.add(key)

        vulns_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    except (OSError, IOError):
        pass
