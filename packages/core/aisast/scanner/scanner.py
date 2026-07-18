"""Security scanner using ClaudeSDKClient with real-time progress tracking."""

import asyncio
import json
import logging
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from rich.console import Console
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions
from claude_agent_sdk.types import (
    AssistantMessage,
    HookMatcher,
    TextBlock,
    ResultMessage,
)

from aisast.agents.definitions import create_agent_definitions
from aisast.models.result import ScanResult
from aisast.models.issue import SecurityIssue, Severity, SEVERITY_RANK
from aisast.prompts.loader import load_prompt
from aisast.config import config, LanguageConfig, ScanConfig, ThreatModelingConfig
from aisast.scanner.progress import ProgressTracker
from aisast.scanner.subagent_manager import (
    SubAgentManager,
    ScanMode,
    SUBAGENT_ORDER,
)
from aisast.scanner.cache import (
    compute_repo_hash,
    get_phases_to_skip,
    update_phase_cache,
    PHASE_ARTIFACTS,
)

__all__ = ["Scanner", "ProgressTracker"]

logger = logging.getLogger(__name__)

AISAST_DIR = ".aisast"
SECURITY_FILE = "SECURITY.md"
THREAT_MODEL_FILE = "THREAT_MODEL.json"
VULNERABILITIES_FILE = "VULNERABILITIES.json"
SCAN_RESULTS_FILE = "scan_results.json"
DIFF_CONTEXT_FILE = "DIFF_CONTEXT.json"
PR_VULNERABILITIES_FILE = "PR_VULNERABILITIES.json"
LWRA_CONTEXT_FILE = "LWRA_CONTEXT.json"
LWRA_REPORT_FILE = "LWRA_REPORT.json"


def _parse_issues_from_scan_results(scan_results_path: Path) -> List[SecurityIssue]:
    """Parse SecurityIssue objects from scan_results.json."""
    if not scan_results_path.exists():
        return []
    try:
        data = json.loads(scan_results_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    raw_issues = data.get("issues") or data.get("vulnerabilities", [])
    if not isinstance(raw_issues, list):
        return []

    issues = []
    for i, raw in enumerate(raw_issues):
        if not isinstance(raw, dict):
            continue
        try:
            severity_str = str(raw.get("severity", "medium")).lower()
            severity = Severity(severity_str) or Severity.MEDIUM

            issue = SecurityIssue(
                id=str(raw.get("threat_id", raw.get("id", f"ISSUE-{i + 1:03d}"))),
                severity=severity,
                title=str(raw.get("title", "Unknown vulnerability")),
                description=str(raw.get("description", "")),
                file_path=str(raw.get("file_path") or raw.get("file", "")),
                line_number=int(raw.get("line_number") or raw.get("line") or 0),
                code_snippet=str(raw.get("code_snippet", "")),
                recommendation=raw.get("recommendation") or raw.get("remediation"),
                cwe_id=raw.get("cwe_id") or raw.get("cwe"),
                finding_type=raw.get("finding_type"),
                attack_scenario=raw.get("attack_scenario") or raw.get("impact"),
                evidence=raw.get("evidence"),
            )
            issues.append(issue)
        except Exception:
            continue

    return issues


def _parse_pr_issues(pr_vulns_path: Path) -> List[SecurityIssue]:
    """Parse SecurityIssue objects from PR_VULNERABILITIES.json."""
    if not pr_vulns_path.exists():
        return []
    try:
        data = json.loads(pr_vulns_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        return []

    issues = []
    for i, raw in enumerate(data):
        if not isinstance(raw, dict):
            continue
        try:
            severity_str = str(raw.get("severity", "medium")).lower()
            severity = Severity(severity_str) or Severity.MEDIUM

            issue = SecurityIssue(
                id=str(raw.get("threat_id", raw.get("id", f"PR-ISSUE-{i + 1:03d}"))),
                severity=severity,
                title=str(raw.get("title", "Unknown vulnerability")),
                description=str(raw.get("description", "")),
                file_path=str(raw.get("file_path", "")),
                line_number=int(raw.get("line_number") or 0),
                code_snippet=str(raw.get("code_snippet", "")),
                recommendation=raw.get("recommendation"),
                cwe_id=raw.get("cwe_id"),
                finding_type=raw.get("finding_type"),
                attack_scenario=raw.get("attack_scenario"),
                evidence=raw.get("evidence"),
            )
            issues.append(issue)
        except Exception:
            continue

    return issues


def _split_threats(threats: List[dict], n: int) -> List[List[dict]]:
    """Split a list of threats into n roughly equal chunks."""
    if n <= 1 or not threats:
        return [threats]
    size = max(1, len(threats) // n)
    chunks = []
    for i in range(0, len(threats), size):
        chunks.append(threats[i : i + size])
    # If rounding left an extra tiny chunk, merge it into the last one
    if len(chunks) > n:
        last = chunks.pop()
        chunks[-1].extend(last)
    return chunks


def _merge_vulnerabilities(parts: List[Path]) -> List[dict]:
    """Merge multiple VULNERABILITIES_part_N.json files, deduplicating by title+file+line."""
    seen: set = set()
    merged: List[dict] = []
    for part_path in parts:
        if not part_path.exists():
            continue
        try:
            data = json.loads(part_path.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                continue
            for v in data:
                key = (
                    v.get("title", ""),
                    v.get("file_path", ""),
                    v.get("line_number", 0),
                )
                if key not in seen:
                    seen.add(key)
                    merged.append(v)
        except (json.JSONDecodeError, OSError):
            continue
    # Sort by severity: critical -> high -> medium -> low -> info
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    merged.sort(key=lambda v: sev_rank.get(v.get("severity", "medium").lower(), 5))
    return merged


class Scanner:
    """
    AI-Native security scanner using ClaudeSDKClient.

    Orchestrates 4 specialized agents sequentially (or Phase 3 in parallel):
    1. Assessment      -> .aisast/SECURITY.md
    2. Threat Modeling -> .aisast/THREAT_MODEL.json
    3. Code Review     -> .aisast/VULNERABILITIES.json  (parallel if workers > 1)
    4. Report Generator-> .aisast/scan_results.json

    Parameters
    ----------
    workers : int
        Number of parallel workers for Phase 3 (code review).
        1 = sequential (default, same as before).
        2-5 = split threats into N chunks and review them concurrently.
    """

    def __init__(
        self,
        model: str = "sonnet",
        debug: bool = False,
        quiet: bool = False,
        workers: int = 1,
    ):
        self.model = model
        self.debug = debug
        self.workers = max(1, workers)
        self.total_cost = 0.0
        self.console = Console(stderr=True) if quiet else Console()
        self.agentic_override: Optional[bool] = None
        self._log_path: Optional[Path] = None

    def configure_agentic_detection(self, override: Optional[bool]) -> None:
        """Override agentic detection: True=force agentic, False=force non-agentic, None=auto."""
        self.agentic_override = override

    def _reset_runtime_state(self) -> None:
        self.total_cost = 0.0

    @staticmethod
    def _ssl_env() -> dict:
        """Return NODE_EXTRA_CA_CERTS env override when a corporate CA cert is present.

        Corporate proxies (Zscaler, Netskope, etc.) intercept TLS and re-sign
        with their own root CA. Node.js (Claude Code CLI) rejects these unless
        the CA is added via NODE_EXTRA_CA_CERTS.

        Priority: manually-exported cert (~/.claude/zscaler_ca.pem) takes
        precedence over any ambient NODE_EXTRA_CA_CERTS already in the shell,
        because the shell may point to a vendor-installed file that doesn't
        cover the MITM interception cert chain.
        """
        import os
        # 1. Manually exported cert takes top priority (verified to work)
        preferred = Path.home() / ".claude" / "zscaler_ca.pem"
        if preferred.exists():
            return {"NODE_EXTRA_CA_CERTS": str(preferred)}
        # 2. Fall back to any ambient env var already in the shell
        if os.environ.get("NODE_EXTRA_CA_CERTS"):
            return {"NODE_EXTRA_CA_CERTS": os.environ["NODE_EXTRA_CA_CERTS"]}
        # 3. Well-known vendor cert locations
        candidates = [
            Path("/etc/ssl/certs/zscaler_ca.pem"),
            Path("/Library/Application Support/Zscaler/ZscalerRootCA.pem"),
        ]
        for p in candidates:
            if p.exists():
                return {"NODE_EXTRA_CA_CERTS": str(p)}
        return {}

    # ------------------------------------------------------------------
    # Prompt helpers
    # ------------------------------------------------------------------

    def _build_scan_execution_mode(
        self,
        *,
        single_subagent: Optional[str],
        resume_from: Optional[str],
        skip_subagents: List[str],
    ) -> str:
        return (
            "<scan_execution_mode>\n"
            "These values are authoritative for this run.\n"
            f"run_only_subagent={single_subagent or 'none'}\n"
            f"resume_from_subagent={resume_from or 'none'}\n"
            f"skip_subagents={','.join(skip_subagents) if skip_subagents else 'none'}\n"
            "</scan_execution_mode>"
        )

    # ------------------------------------------------------------------
    # File counting
    # ------------------------------------------------------------------

    def _count_repo_files(self, repo: Path) -> int:
        extensions = LanguageConfig.get_all_extensions()
        languages = LanguageConfig.detect_languages(repo)
        excluded = ScanConfig.get_excluded_dirs(languages)
        count = 0
        try:
            for f in repo.rglob("*"):
                if not f.is_file():
                    continue
                if any(part in excluded for part in f.parts):
                    continue
                if f.suffix.lower() in extensions:
                    count += 1
        except (OSError, PermissionError):
            pass
        return count

    # ------------------------------------------------------------------
    # Hooks
    # ------------------------------------------------------------------

    def _create_hooks(
        self,
        tracker: ProgressTracker,
        aisast_dir: Optional[Path] = None,
        repo_hash: Optional[str] = None,
    ) -> Dict:
        """Build SDK hooks dict.

        Optionally accepts aisast_dir + repo_hash so SubagentStop can
        update the cache file after each phase completes.
        """

        async def on_pre_tool(hook_input: Any, tool_use_id: Any, ctx: Any) -> Dict:
            tool_name = hook_input.get("tool_name", "") if isinstance(hook_input, dict) else ""
            tool_inp = hook_input.get("tool_input", {}) if isinstance(hook_input, dict) else {}
            tracker.on_tool_start(tool_name, tool_inp)
            return {}

        async def on_post_tool(hook_input: Any, tool_use_id: Any, ctx: Any) -> Dict:
            tool_name = hook_input.get("tool_name", "") if isinstance(hook_input, dict) else ""
            error = hook_input.get("error") if isinstance(hook_input, dict) else None
            tracker.on_tool_complete(tool_name, error is None, str(error) if error else None)
            return {}

        async def on_subagent_stop(hook_input: Any, tool_use_id: Any, ctx: Any) -> Dict:
            agent_name = hook_input.get("agent_type", "") if isinstance(hook_input, dict) else ""
            duration_ms = hook_input.get("duration_ms", 0) if isinstance(hook_input, dict) else 0
            if agent_name:
                tracker.on_subagent_stop(agent_name, duration_ms)
                # Update cache so this phase is skipped next run if source unchanged
                if aisast_dir and repo_hash and agent_name in PHASE_ARTIFACTS:
                    update_phase_cache(aisast_dir, agent_name, repo_hash)
            return {}

        return {
            "PreToolUse": [HookMatcher(hooks=[on_pre_tool])],
            "PostToolUse": [HookMatcher(hooks=[on_post_tool])],
            "SubagentStop": [HookMatcher(hooks=[on_subagent_stop])],
        }

    # ------------------------------------------------------------------
    # Core session runner (reused by both sequential and parallel paths)
    # ------------------------------------------------------------------

    def _log(self, msg: str) -> None:
        """Append a timestamped line to the debug log file if configured."""
        if self._log_path:
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            try:
                with self._log_path.open("a", encoding="utf-8") as fh:
                    fh.write(f"[{ts}] {msg}\n")
            except OSError:
                pass

    async def _run_session(
        self,
        prompt: str,
        options: ClaudeAgentOptions,
        tracker: ProgressTracker,
    ) -> None:
        """Connect a ClaudeSDKClient, stream messages, collect cost."""
        ssl_env = Scanner._ssl_env()
        self._log(
            f"session start | model={getattr(options, 'model', '?')} "
            f"| ssl_env={'NODE_EXTRA_CA_CERTS' in ssl_env}"
        )
        client = ClaudeSDKClient(options=options)
        try:
            await client.connect(prompt)
            self._log("connected to Claude Code CLI")
            async for message in client.receive_messages():
                if isinstance(message, AssistantMessage):
                    for block in getattr(message, "content", []):
                        if isinstance(block, TextBlock):
                            if self.debug:
                                tracker.on_assistant_text(block.text)
                            self._log(f"text | {block.text[:120].replace(chr(10), ' ')}")
                elif isinstance(message, ResultMessage):
                    usage = getattr(message, "usage", None)
                    if usage:
                        cost = float(getattr(usage, "cost_usd", None) or 0.0)
                        self.total_cost += cost
                        self._log(
                            f"result | cost=${cost:.4f} "
                            f"in={getattr(usage, 'input_tokens', '?')} "
                            f"out={getattr(usage, 'output_tokens', '?')}"
                        )
                    else:
                        self._log("result | no usage data")
                    break
                else:
                    self._log(f"msg | {type(message).__name__}")
        except Exception as exc:
            self._log(f"ERROR | {exc}")
            raise
        finally:
            await client.disconnect()
            self._log("session end")

    # ------------------------------------------------------------------
    # Parallel Phase 3: one code-review agent per threat chunk
    # ------------------------------------------------------------------

    async def _run_code_review_chunk(
        self,
        repo: Path,
        aisast_dir: Path,
        chunk_idx: int,
        threats: List[dict],
    ) -> Path:
        """Run a single code-review agent against a subset of threats.

        Writes results to .aisast/VULNERABILITIES_part_{chunk_idx}.json.
        Returns the path to that file.
        """
        chunk_file = aisast_dir / f"THREAT_MODEL_chunk_{chunk_idx}.json"
        output_filename = f"VULNERABILITIES_part_{chunk_idx}.json"
        output_path = aisast_dir / output_filename

        # Write the threat subset for this agent to read
        chunk_file.write_text(json.dumps(threats, indent=2), encoding="utf-8")

        # Load the base code-review prompt and redirect file paths to chunk files
        base_prompt = load_prompt("code_review", category="agents")
        chunk_prompt = base_prompt.replace(
            ".aisast/THREAT_MODEL.json",
            f".aisast/THREAT_MODEL_chunk_{chunk_idx}.json",
        ).replace(
            ".aisast/VULNERABILITIES.json",
            f".aisast/{output_filename}",
        )

        # Silent tracker for parallel workers (no shared progress bar)
        tracker = ProgressTracker(self.console, debug=False)

        options = ClaudeAgentOptions(
            allowed_tools=["Read", "Grep", "Glob", "Write"],
            max_turns=config.get_max_turns(),
            permission_mode="bypassPermissions",
            cwd=str(repo),
            model=config.get_agent_model("code_review", cli_override=self.model),
            env={"CLAUDECODE": "1", **Scanner._ssl_env()},
        )

        if self.debug:
            self.console.print(
                f"  [dim]Parallel worker {chunk_idx + 1}: reviewing {len(threats)} threats...[/dim]"
            )

        try:
            await self._run_session(chunk_prompt, options, tracker)
        finally:
            # Clean up temp chunk file
            try:
                chunk_file.unlink(missing_ok=True)
            except OSError:
                pass

        return output_path

    # ------------------------------------------------------------------
    # Main scan entry points
    # ------------------------------------------------------------------

    async def _execute_scan(
        self,
        repo: Path,
        *,
        single_subagent: Optional[str] = None,
        resume_from: Optional[str] = None,
        skip_subagents: Optional[List[str]] = None,
        delta_context: Optional[str] = None,
        include_diagram: bool = False,
        methodology: str = ThreatModelingConfig.DEFAULT_METHODOLOGY,
    ) -> ScanResult:
        """Core scan execution — handles caching + sequential/parallel routing."""
        skip_subagents = list(skip_subagents or [])
        # Diagram is opt-in — skip by default unless explicitly requested or directly targeted
        if (
            not include_diagram
            and "threat-model-diagram" not in skip_subagents
            and single_subagent != "threat-model-diagram"
        ):
            skip_subagents.append("threat-model-diagram")

        aisast_dir = repo / AISAST_DIR
        aisast_dir.mkdir(parents=True, exist_ok=True)

        scan_start = time.time()

        # ── Step 6: Cache check ──────────────────────────────────────────────
        # Only apply cache for full scans (not --subagent or --resume-from)
        repo_hash: Optional[str] = None
        cache_skips: List[str] = []

        if not single_subagent and not resume_from and not skip_subagents:
            extensions = LanguageConfig.get_all_extensions()
            languages = LanguageConfig.detect_languages(repo)
            excluded = ScanConfig.get_excluded_dirs(languages)
            repo_hash = compute_repo_hash(repo, extensions, excluded)

            cache_skips = get_phases_to_skip(aisast_dir, repo_hash)
            if cache_skips:
                self.console.print(
                    f"\n  [dim cyan]Cache hit — skipping unchanged phases: "
                    f"{', '.join(cache_skips)}[/dim cyan]"
                )

        effective_skip = list(set(skip_subagents + cache_skips))

        # ── Step 5: Parallel Phase 3 routing ────────────────────────────────
        # Use parallel mode when workers > 1 AND doing a full (non-subagent) scan
        # AND code-review is not already cached/skipped
        # AND not a delta scan (delta always runs sequentially)
        use_parallel = (
            self.workers > 1
            and not single_subagent
            and not resume_from
            and "code-review" not in effective_skip
            and not delta_context
        )

        if use_parallel:
            return await self._execute_parallel_scan(
                repo, aisast_dir, scan_start, repo_hash, effective_skip,
                methodology=methodology,
            )

        return await self._execute_sequential_scan(
            repo, aisast_dir, scan_start, repo_hash,
            single_subagent, resume_from, effective_skip,
            delta_context=delta_context,
            include_diagram=include_diagram,
            methodology=methodology,
        )

    # ------------------------------------------------------------------
    # Sequential scan (original behaviour, now extracted to its own method)
    # ------------------------------------------------------------------

    async def _execute_sequential_scan(
        self,
        repo: Path,
        aisast_dir: Path,
        scan_start: float,
        repo_hash: Optional[str],
        single_subagent: Optional[str],
        resume_from: Optional[str],
        skip_subagents: List[str],
        delta_context: Optional[str] = None,
        include_diagram: bool = False,
        methodology: str = ThreatModelingConfig.DEFAULT_METHODOLOGY,
    ) -> ScanResult:
        """Run all 4 phases sequentially through a single Claude session."""
        tracker = ProgressTracker(self.console, debug=self.debug, single_subagent=single_subagent, repo_path=repo)
        threat_modeling_context = self._build_agentic_context(repo)
        agent_defs = create_agent_definitions(
            cli_model=self.model,
            threat_modeling_context=threat_modeling_context,
            delta_context=delta_context,
            methodology=methodology,
        )

        orchestration_prompt = load_prompt("main", category="orchestration")
        execution_mode = self._build_scan_execution_mode(
            single_subagent=single_subagent,
            resume_from=resume_from,
            skip_subagents=skip_subagents,
        )
        full_prompt = f"{orchestration_prompt}\n\n{execution_mode}"

        hooks = self._create_hooks(tracker, aisast_dir=aisast_dir, repo_hash=repo_hash)
        max_turns = config.get_max_turns()

        options = ClaudeAgentOptions(
            agents=agent_defs,
            hooks=hooks,
            max_turns=max_turns,
            permission_mode="bypassPermissions",
            cwd=str(repo),
            model=self.model,
            env={"CLAUDECODE": "1", **Scanner._ssl_env()},
        )

        methodology_label = methodology.upper()
        if include_diagram:
            phases = [
                ("assessment",            "Phase 1/5  Architecture Assessment"),
                ("threat-modeling",       f"Phase 2/5  Threat Modeling ({methodology_label})"),
                ("threat-model-diagram",  "Phase 3/5  Threat Model Diagram"),
                ("code-review",           "Phase 4/5  Code Review"),
                ("report-generator",      "Phase 5/5  Report Generation"),
            ]
        else:
            phases = [
                ("assessment",       "Phase 1/4  Architecture Assessment"),
                ("threat-modeling",  f"Phase 2/4  Threat Modeling ({methodology_label})"),
                ("code-review",      "Phase 3/4  Code Review"),
                ("report-generator", "Phase 4/4  Report Generation"),
            ]
        if single_subagent:
            phases = [(single_subagent, f"Running sub-agent: {single_subagent}")]

        # Remove cached phases from the active set
        active_phases = [(p, d) for p, d in phases if p not in skip_subagents]

        # Initialise the phase plan in the tracker (must happen before render())
        tracker.set_phases(phases, skip=list(skip_subagents))

        # Short-circuit: if every phase is cached, show a static panel and return
        if not active_phases:
            self.console.print(tracker.render())
            self.console.print(
                "[dim cyan]All phases up-to-date. "
                "Use [bold]--no-cache[/bold] to force a full re-scan.[/dim cyan]\n"
            )
            return self._build_scan_result(repo, aisast_dir, scan_start)

        with Live(
            tracker.render(),
            console=self.console,
            refresh_per_second=4,
            transient=False,
        ) as live:
            tracker.set_live(live)
            try:
                await self._run_session(full_prompt, options, tracker)
            except Exception as exc:
                self.console.print(f"\n[bold red]❌ Scan error:[/bold red] {exc}", style="red")
                raise

        return self._build_scan_result(repo, aisast_dir, scan_start)

    # ------------------------------------------------------------------
    # Parallel scan (Phase 1+2 sequential, Phase 3 parallel, Phase 4 sequential)
    # ------------------------------------------------------------------

    async def _execute_parallel_scan(
        self,
        repo: Path,
        aisast_dir: Path,
        scan_start: float,
        repo_hash: Optional[str],
        effective_skip: List[str],
        methodology: str = ThreatModelingConfig.DEFAULT_METHODOLOGY,
    ) -> ScanResult:
        """Run Phase 1+2 sequentially, Phase 3 in parallel workers, Phase 4 sequentially."""
        threat_modeling_context = self._build_agentic_context(repo)
        agent_defs = create_agent_definitions(
            cli_model=self.model,
            threat_modeling_context=threat_modeling_context,
            methodology=methodology,
        )
        orchestration_prompt = load_prompt("main", category="orchestration")
        max_turns = config.get_max_turns()

        # ── Phase 1 + 2 ─────────────────────────────────────────────────────
        phases_1_2 = ["code-review", "report-generator"] + effective_skip
        skip_1_2 = list(set(phases_1_2))

        needs_1_2 = (
            "assessment" not in effective_skip
            or "threat-modeling" not in effective_skip
        )

        if needs_1_2:
            self.console.print("\n  [bold cyan]Phase 1+2: Assessment & Threat Modeling[/bold cyan]")
            tracker_12 = ProgressTracker(self.console, debug=self.debug)
            hooks_12 = self._create_hooks(tracker_12, aisast_dir=aisast_dir, repo_hash=repo_hash)

            prompt_12 = f"{orchestration_prompt}\n\n{self._build_scan_execution_mode(single_subagent=None, resume_from=None, skip_subagents=skip_1_2)}"
            options_12 = ClaudeAgentOptions(
                agents=agent_defs,
                hooks=hooks_12,
                max_turns=max_turns,
                permission_mode="bypassPermissions",
                cwd=str(repo),
                model=self.model,
                env={"CLAUDECODE": "1", **Scanner._ssl_env()},
            )

            active_12 = [
                p for p in [("assessment", "Phase 1/4  Assessment"), ("threat-modeling", "Phase 2/4  Threat Modeling")]
                if p[0] not in effective_skip
            ]

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}"),
                BarColumn(bar_width=30),
                TextColumn("[green]{task.completed}/{task.total} phases"),
                TimeElapsedColumn(),
                console=self.console,
                transient=False,
            ) as progress:
                overall = progress.add_task("AISAST Scan", total=max(len(active_12), 1))
                detail = progress.add_task("  Starting...", total=None)
                tracker_12.set_progress(progress, overall, detail, active_12)
                try:
                    await self._run_session(prompt_12, options_12, tracker_12)
                except Exception as exc:
                    self.console.print(f"\n[bold red]❌ Phase 1/2 error:[/bold red] {exc}", style="red")
                    raise

        # ── Phase 3: Parallel code review ───────────────────────────────────
        threat_model_path = aisast_dir / THREAT_MODEL_FILE
        if not threat_model_path.exists():
            raise RuntimeError(
                "THREAT_MODEL.json not found after Phase 2. Cannot run parallel code review."
            )

        try:
            threats = json.loads(threat_model_path.read_text(encoding="utf-8"))
            if not isinstance(threats, list):
                threats = []
        except (json.JSONDecodeError, OSError):
            threats = []

        if not threats:
            self.console.print(
                "[yellow]⚠️  THREAT_MODEL.json is empty — skipping parallel code review.[/yellow]"
            )
        else:
            chunks = _split_threats(threats, self.workers)
            actual_workers = len(chunks)
            self.console.print(
                f"\n  [bold cyan]Phase 3/4: Code Review "
                f"({actual_workers} parallel workers × "
                f"~{len(chunks[0])} threats each)[/bold cyan]"
            )

            # Run all chunks concurrently
            part_paths = await asyncio.gather(
                *[
                    self._run_code_review_chunk(repo, aisast_dir, i, chunk)
                    for i, chunk in enumerate(chunks)
                ]
            )

            # Merge results into VULNERABILITIES.json
            merged = _merge_vulnerabilities(list(part_paths))
            vuln_path = aisast_dir / VULNERABILITIES_FILE
            vuln_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
            self.console.print(
                f"  [bold green]Phase 3/4 complete[/bold green]  "
                f"[dim]{len(merged)} vulnerabilities merged from {actual_workers} workers[/dim]"
            )

            # Clean up part files
            for p in part_paths:
                try:
                    if p.exists():
                        p.unlink()
                except OSError:
                    pass

            # Update cache for code-review phase
            if repo_hash:
                update_phase_cache(aisast_dir, "code-review", repo_hash)

        # ── Phase 4: Report Generation ───────────────────────────────────────
        self.console.print("\n  [bold cyan]Phase 4/4: Report Generation[/bold cyan]")
        tracker_4 = ProgressTracker(self.console, debug=self.debug)
        hooks_4 = self._create_hooks(tracker_4, aisast_dir=aisast_dir, repo_hash=repo_hash)

        skip_4 = list(set(["assessment", "threat-modeling", "code-review"] + effective_skip))
        prompt_4 = f"{orchestration_prompt}\n\n{self._build_scan_execution_mode(single_subagent=None, resume_from=None, skip_subagents=skip_4)}"
        options_4 = ClaudeAgentOptions(
            agents=agent_defs,
            hooks=hooks_4,
            max_turns=max_turns,
            permission_mode="bypassPermissions",
            cwd=str(repo),
            model=self.model,
            env={"CLAUDECODE": "1", **Scanner._ssl_env()},
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("[green]{task.completed}/{task.total} phases"),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        ) as progress:
            overall = progress.add_task("AISAST Scan", total=1)
            detail = progress.add_task("  Generating report...", total=None)
            tracker_4.set_progress(progress, overall, detail, [("report-generator", "Phase 4/4  Report Generation")])
            try:
                await self._run_session(prompt_4, options_4, tracker_4)
            except Exception as exc:
                self.console.print(f"\n[bold red]❌ Phase 4 error:[/bold red] {exc}", style="red")
                raise

        return self._build_scan_result(repo, aisast_dir, scan_start)

    # ------------------------------------------------------------------
    # Shared result builder
    # ------------------------------------------------------------------

    def _build_scan_result(self, repo: Path, aisast_dir: Path, scan_start: float) -> ScanResult:
        scan_time = round(time.time() - scan_start, 2)
        files_scanned = self._count_repo_files(repo)
        issues = _parse_issues_from_scan_results(aisast_dir / SCAN_RESULTS_FILE)
        return ScanResult(
            repository_path=str(repo),
            issues=issues,
            files_scanned=files_scanned,
            scan_time_seconds=scan_time,
            total_cost_usd=round(self.total_cost, 4),
        )

    # ------------------------------------------------------------------
    # Agentic detection
    # ------------------------------------------------------------------

    def _build_agentic_context(self, repo: Path) -> Optional[str]:
        if self.agentic_override is False:
            return None
        if self.agentic_override is True:
            return (
                "IMPORTANT: This codebase has been classified as AGENTIC (forced by user). "
                "Apply OWASP ASI01-ASI10 threat categories in addition to STRIDE."
            )

        agentic_patterns = [
            "anthropic", "openai", "claude", "gpt", "langchain",
            "autogen", "crewai", "claude_agent_sdk", "semantic_kernel",
            "MCPServer", "MCPClient",
        ]
        for pattern in agentic_patterns:
            try:
                import subprocess
                result = subprocess.run(
                    ["grep", "-r", "--include=*.py", "--include=*.js", "--include=*.ts",
                     "-l", pattern, str(repo)],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return (
                        f"IMPORTANT: Agentic patterns detected ('{pattern}' found). "
                        "Apply OWASP ASI01-ASI10 threat categories in addition to STRIDE."
                    )
            except Exception:
                continue
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(
        self,
        repo_path: str,
        run_lwra: bool = False,
        include_diagram: bool = False,
        methodology: str = ThreatModelingConfig.DEFAULT_METHODOLOGY,
    ) -> ScanResult:
        """
        Run a complete security scan.

        Parameters
        ----------
        repo_path : str
            Path to the repository to scan.
        run_lwra : bool
            If True, run the LWRA phase after the main 4-phase scan.
            The caller must ensure .aisast/LWRA_CONTEXT.json already exists,
            or collect it interactively before calling this method.
        include_diagram : bool
            If True, run the optional threat model diagram phase (Phase 2.5/3/5)
            between threat modeling and code review.
        methodology : str
            Threat-modeling methodology for Phase 2 — "stride" (default), "linddun",
            or "attack-trees".
        """
        self._reset_runtime_state()
        repo = Path(repo_path).resolve()
        if not repo.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
        if self.debug:
            aisast_dir = repo / AISAST_DIR
            aisast_dir.mkdir(parents=True, exist_ok=True)
            self._log_path = aisast_dir / "aisast_debug.log"
            self._log_path.write_text(
                f"=== AISAST debug log — {datetime.now().isoformat()} ===\n",
                encoding="utf-8",
            )
            self._log(f"ssl_env={Scanner._ssl_env() or 'none'}")
        result = await self._execute_scan(repo, include_diagram=include_diagram, methodology=methodology)
        if run_lwra:
            await self._run_lwra_phase(repo, repo / AISAST_DIR)
        return result

    def load_cached_result(self, repo_path: str) -> ScanResult:
        """Return cached scan results instantly — no agents, no network calls.

        Reads whatever artifacts already exist in .aisast/ (SECURITY.md,
        THREAT_MODEL.json, VULNERABILITIES.json, scan_results.json) and builds
        a ScanResult directly from them, bypassing the repo-hash cache check
        and any agent session entirely.
        """
        repo = Path(repo_path).resolve()
        aisast_dir = repo / AISAST_DIR
        return self._build_scan_result(repo, aisast_dir, time.time())

    async def scan_subagent(
        self,
        repo_path: str,
        subagent: str,
        force: bool = False,
        skip_checks: bool = False,
        methodology: str = ThreatModelingConfig.DEFAULT_METHODOLOGY,
    ) -> ScanResult:
        """Run a single specific sub-agent."""
        self._reset_runtime_state()
        repo = Path(repo_path).resolve()
        if not repo.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

        manager = SubAgentManager(repo)

        if not skip_checks:
            valid, error_msg = manager.validate_prerequisites(subagent)
            if not valid:
                raise RuntimeError(
                    f"Cannot run '{subagent}': {error_msg}\n"
                    f"Run a full scan first or use --resume-from to skip earlier phases."
                )
            deps = manager.get_subagent_dependencies(subagent)
            required = deps["requires"]
            if required:
                artifact_status = manager.check_artifact(required)
                if artifact_status.exists:
                    mode = manager.prompt_user_choice(subagent, artifact_status, force=force)
                    if mode == ScanMode.CANCEL:
                        raise RuntimeError("Scan cancelled by user.")
                    elif mode == ScanMode.FULL_RESCAN:
                        return await self._execute_scan(repo, methodology=methodology)

        return await self._execute_scan(repo, single_subagent=subagent, methodology=methodology)

    async def scan_resume_from(
        self,
        repo_path: str,
        from_subagent: str,
        methodology: str = ThreatModelingConfig.DEFAULT_METHODOLOGY,
    ) -> ScanResult:
        """Resume scan from a specific sub-agent onwards."""
        self._reset_runtime_state()
        repo = Path(repo_path).resolve()
        if not repo.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

        manager = SubAgentManager(repo)
        subagents_to_run = manager.get_resume_subagents(from_subagent)
        skip_subagents = [s for s in SUBAGENT_ORDER if s not in subagents_to_run]
        return await self._execute_scan(repo, skip_subagents=skip_subagents, methodology=methodology)

    async def pr_review(
        self,
        repo_path: str,
        diff_context: Any,
        severity_threshold: str = "low",
        known_vulns_path: Optional[Path] = None,
    ) -> ScanResult:
        """Run PR code review on a diff."""
        self._reset_runtime_state()
        repo = Path(repo_path).resolve()
        if not repo.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

        aisast_dir = repo / AISAST_DIR
        aisast_dir.mkdir(parents=True, exist_ok=True)

        if self.debug:
            self._log_path = aisast_dir / "pr_debug.log"
            self._log_path.write_text(
                f"=== PR review debug log — {datetime.now().isoformat()} ===\n",
                encoding="utf-8",
            )
            self._log(f"ssl_env={Scanner._ssl_env() or 'none'}")

        diff_context_path = aisast_dir / DIFF_CONTEXT_FILE
        try:
            diff_dict = diff_context.to_dict() if hasattr(diff_context, "to_dict") else vars(diff_context)
            diff_context_path.write_text(json.dumps(diff_dict, indent=2), encoding="utf-8")
        except Exception as exc:
            raise RuntimeError(f"Failed to serialize diff context: {exc}") from exc

        scan_start = time.time()
        tracker = ProgressTracker(self.console, debug=self.debug, single_subagent="pr-code-review", repo_path=repo)

        pr_prompt = self._build_pr_review_prompt(
            repo=repo,
            diff_context=diff_context,
            known_vulns_path=known_vulns_path,
            severity_threshold=severity_threshold,
        )

        agent_defs = create_agent_definitions(cli_model=self.model)
        hooks = self._create_hooks(tracker)
        max_turns = config.get_max_turns()

        options = ClaudeAgentOptions(
            agents={"pr-code-review": agent_defs["pr-code-review"]},
            hooks=hooks,
            max_turns=max_turns,
            permission_mode="bypassPermissions",
            cwd=str(repo),
            model=self.model,
            env={"CLAUDECODE": "1", **Scanner._ssl_env()},
        )

        pr_phases = [("pr-code-review", "PR Review  Analyzing diff")]
        tracker.set_phases(pr_phases)

        with Live(
            tracker.render(),
            console=self.console,
            refresh_per_second=4,
            transient=False,
        ) as live:
            tracker.set_live(live)
            try:
                await self._run_session(pr_prompt, options, tracker)
            except Exception as exc:
                self.console.print(f"\n[bold red]❌ PR review error:[/bold red] {exc}", style="red")
                raise

        scan_time = round(time.time() - scan_start, 2)
        pr_vulns_path = aisast_dir / PR_VULNERABILITIES_FILE
        issues = _parse_pr_issues(pr_vulns_path)

        if severity_threshold:
            threshold_rank = SEVERITY_RANK.get(severity_threshold.lower(), 0)
            issues = [i for i in issues if SEVERITY_RANK.get(i.severity.value, 0) >= threshold_rank]

        changed_files = getattr(diff_context, "changed_files", [])
        return ScanResult(
            repository_path=str(repo),
            issues=issues,
            files_scanned=len(changed_files) if changed_files else 0,
            scan_time_seconds=scan_time,
            total_cost_usd=round(self.total_cost, 4),
        )

    # ------------------------------------------------------------------
    # LWRA Phase 5
    # ------------------------------------------------------------------

    async def _run_lwra_phase(self, repo: Path, aisast_dir: Path) -> None:
        """Run the LWRA agent directly as the main Claude session.

        Bypasses the orchestrator→Task→subagent delegation pattern entirely.
        The lwra agent's system prompt becomes the session system prompt, and
        the tools are granted directly — no Task tool invocation required.
        """
        agent_defs = create_agent_definitions(cli_model=self.model)
        tracker = ProgressTracker(self.console, debug=self.debug, single_subagent="lwra")
        lwra_agent = agent_defs["lwra"]

        user_prompt = (
            "Perform the LWRA risk adjustment now.\n\n"
            "Steps:\n"
            "1. Read .aisast/scan_results.json — this contains all confirmed vulnerabilities\n"
            "2. Read .aisast/LWRA_CONTEXT.json — this contains the deployment environment context\n"
            "3. Follow your instructions exactly to compute adjusted severities, "
            "risk scores, soft fixes, and code patches for every vulnerability\n"
            "4. Write the complete JSON result to .aisast/LWRA_REPORT.json\n\n"
            "Execute all steps now without asking for confirmation."
        )

        options = ClaudeAgentOptions(
            # Append lwra instructions to the default Claude Code system prompt
            # so the model retains full tool knowledge AND gets the LWRA task.
            system_prompt={"type": "preset", "preset": "claude_code", "append": lwra_agent.prompt},
            hooks=self._create_hooks(tracker),
            max_turns=config.get_max_turns(),
            permission_mode="bypassPermissions",
            cwd=str(repo),
            model=lwra_agent.model or self.model,
            env={"CLAUDECODE": "1", **Scanner._ssl_env()},
        )

        tracker.set_phases([("lwra", "Phase 5/5  Risk Adjustment (LWRA)")])

        with Live(
            tracker.render(),
            console=self.console,
            refresh_per_second=4,
            transient=False,
        ) as live:
            tracker.set_live(live)
            tracker._announce_phase("lwra")
            phase_start = time.time()
            try:
                await self._run_session(user_prompt, options, tracker)
            except Exception as exc:
                self.console.print(
                    f"\n[bold red]❌ LWRA error:[/bold red] {exc}", style="red"
                )
                raise
            # Mark phase complete so the final panel shows ✅
            tracker.on_subagent_stop("lwra", int((time.time() - phase_start) * 1000))

    async def lwra_scan(self, repo_path: str) -> "ScanResult":
        """
        Run only the LWRA phase on an existing scan result.

        Expects .aisast/scan_results.json and .aisast/LWRA_CONTEXT.json to exist.
        If LWRA_CONTEXT.json is missing, collects it interactively.
        """
        from aisast.scanner.env_collector import collect_deployment_context, save_context, load_context

        self._reset_runtime_state()
        repo = Path(repo_path).resolve()
        if not repo.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

        aisast_dir = repo / AISAST_DIR
        scan_results_path = aisast_dir / SCAN_RESULTS_FILE
        if not scan_results_path.exists():
            raise RuntimeError(
                "No scan_results.json found. Run 'aisast scan .' first before running LWRA."
            )

        ctx = load_context(aisast_dir)
        if ctx is None:
            ctx = collect_deployment_context(self.console)
            save_context(ctx, aisast_dir)

        if self.debug:
            self._log_path = aisast_dir / "lwra_debug.log"
            self._log_path.write_text(
                f"=== LWRA debug log — {datetime.now().isoformat()} ===\n",
                encoding="utf-8",
            )
            ssl_env = Scanner._ssl_env()
            self._log(f"ssl_env={ssl_env or 'none'}")

        scan_start = time.time()
        await self._run_lwra_phase(repo, aisast_dir)
        scan_time = round(time.time() - scan_start, 2)

        issues = _parse_issues_from_scan_results(scan_results_path)
        return ScanResult(
            repository_path=str(repo),
            issues=issues,
            files_scanned=self._count_repo_files(repo),
            scan_time_seconds=scan_time,
            total_cost_usd=round(self.total_cost, 4),
        )

    def _preserve_unchanged_findings(self, aisast_dir: Path, changed_files: List[str]) -> None:
        """
        Write VULNERABILITIES_preserved.json containing only findings for files
        that did NOT change. The delta code-review agent merges these back in.
        """
        vuln_path = aisast_dir / VULNERABILITIES_FILE
        if not vuln_path.exists():
            return
        try:
            all_vulns = json.loads(vuln_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        if not isinstance(all_vulns, list):
            return
        changed_set = set(changed_files)
        preserved = [v for v in all_vulns if v.get("file_path", "") not in changed_set]
        preserved_path = aisast_dir / "VULNERABILITIES_preserved.json"
        preserved_path.write_text(json.dumps(preserved, indent=2), encoding="utf-8")

    @staticmethod
    def _backup_artifacts_versioned(aisast_dir: Path) -> int:
        """
        Copy current scan artifacts to versioned names (SECURITY2.md, etc.).
        Returns the version number used.
        """
        artifacts = [
            "SECURITY.md",
            "THREAT_MODEL.json",
            "VULNERABILITIES.json",
            "scan_results.json",
            "scan_report.md",
        ]
        n = 2
        while (aisast_dir / f"SECURITY{n}.md").exists():
            n += 1
        for filename in artifacts:
            src = aisast_dir / filename
            if not src.exists():
                continue
            stem = Path(filename).stem
            ext = Path(filename).suffix
            dst = aisast_dir / f"{stem}{n}{ext}"
            try:
                shutil.copy2(src, dst)
            except OSError:
                pass
        return n

    async def scan_delta(self, repo_path: str, changed_files: List[str]) -> ScanResult:
        """
        Re-run code review on changed files only, preserve findings for unchanged files.

        Steps:
        1. Split existing VULNERABILITIES.json → preserved (unchanged) + stale (changed).
        2. Run phases 3+4 with code-review agent focused on changed files.
           The agent reads VULNERABILITIES_preserved.json and merges them back.
        3. Clean up temp file.
        """
        self._reset_runtime_state()
        repo = Path(repo_path).resolve()
        if not repo.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

        aisast_dir = repo / AISAST_DIR
        self._preserve_unchanged_findings(aisast_dir, changed_files)

        delta_context = (
            f"DELTA SCAN MODE — {len(changed_files)} file(s) changed since the last scan.\n\n"
            "YOUR TASK:\n"
            "1. Read .aisast/THREAT_MODEL.json to understand the threat model.\n"
            "2. Read .aisast/VULNERABILITIES_preserved.json — confirmed findings for UNCHANGED "
            "files. Do NOT re-analyze those files.\n"
            "3. Analyze ONLY these changed files:\n"
            + "\n".join(f"   - {f}" for f in changed_files[:30])
            + ("\n   ... (truncated)" if len(changed_files) > 30 else "")
            + "\n\n4. Write .aisast/VULNERABILITIES.json as the MERGED result of:\n"
            "   - All entries from VULNERABILITIES_preserved.json (copy verbatim).\n"
            "   - New findings from your analysis of the changed files.\n"
            "   If a changed file's old finding is now fixed, omit it.\n"
        )

        try:
            result = await self._execute_scan(
                repo,
                skip_subagents=["assessment", "threat-modeling"],
                delta_context=delta_context,
            )
        finally:
            preserved_path = aisast_dir / "VULNERABILITIES_preserved.json"
            try:
                preserved_path.unlink(missing_ok=True)
            except OSError:
                pass
        return result

    def _build_pr_review_prompt(self, *, repo, diff_context, known_vulns_path, severity_threshold) -> str:
        aisast_dir = repo / AISAST_DIR
        sections: List[str] = [
            "Perform a security review of the provided pull request diff.",
            f"\nSeverity threshold: {severity_threshold} and above.\n",
        ]
        if (aisast_dir / "SECURITY.md").exists():
            sections.append("\n<baseline_context>\nArchitecture context is in .aisast/SECURITY.md\n</baseline_context>")
        if (aisast_dir / "THREAT_MODEL.json").exists():
            sections.append("\n<threat_context>\nKnown threats are in .aisast/THREAT_MODEL.json\n</threat_context>")
        if known_vulns_path and known_vulns_path.exists():
            sections.append(f"\n<known_vulnerabilities>\nKnown vulnerabilities are in {known_vulns_path}\n</known_vulnerabilities>")
        changed_files = getattr(diff_context, "changed_files", []) or getattr(diff_context, "files", [])
        if changed_files:
            sections.append(f"\n<changed_files>\n{chr(10).join(str(f) for f in changed_files[:50])}\n</changed_files>")
        sections.append(
            "\nUse the Task tool to invoke the 'pr-code-review' agent to analyze the diff "
            "and write findings to .aisast/PR_VULNERABILITIES.json. "
            "WAIT for the agent to complete."
        )
        return "\n".join(sections)
