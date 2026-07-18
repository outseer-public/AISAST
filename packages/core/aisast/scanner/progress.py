"""Real-time progress tracking for scan operations."""

import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table
from rich.tree import Tree

SECURITY_FILE = "SECURITY.md"
THREAT_MODEL_FILE = "THREAT_MODEL.json"
VULNERABILITIES_FILE = "VULNERABILITIES.json"
PR_VULNERABILITIES_FILE = "PR_VULNERABILITIES.json"
SCAN_RESULTS_FILE = "scan_results.json"

AGENT_ARTIFACT_MAP = {
    "assessment": SECURITY_FILE,
    "threat-modeling": THREAT_MODEL_FILE,
    "code-review": VULNERABILITIES_FILE,
    "report-generator": SCAN_RESULTS_FILE,
    "pr-code-review": PR_VULNERABILITIES_FILE,
}

_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

# Max files shown in the live tree before we start omitting older ones
_TREE_MAX_FILES = 25


class ProgressTracker:
    """
    Real-time progress tracking for scan operations.

    Renders a Rich Live panel showing each phase's status, elapsed time,
    ops count, and a live directory-tree of files being analyzed.
    Falls back to the legacy Rich Progress API when set_progress() is used
    (e.g. the parallel scan path).
    """

    def __init__(
        self,
        console: Console,
        debug: bool = False,
        single_subagent: Optional[str] = None,
        repo_path: Optional[Path] = None,
    ):
        self.console = console
        self.debug = debug
        self.single_subagent = single_subagent
        self._repo_path = repo_path

        # Phase plan
        self._phases: List[Tuple[str, str]] = []  # [(name, display_desc), ...]
        self._phase_status: Dict[str, str] = {}   # name -> pending | running | done | cached
        self._phase_duration: Dict[str, float] = {}
        self._phase_ops: Dict[str, int] = {}
        self._phase_files: Dict[str, int] = {}

        # Current operation detail line
        self._current_detail = ""
        self._spinner_idx = 0

        # Per-phase counters (reset when a new phase starts)
        self.current_phase: Optional[str] = None
        self.tool_count = 0
        self.files_read: set = set()
        self.files_written: set = set()
        self.subagent_stack: list = []
        self.last_update = datetime.now()
        self.phase_start_time: Optional[float] = None

        # Live file tree: ordered list of relative paths read in the current phase
        self._phase_display_files: List[str] = []

        self._scan_start = time.time()

        # Rich Live reference (sequential path)
        self._live: Optional[Live] = None

        # Legacy Rich Progress reference (parallel path keeps using this)
        self._progress: Optional[Progress] = None
        self._overall_task: Any = None
        self._detail_task: Any = None
        self._completed_phases: set = set()

        self.phase_display = {
            "assessment":       "1/4  Architecture Assessment",
            "threat-modeling":  "2/4  Threat Modeling (STRIDE Analysis)",
            "code-review":      "3/4  Code Review (Security Analysis)",
            "pr-code-review":   "PR   Code Review",
            "report-generator": "4/4  Report Generation",
        }

    # ------------------------------------------------------------------
    # Setup helpers
    # ------------------------------------------------------------------

    def set_phases(
        self,
        phases: List[Tuple[str, str]],
        skip: Optional[List[str]] = None,
    ) -> None:
        """Initialise the phase plan and mark any cached phases."""
        self._phases = phases
        skip = skip or []
        for name, _ in phases:
            self._phase_status[name] = "cached" if name in skip else "pending"
            self._phase_ops[name] = 0
            self._phase_files[name] = 0

    def set_live(self, live: Live) -> None:
        """Attach a Rich Live instance — enables the live panel display."""
        self._live = live

    def set_progress(
        self,
        progress: Progress,
        overall_task: Any,
        detail_task: Any,
        phases: List[Tuple[str, str]],
    ) -> None:
        """Legacy compat: attach a Rich Progress bar (used by the parallel path)."""
        self._progress = progress
        self._overall_task = overall_task
        self._detail_task = detail_task
        if not self._phases:
            self._phases = phases
            for name, _ in phases:
                if name not in self._phase_status:
                    self._phase_status[name] = "pending"

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def _display_path(self, file_path: str) -> str:
        """Return a relative path for display (strips repo root prefix)."""
        if self._repo_path:
            try:
                return str(Path(file_path).relative_to(self._repo_path))
            except ValueError:
                pass
        parts = Path(file_path).parts
        return str(Path(*parts[-4:])) if len(parts) > 4 else file_path

    # ------------------------------------------------------------------
    # File tree building
    # ------------------------------------------------------------------

    def _build_file_tree(self) -> Tuple[Optional[Tree], int]:
        """
        Build a Rich Tree from the files read in the current phase.

        Caps at _TREE_MAX_FILES entries (most recent). Returns
        (tree, number_of_omitted_earlier_files).
        """
        all_files = self._phase_display_files
        total = len(all_files)
        if not total:
            return None, 0

        # Show only the most recent window to prevent panel overflow
        display = all_files[-_TREE_MAX_FILES:]
        omitted = total - len(display)

        # Build a nested dict: {dir_name: {subdir: {...}, filename: None}}
        struct: Dict[str, Any] = {}
        for fp in display:
            parts = Path(fp).parts
            node = struct
            for part in parts[:-1]:          # walk/create directory nodes
                node = node.setdefault(part, {})
            node[parts[-1]] = None           # file leaf

        repo_name = self._repo_path.name if self._repo_path else "project"
        tree = Tree(
            f"[bold cyan]{repo_name}/[/bold cyan]",
            guide_style="dim cyan",
        )
        self._populate_tree_node(tree, struct)
        return tree, omitted

    def _populate_tree_node(self, node: Tree, children: Dict) -> None:
        """Recursively attach directory and file nodes to a Rich Tree."""
        # Directories first, then files — mirrors a standard tree command
        dirs  = {k: v for k, v in sorted(children.items()) if v is not None}
        files = [k for k, v in sorted(children.items()) if v is None]
        for name, subtree in dirs.items():
            branch = node.add(f"[cyan]{name}/[/cyan]")
            self._populate_tree_node(branch, subtree)
        for name in files:
            node.add(f"[green]✅ {name}[/green]")

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _fmt_dur(self, seconds: float) -> str:
        if seconds < 60:
            return f"{seconds:.1f}s"
        m = int(seconds // 60)
        s = seconds % 60
        return f"{m}m {s:.0f}s"

    def _running_elapsed(self) -> float:
        return time.time() - self.phase_start_time if self.phase_start_time else 0.0

    def render(self) -> Panel:
        """Build the Rich Panel that the Live display renders each frame."""
        self._spinner_idx = (self._spinner_idx + 1) % len(_SPINNER_FRAMES)
        spinner = _SPINNER_FRAMES[self._spinner_idx]

        # ── Phase rows ───────────────────────────────────────────────
        phase_table = Table(
            box=None,
            show_header=True,
            header_style="bold dim",
            padding=(0, 1),
            expand=True,
            show_edge=False,
        )
        phase_table.add_column("", width=3, no_wrap=True)
        phase_table.add_column("Phase", ratio=3)
        phase_table.add_column("Time", width=10, justify="right")
        phase_table.add_column("Ops",  width=7,  justify="right")
        phase_table.add_column("Files",width=7,  justify="right")

        completed = 0
        total_active = sum(
            1 for name, _ in self._phases
            if self._phase_status.get(name) != "cached"
        )

        for name, desc in self._phases:
            status = self._phase_status.get(name, "pending")
            ops    = self._phase_ops.get(name, 0)
            files  = self._phase_files.get(name, 0)

            if status == "done":
                completed += 1
                dur = self._fmt_dur(self._phase_duration.get(name, 0))
                phase_table.add_row(
                    "[bold green]✅[/bold green]",
                    f"[green]{desc}[/green]",
                    f"[green]{dur}[/green]",
                    f"[dim]{ops}[/dim]",
                    f"[dim]{files}[/dim]",
                )
            elif status == "running":
                elapsed = self._running_elapsed()
                phase_table.add_row(
                    f"[bold yellow]{spinner}[/bold yellow]",
                    f"[bold yellow]{desc}[/bold yellow]",
                    f"[yellow]{self._fmt_dur(elapsed)}[/yellow]",
                    f"[dim]{self.tool_count}[/dim]",
                    f"[dim]{len(self.files_read)}[/dim]",
                )
            elif status == "cached":
                phase_table.add_row(
                    "[dim]⏭[/dim]",
                    f"[dim]{desc}[/dim]",
                    "[dim]cached[/dim]",
                    "[dim]—[/dim]",
                    "[dim]—[/dim]",
                )
            else:  # pending
                phase_table.add_row(
                    "[dim]○[/dim]",
                    f"[dim]{desc}[/dim]",
                    "[dim]—[/dim]",
                    "[dim]—[/dim]",
                    "[dim]—[/dim]",
                )

        # ── Live file tree ───────────────────────────────────────────
        file_tree, omitted = self._build_file_tree()
        total_read = len(self._phase_display_files)

        # ── Overall progress bar ─────────────────────────────────────
        pct = 0
        if total_active > 0:
            base = completed / total_active
            if (
                self.current_phase
                and self._phase_status.get(self.current_phase) == "running"
            ):
                phase_pct = min(self._running_elapsed() / 90.0, 0.85)
                base = (completed + phase_pct) / total_active
            pct = min(int(base * 100), 99)
        else:
            pct = 100

        bar_w  = 38
        filled = int(bar_w * pct / 100)
        bar    = "█" * filled + "░" * (bar_w - filled)

        elapsed_total = time.time() - self._scan_start
        phase_counter = f"{completed}/{total_active} phases"

        progress_line = (
            f"  [bold cyan]{bar[:filled]}[/bold cyan][dim]{bar[filled:]}[/dim]"
            f"  [bold]{pct}%[/bold]"
            f"   [dim]Elapsed:[/dim] [cyan]{self._fmt_dur(elapsed_total)}[/cyan]"
            f"   [dim]{phase_counter} complete[/dim]"
        )

        # ── Stuck-scan warning ───────────────────────────────────────
        stale_warning = ""
        if self.current_phase and self._phase_status.get(self.current_phase) == "running":
            idle_secs = (datetime.now() - self.last_update).total_seconds()
            if idle_secs > 120:
                idle_str = self._fmt_dur(idle_secs)
                stale_warning = (
                    f"  [bold yellow]⚠️  No activity for {idle_str} — agent may be stuck. "
                    f"Press Ctrl+C then run: aisast scan . --resume-from "
                    f"{self.current_phase}[/bold yellow]"
                )

        # ── Compose panel body ───────────────────────────────────────
        outer = Table(
            box=None, show_header=False, padding=(0, 0),
            expand=True, show_edge=False,
        )
        outer.add_column("content")
        outer.add_row(phase_table)

        if file_tree:
            outer.add_row("")
            header = f"  [dim]Files analyzed: [bold cyan]{total_read}[/bold cyan]"
            if omitted:
                header += f"  [dim](showing latest {_TREE_MAX_FILES})[/dim]"
            header += "[/dim]"
            outer.add_row(header)
            outer.add_row(file_tree)

        outer.add_row("")
        outer.add_row(progress_line)
        if self._current_detail:
            outer.add_row(f"  [dim italic]{self._current_detail}[/dim italic]")
        if stale_warning:
            outer.add_row(stale_warning)

        return Panel(
            outer,
            title="[bold cyan]🛡️  AISAST Security Scan[/bold cyan]",
            border_style="cyan",
            padding=(0, 1),
        )

    # ------------------------------------------------------------------
    # Internal refresh helpers
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        if self._live:
            self._live.update(self.render())
        elif self._progress and self._detail_task is not None:
            self._progress.update(
                self._detail_task, description=f"  {self._current_detail}"
            )

    def _advance_phase(self, agent_name: str) -> None:
        """Advance the legacy Progress bar (parallel path)."""
        if self._progress and self._overall_task is not None:
            if agent_name not in self._completed_phases:
                self._completed_phases.add(agent_name)
                self._progress.advance(self._overall_task)

    # ------------------------------------------------------------------
    # SDK hook callbacks
    # ------------------------------------------------------------------

    def on_tool_start(self, tool_name: str, tool_input: dict) -> None:
        self.tool_count += 1
        if self.current_phase:
            self._phase_ops[self.current_phase] = self.tool_count
        self.last_update = datetime.now()

        if tool_name == "Read":
            file_path = tool_input.get("file_path") or tool_input.get("path") or ""
            if file_path:
                name = Path(file_path).name
                is_new = file_path not in self.files_read
                self.files_read.add(file_path)
                if self.current_phase:
                    self._phase_files[self.current_phase] = len(self.files_read)
                self._current_detail = f"Reading {name}"
                if is_new and ".aisast" not in str(file_path) and self.current_phase:
                    self._phase_display_files.append(self._display_path(file_path))
                if self.debug:
                    self.console.print(f"  📖 Reading {name}", style="dim")

        elif tool_name == "Grep":
            pattern = tool_input.get("pattern", "")
            if pattern:
                self._current_detail = f"Searching: {pattern[:60]}"
                if self.debug:
                    self.console.print(f"  🔍 Searching: {pattern[:60]}", style="dim")

        elif tool_name == "Glob":
            self._current_detail = "Finding files..."

        elif tool_name == "Write":
            file_path = tool_input.get("file_path", "")
            if file_path:
                name = Path(file_path).name
                self.files_written.add(file_path)
                self._current_detail = f"Writing {name}"
                if self.debug:
                    self.console.print(f"  💾 Writing {name}", style="bold green")

        elif tool_name == "Task":
            agent = tool_input.get("agent_name") or tool_input.get("subagent_type", "")
            if agent:
                self._current_detail = f"Launching agent: {agent}"
                self.subagent_stack.append(agent)
                self._announce_phase(agent)
                return  # _announce_phase calls _refresh

        elif tool_name == "LS":
            self._current_detail = "Listing directory"

        self._refresh()

    def _announce_phase(self, phase_name: str) -> None:
        """Mark a phase as running and reset per-phase state."""
        self.current_phase = phase_name
        self.phase_start_time = time.time()
        self.tool_count = 0
        self.files_read.clear()
        self.files_written.clear()
        self._phase_display_files = []        # reset tree for each new phase
        self._phase_ops[phase_name] = 0
        self._phase_files[phase_name] = 0

        if phase_name in self._phase_status:
            self._phase_status[phase_name] = "running"

        display = self.phase_display.get(phase_name, phase_name)
        self._current_detail = f"Phase {display} — agent running..."
        self._refresh()

        if not self._live:
            self.console.print(
                f"\n  [bold cyan]━━━ Phase {display} — Agent Running ━━━[/bold cyan]"
            )

    def on_tool_complete(
        self, tool_name: str, success: bool, error_msg: Optional[str] = None
    ) -> None:
        if not success and self.debug:
            msg = f": {error_msg[:80]}" if error_msg else ""
            self.console.print(f"  ⚠️  Tool {tool_name} failed{msg}", style="yellow")

    def on_subagent_stop(self, agent_name: str, duration_ms: int) -> None:
        if self.subagent_stack and self.subagent_stack[-1] == agent_name:
            self.subagent_stack.pop()

        duration_sec = duration_ms / 1000
        self._phase_duration[agent_name] = duration_sec
        self._phase_ops[agent_name]   = self.tool_count
        self._phase_files[agent_name] = len(self.files_read)

        if agent_name in self._phase_status:
            self._phase_status[agent_name] = "done"

        # A phase that performed zero tool calls almost certainly didn't do
        # any real work — most commonly because the session was cut short by
        # a usage/rate limit or an API error before the model could act.
        # Surface this loudly instead of silently rendering a green ✅, which
        # otherwise looks identical to a genuinely successful (if fast) run.
        if self.tool_count == 0:
            display = self.phase_display.get(agent_name, agent_name)
            self.console.print(
                f"\n  [bold yellow]⚠️  Phase {display} finished in {duration_sec:.1f}s "
                f"with 0 operations — it likely did not actually run.[/bold yellow]\n"
                f"  [dim]Common cause: Claude usage/rate limit reached, or an API "
                f"error before the agent could act. Check the message above "
                f"(e.g. \"out of extra usage\") and rerun with --debug to inspect "
                f".aisast/aisast_debug.log.[/dim]"
            )

        self._current_detail = ""
        self._refresh()

        self._advance_phase(agent_name)

        if not self._live:
            display = self.phase_display.get(agent_name, agent_name)
            expected = AGENT_ARTIFACT_MAP.get(agent_name)
            artifact_ok = expected and expected in [Path(f).name for f in self.files_written]
            status = f"✅ Created {expected}" if artifact_ok else "✅ Done"
            self.console.print(
                f"  [bold green]Phase {display} complete[/bold green]  "
                f"[dim]{duration_sec:.1f}s | {self.tool_count} ops | "
                f"{len(self.files_read)} files[/dim]  "
                f"[green]{status}[/green]"
            )

    def on_assistant_text(self, text: str) -> None:
        if self.debug and text.strip():
            preview = text[:120].replace("\n", " ")
            if len(text) > 120:
                preview += "..."
            self.console.print(f"  💭 {preview}", style="dim italic")

    def get_summary(self) -> Dict[str, Any]:
        return {
            "current_phase": self.current_phase,
            "tool_count": self.tool_count,
            "files_read": len(self.files_read),
            "files_written": len(self.files_written),
            "subagent_depth": len(self.subagent_stack),
        }
