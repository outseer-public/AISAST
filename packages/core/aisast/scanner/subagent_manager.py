"""Sub-agent execution manager with artifact detection and dependency resolution"""

import json
from pathlib import Path
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

import click
from rich.console import Console
from rich.table import Table

console = Console()


class ScanMode(Enum):
    USE_EXISTING = "use_existing"
    FULL_RESCAN = "full_rescan"
    CANCEL = "cancel"


@dataclass
class ArtifactStatus:
    exists: bool
    path: Optional[Path] = None
    valid: bool = False
    age_hours: Optional[float] = None
    size_bytes: Optional[int] = None
    issue_count: Optional[int] = None
    error: Optional[str] = None


SUBAGENT_ARTIFACTS = {
    "assessment": {
        "creates": "SECURITY.md",
        "requires": None,
        "description": "Architecture analysis and security documentation",
    },
    "threat-modeling": {
        "creates": "THREAT_MODEL.json",
        "requires": "SECURITY.md",
        "description": "STRIDE threat analysis",
    },
    "threat-model-diagram": {
        "creates": "THREAT_MODEL_DIAGRAM.md",
        "requires": "THREAT_MODEL.json",
        "description": "Visual ASCII threat model diagram",
    },
    "code-review": {
        "creates": "VULNERABILITIES.json",
        "requires": "THREAT_MODEL.json",
        "description": "Security vulnerability detection",
    },
    "report-generator": {
        "creates": "scan_results.json",
        "requires": "VULNERABILITIES.json",
        "description": "Consolidated scan report",
    },
    "lwra": {
        "creates": "LWRA_REPORT.json",
        "requires": "scan_results.json",
        "description": "Risk adjustment, soft fixes, and code patches",
    },
}

SUBAGENT_ORDER = ["assessment", "threat-modeling", "threat-model-diagram", "code-review", "report-generator", "lwra"]


class SubAgentManager:
    """Manages sub-agent execution, artifact detection, and dependencies"""

    def __init__(self, repo_path: Path, quiet: bool = False):
        self.repo_path = repo_path
        self.aisast_dir = repo_path / ".aisast"
        self.quiet = quiet

    def check_artifact(self, filename: str) -> ArtifactStatus:
        artifact_path = self.aisast_dir / filename

        if not artifact_path.exists():
            return ArtifactStatus(exists=False)

        mtime = artifact_path.stat().st_mtime
        age_hours = (datetime.now() - datetime.fromtimestamp(mtime)).total_seconds() / 3600
        size_bytes = artifact_path.stat().st_size
        valid = True
        issue_count = None
        error = None

        if filename.endswith(".json"):
            try:
                data = json.loads(artifact_path.read_text(encoding="utf-8"))
                if filename == "VULNERABILITIES.json":
                    if isinstance(data, list):
                        issue_count = len(data)
                elif filename == "scan_results.json":
                    if isinstance(data, dict) and "issues" in data:
                        issue_count = len(data["issues"])
            except json.JSONDecodeError as e:
                valid = False
                error = f"Invalid JSON: {e}"
        elif filename.endswith(".md"):
            if not artifact_path.read_text(encoding="utf-8").strip():
                valid = False
                error = "Empty file"

        return ArtifactStatus(
            exists=True,
            path=artifact_path,
            valid=valid,
            age_hours=age_hours,
            size_bytes=size_bytes,
            issue_count=issue_count,
            error=error,
        )

    def get_subagent_dependencies(self, subagent: str) -> Dict[str, Optional[str]]:
        if subagent not in SUBAGENT_ARTIFACTS:
            raise ValueError(f"Unknown sub-agent: {subagent}")
        return {
            "creates": SUBAGENT_ARTIFACTS[subagent]["creates"],
            "requires": SUBAGENT_ARTIFACTS[subagent]["requires"],
        }

    def get_resume_subagents(self, from_subagent: str) -> List[str]:
        if from_subagent not in SUBAGENT_ORDER:
            raise ValueError(f"Unknown sub-agent: {from_subagent}")
        return SUBAGENT_ORDER[SUBAGENT_ORDER.index(from_subagent):]

    def validate_prerequisites(self, subagent: str) -> Tuple[bool, Optional[str]]:
        deps = self.get_subagent_dependencies(subagent)
        required = deps["requires"]
        if required is None:
            return True, None
        status = self.check_artifact(required)
        if not status.exists:
            return False, f"Missing prerequisite: {required}"
        if not status.valid:
            return False, f"Invalid prerequisite {required}: {status.error}"
        return True, None

    def prompt_user_choice(
        self, subagent: str, artifact_status: ArtifactStatus, force: bool = False
    ) -> ScanMode:
        if force:
            return ScanMode.USE_EXISTING

        deps = self.get_subagent_dependencies(subagent)
        required = deps["requires"]

        console.print(f"\n🔍 Checking prerequisites for '{subagent}' sub-agent...")

        if artifact_status.exists and artifact_status.valid:
            age_str = self._format_age(artifact_status.age_hours)
            console.print(
                f"✓ Found: .aisast/{required} (modified: {age_str}", style="green", end=""
            )
            if artifact_status.issue_count is not None:
                console.print(f", {artifact_status.issue_count} issues)", style="green")
            else:
                console.print(")", style="green")

            if artifact_status.age_hours and artifact_status.age_hours > 24:
                console.print(
                    f"  ⚠️  Warning: Artifact is {int(artifact_status.age_hours)}h old",
                    style="yellow",
                )

        console.print(f"\n⚠️  Re-running {subagent} will overwrite existing results.\n")
        console.print("Options:")
        console.print(f"  1. Use existing {required} and run {subagent} only [default]")
        console.print("  2. Re-run entire scan (all sub-agents)")
        console.print("  3. Cancel")

        choice = click.prompt("\nChoice", type=int, default=1, show_default=False)

        if choice == 1:
            return ScanMode.USE_EXISTING
        elif choice == 2:
            return ScanMode.FULL_RESCAN
        else:
            return ScanMode.CANCEL

    def display_artifact_summary(self, artifact_status: ArtifactStatus, filename: str) -> None:
        if not artifact_status.exists:
            return

        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Property", style="dim")
        table.add_column("Value")
        table.add_row("File", filename)
        table.add_row("Status", "✓ Valid" if artifact_status.valid else "❌ Invalid")
        if artifact_status.age_hours is not None:
            table.add_row("Age", self._format_age(artifact_status.age_hours))
        if artifact_status.size_bytes is not None:
            table.add_row("Size", self._format_size(artifact_status.size_bytes))
        if artifact_status.issue_count is not None:
            table.add_row("Issues", str(artifact_status.issue_count))
        if artifact_status.error:
            table.add_row("Error", artifact_status.error)
        console.print(table)

    def _format_age(self, hours: float) -> str:
        if hours < 1:
            return f"{int(hours * 60)}m ago"
        elif hours < 24:
            return f"{int(hours)}h ago"
        return f"{int(hours / 24)}d ago"

    def _format_size(self, bytes_: int) -> str:
        if bytes_ < 1024:
            return f"{bytes_}B"
        elif bytes_ < 1024 * 1024:
            return f"{bytes_ / 1024:.1f}KB"
        return f"{bytes_ / (1024 * 1024):.1f}MB"
