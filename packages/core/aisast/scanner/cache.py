"""Artifact cache management for AISAST scanner.

Stores a SHA-256 hash of all source files after each phase completes.
On the next run, if the hash matches the current repo state AND the
artifact file exists on disk, that phase is skipped entirely.
"""

import hashlib
import json
from pathlib import Path
from typing import List, Set

CACHE_FILE = "cache_state.json"

# Maps phase name -> artifact it creates
PHASE_ARTIFACTS = {
    "assessment": "SECURITY.md",
    "threat-modeling": "THREAT_MODEL.json",
    "code-review": "VULNERABILITIES.json",
    "report-generator": "scan_results.json",
}

# Each phase depends on all previous phases being valid too
PHASE_DEPENDENCIES = {
    "assessment": [],
    "threat-modeling": ["assessment"],
    "code-review": ["assessment", "threat-modeling"],
    "report-generator": ["assessment", "threat-modeling", "code-review"],
}


def compute_repo_hash(repo: Path, extensions: Set[str], excluded_dirs: Set[str]) -> str:
    """Compute a stable SHA-256 hash over all source files in the repo."""
    hasher = hashlib.sha256()
    try:
        files = sorted(
            f for f in repo.rglob("*")
            if f.is_file()
            and f.suffix.lower() in extensions
            and not any(part in excluded_dirs for part in f.parts)
            and CACHE_FILE not in str(f)
        )
        for f in files:
            try:
                rel = str(f.relative_to(repo))
                hasher.update(rel.encode("utf-8"))
                hasher.update(f.read_bytes())
            except (OSError, PermissionError):
                continue
    except (OSError, PermissionError):
        pass
    return hasher.hexdigest()


def _read(aisast_dir: Path) -> dict:
    path = aisast_dir / CACHE_FILE
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _write(aisast_dir: Path, cache: dict) -> None:
    try:
        (aisast_dir / CACHE_FILE).write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except OSError:
        pass


def get_phases_to_skip(aisast_dir: Path, repo_hash: str) -> List[str]:
    """Return phases whose artifacts are up-to-date and can be safely skipped."""
    cache = _read(aisast_dir)
    skip = []
    for phase, artifact in PHASE_ARTIFACTS.items():
        artifact_path = aisast_dir / artifact
        if not artifact_path.exists():
            continue
        if cache.get(f"{phase}_hash") != repo_hash:
            continue
        deps_ok = all(
            cache.get(f"{dep}_hash") == repo_hash
            for dep in PHASE_DEPENDENCIES[phase]
        )
        if deps_ok:
            skip.append(phase)
    return skip


def update_phase_cache(aisast_dir: Path, phase: str, repo_hash: str) -> None:
    """Record that a phase completed successfully with the current repo hash."""
    cache = _read(aisast_dir)
    cache[f"{phase}_hash"] = repo_hash
    _write(aisast_dir, cache)


def invalidate_cache(aisast_dir: Path) -> None:
    """Wipe all cached hashes (forces a full re-scan next run)."""
    _write(aisast_dir, {})
