"""Delta detection — find source files changed since the last AISAST scan."""

import subprocess
from pathlib import Path
from typing import List, Optional, Set


def detect_changed_files(
    repo: Path,
    aisast_dir: Path,
    extensions: Set[str],
    excluded_dirs: Set[str],
) -> List[str]:
    """
    Return relative paths of source files changed since the last scan.
    Tries git first, falls back to mtime comparison against cache file.
    """
    git_result = _git_changed(repo, extensions, excluded_dirs)
    if git_result is not None:
        return git_result
    return _mtime_changed(repo, aisast_dir, extensions, excluded_dirs)


def _git_changed(
    repo: Path,
    extensions: Set[str],
    excluded_dirs: Set[str],
) -> Optional[List[str]]:
    """Return modified + untracked source files via git status, or None if git unavailable."""
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None

    changed: List[str] = []
    for line in result.stdout.splitlines():
        if len(line) < 4:
            continue
        raw = line[3:].strip().strip('"')
        if " -> " in raw:
            raw = raw.split(" -> ")[-1]
        p = Path(raw)
        if p.suffix.lower() in extensions and not any(
            part in excluded_dirs for part in p.parts
        ):
            changed.append(raw)
    return changed


def _mtime_changed(
    repo: Path,
    aisast_dir: Path,
    extensions: Set[str],
    excluded_dirs: Set[str],
) -> List[str]:
    """Return source files with mtime newer than the cache file."""
    cache_file = aisast_dir / "cache_state.json"
    if not cache_file.exists():
        return []

    cache_mtime = cache_file.stat().st_mtime
    changed: List[str] = []
    try:
        for f in repo.rglob("*"):
            if not f.is_file():
                continue
            if f.suffix.lower() not in extensions:
                continue
            if any(part in excluded_dirs for part in f.parts):
                continue
            try:
                if f.stat().st_mtime > cache_mtime:
                    changed.append(str(f.relative_to(repo)))
            except OSError:
                continue
    except (OSError, PermissionError):
        pass
    return changed
