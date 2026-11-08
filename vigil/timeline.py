"""Time-travel: what did the agent's instructions look like at each commit?

`vigil timeline . --max 20` walks recent git history (read-only), scans the
instruction surface at each commit via `git show`, and reports trust over
time. The commit where the score collapses is the rug pull — blame tells
you who, timeline tells you when.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .detectors import scan_files
from .findings import Finding
from .score import score
from .surface import SurfaceFile, discover


@dataclass
class Point:
    commit: str
    date: str
    files: int
    findings: int
    trust: int
    grade: str


def _git(root: Path, *args: str, timeout: int = 20) -> Optional[str]:
    try:
        out = subprocess.run(["git", *args], cwd=str(root), capture_output=True,
                             text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout if out.returncode == 0 else None


def _surface_at(root: Path, commit: str, paths: List[str]) -> List[SurfaceFile]:
    files: List[SurfaceFile] = []
    for rel in paths:
        blob = _git(root, "show", f"{commit}:{rel}")
        if blob is None:
            continue
        # git show decodes bytes as text; re-encode for SurfaceFile
        files.append(SurfaceFile(path=rel, kind="agent_rules", data=blob.encode("utf-8", "replace")))
    return files


def timeline(root: Path, max_commits: int = 20) -> List[Point]:
    root = root.resolve()
    log = _git(root, "log", f"-n{max_commits}", "--format=%H|%ad", "--date=short", "--", ".")
    if not log:
        return []
    # Classify current paths once; history reuses the same inventory.
    current = [f.path for f in discover(root)] or ["AGENTS.md"]
    points: List[Point] = []
    for line in log.strip().splitlines():
        commit, _, date = line.partition("|")
        files = _surface_at(root, commit, current)
        findings: List[Finding] = sorted(scan_files(files), key=lambda f: f.sort_key())
        value, grade, _ = score(findings)
        points.append(Point(commit[:12], date, len(files), len(findings), value, grade))
    return points
