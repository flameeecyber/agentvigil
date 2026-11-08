"""Provenance timeline: who taught the agent this, and when.

Static scanners answer "is this evil now". Reviewers ask "did we approve
this". `vigil blame` answers the second question with git: for each finding,
the commit, author, date and message that introduced the exact lines.

Design: subprocess to git only, read-only commands (`blame --porcelain`,
`log -1`). Outside a git repo, or when git is missing, every lookup returns
`unknown` instead of failing — scanning must never depend on history.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from subprocess import CalledProcessError
import subprocess
from typing import Dict, List, Optional, Sequence

from .findings import Finding


@dataclass
class Blame:
    path: str
    line: int
    commit: str
    author: str
    date: str
    summary: str

    def to_dict(self) -> Dict[str, str]:
        return {"path": self.path, "line": str(self.line), "commit": self.commit,
                "author": self.author, "date": self.date, "summary": self.summary}

    @property
    def known(self) -> bool:
        return self.commit not in ("unknown", "")


def _git(root: Path, *args: str, timeout: int = 10) -> Optional[str]:
    try:
        out = subprocess.run(["git", *args], cwd=str(root), capture_output=True,
                             text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    return out.stdout


def blame_line(root: Path, rel_path: str, line: int) -> Blame:
    unknown = Blame(path=rel_path, line=line, commit="unknown",
                    author="unknown", date="", summary="")
    porcelain = _git(root, "blame", "--porcelain", "-L", f"{line},{line}", "--", rel_path)
    if not porcelain:
        return unknown
    commit = ""
    author = "unknown"
    author_time = ""
    for raw in porcelain.splitlines():
        if raw.startswith("\t"):
            continue
        if len(raw) >= 40 and all(c in "0123456789abcdef" for c in raw[:40]):
            commit = raw[:40]
        elif raw.startswith("author "):
            author = raw[len("author "):].strip() or "unknown"
        elif raw.startswith("author-time "):
            author_time = raw[len("author-time "):].strip()
    if not commit or commit.startswith("0000000"):
        return unknown
    summary = ""
    log = _git(root, "log", "-1", "--format=%s|%ad", "--date=short", commit)
    if log:
        summary = log.strip().split("|")[0][:120]
        if "|" in log.strip() and not author_time:
            pass
    date = ""
    if log and "|" in log:
        date = log.strip().split("|", 1)[1][:20]
    return Blame(path=rel_path, line=line, commit=commit[:12], author=author,
                 date=date or author_time, summary=summary)


def staged_paths(root: Path) -> List[str] | None:
    """Repo-relative staged paths, or None when not a git repo / git missing."""
    try:
        out = subprocess.run(["git", "diff", "--name-only", "--cached", "-z"],
                             cwd=str(root), capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    raw = out.stdout.decode("utf-8", errors="replace")
    return [p for p in raw.split("\x00") if p]


def annotate(root: Path, findings: Sequence[Finding]) -> List[Blame]:
    """Blame each distinct (path, line). One git call per location, cached."""
    seen: Dict[tuple, Blame] = {}
    out: List[Blame] = []
    for f in findings:
        key = (f.path, f.line)
        if key not in seen:
            seen[key] = blame_line(root, f.path, f.line)
        out.append(seen[key])
    return out
