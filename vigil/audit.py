"""Multi-repo audit: one table for every repo under a directory.

`vigil audit ~/code --format markdown` walks immediate subdirectories, scans
each instruction surface, and rolls up trust score + worst finding. Used by
platform teams and as the SecureOrch lead-gen funnel ("here are your 5 worst
repos"). Never recurses into nested checkouts; skips dirs with no surface.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Sequence

from .detectors import scan_files
from .findings import Finding
from .score import score
from .surface import SurfaceFile, discover


@dataclass
class RepoResult:
    name: str
    files: List[SurfaceFile]
    findings: List[Finding]
    value: int
    grade: str
    verdict: str

    def to_dict(self) -> Dict[str, Any]:
        worst = max(self.findings, key=lambda f: f.severity.rank, default=None)
        return {"repo": self.name, "files": len(self.files),
                "findings": len(self.findings), "trust": self.value,
                "grade": self.grade, "verdict": self.verdict,
                "worst": worst.rule_id if worst else None}


def audit(root: Path, max_repos: int = 50) -> List[RepoResult]:
    root = root.resolve()
    out: List[RepoResult] = []
    candidates = sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith("."))[:max_repos]
    for repo in candidates:
        try:
            files = discover(repo)
        except OSError:
            continue
        if not files:
            continue
        findings = sorted(scan_files(files), key=lambda f: f.sort_key())
        value, grade, verdict = score(findings)
        out.append(RepoResult(repo.name, files, findings, value, grade, verdict))
    return sorted(out, key=lambda r: r.value)


def as_markdown(results: Sequence[RepoResult]) -> str:
    lines = ["### agentvigil audit", "", "| repo | trust | findings | worst |",
             "|---|---|---|---|"]
    for r in results:
        worst = max(r.findings, key=lambda f: f.severity.rank, default=None)
        lines.append(f"| {r.name} | {r.value}/100 {r.grade} | {len(r.findings)} | "
                     f"{worst.rule_id if worst else '—'} |")
    return "\n".join(lines) + "\n"


def as_json(results: Sequence[RepoResult]) -> str:
    return json.dumps([r.to_dict() for r in results], indent=2) + "\n"
