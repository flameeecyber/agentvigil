"""Rug-pull detection: what will my agent be told *now* that it wasn't before?

Static scanners answer "is this file evil?" once. The interesting question is
what changed since a human approved the surface. `vigil diff` compares the pinned
lockfile against the working tree and reports file changes, new findings, and
the capability delta ("this PR gives the agent exec.shell").
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .detectors import scan_files
from .findings import Finding, Severity, cap_names, severity_at_least
from .manifest import build_lock, load_lock, verify_lock
from .surface import BINARY_SUFFIXES, MAX_FILE_BYTES, SurfaceFile, _classify, discover

# Capabilities that change what the agent can *do*, not just what it knows.
ESCALATING = {
    "exec.shell",
    "exec.download",
    "net.egress",
    "data.exfil",
    "fs.credentials",
    "fs.write",
    "approval.bypass",
    "agent.self_modify",
    "persistence",
    "tool.spoof",
    "mcp.untrusted",
}


@dataclass
class FileDelta:
    path: str
    status: str  # added | modified | removed
    added_capabilities: Tuple[str, ...] = ()
    removed_capabilities: Tuple[str, ...] = ()
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status,
            "added_capabilities": list(self.added_capabilities),
            "removed_capabilities": list(self.removed_capabilities),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class SurfaceDiff:
    deltas: List[FileDelta] = field(default_factory=list)
    added_capabilities: Tuple[str, ...] = ()
    removed_capabilities: Tuple[str, ...] = ()
    blocking: bool = False
    reason: str = ""

    @property
    def changed(self) -> bool:
        return bool(self.deltas)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "changed": self.changed,
            "blocking": self.blocking,
            "reason": self.reason,
            "added_capabilities": list(self.added_capabilities),
            "removed_capabilities": list(self.removed_capabilities),
            "files": [d.to_dict() for d in self.deltas],
        }


def _caps_from_findings(findings: Sequence[Finding]) -> Set[str]:
    caps: Set[str] = set()
    for finding in findings:
        caps.update(finding.capabilities)
    return caps


def diff_surface(
    root: Path,
    lock: Dict[str, Any],
    *,
    fail_on: Severity = Severity.HIGH,
    strict: bool = False,
) -> SurfaceDiff:
    root = Path(root)
    verification = verify_lock(root, lock)
    current = {f.path: f for f in discover(root)}
    locked = {e["path"]: e for e in lock.get("files", [])}

    changed_files: List[SurfaceFile] = []
    result = SurfaceDiff()

    for path in verification["added"]:
        changed_files.append(current[path])
        result.deltas.append(FileDelta(path=path, status="added"))
    for path in verification["removed"]:
        entry = locked[path]
        result.deltas.append(
            FileDelta(
                path=path,
                status="removed",
                removed_capabilities=tuple(entry.get("capabilities", [])),
            )
        )
    for path in verification["modified"]:
        changed_files.append(current[path])
        result.deltas.append(FileDelta(path=path, status="modified"))

    fresh = scan_files(changed_files, strict=strict)
    by_path: Dict[str, List[Finding]] = {}
    for finding in fresh:
        by_path.setdefault(finding.path, []).append(finding)

    added_all: Set[str] = set()
    for delta in result.deltas:
        old_caps = set(locked.get(delta.path, {}).get("capabilities", []))
        new_caps = _caps_from_findings(by_path.get(delta.path, []))
        if delta.status == "removed":
            delta.added_capabilities = ()
            delta.removed_capabilities = tuple(
                sorted(old_caps | set(delta.removed_capabilities))
            )
        else:
            delta.added_capabilities = tuple(sorted(new_caps - old_caps))
            delta.removed_capabilities = tuple(sorted(old_caps - new_caps))
            added_all.update(delta.added_capabilities)
        delta.findings = sorted(by_path.get(delta.path, []), key=lambda f: f.sort_key())

    result.added_capabilities = tuple(sorted(added_all))
    result.removed_capabilities = tuple(
        sorted({cap for d in result.deltas for cap in d.removed_capabilities})
    )

    serious = [f for f in fresh if severity_at_least(f.severity, fail_on)]
    escalating = sorted(added_all & ESCALATING)
    cap_note = f" New capability: {', '.join(escalating)}." if escalating else ""
    if serious:
        result.blocking = True
        worst = max(serious, key=lambda f: f.severity.rank)
        result.reason = (
            f"{len(serious)} new finding(s) at or above {fail_on.value}; "
            f"worst is {worst.rule_id} in {worst.path}:{worst.line}.{cap_note}"
        )
    elif escalating:
        result.blocking = True
        result.reason = "instruction surface gains capability: " + ", ".join(escalating)
    elif result.changed:
        result.reason = "instruction surface changed; capabilities are unchanged"
    else:
        result.reason = "no change since the lock"

    return result


def build_lock_at_ref(root: Path, ref: str, *, strict: bool = False) -> Dict[str, Any]:
    """Materialize a virtual `vigil.lock` from a git ref (`main`, `HEAD~1`, tag, SHA).

    Allows `vigil diff --base main` to work on any repository in CI before a
    `vigil.lock` file has ever been committed. Read-only git calls only.
    """
    root = Path(root).resolve()
    try:
        ls = subprocess.run(
            ["git", "--no-pager", "ls-tree", "-r", "--name-only", ref],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"git ls-tree failed for ref {ref!r}: {exc}") from exc
    if ls.returncode != 0:
        err = (ls.stderr or "").strip() or f"unknown git ref {ref!r}"
        raise ValueError(f"cannot read git ref {ref!r}: {err}")

    base_files: List[SurfaceFile] = []
    for raw_line in ls.stdout.splitlines():
        rel = raw_line.strip()
        if not rel:
            continue
        suffix = Path(rel).suffix.lower()
        if suffix in BINARY_SUFFIXES:
            continue
        kind = _classify(rel)
        if kind is None:
            continue
        try:
            show = subprocess.run(
                ["git", "--no-pager", "show", f"{ref}:{rel}"],
                cwd=str(root),
                capture_output=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if show.returncode != 0 or len(show.stdout) > MAX_FILE_BYTES:
            continue
        base_files.append(SurfaceFile(path=rel, kind=kind, data=show.stdout))

    base_files.sort(key=lambda f: f.path)
    base_findings = scan_files(base_files, strict=strict)
    lock = build_lock(base_files, base_findings, root)
    lock["ref"] = ref
    return lock
