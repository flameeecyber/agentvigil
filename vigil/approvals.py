"""Approvals: suppression with memory, not `# noqa`.

`vigil approve` records that a human accepted a capability (e.g. the Makefile
needs `exec.shell`) with reviewer + reason + timestamp inside `vigil.lock`.
`vigil diff` then allows that capability and still blocks everything new.

This is the honest answer to false positives: explicit, reviewable, versioned.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence

from . import manifest as manifest_mod
from .detectors import scan_files
from .findings import Finding
from .surface import discover


def current_capabilities(root: Path) -> Dict[str, List[str]]:
    files = discover(root)
    findings = scan_files(files)
    per_file: Dict[str, set] = {}
    for f in findings:
        per_file.setdefault(f.path, set()).update(f.capabilities)
    return {k: sorted(v) for k, v in per_file.items()}


def approve(root: Path, by: str, reason: str,
            lock_path: Path | None = None) -> Dict[str, Any]:
    root = root.resolve()
    lock_file = Path(lock_path) if lock_path else root / manifest_mod.LOCK_NAME
    if lock_file.exists():
        lock = manifest_mod.load_lock(lock_file)
    else:
        files = discover(root)
        lock = manifest_mod.build_lock(files, scan_files(files), root)
        lock["signature"] = None
    caps = current_capabilities(root)
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    approvals: List[Dict[str, Any]] = list(lock.get("approvals", []))
    for path, capabilities in caps.items():
        for cap in capabilities:
            if any(a.get("path") == path and a.get("capability") == cap for a in approvals):
                continue
            approvals.append({"path": path, "capability": cap,
                              "by": by, "reason": reason, "at": now})
    lock["approvals"] = sorted(approvals, key=lambda a: (a["path"], a["capability"]))
    manifest_mod.write_lock(lock_file, lock)
    return {"lock": str(lock_file), "approved": len(approvals), "by": by}


def is_approved(lock: Dict[str, Any], path: str, capability: str) -> bool:
    for a in lock.get("approvals", []):
        if a.get("capability") != capability:
            continue
        if a.get("path") in (path, "*"):
            return True
    return False


def filter_approved(findings: Sequence[Finding], lock: Dict[str, Any]) -> List[Finding]:
    """Findings whose every capability is approved are informational, not blocking."""
    out = []
    for f in findings:
        if f.capabilities and all(is_approved(lock, f.path, c) for c in f.capabilities):
            continue
        out.append(f)
    return out
