"""Instruction-surface SBOM: enterprises already understand SBOMs.

`vigil sbom .` emits a CycloneDX-inspired JSON inventory of every file that
programs the agent (path, kind, sha256, capabilities, trust verdict). Feed it
to existing asset pipelines — no new vocabulary for buyers to learn.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .detectors import scan_files
from .findings import Finding
from .score import score
from .surface import SurfaceFile, discover


def build(root: Path, strict: bool = False) -> Dict[str, Any]:
    from . import chain as chain_engine

    files: List[SurfaceFile] = discover(root)
    findings: List[Finding] = sorted(scan_files(files, strict=strict),
                                    key=lambda f: f.sort_key())
    findings += sorted(chain_engine.correlate(files, findings), key=lambda f: f.sort_key())
    value, grade, verdict = score(findings)
    per_file: Dict[str, List[str]] = {}
    for f in findings:
        per_file.setdefault(f.path, sorted(set(per_file.get(f.path, [])) | set(f.capabilities)))
    components = [{"bom-ref": s.path, "name": s.path, "type": "instruction",
                   "kind": s.kind, "hashes": [{"alg": "SHA-256", "content": s.sha256}],
                   "capabilities": per_file.get(s.path, [])} for s in files]
    return {"bomFormat": "agentvigil-sbom", "specVersion": "1",
            "source": str(root), "trust": {"score": value, "grade": grade, "verdict": verdict},
            "components": components,
            "vulnerabilities": [f.to_dict() for f in findings]}


def dumps(root: Path, strict: bool = False) -> str:
    return json.dumps(build(root, strict=strict), indent=2) + "\n"
