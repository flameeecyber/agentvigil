"""Detector registry. Each detector is a pure function of a SurfaceFile."""

from __future__ import annotations

from typing import Callable, List, Sequence

from ..findings import Finding
from ..surface import SurfaceFile
from . import entropy, mcp, multimodal, patterns, refs, unicode

Detector = Callable[[SurfaceFile], List[Finding]]

REGISTRY: Sequence[Detector] = (
    unicode.scan,
    patterns.scan,
    entropy.scan,
    mcp.scan,
    multimodal.scan,
    refs.scan,
)

# Noisy by design: fire only under `--strict`. Default stays precision-first.
# Rationale documented in docs/decisions.md: one FP complaint costs more than
# one missed LOW. Strict surfaces them for auditors.
STRICT_ONLY = frozenset(
    {
        "AV-AUTO-001",  # unconditional autonomy trigger (LOW, often docs prose)
        "AV-NET-001",  # plaintext HTTP (LOW, often example URLs)
        "AV-IMG-005",  # remote image alone (LOW without delegation prose)
        "AV-MCP-000",  # unparseable config (LOW, needs human look)
        "AV-MCP-010",  # no recognizable server block (INFO)
        "AV-UNI-004",  # ANSI escapes (LOW, often colored CLI help)
    }
)


def scan_file(file: SurfaceFile) -> List[Finding]:
    findings: List[Finding] = []
    for detector in REGISTRY:
        findings.extend(detector(file))
    return findings


def _filter_tier(findings: List[Finding], strict: bool) -> List[Finding]:
    if strict:
        return findings
    return [f for f in findings if f.rule_id not in STRICT_ONLY]


def scan_files(files: Sequence[SurfaceFile], *, strict: bool = False) -> List[Finding]:
    # Parallel only when it pays (large repos); keeps tiny scans deterministic.
    if len(files) >= 32:
        from concurrent.futures import ThreadPoolExecutor

        findings: List[Finding] = []
        with ThreadPoolExecutor(max_workers=8) as pool:
            for out in pool.map(scan_file, files):
                findings.extend(out)
        return _filter_tier(findings, strict)
    findings = []
    for file in files:
        findings.extend(scan_file(file))
    return _filter_tier(findings, strict)
