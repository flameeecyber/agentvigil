"""Rendering: terminal (humans), JSON (pipelines), SARIF (GitHub), Markdown (PR comments)."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence, TextIO

from .findings import Finding, Severity, summarize
from .redact import redact
from .score import breakdown, score
from .surface import KIND_LABELS, SurfaceFile, kinds_summary

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
RED = "\x1b[31m"
BRIGHT_RED = "\x1b[91m"
YELLOW = "\x1b[33m"
BLUE = "\x1b[34m"
GREEN = "\x1b[32m"
MAGENTA = "\x1b[35m"
CYAN = "\x1b[36m"

SEV_COLOR = {
    Severity.CRITICAL: BRIGHT_RED,
    Severity.HIGH: RED,
    Severity.MEDIUM: YELLOW,
    Severity.LOW: BLUE,
    Severity.INFO: DIM,
}


def _supports_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _paint(text: str, color: str, enabled: bool) -> str:
    return f"{color}{text}{RESET}" if enabled else text


def terminal(findings: Sequence[Finding], files: Sequence[SurfaceFile],
             stream: TextIO = sys.stdout, color: Optional[bool] = None,
             verbose: bool = False) -> None:
    color = _supports_color(stream) if color is None else color
    out = stream.write

    value, grade, verdict = score(findings)
    bar_len = 24
    filled = int(round(bar_len * value / 100))
    bar_color = GREEN if value >= 90 else (YELLOW if value >= 50 else RED)
    bar = _paint("█" * filled, bar_color, color) + _paint("░" * (bar_len - filled), DIM, color)

    out("\n")
    out(_paint("agentvigil", BOLD, color) + _paint("  ·  instruction-surface audit", DIM, color) + "\n")
    counts = kinds_summary(files)
    detail = ", ".join(f"{v} {KIND_LABELS.get(k, k)}" for k, v in sorted(counts.items()))
    out(_paint(f"  surface: {len(files)} file(s)" + (f" — {detail}" if detail else ""), DIM, color) + "\n\n")
    out(f"  trust  {bar}  {_paint(str(value), BOLD, color)}/100  "
        f"grade {_paint(grade, BOLD, color)} ({verdict})\n")

    if not findings:
        out("\n  " + _paint("no findings — the surface is clean.", GREEN, color) + "\n\n")
        return

    counts = summarize(findings)
    out("  findings  " + "  ".join(
        f"{_paint(str(counts[s.value]), SEV_COLOR[s], color)} {s.value}"
        for s in Severity if counts[s.value]
    ) + "\n\n")

    current_path = ""
    # Group by file for humans; severity still breaks ties inside a file.
    for finding in sorted(findings, key=lambda f: (f.path, -f.severity.rank, f.line)):
        if finding.path != current_path:
            current_path = finding.path
            out(f"  {_paint(current_path, CYAN, color)}\n")
        sev = _paint(f"[{finding.severity.value:^8}]", SEV_COLOR[finding.severity], color)
        out(f"    {sev} {finding.title}  {_paint(f'{finding.rule_id}  {finding.path}:{finding.line}:{finding.column}', DIM, color)}\n")
        out(f"             {finding.message}\n")
        if finding.evidence:
            out(f"             {_paint('evidence', DIM, color)}  {redact(finding.evidence)[:160]}\n")
        if finding.decoded:
            payload = redact(finding.decoded).replace("\n", " ⏎ ")
            out(f"             {_paint('decoded', MAGENTA, color)}   {payload[:200]}\n")
        if finding.capabilities:
            out(f"             {_paint('grants', DIM, color)}    {', '.join(finding.capabilities)}\n")
        if verbose and finding.remediation:
            out(f"             {_paint('fix', GREEN, color)}       {finding.remediation}\n")
        if verbose and finding.technique:
            out(f"             {_paint('technique', DIM, color)} {finding.technique}\n")
        out("\n")

    caps = breakdown(findings)
    if caps:
        out("  capabilities granted by this surface\n")
        for cap, weight in caps.items():
            out(f"    {cap:<18} {_paint(f'penalty {weight}', DIM, color)}\n")
        out("\n")

    out(_paint("  next: ", DIM, color)
        + "vigil manifest . -o vigil.lock  ·  vigil diff vigil.lock  ·  vigil scan . --sarif\n\n")


def as_markdown(findings: Sequence[Finding], files: Sequence[SurfaceFile]) -> str:
    """One-comment PR body: trust score + worst 10 findings + next step."""
    value, grade, verdict = score(findings)
    lines = [f"### agentvigil — trust {value}/100 (grade {grade}, {verdict})",
               f"Surface: {len(files)} file(s). Findings: {len(findings)}.", ""]
    if not findings:
        lines.append("No findings at or above the threshold. :white_check_mark:")
        return "\n".join(lines) + "\n"
    lines.append("| severity | rule | file | grants |")
    lines.append("|---|---|---|---|")
    for f in sorted(findings, key=lambda x: x.sort_key())[:10]:
        caps = ", ".join(f.capabilities) if f.capabilities else "—"
        lines.append(f"| {f.severity.value} | {f.rule_id} | {f.path}:{f.line} | {caps} |")
    if len(findings) > 10:
        lines.append(f"\n…and {len(findings) - 10} more. Run `vigil scan .` for the full list.")
    worst = max(findings, key=lambda x: x.severity.rank)
    lines.append(f"\nWorst: **{worst.rule_id}** in `{worst.path}:{worst.line}` — {worst.message}")
    if worst.decoded:
        lines.append(f"> decoded: `{redact(worst.decoded)[:160]}`")
    return "\n".join(lines) + "\n"


def as_diff_markdown(deltas: Sequence[Any], added_caps: Sequence[str], blocking: bool, reason: str) -> str:
    icon = ":rotating_light:" if blocking else ":white_check_mark:"
    lines = [f"{icon} agentvigil diff — {'BLOCKED' if blocking else 'allowed'}", ""]
    if added_caps:
        lines.append(f"New capability: `{', '.join(added_caps)}`")
        lines.append("")
    for d in deltas[:10]:
        caps = f" (+{', '.join(d.added_capabilities)})" if d.added_capabilities else ""
        lines.append(f"- `{d.status}` `{d.path}`{caps}")
        for f in d.findings[:3]:
            lines.append(f"  - {f.severity.value} {f.rule_id}: {f.message[:120]}")
    lines.append(f"\n{reason}")
    return "\n".join(lines) + "\n"


def as_json(findings: Sequence[Finding], files: Sequence[SurfaceFile],
           duration_ms: int | None = None) -> str:
    value, grade, verdict = score(findings)
    safe = []
    for f in sorted(findings, key=lambda x: x.sort_key()):
        d = f.to_dict()
        d["evidence"] = redact(d.get("evidence", ""))
        if d.get("decoded"):
            d["decoded"] = redact(d["decoded"])
        safe.append(d)
    payload = {
        "tool": "agentvigil",
        "trust": {"score": value, "grade": grade, "verdict": verdict,
                   **({"duration_ms": duration_ms} if duration_ms is not None else {})},
        "surface": [
            {"path": f.path, "kind": f.kind, "size": f.size, "sha256": f.sha256}
            for f in files
        ],
        "findings": safe,
    }
    return json.dumps(payload, indent=2) + "\n"


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def as_sarif(findings: Sequence[Finding]) -> str:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for finding in sorted(findings, key=lambda f: f.sort_key()):
        rules.setdefault(finding.rule_id, {
            "id": finding.rule_id,
            "name": finding.title.replace(" ", ""),
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.message},
            "help": {"text": finding.remediation},
            "properties": {
                "tags": ["security", "ai-agent", finding.technique] if finding.technique else ["security", "ai-agent"],
                "capabilities": list(finding.capabilities),
                "confidence": finding.confidence,
            },
            "defaultConfiguration": {"level": _SARIF_LEVEL[finding.severity]},
        })
        result: Dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _SARIF_LEVEL[finding.severity],
            "message": {"text": finding.message + (f" Decoded: {redact(finding.decoded)}" if finding.decoded else "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path, "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine": max(1, finding.line),
                        "startColumn": max(1, finding.column),
                        "snippet": {"text": redact(finding.evidence)[:400]},
                    },
                }
            }],
            "partialFingerprints": {
                "instructionSurface/v1": f"{finding.rule_id}:{finding.path}:{finding.line}",
            },
            "properties": {"capabilities": list(finding.capabilities)},
        }
        results.append(result)

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "agentvigil",
                "informationUri": "https://github.com/agentvigil/agentvigil",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2) + "\n"
