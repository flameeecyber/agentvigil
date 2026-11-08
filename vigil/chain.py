"""Kill-chain correlation: single findings are alerts, paths are attacks.

No scanner connects the dots across the surface. A lone `fetch remote URL`
in AGENTS.md is suspicious; the same URL *plus* an unpinned MCP server with
cloud credentials *plus* an approval-bypass flag is a working exploit path.

`correlate(files, findings)` emits AV-CHAIN findings only when two or more
independent primitives combine into one executable path. Each chain cites
the rule ids it builds on so a human can verify it in seconds.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence, Set, Tuple

from .findings import Finding, Severity
from .surface import SurfaceFile

CHAIN_TECHNIQUE = "P3.1"


def _finding_rules(f: Finding) -> Set[str]:
    inner = f.metadata.get("inner_rules") if isinstance(f.metadata, dict) else None
    if isinstance(inner, list):
        return {f.rule_id} | {str(r) for r in inner}
    return {f.rule_id}


def _rule_ids(findings: Sequence[Finding]) -> Set[str]:
    out: Set[str] = set()
    for f in findings:
        out.update(_finding_rules(f))
    return out


def _matching(findings: Sequence[Finding], targets: Set[str]) -> List[Finding]:
    return [f for f in findings if _finding_rules(f) & targets]


def _paths(findings: Sequence[Finding]) -> str:
    return ", ".join(sorted({f.path for f in findings}))


def correlate(
    files: Sequence[SurfaceFile], findings: Sequence[Finding]
) -> List[Finding]:
    by_path: Dict[str, List[Finding]] = {}
    for f in findings:
        by_path.setdefault(f.path, []).append(f)
    all_rules = _rule_ids(findings)
    out: List[Finding] = []

    def emit(
        rule_id: str,
        title: str,
        severity: Severity,
        message: str,
        caps: Tuple[str, ...],
        evidence: str,
        remediation: str,
        sources: Sequence[str],
    ) -> None:
        out.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                path="SURFACE",
                line=1,
                column=1,
                message=message,
                evidence=evidence[:300],
                technique=CHAIN_TECHNIQUE,
                capabilities=caps,
                remediation=remediation,
                detector="chain",
                metadata={"sources": list(sources)},
            )
        )

    # C1: remote-instruction delegation + privileged execution anywhere.
    remote_delegation = {"AV-FETCH-001", "AV-IMG-004", "AV-REF-002"}
    priv_exec = {
        "AV-EXEC-001",
        "AV-EXEC-002",
        "AV-EXEC-003",
        "AV-OBF-001",
        "AV-OBF-002",
        "AV-OBF-003",
        "AV-MCP-003",
        "AV-MCP-007",
    }
    if all_rules & remote_delegation and all_rules & priv_exec:
        emit(
            "AV-CHAIN-001",
            "Kill chain: remote instruction source + local execution primitive",
            Severity.CRITICAL,
            "One file delegates the agent's behaviour to mutable remote content while "
            "another grants shell/download execution. Compromising the remote source "
            "gives code execution.",
            ("exec.shell", "exec.download", "agent.self_modify"),
            f"delegation in {_paths(_matching(findings, remote_delegation))}; "
            f"execution in {_paths(_matching(findings, priv_exec))}",
            "Inline the remote rules as reviewed text AND remove the execution primitive. "
            "Fixing only one side leaves the path open.",
            sorted(all_rules & (remote_delegation | priv_exec)),
        )

    # C2: credential access + exfil sink = complete theft path.
    cred = {"AV-CRED-001", "AV-CRED-002", "AV-SECRET-001", "AV-MCP-005", "AV-REF-001"}
    exfil = {"AV-EXFIL-001", "AV-EXFIL-002"}
    if all_rules & cred and all_rules & exfil:
        emit(
            "AV-CHAIN-002",
            "Kill chain: credential access + exfiltration sink",
            Severity.CRITICAL,
            "The surface can both read secrets and send data out. Either finding alone "
            "is bad; together they are a working theft path.",
            ("fs.credentials", "data.exfil", "net.egress"),
            f"reads in {_paths(_matching(findings, cred))}; "
            f"sinks in {_paths(_matching(findings, exfil))}",
            "Remove the credential reads first (breaks the source), then the sinks.",
            sorted(all_rules & (cred | exfil)),
        )

    # C3: concealment + persistence/approval-bypass = stealth backdoor.
    conceal = {
        "AV-OVR-001",
        "AV-OVR-002",
        "AV-HIDE-001",
        "AV-UNI-001",
        "AV-UNI-002",
        "AV-UNI-003",
        "AV-UNI-005",
        "AV-TOOL-001",
        "AV-MCP-008",
    }
    stealth = {
        "AV-PERSIST-001",
        "AV-BYP-001",
        "AV-MCP-002",
        "AV-MCP-006",
        "AV-AUTO-001",
    }
    if all_rules & conceal and all_rules & stealth:
        emit(
            "AV-CHAIN-003",
            "Kill chain: concealment + persistence or approval bypass",
            Severity.HIGH,
            "Hidden instructions combined with persistence or auto-approval survive "
            "reviews and re-runs: a stealth backdoor.",
            ("agent.deceive", "persistence", "approval.bypass"),
            f"concealment in {_paths(_matching(findings, conceal))}; "
            f"stealth in {_paths(_matching(findings, stealth))}",
            "Delete the hidden text, then remove the persistence/approval flags.",
            sorted(all_rules & (conceal | stealth)),
        )

    # C4: unpinned MCP + credential passthrough = third-party rug pull with keys.
    if "AV-MCP-001" in all_rules and "AV-MCP-005" in all_rules:
        emit(
            "AV-CHAIN-004",
            "Kill chain: unpinned MCP server receives cloud credentials",
            Severity.CRITICAL,
            "A third-party MCP package that can change at any time is handed long-lived "
            "cloud credentials. A rug pull on that package leaks the keys.",
            ("mcp.untrusted", "fs.credentials", "net.egress"),
            _paths(_matching(findings, {"AV-MCP-001", "AV-MCP-005"})),
            "Pin the package to a SHA AND replace the credential with a scoped token.",
            ["AV-MCP-001", "AV-MCP-005"],
        )

    return sorted(out, key=lambda f: f.sort_key())
