"""Findings: the only data type the rest of the tool agrees on.

Every detector produces Findings. A Finding carries a precise span, the
evidence a human needs to verify it, the attack technique it maps to, and the
*capability* it grants the agent. Capabilities are what make `vigil diff`
readable: "this PR grants exec.shell + net.egress" beats "regex matched".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return _WEIGHTS[self]

    @property
    def rank(self) -> int:
        return _RANK[self]


_WEIGHTS = {
    Severity.CRITICAL: 45,
    Severity.HIGH: 22,
    Severity.MEDIUM: 9,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

SEVERITIES_BY_NAME = {s.value: s for s in Severity}


def severity_at_least(value: Severity, threshold: Severity) -> bool:
    return value.rank >= threshold.rank


# Capability vocabulary. Keep it small and stable; it is a public contract
# (lockfiles, PR comments and the benchmark all reference these names).
CAPABILITIES: Dict[str, str] = {
    "exec.shell": "run shell commands",
    "exec.download": "download and execute remote content",
    "net.egress": "send data to an external endpoint",
    "fs.credentials": "read credentials, keys or secret stores",
    "fs.write": "modify files outside the task's scope",
    "agent.self_modify": "change the agent's own instructions or config",
    "approval.bypass": "remove human approval before actions",
    "agent.deceive": "hide its actions from the user",
    "persistence": "establish persistence across sessions",
    "data.exfil": "move local data to an attacker-controlled sink",
    "tool.spoof": "impersonate tool calls or system messages",
    "mcp.untrusted": "depend on an unpinned or unverified MCP package",
}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    path: str
    message: str
    line: int = 1
    column: int = 1
    evidence: str = ""
    technique: str = ""  # taxonomy id, e.g. D2.1 / M1.3 / D3.1
    capabilities: Tuple[str, ...] = ()
    remediation: str = ""
    decoded: Optional[str] = None  # e.g. tag-char payload after decoding
    confidence: str = "high"  # high | medium | low (deterministic detectors are high)
    detector: str = "deterministic"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def sort_key(self) -> Tuple[int, str, int, str]:
        return (-self.severity.rank, self.path, self.line, self.rule_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "evidence": self.evidence,
            "technique": self.technique,
            "capabilities": list(self.capabilities),
            "remediation": self.remediation,
            "decoded": self.decoded,
            "confidence": self.confidence,
            "detector": self.detector,
            "metadata": self.metadata,
        }


def cap_names(caps: Iterable[str]) -> List[str]:
    return sorted({c for c in caps if c})


def summarize(findings: Iterable[Finding]) -> Dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts
