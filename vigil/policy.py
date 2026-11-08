"""Policy gate: the org's red lines, enforced at scan/diff time.

Severity thresholds alone cannot express "our AGENTS.md may never grant
network egress, but our Makefile automation may". A policy file does:

    {"deny": ["exec.download", "fs.credentials"],
     "deny_paths": {"AGENTS.md": ["net.egress"]},
     "fail_on": "medium",
     "allow_rules": ["AV-NET-001"]}

Rules (kept tiny on purpose):
* `deny` — capabilities that always block, wherever they appear.
* `deny_paths` — capabilities blocked only in matching files (substring match).
* `allow_rules` — rule ids that never block (explicit, reviewable exceptions).
* `fail_on` — severity floor for the remaining findings.

Stdlib JSON only. Missing file = no policy. Invalid file = loud error,
never a silent pass.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

from .findings import Finding, Severity, SEVERITIES_BY_NAME, severity_at_least


@dataclass
class Policy:
    deny: Tuple[str, ...] = ()
    deny_paths: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    allow_rules: Tuple[str, ...] = ()
    fail_on: Severity = Severity.HIGH
    name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"deny": list(self.deny),
                "deny_paths": {k: list(v) for k, v in self.deny_paths.items()},
                "allow_rules": list(self.allow_rules),
                "fail_on": self.fail_on.value, "name": self.name}


def load_policy(path: Path) -> Policy:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: policy must be a JSON object")
    deny = tuple(str(c) for c in raw.get("deny", []) or [])
    deny_paths = {str(k): tuple(str(c) for c in v or [])
                  for k, v in dict(raw.get("deny_paths", {}) or {}).items()}
    allow_rules = tuple(str(r) for r in raw.get("allow_rules", []) or [])
    fail_on_raw = str(raw.get("fail_on", "high")).lower()
    if fail_on_raw not in SEVERITIES_BY_NAME:
        raise ValueError(f"{path}: unknown fail_on {fail_on_raw!r}")
    return Policy(deny=deny, deny_paths=deny_paths, allow_rules=allow_rules,
                  fail_on=SEVERITIES_BY_NAME[fail_on_raw], name=raw.get("name", ""))


PRESETS: Dict[str, Dict[str, Any]] = {
    "strict": {
        "name": "strict", "deny": ["exec.download", "exec.shell", "fs.credentials",
                 "data.exfil", "approval.bypass", "agent.self_modify"],
        "deny_paths": {"AGENTS.md": ["net.egress"], "SKILL.md": ["net.egress"]},
        "allow_rules": [], "fail_on": "medium",
    },
    "balanced": {
        "name": "balanced", "deny": ["exec.download", "fs.credentials"],
        "deny_paths": {"AGENTS.md": ["net.egress", "exec.shell"]},
        "allow_rules": ["AV-NET-001"], "fail_on": "high",
    },
    "permissive": {
        "name": "permissive", "deny": ["exec.download"],
        "deny_paths": {}, "allow_rules": ["AV-NET-001", "AV-AUTO-001"],
        "fail_on": "critical",
    },
}


def preset(name: str) -> Policy:
    if name not in PRESETS:
        raise ValueError(f"unknown preset {name!r} (choose {', '.join(PRESETS)})")
    raw = PRESETS[name]
    return Policy(deny=tuple(raw["deny"]),
                  deny_paths={k: tuple(v) for k, v in raw["deny_paths"].items()},
                  allow_rules=tuple(raw["allow_rules"]),
                  fail_on=SEVERITIES_BY_NAME[raw["fail_on"]], name=name)


@dataclass
class PolicyVerdict:
    blocking: bool
    reason: str
    violations: List[Finding]

    def to_dict(self) -> Dict[str, Any]:
        return {"blocking": self.blocking, "reason": self.reason,
                "violations": [f.to_dict() for f in self.violations]}


def evaluate(findings: Sequence[Finding], policy: Policy) -> PolicyVerdict:
    violations: List[Finding] = []
    for f in findings:
        if f.rule_id in policy.allow_rules:
            continue
        caps = set(f.capabilities)
        if caps & set(policy.deny):
            violations.append(f)
            continue
        for substr, denied in policy.deny_paths.items():
            if substr in f.path and caps & set(denied):
                violations.append(f)
                break
        else:
            if severity_at_least(f.severity, policy.fail_on):
                violations.append(f)
    if not violations:
        return PolicyVerdict(blocking=False, reason="policy allows the surface", violations=[])
    worst = max(violations, key=lambda f: f.severity.rank)
    caps_hit = sorted({c for f in violations for c in f.capabilities
                       if c in set(policy.deny) or any(c in v for v in policy.deny_paths.values())})
    extra = f" Denied capability: {', '.join(caps_hit)}." if caps_hit else ""
    return PolicyVerdict(
        blocking=True,
        reason=f"policy blocks {len(violations)} finding(s); worst is {worst.rule_id} "
               f"in {worst.path}:{worst.line}.{extra}",
        violations=sorted(violations, key=lambda f: f.sort_key()),
    )
