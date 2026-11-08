"""Transitive context-reference & shadow-surface detector.

Modern coding agents expand references inside steering and rules files before
the model runs:
* Kiro steering/specs expand `#[[file:path/to/file]]` inline;
* Claude Code / Cursor rules expand `@path/to/file` context mentions;
* Agent skills import remote skill packs (`npx skills add ...` or mutable
  `raw.githubusercontent.com/.../main/...` rule URLs).

Attackers abuse this to keep `AGENTS.md` clean while smuggling the payload in a
traversed path (`#[[file:../../.env]]`), a mutable branch URL, or a non-surface
fixture (`#[[file:tests/fixtures/notes.txt]]`) that reviewers ignore.

Pure function of `SurfaceFile` — no filesystem I/O inside the detector.
"""

from __future__ import annotations

import posixpath
import re
from typing import List, Tuple

from ..findings import Finding, Severity
from ..surface import SurfaceFile, _classify

# Kiro native context reference: #[[file:relative/path]]
KIRO_FILE_REF_RE = re.compile(r"#\[\[\s*file\s*:\s*([^\]]+?)\s*\]\]", re.IGNORECASE)

# Explicit @file context includes at token boundaries (excluding emails and @scope/pkg@1.0).
AT_FILE_REF_RE = re.compile(
    r"(?:^|[\s(])@((?:\.\./|~/|/etc/|/root/|/home/)[^\s),:;\"'`]+|"
    r"[A-Za-z0-9_./-]+\.(?:md|mdc|txt|yaml|yml|json|sh|py|env))\b",
    re.MULTILINE,
)

# Markdown links pointing to parent-directory traversal or dotfiles.
TRAVERSAL_LINK_RE = re.compile(
    r"\[[^\]]{1,120}\]\(\s*((?:\.\./){2,}[^\s)]+|~/?\.[^\s)]+|/etc/[^\s)]+)\s*\)"
)

SENSITIVE_TARGET_RE = re.compile(
    r"(?:^|/)(?:\.env(?:\.\w+)?|\.ssh|\.aws|\.gnupg|\.kube|\.netrc|\.npmrc|"
    r"id_rsa|id_ed25519|passwd|shadow|\.git/config)\b",
    re.IGNORECASE,
)

# Unpinned external skill install or mutable branch rule/skill URL.
UNPINNED_SKILL_RE = re.compile(
    r"\b(?:npx|bunx|pnpx)\s+(?:-y\s+)?skills(?:-cli)?\s+add\s+([^\s;|&]+)"
    r"|https?://raw\.githubusercontent\.com/[^\s/\"')]+/[^\s/\"')]+/"
    r"(?:refs/heads/)?(?:main|master|HEAD)/[^\s\"')]+\.(?:md|mdc|sh|json)\b",
    re.IGNORECASE,
)
PIN_RE = re.compile(r"@\d+\.\d+|@[0-9a-f]{7,40}\b|#[0-9a-f]{7,40}\b")


def _line_col(text: str, index: int) -> Tuple[int, int]:
    return text.count("\n", 0, index) + 1, index - text.rfind("\n", 0, index)


def _escapes_root(source_path: str, ref_target: str) -> bool:
    target = ref_target.strip()
    if target.startswith(("/", "~", "\\")):
        return True
    base_dir = posixpath.dirname(source_path)
    joined = (
        posixpath.normpath(posixpath.join(base_dir, target))
        if base_dir
        else posixpath.normpath(target)
    )
    return joined == ".." or joined.startswith("../") or joined.startswith("/")


def _normalize_repo_rel(source_path: str, ref_target: str) -> str:
    base_dir = posixpath.dirname(source_path)
    joined = (
        posixpath.normpath(posixpath.join(base_dir, ref_target.strip()))
        if base_dir
        else posixpath.normpath(ref_target.strip())
    )
    return joined.lstrip("./")


def extract_refs(file: SurfaceFile) -> List[str]:
    """Return normalized repo-relative paths referenced via `#[[file:...]]` or `@file`."""
    text = file.text
    refs: List[str] = []
    for m in KIRO_FILE_REF_RE.finditer(text):
        refs.append(m.group(1).strip())
    for m in AT_FILE_REF_RE.finditer(text):
        refs.append(m.group(1).strip())
    return sorted(dict.fromkeys(refs))


def scan(file: SurfaceFile) -> List[Finding]:
    if file.kind not in ("agent_rules", "skill", "spec"):
        return []
    text = file.text
    findings: List[Finding] = []
    seen = set()

    def add(
        rule_id: str,
        title: str,
        severity: Severity,
        index: int,
        message: str,
        technique: str,
        caps: Tuple[str, ...],
        evidence: str,
        remediation: str,
        ref_target: str = "",
    ) -> None:
        line, col = _line_col(text, index)
        key = (rule_id, line, ref_target)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                path=file.path,
                line=line,
                column=col,
                message=message,
                evidence=evidence[:240],
                technique=technique,
                capabilities=caps,
                remediation=remediation,
                detector="refs",
                metadata={"target": ref_target} if ref_target else {},
            )
        )

    # 1. Kiro `#[[file:...]]` directives
    for m in KIRO_FILE_REF_RE.finditer(text):
        target = m.group(1).strip()
        if _escapes_root(file.path, target) or SENSITIVE_TARGET_RE.search(target):
            add(
                "AV-REF-001",
                "Context reference escapes repository root or targets secrets",
                Severity.HIGH,
                m.start(),
                f"Directive `{m.group(0)}` pulls '{target}' (outside repo boundary or sensitive store) "
                "into the agent's instruction context.",
                "D2.2",
                ("fs.credentials", "agent.deceive"),
                m.group(0),
                "Remove the reference; context includes must stay inside reviewed repository files.",
                ref_target=target,
            )
        else:
            norm = _normalize_repo_rel(file.path, target)
            if _classify(norm) is None:
                add(
                    "AV-REF-003",
                    "Shadow instruction surface via context include",
                    Severity.MEDIUM,
                    m.start(),
                    f"`{m.group(0)}` injects '{norm}' into the agent's instruction context, "
                    "but that file is outside standard instruction-surface paths.",
                    "M2.2",
                    ("agent.deceive",),
                    m.group(0),
                    f"Move shared instructions into `.kiro/steering/` or review and pin '{norm}'.",
                    ref_target=norm,
                )

    # 2. `@path` context mentions that escape root or hit secrets
    for m in AT_FILE_REF_RE.finditer(text):
        target = m.group(1).strip()
        if _escapes_root(file.path, target) or SENSITIVE_TARGET_RE.search(target):
            add(
                "AV-REF-001",
                "Context reference escapes repository root or targets secrets",
                Severity.HIGH,
                m.start(),
                f"Context reference `@{target}` pulls an external or sensitive file into agent memory.",
                "D2.2",
                ("fs.credentials", "agent.deceive"),
                m.group(0).strip(),
                "Delete the `@` reference and never include parent directories or secret files.",
                ref_target=target,
            )

    # 3. Markdown traversal links to outside repo / sensitive paths
    for m in TRAVERSAL_LINK_RE.finditer(text):
        target = m.group(1).strip()
        if _escapes_root(file.path, target) or SENSITIVE_TARGET_RE.search(target):
            add(
                "AV-REF-001",
                "Context reference escapes repository root or targets secrets",
                Severity.HIGH,
                m.start(),
                f"Link `{m.group(0)}` traverses outside the repository or into a sensitive path.",
                "D2.2",
                ("fs.credentials", "agent.deceive"),
                m.group(0),
                "Keep instruction links within the repository.",
                ref_target=target,
            )

    # 4. Unpinned remote skill or branch-mutable instruction URL
    for m in UNPINNED_SKILL_RE.finditer(text):
        pkg = m.group(1) or m.group(0)
        if m.group(1) and PIN_RE.search(m.group(1)):
            continue
        add(
            "AV-REF-002",
            "Mutable external skill or branch-pinned instruction import",
            Severity.HIGH,
            m.start(),
            f"Instruction imports mutable remote content (`{m.group(0)[:100]}`) without a commit SHA "
            "or version pin; upstream changes silently reprogram the agent.",
            "D3.1",
            ("mcp.untrusted", "agent.self_modify"),
            m.group(0),
            "Vendor the skill/rule file into the repository and pin it in `vigil.lock`, or pin to a full commit SHA.",
            ref_target=pkg,
        )

    return findings
