"""Pattern rule pack.

Rules are data: one line each, with the capability they grant documented next to
them. This is deliberately dumb and fast — the semantic layer is what handles
prose, and the benchmark measures both.
"""

from __future__ import annotations

import re
from typing import Dict, List, Pattern, Tuple

from ..findings import Finding, Severity
from ..surface import SurfaceFile

MAX_PER_RULE = 5

RULES: List[Dict] = [
    {
        "id": "AV-EXEC-001",
        "title": "Download-and-execute instruction",
        "severity": Severity.CRITICAL,
        "technique": "D2.1",
        "caps": ("exec.download", "exec.shell", "net.egress"),
        "regex": r"(?:curl|wget|fetch)\s+[^\n|;]{0,120}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b",
        "message": "Instruction tells the agent to pipe remote content into a shell.",
        "remediation": "Remove the instruction. No legit repo setup requires `curl | sh` from an agent.",
    },
    {
        "id": "AV-EXEC-002",
        "title": "Shell command embedded in instruction text",
        "severity": Severity.HIGH,
        "technique": "D2.1",
        "caps": ("exec.shell",),
        "regex": r"(?:^|[\s(])(?:bash|sh|zsh)\s+-[ci]\s+[\"'][^\"'\n]{8,200}[\"']",
        "message": "Instruction hands the agent a shell one-liner to run.",
        "remediation": "Describe the task instead of prescribing a command; let the agent use its sandbox.",
    },
    {
        "id": "AV-EXEC-003",
        "title": "PowerShell / eval execution primitive",
        "severity": Severity.HIGH,
        "technique": "D2.1",
        "caps": ("exec.shell",),
        "regex": r"\b(?:iex|Invoke-Expression|eval)\s*[\(\s]\s*[\"'`]",
        "message": "Dynamic code execution primitive in an instruction file.",
        "remediation": "Remove the primitive; treat the file as untrusted.",
    },
    {
        "id": "AV-CRED-001",
        "title": "Credential or key material path referenced",
        "severity": Severity.HIGH,
        "technique": "D2.2",
        "caps": ("fs.credentials",),
        "regex": r"(?:~|/root|/home/[\w.-]+)?/\.(?:ssh|aws|gnupg|kube|docker|config/gcloud)\b|id_rsa|id_ed25519|\.netrc|\.npmrc|credentials\.json",
        "message": "Agent instruction points at a credential store.",
        "remediation": "Instructions should never direct the agent to key material. Remove and rotate if exposed.",
    },
    {
        "id": "AV-CRED-002",
        "title": "Environment or secret dump",
        "severity": Severity.MEDIUM,
        "technique": "D2.2",
        "caps": ("fs.credentials",),
        "regex": r"\b(?:printenv|env\s*\||cat\s+\.env|os\.environ(?![.\w\[])|process\.env(?![.\w\[])|Get-ChildItem\s+Env:)\b",
        "message": "Instruction asks the agent to enumerate secrets from the environment.",
        "remediation": "Scope the instruction to the specific non-secret variable it needs.",
    },
    {
        "id": "AV-EXFIL-001",
        "title": "Known exfiltration sink",
        "severity": Severity.HIGH,
        "technique": "D2.3",
        "caps": ("data.exfil", "net.egress"),
        "regex": r"(?:webhook\.site|pastebin\.com|transfer\.sh|requestbin|pipedream\.net|interact\.sh|oast\.(?:live|me|fun|site)|burpcollaborator\.net|ngrok\.(?:io|app))",
        "message": "Instruction references a service commonly used to receive stolen data.",
        "remediation": "Remove the URL. Check git history for when it was added.",
    },
    {
        "id": "AV-EXFIL-002",
        "title": "Bulk outbound POST from instruction text",
        "severity": Severity.HIGH,
        "technique": "D2.3",
        "caps": ("data.exfil", "net.egress"),
        "regex": r"(?:curl\s+[^\n]{0,80}(?:-d|--data|--upload-file|-F)\s|requests\.post\(|invoke-webrequest[^\n]{0,40}-method\s+post)",
        "message": "Instruction builds an outbound request carrying data.",
        "remediation": "Explain why the task needs network egress; if it does not, delete the instruction.",
    },
    {
        "id": "AV-OVR-001",
        "title": "Instruction-override phrasing",
        "severity": Severity.HIGH,
        "technique": "D1.2",
        "caps": ("agent.deceive",),
        "regex": r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|other)\s+(?:instructions?|rules?|context|guidance)",
        "message": "Text tries to nullify the operator's instructions (classic injection preamble).",
        "remediation": "Delete. Legitimate documentation never needs to disable the agent's rules.",
    },
    {
        "id": "AV-OVR-002",
        "title": "Concealment from the user",
        "severity": Severity.HIGH,
        "technique": "M2.2",
        "caps": ("agent.deceive",),
        "regex": r"(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal|show|alert)[^\n.]{0,40}(?:user|human|developer)|without\s+(?:telling|informing|alerting)\s+the\s+user|silently\s+(?=[^.\n]{0,30}\b(?:run|execute|install|modify|delete|remove|push|send|upload|edit|write|commit|proceed|continue|skip|disable|overwrite|exfiltrate)\b)",
        "message": "Instruction asks the agent to hide what it does.",
        "remediation": "Delete. Hidden actions are a defining property of malicious instructions.",
    },
    {
        "id": "AV-BYP-001",
        "title": "Approval-bypass flag",
        "severity": Severity.HIGH,
        "technique": "D3.1",
        "caps": ("approval.bypass",),
        "regex": r"--dangerously-skip-permissions|--yolo\b|bypassPermissions|--trust-all-tools",
        "message": "Config disables the human approval step for agent actions.",
        "remediation": "Remove the flag; allow-list specific safe commands instead.",
    },
    {
        "id": "AV-TOOL-001",
        "title": "Tool-call or role spoofing marker",
        "severity": Severity.HIGH,
        "technique": "M1.1",
        "caps": ("tool.spoof",),
        "regex": r"<\|?\s*(?:im_start|im_end|system|endoftext)\s*\|?>|<function_calls>|</?tool_use>|\[/?INST\]|^\s*(?:system|developer)\s*:\s*\S",
        "message": "Text impersonates a chat role or tool-call envelope to gain instruction priority.",
        "remediation": "Escape or remove the marker; it has no legitimate place in documentation.",
    },
    {
        "id": "AV-PERSIST-001",
        "title": "Persistence mechanism",
        "severity": Severity.HIGH,
        "technique": "P2.3",
        "caps": ("persistence", "exec.shell"),
        "regex": r">>?\s*~?/?\.(?:bashrc|zshrc|bash_profile|profile)\b|crontab\s+-\S|systemctl\s+enable|launchctl\s+load|(?:write|create|modify)[^\n.]{0,40}\.git/hooks",
        "message": "Instruction establishes persistence outside the task.",
        "remediation": "Remove. Task instructions should not modify shell profiles, cron or git hooks.",
    },
    {
        "id": "AV-OBF-001",
        "title": "Encoded or obfuscated execution",
        "severity": Severity.HIGH,
        "technique": "M1.3",
        "caps": ("exec.shell", "agent.deceive"),
        "regex": r"base64\s+(?:-d|--decode)[^\n|]{0,40}\||eval\s*\(\s*(?:atob|Buffer\.from)|\bfromCharCode\b|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}",
        "message": "Instruction decodes an encoded blob at runtime instead of showing it.",
        "remediation": "Show the decoded content or delete the instruction.",
    },
    {
        "id": "AV-HIDE-001",
        "title": "Hidden comment containing imperative text",
        "severity": Severity.HIGH,
        "technique": "M2.2",
        "caps": ("agent.deceive",),
        "regex": r"<!--(?:(?!-->)[\s\S]){0,400}?\b(?:ignore|execute|run|send|fetch|read|delete|exfiltrate|curl)\b(?:(?!-->)[\s\S]){0,400}?-->",
        "message": "An HTML comment invisible in rendered Markdown carries an instruction.",
        "remediation": "Delete the comment. Review the raw file, not the rendered view.",
    },
    {
        "id": "AV-FETCH-001",
        "title": "Instruction to fetch and follow remote instructions",
        "severity": Severity.HIGH,
        "technique": "D2.3",
        "caps": ("net.egress", "agent.self_modify"),
        "regex": r"(?:fetch|download|read)\s+https?://\S{4,120}\s*(?:and|then)\s*(?:follow|obey|apply|execute)\b",
        "message": "Instruction delegates the agent's behaviour to remote content the reviewer cannot see.",
        "remediation": "Inline the rules instead of pointing at a mutable remote document.",
    },
    {
        "id": "AV-SECRET-001",
        "title": "Embedded secret in an instruction file",
        "severity": Severity.HIGH,
        "technique": "D2.2",
        "caps": ("fs.credentials",),
        "regex": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "message": "A live-looking credential is committed inside an agent instruction file.",
        "remediation": "Rotate the credential, purge git history, and keep secrets out of instruction files.",
    },
    {
        "id": "AV-AUTO-001",
        "title": "Unconditional autonomy trigger",
        "severity": Severity.LOW,
        "technique": "P2.2",
        "caps": (),
        "regex": r"(?:before|after)\s+(?:every|each)\s+(?:command|tool\s*call|response|commit)[^\n]{0,60}",
        "message": "Instruction sets an always-on behaviour hook; verify it is intended.",
        "remediation": "Scope the trigger to the specific task it supports.",
    },
    {
        "id": "AV-NET-001",
        "title": "Plaintext HTTP endpoint",
        "severity": Severity.LOW,
        "technique": "D3.2",
        "caps": ("net.egress",),
        "regex": r"\bhttp://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-z0-9.-]+",
        "message": "Instruction sends the agent to a non-TLS endpoint.",
        "remediation": "Use HTTPS; a plaintext endpoint can be modified in transit.",
    },
]

_COMPILED: List[Tuple[Dict, Pattern[str]]] = [
    (rule, re.compile(rule["regex"], re.IGNORECASE | re.MULTILINE)) for rule in RULES
]

# Precision guards for prose that describes an attack instead of instructing one.
# These demote a match to LOW; they never delete it. The finding, span and
# capability stay visible so a reviewer can decide, and policy can still deny the
# capability. This is a heuristic, documented as such in docs/benchmark.md.
NEGATION_RE = re.compile(
    r"\b(?:never|do\s+not|don't|must\s+not|should\s+not|avoid|refuse\s+to)\b",
    re.IGNORECASE,
)
DOCUMENTATION_CUE_RE = re.compile(
    r"\b(?:example|sample|fixture|test|literal|phrase|quoted|mention|documentation|assert)\b",
    re.IGNORECASE,
)
SENTENCE_BOUNDARY_RE = re.compile(r"[.!?;]\s+")
NEGATION_GUARDED = frozenset(
    {"AV-EXEC-001", "AV-CRED-001", "AV-CRED-002", "AV-EXFIL-001", "AV-FETCH-001"}
)
QUOTED_GUARDED = frozenset({"AV-OVR-001", "AV-TOOL-001"})


def _line_bounds(text: str, index: int) -> Tuple[int, int]:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    return start, end if end != -1 else len(text)


def _inside_inline_code(text: str, index: int) -> bool:
    start, _ = _line_bounds(text, index)
    return text[start:index].count("`") % 2 == 1


def _mention_context(rule_id: str, text: str, start: int, end: int) -> str:
    """Return a context label when a match looks like prose *about* an attack.

    Conservative by design: a negation must appear earlier in the same sentence,
    and a quoted literal must sit in an explicit example/test sentence. An actual
    instruction (no negation or documentation cue) keeps its declared severity.
    """
    line_start, line_end = _line_bounds(text, start)
    before = text[line_start:start]
    # Scope a negation to the current sentence. A period inside a URL or path
    # has no trailing whitespace, so it does not create a false boundary.
    boundaries = list(SENTENCE_BOUNDARY_RE.finditer(before))
    if boundaries:
        before = before[boundaries[-1].end():]
    if rule_id in NEGATION_GUARDED and NEGATION_RE.search(before[-160:]):
        return "negated-mention"

    if rule_id in QUOTED_GUARDED:
        line = text[line_start:line_end]
        quoted = _inside_inline_code(text, start)
        if not quoted:
            previous = text[start - 1] if start else ""
            following = text[end] if end < len(text) else ""
            quoted = previous in "\"'" and following in "\"'"
        if quoted and DOCUMENTATION_CUE_RE.search(line):
            return "documented-literal"

    if rule_id == "AV-HIDE-001" and _inside_inline_code(text, start):
        return "inline-code-example"

    return ""


def rules() -> List[Dict]:
    return RULES


def _line_col(text: str, index: int) -> Tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    return line, index - text.rfind("\n", 0, index)


def scan(file: SurfaceFile) -> List[Finding]:
    text = file.text
    findings: List[Finding] = []
    for rule, pattern in _COMPILED:
        hits = 0
        for match in pattern.finditer(text):
            if hits >= MAX_PER_RULE:
                break
            hits += 1
            line, col = _line_col(text, match.start())
            evidence_start = max(0, match.start() - 40)
            evidence_end = min(len(text), match.end() + 40)
            context = _mention_context(rule["id"], text, match.start(), match.end())
            severity = Severity.LOW if context else rule["severity"]
            message = rule["message"]
            metadata = {}
            if context:
                message += (
                    " Matched in a documentation or prohibition context; "
                    "verify it is not an active instruction."
                )
                metadata["context"] = context
            findings.append(Finding(
                rule_id=rule["id"],
                title=rule["title"],
                severity=severity,
                path=file.path,
                line=line,
                column=col,
                message=message,
                evidence=text[evidence_start:evidence_end].replace("\n", "\\n").strip(),
                technique=rule["technique"],
                capabilities=tuple(rule["caps"]),
                remediation=rule["remediation"],
                confidence="medium" if context else "high",
                detector="patterns",
                metadata=metadata,
            ))
    return findings
