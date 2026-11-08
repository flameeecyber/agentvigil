"""MCP configuration detector.

MCP servers are the agent's hands. The config that launches them is fetched from
a repo and evaluated with the developer's full privileges, so we check:

* unpinned registry installs (`npx -y pkg` resolves to whatever ships today);
* plaintext transport to a remote server;
* approval-bypass flags and shell wrappers;
* credential passthrough into a third-party process.

Tool *descriptions* are the other half (tool poisoning) and are handled by the
text detectors plus the runtime proxy.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..findings import Finding, Severity
from ..surface import SurfaceFile

COMMENT_RE = re.compile(r"^\s*//.*$", re.MULTILINE)
TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")
PINNED_RE = re.compile(r"@\d+\.\d+|@\^?\d|==\d|@sha256:|#\d{7,}")
UNPINNED_INSTALLERS = (
    ("npx", 0),
    ("uvx", 0),
    ("pipx", 0),
    ("bunx", 0),
    ("pnpx", 0),
)
SECRET_ENV_RE = re.compile(
    r"^(?:AWS_|GITHUB_TOKEN|GH_TOKEN|OPENAI|ANTHROPIC|AZURE_|GOOGLE_|"
    r"DATABASE_URL|SSH_|NPM_TOKEN|DOCKER_|KUBE)",
    re.IGNORECASE,
)
INLINE_EXEC_RE = re.compile(
    r"(?:^|[\s/])(?:python3?\s+-c|node\s+-e|deno\s+eval|ruby\s+-e|perl\s+-e|"
    r"nc\s+-e|ncat\s+-e|socat\b|ngrok\b)",
    re.IGNORECASE,
)
TOOL_SHADOW_RE = re.compile(
    r"<\s*important\s*>|\bsidenote\s*:|"
    r"(?:before|after|when)\s+(?:calling|using|invoking)\s+(?:any\s+|the\s+)?[a-z0-9_-]{2,30}\s+tool\b|"
    r"pass\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:~|/|\.(?:ssh|aws|env))",
    re.IGNORECASE,
)


def _load(path_text: str) -> Optional[Dict[str, Any]]:
    stripped = COMMENT_RE.sub("", path_text)
    stripped = TRAILING_COMMA_RE.sub(r"\1", stripped)
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _servers(doc: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    for key in ("mcpServers", "servers", "mcp_servers"):
        block = doc.get(key)
        if isinstance(block, dict):
            for name, spec in block.items():
                if isinstance(spec, dict):
                    yield str(name), spec


def _args(spec: Dict[str, Any]) -> List[str]:
    raw = spec.get("args")
    if isinstance(raw, list):
        return [str(a) for a in raw]
    if isinstance(raw, str):
        return raw.split()
    return []


def scan(file: SurfaceFile) -> List[Finding]:
    if file.kind != "mcp_config":
        return []
    text = file.text
    doc = _load(text)
    findings: List[Finding] = []

    def add(
        rule_id: str,
        title: str,
        severity: Severity,
        message: str,
        caps: Tuple[str, ...],
        remediation: str,
        name: str = "",
        evidence: str = "",
    ) -> None:
        line = 1
        needle = f'"{name}"' if name else ""
        if needle:
            idx = text.find(needle)
            if idx > 0:
                line = text.count("\n", 0, idx) + 1
        findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                path=file.path,
                line=line,
                message=message,
                evidence=evidence or (needle or ""),
                technique="D3.1",
                capabilities=caps,
                remediation=remediation,
                detector="mcp",
                metadata={"server": name} if name else {},
            )
        )

    if doc is None:
        add(
            "AV-MCP-000",
            "Unparseable MCP configuration",
            Severity.LOW,
            "The config could not be parsed as JSON, so its servers cannot be reviewed.",
            (),
            "Fix the JSON or remove the file.",
            evidence=text.strip()[:120],
        )
        return findings

    servers = list(_servers(doc))
    if not servers:
        add(
            "AV-MCP-010",
            "MCP config with no recognizable server block",
            Severity.INFO,
            "No `mcpServers`/`servers` entries found; the file may use an unknown schema.",
            (),
            "Confirm the schema this client expects.",
        )

    for name, spec in servers:
        args = _args(spec)
        command = str(spec.get("command", "")) + " " + " ".join(args)
        url = str(spec.get("url", spec.get("endpoint", "")) or "")
        joined = f"{command} {url}"

        for installer, _ in UNPINNED_INSTALLERS:
            if installer in args or command.strip().startswith(installer):
                package = next(
                    (a for a in args if not a.startswith("-") and a != installer), ""
                )
                if package and not PINNED_RE.search(package):
                    add(
                        "AV-MCP-001",
                        "Unpinned MCP package install",
                        Severity.HIGH,
                        f"Server '{name}' is installed with `{installer}` but '{package}' has no "
                        "version or commit pin: the code your agent runs can change without review "
                        "(rug pull).",
                        ("mcp.untrusted", "exec.shell"),
                        "Pin the package version or use a commit SHA.",
                        name,
                        joined,
                    )

        if re.search(r"--dangerously-skip-permissions|--yolo\b|--trust-all", joined):
            add(
                "AV-MCP-002",
                "MCP server disables approval",
                Severity.HIGH,
                f"Server '{name}' is launched with an approval-bypass flag.",
                ("approval.bypass",),
                "Remove the flag.",
                name,
                joined,
            )

        if re.search(r"(?:^|[\s/])(?:ba)?sh\s+-c\b", joined):
            add(
                "AV-MCP-003",
                "MCP server launched through a shell",
                Severity.MEDIUM,
                f"Server '{name}' is started via `sh -c`, so shell metacharacters in the config "
                "are interpreted.",
                ("exec.shell",),
                "Invoke the binary directly with an argument list.",
                name,
                joined,
            )

        if url.startswith("http://"):
            add(
                "AV-MCP-004",
                "Plaintext remote MCP endpoint",
                Severity.HIGH,
                f"Server '{name}' connects to {url} over HTTP; tool descriptions and results can "
                "be modified in transit (SSE injection).",
                ("net.egress", "mcp.untrusted"),
                "Use HTTPS with certificate validation.",
                name,
                url,
            )

        env = spec.get("env")
        if isinstance(env, dict):
            risky = sorted(k for k in env if SECRET_ENV_RE.search(str(k)))
            if risky:
                add(
                    "AV-MCP-005",
                    "Credentials passed into MCP server",
                    Severity.HIGH,
                    f"Server '{name}' receives {', '.join(risky)} in its environment. A tool "
                    "description can ask the model to send these to any allowed host.",
                    ("fs.credentials", "net.egress"),
                    "Give the server a scoped token; never pass long-lived cloud credentials.",
                    name,
                    ", ".join(risky),
                )

        if spec.get("autoApprove") is True or spec.get("alwaysAllow") is True:
            add(
                "AV-MCP-006",
                "Server tools auto-approved",
                Severity.MEDIUM,
                f"Server '{name}' enables auto-approval for its tools.",
                ("approval.bypass",),
                "Require approval for state-changing tools.",
                name,
            )

        if INLINE_EXEC_RE.search(joined):
            add(
                "AV-MCP-007",
                "Inline code interpreter or tunnel in MCP command",
                Severity.HIGH,
                f"Server '{name}' executes inline code or opens a tunnel (`{INLINE_EXEC_RE.search(joined).group(0).strip()}`).",  # type: ignore[union-attr]
                ("exec.shell", "net.egress"),
                "Replace inline `-c`/`-e` scripts with a reviewed, version-pinned entry point.",
                name,
                joined.strip()[:160],
            )

        spec_blob = json.dumps(spec, ensure_ascii=False)
        shadow_hit = TOOL_SHADOW_RE.search(spec_blob)
        if shadow_hit:
            add(
                "AV-MCP-008",
                "Cross-tool shadowing or poisoned MCP descriptor",
                Severity.CRITICAL,
                f"Server '{name}' embeds coercive cross-tool instructions (`{shadow_hit.group(0)}`).",
                ("tool.spoof", "agent.deceive"),
                "Remove the server immediately; tool metadata must never hijack other tools.",
                name,
                shadow_hit.group(0),
            )

    # Also check top-level `tools` arrays in static MCP tool catalogs / fixtures.
    tools_block = doc.get("tools")
    if isinstance(tools_block, list):
        for tool in tools_block:
            if not isinstance(tool, dict):
                continue
            tname = str(tool.get("name", "tool"))
            tblob = json.dumps(tool, ensure_ascii=False)
            shadow_hit = TOOL_SHADOW_RE.search(tblob)
            if shadow_hit:
                add(
                    "AV-MCP-008",
                    "Cross-tool shadowing or poisoned MCP descriptor",
                    Severity.CRITICAL,
                    f"Tool '{tname}' embeds coercive cross-tool instructions (`{shadow_hit.group(0)}`).",
                    ("tool.spoof", "agent.deceive"),
                    "Strip coercive prompt instructions from the tool description.",
                    tname,
                    shadow_hit.group(0),
                )

    return findings
