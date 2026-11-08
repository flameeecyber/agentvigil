"""Runtime gate: a stdio MCP proxy that sanitizes tool descriptions.

`vigil mcp -- npx -y @some/mcp-server` sits between the client and the server.
It forwards JSON-RPC untouched except for `tools/list` results, where it:

* strips invisible characters (tag chars, bidi controls, zero-width) that encode
  hidden instructions and render as nothing in the client UI;
* records a hash per tool descriptor so a later `tools/list` that quietly changes
  is visible in the log (rug-pull detection at runtime);
* keeps a redacted copy of what it removed, for the incident report.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, TextIO, Tuple

from .detectors import patterns
from .detectors.mcp import TOOL_SHADOW_RE
from .surface import SurfaceFile

STRIP_CODEPOINTS = (
    list(range(0x202A, 0x202F))
    + list(range(0x2066, 0x206A))
    + [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF]
    + list(range(0xE0000, 0xE0080))
    + list(range(0xFE00, 0xFE10))
    + list(range(0xE0100, 0xE01F0))
)
_STRIP_TABLE = dict.fromkeys(STRIP_CODEPOINTS, None)


@dataclass
class Redaction:
    tool: str
    removed: str
    count: int

    def to_dict(self) -> Dict[str, Any]:
        return {"tool": self.tool, "removed": self.removed, "count": self.count}


def sanitize_text(text: str) -> Tuple[str, str, int]:
    """Return (clean, removed_snippet, removed_count)."""
    removed_chars = [ch for ch in text if ord(ch) in _STRIP_TABLE]
    clean = text.translate(_STRIP_TABLE)
    return clean, "".join(removed_chars)[:200], len(removed_chars)


def scan_tool_semantics(
    name: str, description: str, schema_text: str = ""
) -> List[str]:
    """Run deterministic pattern + cross-tool shadowing rules over a tool descriptor."""
    combined = f"{description}\n{schema_text}".strip()
    if not combined:
        return []
    virtual = SurfaceFile(
        path=f"mcp:{name}",
        kind="agent_rules",
        data=combined.encode("utf-8", errors="replace"),
    )
    hits = [f.rule_id for f in patterns.scan(virtual)]
    if TOOL_SHADOW_RE.search(combined):
        hits.append("AV-MCP-008")
    return sorted(dict.fromkeys(hits))


def sanitize_tools_result(
    message: Dict[str, Any],
    *,
    known_hashes: Optional[Dict[str, str]] = None,
    block_poisoned: bool = False,
) -> Tuple[Dict[str, Any], List[Redaction]]:
    result = message.get("result")
    if not isinstance(result, dict):
        return message, []
    tools = result.get("tools")
    if not isinstance(tools, list):
        return message, []

    redactions: List[Redaction] = []
    kept_tools: List[Dict[str, Any]] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = str(tool.get("name", "?"))
        for field_name in ("description", "title"):
            value = tool.get(field_name)
            if isinstance(value, str):
                clean, removed, count = sanitize_text(value)
                if count:
                    tool[field_name] = clean
                    redactions.append(
                        Redaction(tool=name, removed=removed, count=count)
                    )
        schema = tool.get("inputSchema")
        schema_str = ""
        if isinstance(schema, dict):
            encoded = json.dumps(schema, ensure_ascii=False)
            clean, removed, count = sanitize_text(encoded)
            schema_str = clean
            if count:
                try:
                    tool["inputSchema"] = json.loads(clean)
                    redactions.append(
                        Redaction(tool=name, removed=removed, count=count)
                    )
                except json.JSONDecodeError:
                    pass
        digest = hashlib.sha256(
            json.dumps(tool, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()[:16]
        tool.setdefault("x-vigil-descriptor-sha256", digest)

        # Semantic tool-poisoning inspection on the visible text
        desc_text = str(tool.get("description", "") or "")
        sem_hits = scan_tool_semantics(name, desc_text, schema_str)
        if sem_hits:
            tool["x-vigil-findings"] = sem_hits

        # Runtime rug-pull detection against pinned tool hashes
        if known_hashes is not None:
            prev = known_hashes.get(name)
            if prev and prev != digest:
                tool["x-vigil-rug-pull"] = f"{prev}->{digest}"
                sem_hits = sorted(set(sem_hits) | {"AV-MCP-RUGPULL"})
                tool["x-vigil-findings"] = sem_hits
            else:
                known_hashes[name] = digest

        if block_poisoned and sem_hits:
            tool["description"] = f"[blocked by agentvigil: {', '.join(sem_hits)}]"
        kept_tools.append(tool)
    result["tools"] = kept_tools
    return message, redactions


def run_proxy(
    command: Sequence[str],
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    lock_path: Optional[Path] = None,
    block_poisoned: bool = False,
) -> int:
    if not command:
        print("usage: vigil mcp -- <server command> [args...]", file=sys.stderr)
        return 2
    known_hashes: Dict[str, str] = {}
    if lock_path and lock_path.exists():
        try:
            lock_doc = json.loads(lock_path.read_text(encoding="utf-8"))
            if isinstance(lock_doc.get("mcp_tools"), dict):
                known_hashes.update(
                    {str(k): str(v) for k, v in lock_doc["mcp_tools"].items()}
                )
        except (OSError, json.JSONDecodeError):
            pass

    child = subprocess.Popen(
        list(command),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
    )
    assert child.stdin and child.stdout

    def pump_client() -> None:
        try:
            for line in stdin:
                child.stdin.write(line)
                child.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                child.stdin.close()
            except OSError:
                pass

    thread = threading.Thread(target=pump_client, daemon=True)
    thread.start()

    try:
        for line in child.stdout:
            stripped = line.strip()
            if not stripped.startswith("{"):
                stdout.write(line)
                stdout.flush()
                continue
            try:
                message = json.loads(stripped)
            except json.JSONDecodeError:
                stdout.write(line)
                stdout.flush()
                continue
            sanitized, redactions = sanitize_tools_result(
                message, known_hashes=known_hashes, block_poisoned=block_poisoned
            )
            for redaction in redactions:
                print(
                    f"[vigil] stripped {redaction.count} invisible char(s) from tool "
                    f"'{redaction.tool}': {redaction.removed!r}",
                    file=sys.stderr,
                )
            for tool in (sanitized.get("result") or {}).get("tools") or []:
                if isinstance(tool, dict) and tool.get("x-vigil-rug-pull"):
                    print(
                        f"[vigil] rug-pull detected on tool '{tool.get('name')}': "
                        f"hash {tool['x-vigil-rug-pull']}",
                        file=sys.stderr,
                    )
                elif isinstance(tool, dict) and tool.get("x-vigil-findings"):
                    print(
                        f"[vigil] poisoned tool '{tool.get('name')}': "
                        f"{', '.join(tool['x-vigil-findings'])}",
                        file=sys.stderr,
                    )
            stdout.write(json.dumps(sanitized, ensure_ascii=False) + "\n")
            stdout.flush()
    except KeyboardInterrupt:
        pass

    if lock_path and lock_path.exists() and known_hashes:
        try:
            lock_doc = json.loads(lock_path.read_text(encoding="utf-8"))
            lock_doc["mcp_tools"] = dict(sorted(known_hashes.items()))
            lock_path.write_text(
                json.dumps(lock_doc, indent=2) + "\n", encoding="utf-8"
            )
        except (OSError, json.JSONDecodeError):
            pass

    child.terminate()
    return child.wait()
