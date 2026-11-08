"""Read-only MCP server: lets the agent ask agentvigil about its own surface.

This is the counterpart to `vigil mcp` (the sanitizing proxy). The proxy protects
the agent *from* a server; this server lets the agent *consult* the scanner:

    vigil mcp-serve        # stdio JSON-RPC, no network, no code execution

Tools are deliberately narrow and read-only. Nothing here writes, fixes, or
executes scanned content; the worst a confused model can do is ask for a report.
Protocol: MCP 2024-11-05 (`initialize`, `tools/list`, `tools/call`, `ping`).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO

from . import __version__
from . import chain as chain_engine
from .detectors import patterns as pattern_pack
from .detectors import scan_files
from .diff import diff_surface
from .findings import Severity
from .manifest import LOCK_NAME, build_lock, load_lock, verify_lock
from .score import breakdown, score
from .surface import discover

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "agentvigil", "version": __version__}

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "scan_surface",
        "description": (
            "Audit the instruction surface of a repository (AGENTS.md, skills, "
            "MCP configs, Kiro steering/specs) and return findings with spans, "
            "capabilities and decoded hidden payloads. Read-only."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Repository root", "default": "."},
                "strict": {
                    "type": "boolean",
                    "description": "Include noisy LOW/INFO rules",
                    "default": False,
                },
            },
        },
    },
    {
        "name": "capability_report",
        "description": (
            "Return the trust score and the capabilities the instruction surface "
            "grants the agent (exec.shell, fs.credentials, net.egress, ...). "
            "Use before running a task in an unfamiliar repository."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "default": "."}},
        },
    },
    {
        "name": "verify_lock",
        "description": (
            "Compare the repository's current instruction surface against "
            "vigil.lock and report added/removed/modified files plus the Merkle "
            "root check. Detects a rug pull since a human approved the surface."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "default": "."},
                "lock": {"type": "string", "description": "Lockfile path override"},
            },
        },
    },
    {
        "name": "list_rules",
        "description": "List the deterministic rule pack (id, severity, title).",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _result(msg_id: Any, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": payload}


def _error(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _text(payload: Any) -> Dict[str, Any]:
    return {
        "content": [
            {"type": "text", "text": json.dumps(payload, indent=2, ensure_ascii=False)}
        ],
        "isError": False,
    }


def _scan(root_arg: str, strict: bool = False) -> Dict[str, Any]:
    root = Path(root_arg)
    if not root.exists():
        raise ValueError(f"no such path: {root}")
    files = discover(root)
    findings = scan_files(files, strict=strict)
    findings.extend(chain_engine.correlate(files, findings))
    findings.sort(key=lambda f: f.sort_key())
    value, grade, verdict = score(findings)
    return {
        "path": str(root.resolve()),
        "trust": {"score": value, "grade": grade, "verdict": verdict},
        "files": len(files),
        "findings": [f.to_dict() for f in findings],
        "capabilities": sorted({c for f in findings for c in f.capabilities}),
    }


def _capability_report(root_arg: str) -> Dict[str, Any]:
    scanned = _scan(root_arg)
    findings = scanned["findings"]
    return {
        "path": scanned["path"],
        "trust": scanned["trust"],
        "capabilities": breakdown(
            [
                type("F", (), {"capabilities": f["capabilities"], "severity": Severity(f["severity"])})()
                for f in findings
            ]
        ),
        "counts": {
            sev: sum(1 for f in findings if f["severity"] == sev)
            for sev in ("critical", "high", "medium", "low", "info")
        },
    }


def _verify(root_arg: str, lock_arg: Optional[str]) -> Dict[str, Any]:
    root = Path(root_arg)
    lock_path = Path(lock_arg) if lock_arg else root / LOCK_NAME
    if not lock_path.exists():
        raise ValueError(f"no lockfile at {lock_path}; run `vigil manifest .`")
    lock = load_lock(lock_path)
    result = verify_lock(root, lock)
    result["lock"] = str(lock_path)
    return result


def _call_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    if name == "scan_surface":
        return _text(_scan(str(args.get("path") or "."), bool(args.get("strict", False))))
    if name == "capability_report":
        return _text(_capability_report(str(args.get("path") or ".")))
    if name == "verify_lock":
        return _text(_verify(str(args.get("path") or "."), args.get("lock")))
    if name == "list_rules":
        return _text(
            [
                {
                    "id": rule["id"],
                    "severity": rule["severity"].value,
                    "title": rule["title"],
                }
                for rule in pattern_pack.rules()
            ]
        )
    raise ValueError(f"unknown tool: {name}")


def handle_message(message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """One JSON-RPC message in, one response out (None for notifications)."""
    method = message.get("method")
    msg_id = message.get("id")

    if method == "initialize":
        return _result(
            msg_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        )
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return _result(msg_id, {})
    if method == "tools/list":
        return _result(msg_id, {"tools": TOOLS})
    if method == "tools/call":
        params = message.get("params") or {}
        name = str(params.get("name") or "")
        args = params.get("arguments") or {}
        try:
            return _result(msg_id, _call_tool(name, args if isinstance(args, dict) else {}))
        except (OSError, ValueError) as exc:
            return _result(
                msg_id,
                {
                    "content": [{"type": "text", "text": f"agentvigil: {exc}"}],
                    "isError": True,
                },
            )
    return _error(msg_id, -32601, f"method not found: {method}")


def serve(stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> int:
    """Serve MCP over newline-delimited JSON until stdin closes."""
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            stdout.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            stdout.flush()
            continue
        if not isinstance(message, dict):
            stdout.write(json.dumps(_error(None, -32600, "invalid request")) + "\n")
            stdout.flush()
            continue
        response = handle_message(message)
        if response is None:
            continue
        stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
        stdout.flush()
    return 0
