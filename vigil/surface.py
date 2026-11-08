"""Instruction-surface discovery.

The instruction surface is every file an agentic coding assistant may read and
*treat as instructions*: rules files, skills, MCP server configs, and the
automation those instructions can invoke. Discovery is convention-based on
purpose: no configuration, sensible defaults, everything overridable.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

MAX_FILE_BYTES = 1_500_000

SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".next",
    ".nuxt",
    "vendor",
    ".terraform",
}

# Exact filenames -> surface kind. Lower-cased comparison.
EXACT_NAMES: Dict[str, str] = {
    "agents.md": "agent_rules",
    "claude.md": "agent_rules",
    "gemini.md": "agent_rules",
    "copilot-instructions.md": "agent_rules",
    "windsurfrules": "agent_rules",
    "clinerules": "agent_rules",
    ".cursorrules": "agent_rules",
    ".rules": "agent_rules",
    ".goosehints": "agent_rules",
    "skill.md": "skill",
    "mcp.json": "mcp_config",
    ".mcp.json": "mcp_config",
    "claude_desktop_config.json": "mcp_config",
}

# Glob patterns (posix, matched against the repo-relative path).
GLOBS: List[Tuple[str, str]] = [
    (".cursor/rules/*", "agent_rules"),
    (".cursor/rules/**/*", "agent_rules"),
    (".cursor/*.mdc", "agent_rules"),
    (".github/instructions/*.md", "agent_rules"),
    (".kiro/steering/*", "agent_rules"),
    (".kiro/steering/**/*", "agent_rules"),
    (".kiro/specs/*", "spec"),
    (".kiro/specs/**/*", "spec"),
    (".kiro/hooks/*", "automation"),
    (".kiro/hooks/**/*", "automation"),
    (".agents/skills/**/*", "skill"),
    (".claude/skills/**/*", "skill"),
    (".kiro/skills/**/*", "skill"),
    ("*.svg", "agent_asset"),
    ("assets/*.png", "agent_asset"),
    ("assets/**/*", "agent_asset"),
    ("images/**/*", "agent_asset"),
    (".claude/agents/*.md", "agent_rules"),
    ("*.mcp.json", "mcp_config"),
    (".vscode/mcp.json", "mcp_config"),
    (".vscode/tasks.json", "automation"),
    (".devcontainer/devcontainer.json", "automation"),
    (".pre-commit-config.yaml", "automation"),
    ("Makefile", "automation"),
    (".git/hooks/*", "automation"),
    ("scripts/*.sh", "automation"),
]

# Files that are useful for context but should not be scanned as instructions
# by default (huge, generated, or binary).
BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tgz", ".tar", ".whl", ".so", ".dylib", ".dll", ".exe", ".bin", ".pyc",
    ".woff", ".woff2", ".ttf", ".mp4", ".mov", ".mp3",
}

IGNORE_NAME = ".vigilignore"


def _ignore_patterns(root: Path) -> List[str]:
    """Read `.vigilignore`: one glob or directory prefix per line.

    Test corpora and attack documentation are data, not instructions the agent
    obeys. Excluding them keeps the repo able to gate itself without weakening
    detection for real surface files.
    """
    try:
        raw = (Path(root) / IGNORE_NAME).read_text(encoding="utf-8")
    except OSError:
        return []
    patterns: List[str] = []
    for line in raw.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            patterns.append(line.rstrip("/"))
    return patterns


def _ignored(rel_posix: str, patterns: Sequence[str]) -> bool:
    for pattern in patterns:
        if rel_posix == pattern or rel_posix.startswith(pattern + "/"):
            return True
        if fnmatch.fnmatch(rel_posix, pattern) or fnmatch.fnmatch(rel_posix, pattern + "/*"):
            return True
    return False


KIND_LABELS = {
    "agent_rules": "agent rules",
    "skill": "agent skill",
    "mcp_config": "MCP config",
    "spec": "agent spec",
    "automation": "agent-reachable automation",
    "agent_asset": "agent-referenced asset",
}


@dataclass
class SurfaceFile:
    path: str  # repo-relative posix path
    kind: str
    data: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def text(self) -> str:
        return self.data.decode("utf-8", errors="replace")


def _classify(rel_posix: str) -> Optional[str]:
    name = rel_posix.rsplit("/", 1)[-1].lower()
    if name in EXACT_NAMES:
        return EXACT_NAMES[name]
    for pattern, kind in GLOBS:
        if fnmatch.fnmatch(rel_posix, pattern) or fnmatch.fnmatch(rel_posix, "*/" + pattern):
            return kind
    return None


def _walk(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for filename in sorted(filenames):
            yield Path(dirpath) / filename


def discover(root: Path) -> List[SurfaceFile]:
    """Find every instruction-bearing file under ``root``.

    ``root`` may be a directory or one explicitly named surface file. An
    explicit file bypasses `.vigilignore`: asking to scan it is intent to scan
    it, even when it lives in an excluded corpus.
    """
    root = Path(root).resolve()
    if root.is_file():
        kind = _classify(root.name)
        if kind is None or root.suffix.lower() in BINARY_SUFFIXES:
            return []
        try:
            if root.stat().st_size > MAX_FILE_BYTES:
                return []
            data = root.read_bytes()
        except OSError:
            return []
        return [SurfaceFile(path=root.name, kind=kind, data=data)]

    patterns = _ignore_patterns(root)
    results: List[SurfaceFile] = []
    for file_path in _walk(root):
        try:
            rel = file_path.relative_to(root).as_posix()
        except ValueError:
            continue
        if _ignored(rel, patterns):
            continue
        kind = _classify(rel)
        if kind is None:
            if file_path.suffix.lower() in BINARY_SUFFIXES:
                continue
            continue
        if file_path.suffix.lower() in BINARY_SUFFIXES:
            continue
        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                continue
            data = file_path.read_bytes()
        except (OSError, PermissionError):
            continue
        results.append(SurfaceFile(path=rel, kind=kind, data=data))
    results.sort(key=lambda f: f.path)
    return results


IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico"}


def discover_assets(root: Path) -> List[SurfaceFile]:
    """Co-located images/SVGs reviewers skip but vision agents read."""
    root = Path(root).resolve()
    if root.is_file():
        if root.suffix.lower() not in IMAGE_SUFFIXES:
            return []
        try:
            if root.stat().st_size > MAX_FILE_BYTES:
                return []
            data = root.read_bytes()
        except OSError:
            return []
        return [SurfaceFile(path=root.name, kind="agent_asset", data=data)]

    patterns = _ignore_patterns(root)
    assets: List[SurfaceFile] = []
    for file_path in _walk(root):
        if file_path.suffix.lower() not in IMAGE_SUFFIXES:
            continue
        try:
            rel = file_path.relative_to(root).as_posix()
        except ValueError:
            continue
        if _ignored(rel, patterns):
            continue
        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                continue
            data = file_path.read_bytes()
        except (OSError, PermissionError):
            continue
        assets.append(SurfaceFile(path=rel, kind="agent_asset", data=data))
    assets.sort(key=lambda f: f.path)
    return assets


def kinds_summary(files: Iterable[SurfaceFile]) -> Dict[str, int]:
    summary: Dict[str, int] = {}
    for f in files:
        summary[f.kind] = summary.get(f.kind, 0) + 1
    return summary
