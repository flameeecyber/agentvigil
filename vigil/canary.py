"""Zero-daemon agent canary / tripwire tokens.

Static scanning and lockfiles gate the instruction surface *before* the agent
runs. `vigil canary` answers the post-execution question without a cloud callback
server: "did the agent or an MCP tool exfiltrate context from this repo?"

How it works (stdlib-only, offline):
1. `generate(root, label=...)` derives a deterministic, self-checksumming token
   `VIGIL-CANARY-<8-hex-id>-<8-hex-mac>` scoped to the repo's Merkle root (or a
   caller seed) and records its SHA-256 digest in `vigil.lock` (`canaries`).
2. `check_text(text, lock=...)` scans agent transcripts, MCP stdio logs, or
   outbound request captures for the canary in raw, Base64, or hex form.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import manifest as manifest_mod
from .detectors import scan_files
from .surface import discover

CANARY_PREFIX = "VIGIL-CANARY-"
CANARY_RE = re.compile(r"\bVIGIL-CANARY-([0-9a-f]{8})-([0-9a-f]{8})\b", re.IGNORECASE)
_MAC_KEY = b"agentvigil-canary-v1"


@dataclass
class CanaryToken:
    canary_id: str
    token: str
    sha256: str
    label: str
    created_at: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "id": self.canary_id,
            "sha256": self.sha256,
            "label": self.label,
            "created_at": self.created_at,
        }


@dataclass
class CanaryHit:
    canary_id: str
    token: str
    encoding: str  # raw | base64 | hex
    line: int
    snippet: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canary_id": self.canary_id,
            "token": self.token,
            "encoding": self.encoding,
            "line": self.line,
            "snippet": self.snippet,
        }


def _mac_for(canary_id: str) -> str:
    return hmac.new(
        _MAC_KEY, canary_id.lower().encode("ascii"), hashlib.sha256
    ).hexdigest()[:8]


def is_valid_token(token: str) -> bool:
    m = CANARY_RE.fullmatch(token.strip())
    if not m:
        return False
    cid, mac = m.group(1).lower(), m.group(2).lower()
    return hmac.compare_digest(_mac_for(cid), mac)


def mint(seed: str, label: str = "default") -> CanaryToken:
    canary_id = hashlib.sha256(f"{seed}:{label}".encode("utf-8")).hexdigest()[:8]
    mac = _mac_for(canary_id)
    token = f"{CANARY_PREFIX}{canary_id}-{mac}"
    digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    return CanaryToken(
        canary_id=canary_id, token=token, sha256=digest, label=label, created_at=now
    )


def register_canary(
    root: Path, label: str = "default", lock_path: Optional[Path] = None
) -> CanaryToken:
    """Mint a repo-scoped canary and record its SHA-256 in `vigil.lock`."""
    root = Path(root).resolve()
    lock_file = Path(lock_path) if lock_path else root / manifest_mod.LOCK_NAME
    if lock_file.exists():
        lock = manifest_mod.load_lock(lock_file)
    else:
        files = discover(root)
        lock = manifest_mod.build_lock(files, scan_files(files), root)
    seed = f"{root.name}:{lock.get('root', '')}"
    canary = mint(seed, label=label)
    existing: List[Dict[str, str]] = list(lock.get("canaries", []))
    if not any(c.get("id") == canary.canary_id for c in existing):
        existing.append(canary.to_dict())
    lock["canaries"] = existing
    manifest_mod.write_lock(lock_file, lock)
    return canary


def check_text(text: str, lock: Optional[Dict[str, Any]] = None) -> List[CanaryHit]:
    """Scan a log/transcript for raw, Base64-encoded, or hex-encoded canary tokens."""
    known_ids = {
        c.get("id") for c in (lock or {}).get("canaries", []) if isinstance(c, dict)
    }
    hits: List[CanaryHit] = []
    seen = set()

    def _record(cid: str, tok: str, enc: str, pos: int) -> None:
        line = text.count("\n", 0, pos) + 1
        key = (cid, enc, line)
        if key in seen:
            return
        seen.add(key)
        start = max(0, pos - 30)
        end = min(len(text), pos + 60)
        hits.append(
            CanaryHit(
                canary_id=cid,
                token=tok,
                encoding=enc,
                line=line,
                snippet=text[start:end].replace("\n", "\\n").strip(),
            )
        )

    # 1. Raw matches
    for m in CANARY_RE.finditer(text):
        cid, mac = m.group(1).lower(), m.group(2).lower()
        if hmac.compare_digest(_mac_for(cid), mac) or cid in known_ids:
            _record(cid, m.group(0), "raw", m.start())

    # 2. Base64-encoded blobs
    for m in re.finditer(r"[A-Za-z0-9+/]{24,}={0,2}", text):
        blob = m.group(0)
        padded = blob + "=" * (-len(blob) % 4)
        try:
            decoded = base64.b64decode(padded, validate=False).decode(
                "utf-8", errors="ignore"
            )
        except Exception:
            continue
        for sub in CANARY_RE.finditer(decoded):
            cid, mac = sub.group(1).lower(), sub.group(2).lower()
            if hmac.compare_digest(_mac_for(cid), mac) or cid in known_ids:
                _record(cid, sub.group(0), "base64", m.start())

    # 3. Hex-encoded blobs
    for m in re.finditer(r"(?:[0-9a-fA-F]{2}){20,}", text):
        try:
            decoded = bytes.fromhex(m.group(0)).decode("utf-8", errors="ignore")
        except ValueError:
            continue
        for sub in CANARY_RE.finditer(decoded):
            cid, mac = sub.group(1).lower(), sub.group(2).lower()
            if hmac.compare_digest(_mac_for(cid), mac) or cid in known_ids:
                _record(cid, sub.group(0), "hex", m.start())

    return hits
