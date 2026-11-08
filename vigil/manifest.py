"""The lockfile.

`vigil.lock` is the provenance artifact: a Merkle root over the canonical
instruction surface plus the capabilities each file grants. It is designed to be
committed, reviewed in a PR, and signed in CI — the same social contract as
`package-lock.json`, applied to the text that programs your agent.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import __version__
from .findings import Finding, cap_names
from .surface import SurfaceFile, discover

SCHEMA = "agentvigil.lock/v1"
LOCK_NAME = "vigil.lock"


def _leaf(path: str, digest: str) -> str:
    return hashlib.sha256(f"{path}\0{digest}".encode("utf-8")).hexdigest()


def merkle_root(leaves: Sequence[str]) -> str:
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256((level[i] + level[i + 1]).encode("ascii")).hexdigest()
            for i in range(0, len(level), 2)
        ]
    return level[0]


def canonical_entry(file: SurfaceFile, caps: Iterable[str] = ()) -> Dict[str, Any]:
    return {
        "path": file.path,
        "kind": file.kind,
        "sha256": file.sha256,
        "size": file.size,
        "capabilities": cap_names(caps),
    }


def build_lock(files: Sequence[SurfaceFile],
               findings: Sequence[Finding],
               root: Optional[Path] = None) -> Dict[str, Any]:
    per_file: Dict[str, set] = {f.path: set() for f in files}
    for finding in findings:
        if finding.path in per_file:
            per_file[finding.path].update(finding.capabilities)
    entries = [canonical_entry(f, per_file.get(f.path, ())) for f in files]
    entries.sort(key=lambda e: e["path"])
    leaves = [_leaf(e["path"], e["sha256"]) for e in entries]
    return {
        "schema": SCHEMA,
        "tool": f"agentvigil/{__version__}",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "root": merkle_root(leaves),
        "file_count": len(entries),
        "files": entries,
        "signature": None,
    }


def dumps(lock: Dict[str, Any]) -> str:
    return json.dumps(lock, indent=2, sort_keys=False) + "\n"


def write_lock(path: Path, lock: Dict[str, Any]) -> None:
    path.write_text(dumps(lock), encoding="utf-8")


def load_lock(path: Path) -> Dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA:
        raise ValueError(f"{path}: unsupported lock schema {data.get('schema')!r}")
    return data


def verify_lock(root: Path, lock: Dict[str, Any]) -> Dict[str, Any]:
    """Recompute the surface and compare against the lock."""
    files = discover(root)
    current = {f.path: f for f in files}
    locked = {e["path"]: e for e in lock.get("files", [])}

    added = sorted(set(current) - set(locked))
    removed = sorted(set(locked) - set(current))
    modified = sorted(
        p for p in set(current) & set(locked)
        if current[p].sha256 != locked[p]["sha256"]
    )
    leaves = [_leaf(e["path"], e["sha256"]) for e in lock.get("files", [])]
    root_ok = merkle_root(leaves) == lock.get("root")
    return {
        "root_ok": root_ok,
        "expected_root": lock.get("root"),
        "computed_root": merkle_root(leaves),
        "added": added,
        "removed": removed,
        "modified": modified,
        "clean": root_ok and not (added or removed or modified),
    }


# --------------------------------------------------------------------------
# signing (optional: requires `cryptography`)
# --------------------------------------------------------------------------

def keygen(path: Path) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    os.chmod(path, 0o600)
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return pub.hex()


def _signing_payload(lock: Dict[str, Any]) -> bytes:
    body = {k: v for k, v in lock.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_lock(lock: Dict[str, Any], key_path: Path) -> Dict[str, Any]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("signing key must be an Ed25519 private key")
    signature = key.sign(_signing_payload(lock))
    lock = dict(lock)
    lock["signature"] = {
        "alg": "ed25519",
        "key_id": hashlib.sha256(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).hexdigest()[:16],
        "value": signature.hex(),
    }
    return lock


def verify_signature(lock: Dict[str, Any], public_key_hex: str) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    sig = lock.get("signature") or {}
    if sig.get("alg") != "ed25519" or not sig.get("value"):
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        key.verify(bytes.fromhex(sig["value"]), _signing_payload(lock))
        return True
    except Exception:
        return False
