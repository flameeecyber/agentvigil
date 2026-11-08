"""Encoded-blob detector: decode, then re-scan the decoded text.

Attackers put payloads in base64 or hex because reviewers' eyes skip long
strings. We decode candidate blobs (one level, bounded size) and look for the
same escalation vocabulary the pattern pack uses.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import List, Optional, Tuple

from ..findings import Finding, Severity
from ..surface import SurfaceFile
from . import patterns

MIN_BLOB = 80
MAX_DECODE = 400_000

BASE64_RE = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){60,}")

INTERESTING = re.compile(
    r"\b(?:curl|wget|bash|sh|powershell|invoke-expression|subprocess|os\.system|"
    r"requests\.(?:get|post)|http[s]?://|/bin/sh|exec\(|eval\(|chmod|"
    r"\.ssh|\.aws|token|api[_-]?key)\b",
    re.IGNORECASE,
)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(data)


def _try_decode(blob: str, encoding: str) -> Optional[bytes]:
    try:
        if encoding == "base64":
            padded = blob + "=" * (-len(blob) % 4)
            return base64.b64decode(padded, validate=False)
        return bytes.fromhex(blob)
    except (binascii.Error, ValueError):
        return None


def _line_col(text: str, index: int) -> Tuple[int, int]:
    return text.count("\n", 0, index) + 1, index - text.rfind("\n", 0, index)


def scan(file: SurfaceFile) -> List[Finding]:
    text = file.text
    findings: List[Finding] = []
    seen_spans = set()

    for encoding, regex in (("base64", BASE64_RE), ("hex", HEX_RE)):
        for match in regex.finditer(text):
            blob = match.group(0)
            if len(blob) > MAX_DECODE * 2:
                continue
            start = match.start()
            # Heuristic: long runs inside identifiers/URLs are rarely payloads.
            if (
                start > 0
                and text[start - 1].isalnum()
                and "/" not in text[start - 1 : start + 4]
            ):
                continue
            decoded = _try_decode(blob, encoding)
            if not decoded or len(decoded) < 24:
                continue
            if _printable_ratio(decoded) < 0.85:
                continue
            decoded_text = decoded.decode("utf-8", errors="replace")
            hit = INTERESTING.search(decoded_text)
            if not hit:
                continue
            key = (start, len(blob))
            if key in seen_spans:
                continue
            seen_spans.add(key)
            line, col = _line_col(text, start)
            preview = decoded_text.strip()[:280]
            virtual = SurfaceFile(path=file.path, kind=file.kind, data=decoded)
            inner_hits = patterns.scan(virtual)
            inner_caps = sorted({c for h in inner_hits for c in h.capabilities})
            inner_rules = sorted({h.rule_id for h in inner_hits})
            merged_caps = tuple(
                dict.fromkeys(("exec.shell", "agent.deceive") + tuple(inner_caps))
            )
            meta = {"encoding": encoding, "decoded_bytes": len(decoded)}
            if inner_rules:
                meta["inner_rules"] = inner_rules
            findings.append(
                Finding(
                    rule_id=f"AV-OBF-00{2 if encoding == 'base64' else 3}",
                    title=f"Encoded {('base64' if encoding == 'base64' else 'hex')} payload decodes to executable content",
                    severity=Severity.HIGH,
                    path=file.path,
                    line=line,
                    column=col,
                    message=(
                        f"A {len(blob)}-character {encoding} blob decodes to text containing "
                        f"'{hit.group(0)}'."
                    ),
                    evidence=blob[:120] + ("..." if len(blob) > 120 else ""),
                    technique="M1.3",
                    capabilities=merged_caps,
                    decoded=preview,
                    remediation="Inline the readable content or delete the instruction.",
                    detector="entropy",
                    metadata=meta,
                )
            )

    return findings
