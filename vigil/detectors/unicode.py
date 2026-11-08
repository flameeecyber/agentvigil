"""Unicode smuggling detector.

Instruction files are text, so attackers hide instructions in characters humans
cannot see:

* tag characters (U+E0000..U+E007F) encode a full ASCII payload that renders as
  nothing in every editor and terminal;
* bidi controls (U+202A..U+202E, U+2066..U+2069) reverse or reorder text so the
  rendered file differs from the bytes the model reads;
* zero-width characters split keywords ("ig<ZWSP>nore all rules");
* variation-selector runs (U+FE00..U+FE0F, U+E0100..U+E01EF) carry stego bits.

Every finding here includes the *decoded* payload, because "there is a weird
character" is not evidence and "your agent is told to curl | sh" is.
"""

from __future__ import annotations

import unicodedata
from typing import Dict, List, Tuple

from ..findings import Finding, Severity
from ..surface import SurfaceFile
from . import patterns

BIDI = {
    0x202A: "LRE",
    0x202B: "RLE",
    0x202C: "PDF",
    0x202D: "LRO",
    0x202E: "RLO",
    0x2066: "LRI",
    0x2067: "RLI",
    0x2068: "FSI",
    0x2069: "PDI",
}
ZERO_WIDTH = {
    0x200B: "ZWSP",
    0x200C: "ZWNJ",
    0x200D: "ZWJ",
    0x2060: "WJ",
    0x2061: "FA",
    0x2062: "IT",
    0x2063: "IS",
    0x2064: "IP",
    0xFEFF: "BOM",
}
TAG_BASE = 0xE0000
TAG_RANGE = range(0xE0020, 0xE007F)

# Common Cyrillic/Greek homoglyphs used to make "ignоre" look like "ignore".
HOMOGLYPH_RANGES = (
    (0x0400, 0x04FF),  # Cyrillic
    (0x0370, 0x03FF),  # Greek
)
HOMOGLYPH_LOOKALIKES = set("аеорсхуіјѕԁɡАВЕКМНОРСТХІЈЅ")

MAX_FINDINGS_PER_FILE = 40


def _line_col(text: str, index: int) -> Tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    last_newline = text.rfind("\n", 0, index)
    return line, index - last_newline


def _snippet(text: str, index: int, width: int = 60) -> str:
    start = max(0, index - width // 2)
    end = min(len(text), index + width // 2)
    return text[start:end].replace("\n", "\\n")


def _decode_tags(chars: List[str]) -> str:
    return "".join(chr(ord(c) - TAG_BASE) for c in chars if ord(c) in TAG_RANGE)


def _is_printable_ascii(text: str) -> bool:
    if not text or len(text) < 4:
        return False
    good = sum(1 for c in text if c in "\t\n\r" or 32 <= ord(c) <= 126)
    return (good / len(text)) >= 0.85


def _decode_variation_selectors(chars: List[str]) -> str:
    """Decode emoji/variation-selector steganography into plaintext when possible.

    Supports three schemes seen in the wild:
    1. Direct ASCII in U+E0120..U+E017E (cp - 0xE0100).
    2. 256-byte VS table (U+FE00..U+FE0F -> 0..15, U+E0100..U+E01EF -> 16..255).
    3. Nibble pairs in U+FE00..U+FE0F ((hi << 4) | lo).
    """
    cps = [ord(c) for c in chars]
    if all(0xE0120 <= cp <= 0xE017E for cp in cps):
        direct = "".join(chr(cp - 0xE0100) for cp in cps)
        if _is_printable_ascii(direct):
            return direct

    raw_bytes: List[int] = []
    for cp in cps:
        if 0xFE00 <= cp <= 0xFE0F:
            raw_bytes.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            raw_bytes.append(cp - 0xE0100 + 16)
    if raw_bytes:
        try:
            candidate = bytes(raw_bytes).decode("utf-8")
            if _is_printable_ascii(candidate):
                return candidate
        except UnicodeDecodeError:
            pass

    if (
        len(cps) >= 8
        and len(cps) % 2 == 0
        and all(0xFE00 <= cp <= 0xFE0F for cp in cps)
    ):
        nibbles = [
            ((cps[i] - 0xFE00) << 4) | (cps[i + 1] - 0xFE00)
            for i in range(0, len(cps), 2)
        ]
        try:
            candidate = bytes(nibbles).decode("utf-8")
            if _is_printable_ascii(candidate):
                return candidate
        except UnicodeDecodeError:
            pass

    return ""


def _inner_analysis(
    file_path: str, file_kind: str, payload: str
) -> Tuple[Tuple[str, ...], List[str]]:
    """Re-scan a decoded payload with the pattern pack to attribute hidden capabilities."""
    if not payload.strip():
        return (), []
    virtual = SurfaceFile(
        path=file_path, kind=file_kind, data=payload.encode("utf-8", errors="replace")
    )
    hits = patterns.scan(virtual)
    caps = sorted({c for h in hits for c in h.capabilities})
    rules = sorted({h.rule_id for h in hits})
    return tuple(caps), rules


def scan(file: SurfaceFile) -> List[Finding]:
    text = file.text
    if not text:
        return []

    findings: List[Finding] = []
    seen: Dict[Tuple[str, int], bool] = {}
    tag_run: List[str] = []
    tag_start = 0
    var_run: List[str] = []
    var_start = 0

    def add(
        rule_id: str,
        title: str,
        severity: Severity,
        index: int,
        message: str,
        technique: str,
        caps: Tuple[str, ...],
        decoded: str = "",
        remediation: str = "",
        metadata: Dict[str, object] | None = None,
    ) -> None:
        line, col = _line_col(text, index)
        key = (rule_id, line)
        if key in seen or len(findings) >= MAX_FINDINGS_PER_FILE:
            return
        seen[key] = True
        findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                path=file.path,
                line=line,
                column=col,
                message=message,
                evidence=_snippet(text, index),
                technique=technique,
                capabilities=caps,
                decoded=decoded or None,
                remediation=remediation,
                detector="unicode",
                metadata=dict(metadata) if metadata else {},
            )
        )

    def _flush_tags() -> None:
        nonlocal tag_run
        if not tag_run:
            return
        payload = _decode_tags(tag_run)
        if payload.strip():
            inner_caps, inner_rules = _inner_analysis(file.path, file.kind, payload)
            merged_caps = tuple(
                dict.fromkeys(("agent.deceive", "tool.spoof") + inner_caps)
            )
            meta = {"inner_rules": inner_rules} if inner_rules else None
            add(
                "AV-UNI-001",
                "Hidden instruction encoded in Unicode tag characters",
                Severity.CRITICAL,
                tag_start,
                f"{len(tag_run)} invisible tag characters encode {len(payload)} bytes of "
                "text that the model reads and humans cannot see.",
                "M1.3",
                merged_caps,
                decoded=payload,
                remediation="Delete the tag characters. Treat any file containing them as untrusted.",
                metadata=meta,
            )
        tag_run = []

    def _flush_vars() -> None:
        nonlocal var_run
        if len(var_run) >= 8:
            vs_payload = _decode_variation_selectors(var_run)
            inner_caps, inner_rules = (
                _inner_analysis(file.path, file.kind, vs_payload)
                if vs_payload
                else ((), [])
            )
            merged_caps = tuple(dict.fromkeys(("agent.deceive",) + inner_caps))
            meta = {"inner_rules": inner_rules} if inner_rules else None
            sev = Severity.HIGH if vs_payload else Severity.MEDIUM
            add(
                "AV-UNI-005",
                "Variation-selector steganography run",
                sev,
                var_start,
                f"{len(var_run)} consecutive variation selectors carry hidden bits "
                "(emoji/VS stego channel).",
                "M1.3",
                merged_caps,
                decoded=vs_payload,
                remediation="Normalize the file to NFC and remove variation selectors.",
                metadata=meta,
            )
        var_run = []

    for i, ch in enumerate(text):
        cp = ord(ch)

        # Tag characters: highest-signal smuggling primitive.
        if cp in TAG_RANGE:
            if not tag_run:
                tag_start = i
            tag_run.append(ch)
            continue
        elif tag_run:
            _flush_tags()

        if cp in BIDI:
            add(
                "AV-UNI-002",
                f"Bidirectional override character U+{cp:04X} ({BIDI[cp]})",
                Severity.HIGH,
                i,
                "Bidi controls make the file render differently from the bytes the agent reads "
                "(Trojan Source class).",
                "M1.3",
                ("agent.deceive",),
                remediation="Strip the control character; review the file as raw bytes.",
            )
        elif cp in ZERO_WIDTH and not (cp == 0xFEFF and i == 0):
            add(
                "AV-UNI-003",
                f"Zero-width character U+{cp:04X} ({ZERO_WIDTH[cp]})",
                Severity.MEDIUM,
                i,
                "Zero-width characters are used to split keywords past text filters while the "
                "model still reads them as one token.",
                "M1.3",
                ("agent.deceive",),
                remediation="Remove invisible characters; scan the raw bytes.",
            )
        elif cp == 0x1B and i + 1 < len(text) and text[i + 1] == "[":
            add(
                "AV-UNI-004",
                "ANSI escape sequence in an instruction file",
                Severity.LOW,
                i,
                "Terminal escape sequences can hide or rewrite output shown to a human reviewer.",
                "M1.3",
                ("agent.deceive",),
                remediation="Remove escape sequences from instruction files.",
            )

        # Variation selectors: stego payload carrier when they appear in runs.
        if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
            if not var_run:
                var_start = i
            var_run.append(ch)
        elif var_run:
            _flush_vars()

        # Mixed-script homoglyphs inside otherwise-Latin words.
        if (
            any(lo <= cp <= hi for lo, hi in HOMOGLYPH_RANGES)
            and ch in HOMOGLYPH_LOOKALIKES
        ):
            left = text[i - 1] if i else ""
            right = text[i + 1] if i + 1 < len(text) else ""
            if (
                left.isascii()
                and left.isalpha()
                and right.isascii()
                and right.isalpha()
            ):
                add(
                    "AV-UNI-006",
                    "Homoglyph character inside a Latin word",
                    Severity.MEDIUM,
                    i,
                    f"U+{cp:04X} ({unicodedata.name(ch, 'unknown')}) is visually identical to a "
                    "Latin letter and is used to evade keyword matching.",
                    "M1.3",
                    ("agent.deceive",),
                    remediation="Replace with the ASCII letter or treat the file as untrusted.",
                )

    # A payload at end-of-file never gets flushed by the loop above.
    _flush_tags()
    _flush_vars()

    return findings
