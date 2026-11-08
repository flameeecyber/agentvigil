"""Multimodal smuggling detector (Ghostcommit class).

Text-only scanners miss the newest channel: instructions hidden in images,
SVG files, and data URIs referenced *from* instruction files.

What this covers (stdlib-only, no image libs):
* SVG files and inline `<svg>` blocks: hidden `<text>`, `<foreignObject>`,
  `<script>`, event-handler attributes (`onload=`), and CSS that makes text
  invisible (`display:none`, 1px fonts) while the model still reads the XML.
* Markdown/HTML image references that delegate behaviour to remote pixels:
  `![alt](https://...)` + "follow the instructions in the image".
* Base64 data-URI images with suspicious surrounding prose.
* PNG `tEXt`/`zTXt`/`iTXt` ancillary chunks: free-form keywords the model
  reads when the agent opens the image with a vision tool.

Every finding carries evidence a human can verify. Binary parsing is
bounded and never executes anything.
"""

from __future__ import annotations

import base64
import binascii
import re
import struct
import zlib
from typing import List, Tuple

from ..findings import Finding, Severity
from ..surface import SurfaceFile

MAX_SVG_BYTES = 500_000
MAX_DATA_URI = 200_000
MAX_PNG_BYTES = 2_000_000

# Inline SVG or an .svg file on the surface.
SVG_TAG_RE = re.compile(r"<\s*(svg|foreignObject|script|image|text|metadata)\b[^>]{0,2000}>",
                         re.IGNORECASE | re.DOTALL)
EVENT_HANDLER_RE = re.compile(r"\bon(?:load|click|error|mouseover|focus)\s*=\s*[\"'][^\"']{1,400}[\"']",
                              re.IGNORECASE)
HIDDEN_CSS_RE = re.compile(r"(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|"
                           r"font-size\s*:\s*0|width\s*:\s*1px|height\s*:\s*1px)",
                           re.IGNORECASE)
MD_IMAGE_RE = re.compile(r"!\[[^\]]{0,200}\]\(\s*(https?://[^)\s]{4,300}|data:image/[^)\s]{10,200000})",
                         re.IGNORECASE)
HTML_IMG_RE = re.compile(r"<\s*img\b[^>]{0,2000}(?:src\s*=\s*[\"'](https?://[^\"']{4,300}|"
                         r"data:image/[^\"']{10,200000})[\"'])?[^>]{0,2000}>",
                         re.IGNORECASE | re.DOTALL)
FOLLOW_IMAGE_RE = re.compile(r"(follow|obey|apply|execute|read|extract)\b[^.\n]{0,80}\b"
                             r"(image|picture|screenshot|diagram|qr|barcode)\b",
                             re.IGNORECASE)
DATA_URI_RE = re.compile(r"data:image/(?:png|jpeg|gif|webp|svg\+xml);base64,[A-Za-z0-9+/=\s]{100,200000}",
                         re.IGNORECASE)
INTERESTING_PNG_KEYWORDS = re.compile(
    r"\b(?:ignore|execute|run|curl|wget|bash|powershell|token|api[_-]?key|"
    r"\.ssh|\.aws|exfiltrat|instruction|prompt)\b", re.IGNORECASE)


def _line_col(text: str, index: int) -> Tuple[int, int]:
    return text.count("\n", 0, index) + 1, index - text.rfind("\n", 0, index)


def _scan_text_vectors(file: SurfaceFile) -> List[Finding]:
    text = file.text
    findings: List[Finding] = []

    def add(rule_id: str, title: str, severity: Severity, index: int,
            message: str, caps: Tuple[str, ...], remediation: str,
            evidence: str = "") -> None:
        line, col = _line_col(text, index)
        start = max(0, index - 40)
        findings.append(Finding(
            rule_id=rule_id, title=title, severity=severity,
            path=file.path, line=line, column=col, message=message,
            evidence=(evidence or text[start:index + 120].replace("\n", "\\n").strip())[:300],
            technique="M1.4", capabilities=caps,
            remediation=remediation, detector="multimodal",
        ))

    is_svg = file.path.lower().endswith(".svg")
    haystack = text if len(text) <= MAX_SVG_BYTES else text[:MAX_SVG_BYTES]

    if is_svg or "<svg" in haystack.lower():
        for m in SVG_TAG_RE.finditer(haystack):
            tag = m.group(1).lower()
            if tag in ("script", "foreignobject"):
                add("AV-IMG-001", "Active content embedded in SVG on the instruction surface",
                    Severity.HIGH, m.start(),
                    f"SVG contains <{tag}>: code that runs when the image is previewed.",
                    ("exec.shell", "agent.deceive"),
                    "Remove the element or replace the SVG with a raster export.")
                break
        m = EVENT_HANDLER_RE.search(haystack)
        if m:
            add("AV-IMG-002", "Event handler inside SVG/image markup",
                Severity.HIGH, m.start(),
                "SVG/HTML image markup carries an on* event handler (script execution on preview).",
                ("exec.shell", "agent.deceive"),
                "Strip event attributes from images committed to the repo.")
        if HIDDEN_CSS_RE.search(haystack) and re.search(r"<\s*text\b", haystack, re.IGNORECASE):
            idx = HIDDEN_CSS_RE.search(haystack).start()  # type: ignore[union-attr]
            add("AV-IMG-003", "Visually hidden text inside SVG",
                Severity.MEDIUM, idx,
                "SVG text is styled invisible to humans but readable by vision models.",
                ("agent.deceive",),
                "Make the text visible or move the instruction into Markdown.")

    for m in MD_IMAGE_RE.finditer(text):
        target = m.group(1)
        # Remote image + nearby instruction to obey it = delegation to pixels.
        window = text[max(0, m.start() - 400):m.end() + 400]
        if FOLLOW_IMAGE_RE.search(window):
            add("AV-IMG-004", "Instruction delegates behaviour to a remote image",
                Severity.HIGH, m.start(),
                f"Agent is told to follow instructions inside an image at {target[:80]} "
                "that reviewers cannot diff.",
                ("net.egress", "agent.deceive", "agent.self_modify"),
                "Inline the rules as text instead of pointing at pixels.")
        elif target.startswith("http"):
            # Remote images alone are low signal; record at LOW so policy can allow.
            add("AV-IMG-005", "Remote image referenced from instruction file",
                Severity.LOW, m.start(),
                f"Instruction file loads a remote image ({target[:80]}): content can "
                "change without review.",
                ("net.egress",),
                "Vendor the image into the repo and pin its hash.")
    for m in HTML_IMG_RE.finditer(text):
        window = text[max(0, m.start() - 400):m.end() + 400]
        if FOLLOW_IMAGE_RE.search(window):
            add("AV-IMG-004", "Instruction delegates behaviour to a remote image",
                Severity.HIGH, m.start(),
                "Agent is told to follow instructions inside an <img> reviewers cannot diff.",
                ("net.egress", "agent.deceive", "agent.self_modify"),
                "Inline the rules as text instead of pointing at pixels.")

    for m in DATA_URI_RE.finditer(text):
        if len(m.group(0)) > MAX_DATA_URI:
            continue
        window = text[max(0, m.start() - 300):m.end() + 300]
        if FOLLOW_IMAGE_RE.search(window) or INTERESTING_PNG_KEYWORDS.search(window):
            add("AV-IMG-006", "Embedded image payload with suspicious surrounding prose",
                Severity.MEDIUM, m.start(),
                "A data-URI image sits next to instruction-like prose; reviewers see "
                "pixels, the agent reads text.",
                ("agent.deceive",),
                "Replace the embedded image with text or a checked-in file.")

    return findings


def scan_png_chunks(data: bytes, path: str) -> List[Finding]:
    """Scan PNG ancillary text chunks for instruction-like content.

    Pure function of bytes; called by `vigil scan` for co-located assets and
    directly testable without touching disk.
    """
    findings: List[Finding] = []
    if len(data) < 8 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return []
    if len(data) > MAX_PNG_BYTES:
        return []
    offset = 8
    while offset + 12 <= len(data):
        try:
            (length,) = struct.unpack(">I", data[offset:offset + 4])
        except struct.error:
            break
        ctype = data[offset + 4:offset + 8]
        end = offset + 8 + length + 4
        if length > 1_000_000 or end > len(data):
            break
        chunk = data[offset + 8:offset + 8 + length]
        if ctype in (b"tEXt", b"zTXt", b"iTXt"):
            try:
                if ctype == b"tEXt":
                    payload = chunk.split(b"\x00", 1)[-1].decode("latin-1", errors="replace")
                elif ctype == b"zTXt":
                    parts = chunk.split(b"\x00", 2)
                    payload = zlib.decompress(parts[-1]).decode("latin-1", errors="replace") if len(parts) == 3 else ""
                else:
                    parts = chunk.split(b"\x00", 3)
                    raw = parts[-1]
                    if len(parts) == 4 and parts[1:2] == b"\x01":
                        raw = zlib.decompress(parts[2] if len(parts) == 3 else raw)
                    payload = raw.decode("utf-8", errors="replace")
            except (zlib.error, IndexError, ValueError):
                payload = ""
            if payload and len(payload) >= 8 and INTERESTING_PNG_KEYWORDS.search(payload):
                findings.append(Finding(
                    rule_id="AV-IMG-010", title="Instruction-like text inside PNG metadata",
                    severity=Severity.MEDIUM, path=path, line=1, column=1,
                    message=f"PNG {ctype.decode('ascii', errors='replace')} chunk contains "
                    f"'{INTERESTING_PNG_KEYWORDS.search(payload).group(0)}'.",  # type: ignore[union-attr]
                    evidence=payload.strip()[:200],
                    technique="M1.4", capabilities=("agent.deceive",),
                    remediation="Strip PNG metadata (e.g. `pngcrush -rem text`) or vendor a clean export.",
                    decoded=payload.strip()[:280] or None,
                    detector="multimodal",
                ))
                break  # one finding per file is enough signal
        offset = end
        if ctype == b"IEND":
            break
    return findings


def scan(file: SurfaceFile) -> List[Finding]:
    # SVG files are text: scan them fully. Other text files: scan references.
    if file.path.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp")):
        return []
    try:
        return _scan_text_vectors(file)
    except re.error:
        return []
