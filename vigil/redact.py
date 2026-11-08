"""Secrets redaction: findings must never leak the credential they flag.

Detectors match live-looking secrets (AV-SECRET-001) to warn. Rendering must
show *that* a secret exists and its shape, never the value — terminal, JSON,
SARIF and Markdown all pass through here.
"""

from __future__ import annotations

import re

_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{24,}"), "[REDACTED_API_KEY]"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[^-]*-----END [^-]*-----"),
     "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"(?i)(aws_secret_access_key['\"\s:=]+)([^'\"\s,}]{8,})"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(secret['\"\s:=]+)([^'\"\s,}]{8,})"), r"\1[REDACTED]"),
]


def redact(text: str) -> str:
    if not text:
        return text
    out = text
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    return out
