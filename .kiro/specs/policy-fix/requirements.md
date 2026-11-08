# Spec: Policy Gate, PR Markdown & Safe Auto-Fix (`vigil/policy.py`, `vigil fix`)

## Problem Statement
Severity thresholds cannot express path-specific capability red lines (e.g. `AGENTS.md` may never grant `net.egress`, while `Makefile` may). And when invisible smuggling characters are detected, maintainers need a one-command safe remediation that never alters visible text.

## Acceptance Criteria
1. **WHEN** `--policy policy.json` is passed to `vigil scan` or `vigil diff`, **THE SYSTEM SHALL** block on any finding granting a capability in `deny` or matching `deny_paths`, while exempting rule IDs in `allow_rules`.
2. **WHEN** a policy JSON file is malformed or unreadable, **THE SYSTEM SHALL** fail loudly with exit code `2` (`EXIT_UNTRUSTED`) and never silently pass.
3. **WHEN** `--format markdown` is passed to `vigil scan` or `vigil diff`, **THE SYSTEM SHALL** render a PR-comment-ready Markdown summary with redacted evidence and capability delta.
4. **WHEN** `vigil fix` is run without `--apply`, **THE SYSTEM SHALL** report the count of invisible smuggling characters per file without writing to disk; with `--apply`, it shall strip only `STRIP_CODEPOINTS` and preserve all visible bytes.
