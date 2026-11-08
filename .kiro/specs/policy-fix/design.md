# Design: policy gate, PR markdown and safe fix

## Overview

Severity thresholds cannot express path-specific red lines. A tiny JSON policy
adds capability denials per path, explicit rule exemptions, and a severity floor.
`vigil fix` handles the one class of finding that can be remediated without
changing meaning: invisible characters.

## Policy evaluation order

For each finding:

1. `allow_rules` — if the rule id is listed, never block.
2. `deny` — if any capability intersects the global deny set, block.
3. `deny_paths` — if the file path matches a substring and a capability
   intersects that entry's set, block.
4. `fail_on` — otherwise block when severity is at or above the floor.

Loading is strict: unreadable or malformed JSON raises, and the CLI maps that to
exit code `2` (`EXIT_UNTRUSTED`). A policy file never silently degrades to "pass".

## Markdown

One PR-comment body: trust score, a 10-row severity/rule/file/capability table,
the worst finding, and the decoded payload when present. Evidence passes through
`redact` so a secret is named, never printed.

## Fix

`STRIP_CODEPOINTS` is the same table the MCP proxy uses. `vigil fix` is a dry run
by default; `--apply` writes only files where at least one invisible character was
removed. Visible bytes are never rewritten and semantic findings (download-exec,
credential access) are only reported.

## Properties (PBT)

- A rule in `allow_rules` never produces a blocking verdict.
- Malformed policy → exit 2, never exit 0.
- `fix` preserves every visible character and is idempotent.
- Adding a finding never raises the trust score.

## Failure modes

- Substring path matching can over-match (`AGENTS.md` also matches
  `docs/AGENTS.md`); documented, and stricter globbing is future work.
- `fix --apply` rewrites files, so it is opt-in and prints the count first.
