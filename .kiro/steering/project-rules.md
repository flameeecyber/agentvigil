---
inclusion: always
---

# Steering: how to work on agentvigil

## What this project is
A security CLI that audits, pins and gates the instruction surface of AI coding agents
(rules files, skills, MCP configs). Precision beats volume: a false positive costs a user's
trust, a missed critical costs their credentials.

## Non-negotiables
- Core (`vigil/`) is stdlib-only. Optional features live behind extras (`llm`, `sign`).
- Every finding has: precise span, human-readable evidence, technique id, capability tags,
  and a remediation. No finding without evidence.
- Never execute or import scanned content. Scanning is read-only.
- Detectors are pure functions of a `SurfaceFile`. No I/O inside detectors.
- New detector => new test with a malicious AND a benign fixture that must not fire.
- Public data shapes (`vigil.lock`, SARIF output, capability names) are contracts: bump a
  schema version rather than changing them without a bump.
- Benchmarks are reproducible: `python -m bench.run` prints the table.

## Style
- Python 3.9+, `from __future__ import annotations`, dataclasses, type hints on public APIs.
- CLI output: lowercase, no exclamation marks, always say what to do next.
- Comments explain *why* (the attack), not *what* (the loop).

## Definition of done for any change
1. `python -m pytest -q` green.
2. `vigil scan examples/evil-repo` still reports the seeded findings.
3. `vigil scan examples/clean-repo` reports nothing at `high` or above.
4. No new dependency without an explicit note in `docs/decisions.md`.

## When in doubt
Prefer the smaller change that keeps the demo working. The demo is the product.
