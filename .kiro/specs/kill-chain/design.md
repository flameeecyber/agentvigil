# Design: kill-chain correlation and provenance

## Overview

Individual detectors produce alerts. Reviewers need paths. `correlate()` takes the
whole surface plus its findings and emits a finding only when independent
primitives combine into one executable chain, citing the rules it builds on.

## Chain rules

| Id | Left side | Right side | Severity |
|---|---|---|---|
| `AV-CHAIN-001` | remote delegation (`AV-FETCH-001`, `AV-IMG-004`, `AV-REF-002`) | privileged execution (`AV-EXEC-*`, `AV-OBF-*`, `AV-MCP-003`, `AV-MCP-007`) | critical |
| `AV-CHAIN-002` | credential access (`AV-CRED-*`, `AV-SECRET-001`, `AV-MCP-005`, `AV-REF-001`) | exfiltration sink (`AV-EXFIL-*`) | critical |
| `AV-CHAIN-003` | concealment (`AV-OVR-*`, `AV-HIDE-001`, `AV-UNI-*`, `AV-TOOL-001`, `AV-MCP-008`) | persistence / approval bypass (`AV-PERSIST-001`, `AV-BYP-001`, `AV-MCP-002/006`, `AV-AUTO-001`) | high |
| `AV-CHAIN-004` | unpinned MCP package (`AV-MCP-001`) | credential passthrough (`AV-MCP-005`) | critical |

## Decisions

- **Cross-primitive gate.** A chain requires both sides; one finding never
  produces a chain. `--no-chains` disables the layer entirely.
- **Inner rules count.** `metadata["inner_rules"]` from decoded payloads is
  included, so a Unicode-smuggled `curl | sh` participates in C1.
- **Pseudo-path `SURFACE`.** Chains span files, so they are not attributable to a
  line; the evidence lists the contributing paths and rule ids.
- **Blame is opt-in and read-only.** `git blame --porcelain` per distinct
  `(path, line)`, cached, returning `unknown` outside a repository.

## Properties (PBT)

- No input produces a chain with only one of the two sides present.
- Every emitted chain has non-empty `metadata["sources"]`.
- `correlate` is deterministic and does not mutate its inputs.
- `blame_line` never raises when git is missing or the path is untracked.

## Failure modes

- Correlating across the whole surface can produce a chain from unrelated files
  in a monorepo; policy can exempt specific rule ids.
- Blame is slow on very large histories; it stays behind `--blame`.
