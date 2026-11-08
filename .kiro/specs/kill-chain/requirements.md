# Spec: Kill-Chain Correlation & Provenance Blame (`AV-CHAIN-001..004`, `vigil blame`)

## Problem Statement
Single-rule alerts lose context across files. An attacker splits an exploit across `AGENTS.md` (remote delegation or credential read) and `.mcp.json` (execution primitive or exfiltration sink). Reviewers need both the connected attack path and the git provenance of who introduced each primitive.

## Acceptance Criteria
1. **WHEN** a surface combines remote instruction delegation (`AV-FETCH-001`, `AV-IMG-004`, `AV-REF-002`) with privileged execution (`AV-EXEC-*`, `AV-OBF-*`, `AV-MCP-003`, `AV-MCP-007`), **THE SYSTEM SHALL** emit `AV-CHAIN-001` (`critical`) citing the source rule IDs.
2. **WHEN** a surface combines credential access (`AV-CRED-*`, `AV-SECRET-001`, `AV-MCP-005`, `AV-REF-001`) with an exfiltration sink (`AV-EXFIL-*`), including primitives decoded from Unicode tags or Base64 (`inner_rules`), **THE SYSTEM SHALL** emit `AV-CHAIN-002` (`critical`).
3. **WHEN** a surface combines concealment (`AV-OVR-*`, `AV-HIDE-001`, `AV-UNI-*`, `AV-TOOL-001`, `AV-MCP-008`) with persistence or approval bypass, **THE SYSTEM SHALL** emit `AV-CHAIN-003` (`high`).
4. **WHEN** a surface combines an unpinned MCP package (`AV-MCP-001`) with credential passthrough (`AV-MCP-005`), **THE SYSTEM SHALL** emit `AV-CHAIN-004` (`critical`).
5. **WHEN** `vigil blame PATH:LINE` or `vigil scan --blame` is invoked, **THE SYSTEM SHALL** query `git blame --porcelain` read-only and return graceful `unknown` outside a git repository.
