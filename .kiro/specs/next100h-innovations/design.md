# Design: transitive refs, MCP poisoning, lockless diff, canaries, graphs

## Overview

Five independent capabilities that move the tool from "scanner" to "review
workflow". Each is stdlib-only and demoable in under a minute.

## 1. Transitive context references (`vigil/detectors/refs.py`)

Parse `#[[file:...]]`, `@path` and markdown links. Flag paths that escape the
repository or target credential stores (`AV-REF-001`), unpinned remote
skills/branches (`AV-REF-002`), and includes that pull a non-surface file into
context (`AV-REF-003`). `extract_refs()` also feeds the attack-path graph.

## 2. MCP poisoning and runtime pinning (`vigil/proxy.py`)

The stdio proxy forwards JSON-RPC untouched except `tools/list`:

- strip invisible characters from `description`, `title` and `inputSchema`;
- hash each sanitized descriptor, expose `x-vigil-descriptor-sha256`;
- compare with `known_hashes` from `vigil.lock` and mark drift
  `x-vigil-rug-pull` plus `AV-MCP-RUGPULL`;
- run deterministic semantics over visible text; `--block-poisoned` replaces a
  poisoned description before the client sees it.

## 3. Lockless base-ref diff (`vigil/diff.py`)

`build_lock_at_ref()` materializes a virtual lock from any git ref through
read-only `git ls-tree` + `git show`, so a PR can be gated before `vigil.lock`
has ever been committed.

## 4. Zero-daemon canaries (`vigil/canary.py`)

`VIGIL-CANARY-<id8>-<mac8>` where the MAC is HMAC-SHA256 over the id with a fixed
domain key. Deterministic per `(repo name, merkle root, label)`, self-validating,
recorded by digest in `vigil.lock`. `check_text()` finds raw, Base64 and hex
leaks in transcripts.

## 5. Attack-path graph (`vigil/graph.py`)

A dependency-free layered SVG: files → capabilities → chains, embedded in HTML
reports and `vigil serve`. DOT remains available for Graphviz users.

## Additions in this iteration

- `vigil mcp-serve`: a read-only MCP server (scan, capability report, verify,
  rule list) so Kiro can consult the scanner instead of guessing.
- `vigil serve --theme kiroween`: opt-in Costume-Contest report.
- `.vigilignore`: exclude attack corpora from the repo's own gate.

## Properties (PBT)

- A valid canary token validates; a one-character mutation does not.
- `sanitize_tools_result` is idempotent and preserves visible description text.
- `build_lock_at_ref` only reads git (no writes, no checkout).
- `to_svg` output parses as XML and escapes file names.
