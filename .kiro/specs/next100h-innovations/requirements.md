# Spec: Next-100H Innovations — Context Refs, MCP Poisoning/Pinning, Ref-Diff, Canaries & SVG Graph

## Problem Statement
Attackers evolve past single-file rules into:
1. Transitive context inclusion (`#[[file:../../.env]]`, `@../secrets`, mutable remote skills),
2. Cross-tool MCP description poisoning and mid-session MCP descriptor rug pulls,
3. PRs against repositories that have not yet committed `vigil.lock`,
4. Silent exfiltration during agent execution where no static gate was run.

## Acceptance Criteria
1. **Transitive Context Detector (`AV-REF-001..003`)**: `vigil/detectors/refs.py` detects path traversal or secret targets in `#[[file:...]]`, `@path`, and markdown links (`AV-REF-001`), unpinned remote skill/branch imports (`AV-REF-002`), and shadow instruction surface includes (`AV-REF-003`).
2. **MCP Tool Poisoning & Runtime Pinning (`AV-MCP-007..008`, `vigil mcp --lock`)**: Static MCP scanning flags inline code interpreters/tunnels (`AV-MCP-007`) and coercive cross-tool shadowing (`AV-MCP-008`). Runtime proxy `sanitize_tools_result` inspects visible tool descriptions for injection rules, detects descriptor hash drift (`x-vigil-rug-pull`) against `known_hashes`, and neutralizes poisoned descriptions under `--block-poisoned`.
3. **Lockless Git-Ref Diff (`vigil diff --base <ref>`)**: `build_lock_at_ref` materializes a baseline lock directly from any git ref (`main`, `HEAD~1`) via read-only `git ls-tree` and `git show` so PR capability diffs work before `vigil.lock` is committed.
4. **Zero-Daemon Agent Canaries (`vigil canary`)**: `vigil/canary.py` mints deterministic, self-checksumming `VIGIL-CANARY-<id>-<mac>` tokens recorded in `vigil.lock` and detects raw, Base64, and hex-encoded canary leaks in transcripts.
5. **Self-Contained SVG Attack-Path Graph (`vigil graph --format svg`)**: `vigil/graph.py` renders a dependency-free layered SVG diagram (`Files -> Capabilities -> Kill Chains`) and embeds it in HTML reports and `vigil serve`.
