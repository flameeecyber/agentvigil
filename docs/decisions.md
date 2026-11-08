# ADR log

1. Stdlib-only core — install friction kills security tools; extras behind `llm`/`sign`.
2. Pure detector functions — enables bench, fuzzing, third-party payloads without plugins.
3. Capability vocabulary as contract — `exec.shell`, `fs.credentials`, etc. stable across lock/SARIF/bench.
4. Chains only on cross-primitive combos — avoids double-counting, keeps precision.
5. Policy as JSON not YAML — no dependency; loud failure on bad file.
6. Fix touches only invisible chars — semantics are reported, never auto-rewritten.

7. Default/strict tiers — LOW/INFO rules (AV-NET-001, AV-AUTO-001, AV-IMG-005, AV-MCP-000/010, AV-UNI-004) fire only under --strict; precision beats recall in default.
8. `vigil init` owns onboarding — lock + policy + hook in one command; time-to-first-finding <90s is the metric.

9. `.vigilignore` for attack corpora — `examples/`, `bench/` and `.kiro/specs/` are data or prose *about* attacks, not instructions the agent obeys. Excluding them lets the repo pass its own gate; everything else is still scanned. Same syntax as gitignore for the common cases (directory prefix or glob), no negation.

10. A read-only MCP server, not just the proxy — `vigil mcp` protects the agent from a server; `vigil mcp-serve` lets the agent consult the scanner (`scan_surface`, `capability_report`, `verify_lock`, `list_rules`). No write or fix tools over MCP: a confused model must not be able to approve its own surface.

11. Property-based tests with stdlib only — seeded `random` generators, fixed iteration counts, no Hypothesis. The no-dependency rule matters more than shrinking ergonomics; failures print the exact input.

12. The Kiroween theme is opt-in — `vigil serve --theme kiroween`; plain HTML stays the default so CI screenshots, JSON and SARIF consumers do not change. The theme must reveal decoded payloads, never obscure them.

13. Both hook surfaces are kept — `.kiro/hooks/*.json` (v1, IDE/CLI) for Kiro, and `.kiro/hooks/pre-commit.sh` for plain git. They call the same commands; neither is required for `vigil scan` to work.

14. The default report is a triage workbench, not a table — server-rendered cards mean filtering is an enhancement, not a requirement; `<details>` is the only progressive disclosure. JavaScript filters, sorts and copies but never injects finding data (`innerHTML` is not used). The page ships with a hash-based CSP (`style-src`/`script-src` SHA-256, no `unsafe-inline`), zero external assets, URL-encoded filter state, and `no-store`/`nosniff`/`no-referrer` headers. The Kiroween theme stays opt-in and keeps its own style-only CSP because it ships no JavaScript.

15. Review ticks are browser-local, not a triage store — a read-only server must not grow writable status state, and a second status database would compete with `vigil.lock` / `vigil approve`. Each finding gets a content-bound key (SHA-256 of rule, path, line, title); only those 12-hex keys are stored in `localStorage`, scoped by root. The UI exposes progress, unreviewed/reviewed filters and a Markdown checklist of visible findings, all as progressive enhancement. The ticks are explicitly disposable: clearing site data resets them, and they are never treated as approval. This gives a daily reviewer a working loop without accounts, cookies, POST endpoints or telemetry.

16. Benchmark labels are strict and hand-authored — a case is invalid, not skipped, when its file is missing or its labels are malformed; `must_not_fire` is enforced alongside `must_fire`; benign controls include Markdown, JSON and SVG. The corpus is explicitly in-repo and synthetic, so its numbers are regression evidence, not an external precision claim. Matches in an explicit prohibition or quoted-documentation context are demoted to LOW with `metadata.context`, not deleted: the finding and capability stay reviewable, while the default high+ gate stops flagging prose that describes an attack. This guard is a heuristic, documented in `docs/benchmark.md`.

17. External spot checks are precision evidence, not benchmark claims — 17 public instruction files pinned to commits exposed three real defects: `--no-sandbox` is a browser sandbox flag, not an agent approval bypass; bare `silently` matches ordinary prose; `process.env.NODE_ENV` is a property read, not an environment dump. All three rules were narrowed and regression-tested. The sample is small, not randomly selected, and not independently labeled, so it can support “no high+ false positives on these files” and nothing broader. A genuine benchmark still needs a pre-registered sample and independent labelers.
