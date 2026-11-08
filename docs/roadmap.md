# agentvigil NEXT 300H — from hackathon win to field standard

Goal: turn the submission into a neutral, independently usable provenance layer for agent context.
Rule: each phase ships a stranger-usable artifact. No phase needs the next. The north star is adoption of a small, reviewable format—not feature count.

**Source of truth before the deadline:** [`docs/submission.md`](submission.md)
describes the current contest gates. This roadmap must not pull feature work
ahead of those gates.

## Phase A — Submission gate (now to Dec 4; feature freeze)

Win the rubric with working evidence, not a larger roadmap. The product and test suite are already ahead of the packaging; spend this phase making the existing work installable, inspectable, and easy to judge.

1. **Isolate the submission repository.** Create/verify a clean project root containing only the product; put `.kiro/`, the full Apache-2.0 license, README, tests, and CI at that root. Confirm `.kiro/` is tracked and visible. Never publish the home-directory Git root.
2. **Prove the stranger path from a clean clone.** Install with the documented command; run tests, benchmark, `vigil scan`, and `vigil serve`. Fix only release-blocking failures; record exact commands and results.
3. **Ship the required functional URL.** Deploy the existing read-only report/demo with no login, no external assets, and no execution of scanned content. If hosting is unreliable, use the simplest static/demo fallback that satisfies the rules; do not build a hosted scanning service.
4. **Record the sub-three-minute story.** Show one real scan → decoded evidence → capability/provenance decision → useful next action. Keep the product on screen, captions on, and claims limited to reproducible results. Test the final public link in a clean session.
5. **Finish the submission packet.** Confirm one eligible category against the actual rules, complete the Kiro-use write-up, verify repo/URL/video links, and submit by Dec 3 with Dec 4 reserved as buffer.
6. **Publish only evidence that exists.** Report the current benchmark size and limitations accurately; do not imply 300 payloads, external adoption, or a deployed service until those are real.

**Frozen until submission:** no new detector families, GitHub App, hosted multi-repo service, VS Code extension, signing variant, or roadmap-only polish. Existing `approve`, `graph`, and `audit` commands are demo material only if they already work cleanly; they are not blockers. Fix precision or demo-breaking defects ahead of optional features.

**Gate:** a stranger can clone the isolated public repo, install it, run the quickstart, open the functional URL, and understand the evidence in under three minutes. If any part fails, all remaining time goes to that failure. If the 25-repo FP sample exceeds 20%, freeze distribution claims and fix/demote noisy defaults before release.

## Phase B — Prove the format travels (50-150h, after submission)

Earn the “standard” claim through independent use. Keep the detector free and offline; the first platform feature is a portable contract, not a hosted dashboard.

7. **Freeze and publish the lockfile contract.** Specify versioning, canonicalization, path/kind/hash fields, capability semantics, signature verification, and downgrade/unknown-version behavior. Include golden input/output vectors and a threat model; separate normative requirements from this CLI's implementation choices.
8. **Make conformance reproducible.** Ship a small, safe fixture suite that a second implementation can run without importing `vigil`. Pin expected outputs and corpus provenance; report per-technique recall, false positives on benign repos, and runtime separately. Keep the current small baseline labeled as such; expand toward 300 only with deduplication, independent review, and a documented held-out protocol.
9. **Get one independent adopter before building the PR bot.** Ask an unrelated maintainer to generate, review, commit, and verify a lock in CI. Record install time, confusing fields, false positives, and any format breakage; resolve those before declaring the schema stable.
10. **Grow the benchmark with outside scrutiny.** Accept contributed payloads through a five-minute template and review process; label benign counterexamples too. Add the dedicated MCP track only when it has independent labels and a repeatable runner. Never execute corpus content.
11. **Then add the lowest-friction CI integration.** Start with documented SARIF/GitHub Actions and capability-delta output. Build a GitHub App only after at least three external repos run the CLI in CI and maintainers request PR comments; the bot must be a thin client of the public format and CLI behavior.
12. **First disclosure, responsibly.** Use opt-in or clearly authorized scans, private notification, and aggregate public reporting only; never name-and-shame a repository.

**Gate:** one non-author repository uses a committed lock in CI, and at least ten accepted payload contributions come from non-authors by day 90. If not, stop new integrations and fix onboarding, format friction, or contribution ergonomics. A larger corpus without independent labels is not progress.

## Phase C — Platform only after pull (150-300h, Feb-Apr)

13. Provenance graph v2: time-travel (`lock @ main` vs `lock @ PR` vs `HEAD`) and blame timeline.
14. Cross-ecosystem adapters: Cursor/Copilot/Gemini convention packs and lock migration, each backed by conformance fixtures.
15. Behavioral baseline (no ML libs): per-repo tool-use histograms and rarity scoring for new capabilities; opt-in and explainable.
16. Compliance mapping: lock + findings → SOC2/NIST-AI-RMF/ISO evidence pack, with explicit control-to-evidence mappings and no compliance guarantee.
17. Federated intel (privacy-safe): opt-in, anonymized technique counts only; never file contents or repository identifiers.
18. `vigil monitor` for scheduled drift alerts only if users need scheduled rescans; preserve a useful file-based/CI path without a service.
19. v1.0 org policy distribution and optional SSO/audit retention only after repeated organizational use justifies hosted operations.

**Platform gate:** do not build the dashboard/hosted tier until five independent teams use the CLI or lock monthly and at least two ask for shared policy/reporting. If that demand is absent, keep investing in the spec, reference tooling, and conformance suite instead.

Kill: any Phase C item that needs a daemon/database by default is cut — files you can diff beat services you must run.

## What NOT to build (ever)

Sandboxing, model alignment, syscalls, blockchain anchoring, quantum crypto,
AI-vs-AI arena, autonomous red-team agents. They bloat scope and lose trust.

## Metrics and decision gates

- **A — submission:** clean-clone install-to-first-finding under 90s; publish the measured FP result on the stated repo sample (target <10%, never hide a miss); URL and video open without login; submission confirmation received by Dec 3.
- **B — portability:** at least one non-author repo commits and verifies a lock in CI; at least 10 accepted non-author payloads; report per-technique benchmark results and benign-repo false positives. These are independent-use signals, not star counts.
- **C — platform pull:** five independent teams use the CLI/lock monthly for two consecutive months, two explicitly request shared policy/reporting, and any paid pilot covers ongoing service cost before a hosted tier is built.

If a gate misses, diagnose the adoption or precision bottleneck before adding scope. Stars, lines of code, and unreviewed corpus size do not substitute for these gates.
