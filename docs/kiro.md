# How this was built with Kiro

Timeline (specs → steering → hooks → agent → MCP → PBT), with friction.

## Specs (requirements → design → tasks → code → tests)

Each spec is a three-file unit, not a single requirements dump:

| Spec | Design | Tasks | Code | Tests |
|---|---|---|---|---|
| `unicode-smuggling` | `design.md` | `tasks.md` | `vigil/detectors/unicode.py` | `tests/test_unicode.py`, `test_spec_coverage.py` |
| `multimodal` | `design.md` | `tasks.md` | `vigil/detectors/multimodal.py` + PNG scan | `tests/test_advanced.py`, `test_spec_coverage.py` |
| `kill-chain` | `design.md` | `tasks.md` | `vigil/chain.py`, `vigil/provenance.py` | `tests/test_advanced.py`, `test_spec_coverage.py` |
| `policy-fix` | `design.md` | `tasks.md` | `vigil/policy.py`, `vigil/report.py`, `vigil fix` | `tests/test_advanced.py`, `test_spec_coverage.py` |
| `next100h-innovations` | `design.md` | `tasks.md` | `refs.py`, `proxy.py`, `diff.py`, `canary.py`, `graph.py`, `mcp_server.py`, `ui.py`, `dashboard.py`, `theme.py` | `tests/test_next.py`, `test_mcp.py`, `test_mcp_server.py`, `test_ui.py`, `test_theme.py`, `test_spec_coverage.py` |

The design docs carry the decisions and the properties; the task lists are the
honest state (`- [x]` means implemented **and** asserted, `- [ ]` means still
open). No spec without a test.

## Steering

Three modes, all used deliberately:

- `.kiro/steering/project-rules.md` — `inclusion: always`, the non-negotiables
  (stdlib core, evidence-first findings, pure detectors, no execution of scanned content).
- `.kiro/steering/product.md` — `inclusion: always`, the audience, the three
  questions the tool answers, and the explicit non-goals.
- `.kiro/steering/ui-theme.md` — `inclusion: fileMatch` on `vigil/theme.py`,
  `serve.py`, `dashboard.py`, `graph.py`: spooky must reveal function, never hide it.

The irony we demo: the agent that builds agentvigil is governed by files
agentvigil scans, and this repo passes its own gate thanks to `.vigilignore`.

## Hooks (real Kiro v1 hooks, plus a git hook)

`.kiro/hooks/` contains standalone v1 JSON hooks that Kiro actually loads:

- `surface-guard.json` — on save of `AGENTS.md`, `SKILL.md`, `.mcp.json`,
  `.cursorrules`, `.kiro/steering/**`, run `vigil scan . --fail-on high -q`; a
  non-zero exit sends the findings back to the agent.
- `diff-on-stop.json` — `agentStop` runs `vigil diff --fail-on high`: the
  capability delta since the approved lock, not just "any change".
- `lock-on-demand.json` — `userTriggered` runs `vigil manifest . -o vigil.lock`
  after a human reviews the surface.

`.kiro/hooks/pre-commit.sh` remains for plain-git contributors and calls the same
commands. It is a git hook, not a Kiro hook; earlier drafts conflated the two.

## Custom agent

`.kiro/agents/surface-auditor.json` scopes an agent to this task: read/write/shell,
the agentvigil MCP tools, steering as resources, and allow-listed shell rules for
`python -m vigil.cli *` + `pytest *`. Its prompt forbids executing scanned content
and requires rule id + span + decoded payload for every claim.

## MCP

Two different things, both shipped:

- `vigil mcp -- <server>` — the **proxy**: sanitizes `tools/list` descriptions,
  hashes descriptors, flags `x-vigil-rug-pull` on drift, `--block-poisoned`
  neutralizes a poisoned tool before the client reads it.
- `vigil mcp-serve` — the **server**: read-only tools (`scan_surface`,
  `capability_report`, `verify_lock`, `list_rules`) wired into Kiro through
  `.kiro/settings/mcp.json`. The agent can ask "is this repo safe for me to read?"
  instead of guessing.

Demo: the proxy cleans a poisoned description; the server answers a scan request.

## Property-based testing

`tests/test_properties.py` states rules that must hold for all inputs, with seeded
generation and no new dependency:

- sanitization removes hidden code points, preserves visible ASCII, is idempotent;
- scanning the same bytes twice is identical;
- the Merkle root is order-independent and content-bound;
- trust score is bounded and never rises when findings are added;
- `allow_rules` always exempts its rule.

`tests/test_spec_coverage.py` pins each acceptance criterion that previously had
no assertion (refs, IMG-002/003, UNI-005 decode, `inner_rules`, CHAIN-003,
`deny_paths`, malformed policy exit 2, `fix`, `--base`, canary encodings, rug-pull,
SVG well-formedness).

## Costume Contest

The default `vigil serve .` is a keyboard-first triage workbench: trust ring,
severity/capability filters in the URL, server-rendered finding cards with
`<details>` evidence, decoded payloads, copyable fixes, light/dark following the
OS, and a hash-based CSP with no external assets. The rationale is in
[`ux.md`](ux.md); the contract is `tests/test_ui.py`.

`vigil serve . --theme kiroween` renders the séance: rooms (files), apparitions
(findings), ghost script (decoded payloads), constellation (attack-path SVG).
Opt-in, no JavaScript, no CDN, `prefers-reduced-motion` respected, every dynamic
string escaped and redacted.

## Friction log (honest)

- Kiro suggested a K8s/Kafka architecture; rejected — stdlib-only wins installs.
- First chain engine double-counted single findings; fixed with the cross-primitive
  gate and `--no-chains`.
- Image scanning FP'd on docs with logos; remote-alone demoted to LOW, delegation
  stays HIGH.
- Blame was slow on 5k-file repos; made opt-in (`--blame`) with a per-location cache.
- The first "hook" was a shell script in `.kiro/hooks/`, which Kiro ignores. Reading
  the IDE 1.0 hook docs (`.kiro/hooks/*.json`, `when`/`then`) fixed it; both
  surfaces are now kept and documented.
- Self-scan initially failed on the project's own spec prose; `.vigilignore` plus
  one honest wording fix in steering made the gate real instead of decorative.
