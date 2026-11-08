# agentvigil ADVANCED — what makes this win, trend, and stay novel

This is the *innovation + execution* layer: six shippable features, each
demoable in under 60 seconds, each stdlib-only.

## 1. The thesis in one paragraph

Scanners answer "is this file evil". Teams need "what changed, who approved
it, what can the agent do now, and how do I fix it in one click". The 6
features below turn agentvigil from a scanner into **the provenance + policy
+ fix layer** for the instruction surface. Each one is a GitHub screenshot,
a PR comment, or a 20-second demo moment — that is what trends and what
judges score.

## 2. The 6 advanced features (all implemented, all tested)

### F1. Multimodal smuggling detector (`AV-IMG-*`, `vigil/detectors/multimodal.py`)
Why novel: Ghostcommit (Jul 2026) hides prompt injection in images; every
existing scanner is text-only. We scan SVG active content, hidden SVG text,
remote-image delegation ("follow the instructions in the image"), data-URI
images, and PNG tEXt/zTXt/iTXt chunks — stdlib only (`struct`+`zlib`).
Demo: evil SVG with `<script>` + remote image delegation → 2 findings.
Rules: AV-IMG-001..006 text vectors, AV-IMG-010 PNG metadata.

### F2. Kill-chain correlation (`AV-CHAIN-*`, `vigil/chain.py`)
Why novel: nobody connects dots across files. We emit 4 chains only when
independent primitives combine: C1 remote-delegation+exec, C2 creds+exfil,
C3 concealment+persistence, C4 unpinned MCP + credential passthrough.
Each chain cites source rule ids. Evil-repo yields 3 critical chains;
clean-repo yields zero. This is the "oh, it's an attack path" moment.

### F3. Provenance blame (`vigil blame`, `vigil/provenance.py`)
Why novel: `mcp-scan`, `tirith`, Snyk agent-scan never say who introduced
the line. We wrap `git blame --porcelain` read-only; outside git we return
`unknown` instead of failing. `vigil scan --blame` enriches JSON with
commit/author/date. Demo: blame AV-EXEC-001 line → "introduced by X 3 days
ago in 'add telemetry'". Turns a finding into a review conversation.

### F4. Policy gate (`vigil/policy.py`, `--policy examples/policy.json`)
Why novel: severity thresholds cannot express "AGENTS.md may never grant
net.egress but Makefile may". Policy JSON supports global `deny`,
per-path `deny_paths`, explicit `allow_rules`, and `fail_on`. Invalid file
fails loud, never silent pass. Demo: same repo passes default but blocks
under strict policy with "Denied capability: exec.download".

### F5. PR-native Markdown (`--format markdown`, `vigil/report.py`)
Why trending: maintainers live in PRs, not terminals. `vigil scan
--format markdown` prints a 10-row table + worst finding + decoded payload;
`vigil diff --format markdown` prints BLOCKED/allowed + capability delta.
Paste into a GitHub Action comment. This is the screenshot that gets
retweeted, and the artifact judges check for "deployed URL + CI".

### F6. Safe auto-fix (`vigil fix [--apply]`, dry-run by default)
Why adopted: scanners that only alarm get uninstalled. `vigil fix` strips
only invisible smuggling chars (tag/bidi/zero-width via the same strip
table as the MCP proxy) and never rewrites semantics. `curl|sh` is reported,
not auto-edited. Dry-run lists counts; `--apply` writes cleaned files;
rerun `vigil scan` confirms. Safe to demo, safe to trust.

## 3. Commands after this upgrade

```console
vigil scan . --format markdown          # PR comment body
vigil scan . --policy policy.json       # org red lines
vigil scan . --blame                   # who taught the agent this
vigil diff --format markdown            # what the PR grants
vigil blame AGENTS.md:17 --json         # provenance for one line
vigil fix .                             # dry-run strip of invisible chars
vigil fix . --apply                     # write cleaned files
```

## 4. Judging mapping (score yourself weekly 1-5)

| Criterion | 5 looks like | Our evidence (new in bold) |
|---|---|---|
| Potential value | maintainer installs this week unasked | 1-command, FP table, GH Action, **policy.json, fix, PR markdown** |
| Implementation (Kiro) | specs→tests, steering, hooks, MCP, friction log | existing `.kiro/` + **new specs per F1-F6**, hook runs `vigil scan --policy`, MCP proxy + sanitizer |
| Quality & design | precise spans, calm output, honest docs | decoded payloads, **chain sources, blame commit, markdown tables**, threat model |
| Originality | "I haven't seen that" | lockfile + rug-pull + proxy + **image stego + chains + blame + policy + fix** |

## 5. GitHub trending plan (sequence matters)

T-7d: publish taxonomy + 3 chain screenshots + PNG-stego PoC. Collect 10
reviewers from security Discords; fix top 3 FPs.
T-1d: seed Show HN draft, r/netsec draft, 12s GIF (scan → decode → diff
→ blame → fix). README hero: GIF + `pipx install` + 3-command quickstart.
T-0 (Tue-Thu 14-16 UTC): release v0.2.0 + HN "Show HN: lockfile for the
files that program your agent" + X thread with decoded tag payload +
PNG chunk + chain screenshot.
T+2h: answer every comment with a test, post FP table when challenged.
T+1d: "we scanned top 200 repos" aggregate stats only, private disclosure
only, never name-and-shame.

Assets ready: GIF, `vigil diff` screenshot, PR markdown screenshot,
badge, CONTRIBUTING "add a payload in 5 min".

## 6. 50-day execution deltas (what changes vs PLAN-vigil.md)

Week 2 add: multimodal detector + PNG corpus (20 benign images, 5 stego).
Week 3 add: blame + policy; rug-pull demo now shows author + policy block.
Week 4 add: chains + fix; MCP proxy demo + `vigil fix --apply` before/after.
Week 5 add: benchmark v2 with image + chain tracks; `docs/kiro.md` covers
F1-F6 specs; video shot list gains 2 shots (0:55 chain graph, 2:05 fix).
Cut list unchanged: never cut decoded evidence, diff, SARIF, threat model,
video. If behind, cut Bedrock provider and hosted demo first.

## 7. Risks specific to advanced features

| Risk | Response |
|---|---|
| Image scanning FPs on docs with logos | Remote-image alone is LOW; only delegation+prose escalates; policy can allow |
| Blame slow on huge repos | One git call per (path,line), cached; `--blame` opt-in, never default |
| Policy too strict blocks legit repos | Ship `examples/policy.json` as strict + document relaxed variant; violations cite rule id |
| Fix accused of rewriting user files | Dry-run default, only invisible chars, semantic findings never auto-edited |
| Chains feel like double-counting | Chains cite sources and only fire on cross-file combos; `--no-chains` flag exists |

## 8. Definition of done for ADVANCED

- `pytest -q` green (33 tests incl. `test_advanced.py`).
- `vigil scan examples/evil-repo` shows AV-CHAIN + AV-IMG where applicable.
- `vigil scan examples/clean-repo` stays quiet at high+.
- `vigil scan . --policy examples/policy.json` blocks on evil, allows on clean.
- `vigil blame AGENTS.md:17` returns commit or graceful unknown.
- `vigil fix .` dry-run lists counts, writes nothing.
- README + `docs/kiro.md` document F1-F6 with screenshots.
