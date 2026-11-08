# Submission checklist (Dec 4, 14:00 PT = Dec 5, ~05:00 WIB)

## Verified done in the repo

- [x] Full Apache-2.0 `LICENSE` text at the package root
- [x] Source install quickstart: `pipx install .` from a clone (PyPI release
      pending; `python -m pip install .` is the fallback)
- [x] `.kiro/` with specs (requirements/design/tasks), steering (always + fileMatch),
      Kiro v1 hooks, custom agent, and workspace MCP config
- [x] README quickstart + install + Kiro harness section
- [x] Working CLI: `scan`, `manifest`, `diff`, `verify`, `mcp`, `mcp-serve`,
      `blame`, `fix`, `graph`, `canary`, `serve`, `audit`, `dashboard`, `sbom`
- [x] `docs/kiro.md` with spec→test map, hooks, agent, MCP, PBT, friction log
- [x] Property-based tests + one regression test per acceptance criterion
- [x] Benchmark 29/29 labeled payloads (30/30 required rules), 13/13 benign
      controls quiet at high+; `bench/index.html` scoreboard. This is a hand-
      authored, in-repository synthetic corpus, not an external evaluation.
- [x] External spot check: 17 pinned public instruction files. Nine development
      files exposed three precision defects (fixed); eight held-out files then
      produced one true-positive unpinned-skill finding and no other findings.
      See `bench/external.md`; 17 files are not a production FP rate.
- [x] CI gates: tests, bench, clean fixture, evil fixture, SARIF
- [x] `vigil.lock` committed (dogfooded provenance)
- [x] `vigil serve --theme kiroween` Costume-Contest report

## Still required for Devpost (not code)

- [ ] Publish a **clean public GitHub repo** whose root contains `.kiro/`,
      `README.md`, `LICENSE` (do not publish the parent home-directory repo)
- [ ] Replace root `LICENSE` with the full Apache-2.0 text so GitHub detects it
- [ ] Deploy `vigil serve` and provide the **functional app URL**; the Docker
      default already serves `examples/evil-repo` on `0.0.0.0:8000`
- [ ] Record and upload the **< 3 min** demo video to YouTube
- [ ] Write the text description and the Kiro usage write-up in the form
- [ ] Declare **one** category: Costume Contest
- [ ] Optional bonus: blog post published during the period, mentioning
      Kiroween 2026
- [ ] Optional bonus: social post **starting with** `#KiroweenHackathon26`
- [ ] Submit by Dec 3, keep Dec 4 as buffer

## Honest gaps

- No GitHub App / PR bot; the workflow is CI + CLI.
- No hosted multi-repo service; `audit`/`dashboard` are local.
- Detectors are deterministic only by default; `--llm` needs a provider key.
- No sandbox or runtime VM; this protects the instruction channel, not execution.
- Benchmark labels are self-authored and in-repo. The 17-file external check
  is a small pinned spot check, not a representative sample or a production
  false-positive table. Do not describe either result as a general precision
  rate.
- The prohibition/quoted-documentation precision guard is heuristic; a payload
  phrased as a prohibition can still evade the default high+ gate.
