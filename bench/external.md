# External instruction-file checks

This is a small **external quietness check**, not an external benchmark. It asks
whether the high+ gate stays quiet on real instruction files that the project
did not author. It does not measure recall, and it is not a production
false-positive rate.

Files were downloaded from public repositories at pinned commits, scanned
locally, and not vendored. Raw URL:
`https://raw.githubusercontent.com/<repo>/<commit>/<path>`.

## Method

```console
# One directory per repository keeps the canonical basename (AGENTS.md,
# CLAUDE.md, GEMINI.md, copilot-instructions.md) that discovery recognizes.
python -m vigil.cli scan /tmp/vigil-external-tree --json --strict
```

The positive control is the repository's own labeled payload, copied to a
recognized name so a clean result cannot be a broken scan:

```console
mkdir -p /tmp/vigil-control
cp bench/payloads/D2.1-download-exec/curl-pipe/file.md /tmp/vigil-control/AGENTS.md
python -m vigil.cli scan /tmp/vigil-control --json --strict
# -> AV-EXEC-001, critical
```

## Development sample (used to find precision defects)

Nine files from nine repositories, 96,888 bytes. This sample is **not held
out**: its findings drove three rule corrections, so it is now a regression
sample.

| Repository | Commit | Path | Bytes | High+ before | High+ after |
|---|---|---|---:|---:|---:|
| anthropics/claude-code | `0ed94698` | `CLAUDE.md` | 2,218 | 0 | 0 |
| anomalyco/opencode | `caf8d6a5` | `AGENTS.md` | 17,380 | `AV-OVR-002` | 0 |
| google-gemini/gemini-cli | `62bab5b2` | `GEMINI.md` | 4,610 | 0 | 0 |
| QwenLM/qwen-code | `5ee128e7` | `AGENTS.md` | 18,361 | `AV-OVR-002` | 0 |
| cline/cline | `94eecbbe` | `AGENTS.md` | 5,449 | `AV-BYP-001` ×2 | 0 |
| aaif-goose/goose | `5bad61a8` | `AGENTS.md` | 6,081 | 0 | 0 |
| vercel/next.js | `ec8ddcd7` | `AGENTS.md` | 31,539 | 0 | 0 |
| microsoft/vscode | `fdefc478` | `AGENTS.md` | 271 | 0 | 0 |
| charmbracelet/crush | `8f1f0295` | `AGENTS.md` | 10,979 | 0 | 0 |

The five pre-fix high+ hits were two `AV-OVR-002` concealment matches, two
`AV-BYP-001` approval-bypass matches on `--no-sandbox`, and one
`AV-CHAIN-003` correlation. There were also four medium `AV-CRED-002` matches
on `process.env` references (mostly property reads such as
`process.env.NODE_ENV`).

After the fixes the same sample has **0 high+ findings** and one LOW
`AV-CRED-002` (an `Avoid modifying process.env` instruction, demoted as a
negated mention). The fixes:

- `--no-sandbox` is a Chromium sandbox flag, not an agent approval flag; it was
  removed from `AV-BYP-001`.
- Bare `silently` matched ordinary prose ("nothing is silently dropped"). The
  rule now requires a concealment action verb within the same sentence.
- `process.env.NODE_ENV` is a property read, not an environment dump. The rule
  now requires bare `process.env` / `os.environ`; property access is ignored.
- Negated environment-dump mentions are demoted to LOW with the existing
  precision guard.

## Held-out sample (not used for tuning)

Eight different files from eight repositories, 111,889 bytes. No rule was
changed after seeing this result.

| Repository | Commit | Path | Bytes | High+ |
|---|---|---|---:|---:|
| microsoft/vscode-copilot-chat | `5863f5a7` | `.github/copilot-instructions.md` | 17,401 | 0 |
| supabase/supabase | `dc73b346` | `AGENTS.md` | 7,035 | 0 |
| prisma/prisma | `557c0d4c` | `AGENTS.md` | 11,687 | `AV-REF-002` |
| openai/openai-python | `a1175a35` | `AGENTS.md` | 4,470 | 0 |
| astral-sh/uv | `3e2f08f8` | `AGENTS.md` | 3,746 | 0 |
| modelcontextprotocol/servers | `36380287` | `AGENTS.md` | 51,210 | 0 |
| withastro/astro | `39ede5f0` | `AGENTS.md` | 8,925 | 0 |
| remix-run/react-router | `fcfccb2e` | `AGENTS.md` | 7,415 | 0 |

The single finding is `AV-REF-002` on
`npx skills add prisma/ignite/skills/.pilot --skill '*'`: an unpinned external
skill import, which is the rule working as designed. It is a true positive by
the rule's policy, not a scanner error, even if the repository considers the
workflow acceptable. There were no other findings at any severity.

## What this supports, and what it does not

Across the 17 files (208,777 bytes), after the fixes there are **0 high+
false positives** and **1 high true positive**. That is evidence the in-repo
benign result is not only an artifact of our own prose, and that the scan is
not silent on real content.

It is not:

- a random or representative sample of repositories;
- independently labeled by a second reviewer;
- a recall measurement (one true positive does not establish detection);
- a production false-positive rate (17 files is far too small);
- a held-out check of the rules as a whole, because the development sample was
  used to change them. The eight-file held-out sample was not used for tuning,
  but it was selected after the fixes, not before.

The next credible step is a larger, pre-registered sample with two independent
labelers and a published per-rule FP table.
