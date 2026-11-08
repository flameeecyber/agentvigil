# 3-minute demo (shot list, scripted to the second)

| Time | Shot | Line |
|---|---|---|
| 0:00 | Clone evil-repo, agent proposes `curl|sh` | "This repo just told my AI agent to run a script." |
| 0:15 | `vigil scan` → critical tag-char decode appears | "The instruction was invisible. Here it is." |
| 0:40 | `vigil serve examples/evil-repo` → workbench | "One page answers: how bad, what can it do, what do I run?" |
| 1:00 | Filter high, expand a finding, show evidence + decoded | "Every claim has a span, and the hidden payload is decoded." |
| 1:20 | Click a surface path to filter; copy the fix command | "Triage is one click and one copy, not a dashboard tour." |
| 1:35 | `vigil manifest` → lockfile, merkle root | "Now the surface is pinned like a dependency." |
| 1:50 | PR changes one line; `vigil diff --format markdown` blocks | "When it changes, review sees what it grants." |
| 2:05 | `vigil blame AGENTS.md:17` → commit/author | "We know who taught the agent this." |
| 2:15 | `vigil mcp` strips poisoned tool description | "Even at runtime, the agent doesn't read the lie." |
| 2:25 | `vigil fix` dry-run → apply → rescan clean | "Strip the invisible, keep the visible." |
| 2:35 | `python -m bench.run` → 29/29, benign 13/13 quiet | "Twenty-nine labeled synthetic cases, thirteen benign controls, one command. Not an external benchmark." |
| 2:50 | End card: name, Apache-2.0, "built with Kiro" | — |

Serve the fixture, not the clean repo, for the UI shot:

```console
vigil serve examples/evil-repo --port 8000
# optional Costume Contest variant:
vigil serve examples/evil-repo --theme kiroween
```

Rules: no intro animation, captions on, terminal font ≥18pt, 1440p,
product on screen ≥80% of runtime. Do not claim a hosted build in the video
unless `vigil serve` is actually reachable at the URL shown.
