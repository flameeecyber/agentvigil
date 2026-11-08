# Visual strategy: the triage workbench

The report is not a screenshot. It is the place a maintainer lands after CI
fails, the place a reviewer opens when a PR touches `.kiro/`, and the artifact
a judge opens from the submission link. All three need the same three answers
in the first screen:

1. **What is urgent?** — trust score, verdict, critical/high count.
2. **What can the agent actually do?** — capabilities, not just rule names.
3. **What do I run next?** — one copyable command, not a documentation hunt.

The previous plain report answered (1) and then showed a 50-row table. That is a
log, not a triage surface. The Kiroween theme answered all three but is opt-in
and intentionally theatrical. This rebuild gives the *default* report the same
clarity without the costume.

## Principles

| Principle | Consequence in the UI |
|---|---|
| Urgency before inventory | Score ring + verdict + critical/high KPI above the fold; files below findings. |
| Evidence without navigation | Every finding expands in place to evidence, decoded payload, remediation, detection. |
| Reversible filtering | Filters live in the URL; `Esc` clears; no state is lost on reload. |
| Calm by default | Severity color is a 3px edge and a label, never a full red card. One accent, no gradients. |
| Offline and inspectable | One stylesheet, two small scripts, no fonts/CDN/telemetry. `view-source` is the whole app. |
| Read-only means read-only | No POST, no writes, no fix execution from the browser. Actions are commands you copy. |

## Information hierarchy

```
header        identity · read-only · pinned/unpinned · theme · print · shortcuts
hero          ring, score, grade, verdict, one-sentence advice, KPIs (incl. reviewed)
toolbar       search · severity chips (all/urgent/…) · capability · sort
toolbar row   review state · fixable · progress · compact · copy summary · clear marks
findings      severity strip · worst-first cards → evidence/fix details
attack path   files → capabilities → kill chains (SVG)
kill chains   composed paths, or an explicit "none fire"
capabilities  blast radius with penalty meters
surface       every instruction file; click a path to filter
actions       copyable fix / manifest / diff commands
footer        endpoints and limits
```

Progressive disclosure is three levels: **score → finding card → `<details>`**.
Nothing requires a second page, a modal, or a network round trip.

## Visual system

Tokens are CSS custom properties in `vigil/ui.py`. A `prefers-color-scheme` media
query provides the light palette by default; `data-theme` on `<html>` overrides
it. The header toggle cycles `auto → light → dark` and persists the choice
locally. The palette is duplicated rather than using `light-dark()` so older
browsers still get a working theme and the toggle is never a dead button.

| Token | Dark | Light | Use |
|---|---|---|---|
| `--bg` | `#0a0e13` | `#f6f8fa` | page |
| `--panel` | `#121a24` | `#ffffff` | cards, toolbar |
| `--panel-2` | `#0d141c` | `#f0f3f6` | code, inset chips |
| `--line` | `#223041` | `#d1d9e0` | borders |
| `--ink` | `#e6edf3` | `#1f2328` | primary text |
| `--dim` | `#9aa7b4` | `#59636e` | secondary text |
| `--crit` | `#ff7b72` | `#cf222e` | critical |
| `--high` | `#ffa657` | `#bc4c00` | high |
| `--med` | `#e3b341` | `#9a6700` | medium |
| `--low` | `#79c0ff` | `#0969da` | low / links |
| `--ok` | `#3fb950` | `#1a7f37` | trusted, clean |

- Type: system UI for prose, `ui-monospace` for rules, paths, hashes and
  commands. No webfonts, so first render never waits on the network.
- Spacing: 4/8/10/14/18/24; cards 13–15px padding; page max 1180px.
- Severity is never color-only: each card carries an uppercase label and a
  dot, and the chip includes the count.
- The graph is a dark technical diagram in both themes; it sits in its own
  bordered viewport so the inversion reads as intentional.

## Interaction model

- **Search** matches rule, path, title, message, capability and technique.
- **Severity chips** are pressed-state buttons with counts; **urgent** is the
  critical+high preset. **Capability** narrows to one grant; **sort** switches
  worst / file / rule.
- **Review filters** are all / unreviewed / reviewed; **fixable** narrows to
  findings with a canned remediation. Both compose with search, severity and
  capability.
- **URL state** (`?q=exec&sev=urgent&cap=exec.shell&review=unreviewed&fix=1`) makes
  a filtered view shareable and survives reload. This replaces "saved views"
  without a backend.
- **Click a surface path** to filter to that file — the most common triage move.
- **Review** is a local tick plus a progress KPI. `Copy summary` produces a
  Markdown checklist of the currently visible findings for a PR or issue.
- **Density** switches comfortable/compact and persists; **Export** exposes the
  Markdown, SARIF, JSON, graph and badge endpoints without hunting the footer.
- **Copy** buttons exist for path:line, the whole finding, each next command and
  the triage summary. Clipboard failures fall back to a hidden textarea.

Keyboard:

| Key | Action |
|---|---|
| `/` | focus search |
| `j` / `k` | next / previous visible finding |
| `Enter` | toggle evidence on the focused finding |
| `e` | expand or collapse all evidence |
| `c` | copy the focused path:line |
| `r` | mark the focused finding reviewed |
| `s` | copy the visible triage summary |
| `d` | toggle compact density |
| `Esc` | clear the query or close the shortcut dialog |
| `?` | shortcut dialog |

## States

- **Clean** — a deliberate empty state, not a blank table: check, "Clean
  surface", and the pin/gate commands.
- **No matches** — explains how to reset; the query stays in the URL.
- **Unpinned** — a red `unpinned` pill with the reason in its title; the
  manifest command is one copy away.
- **Decoded payload** — shown in a bordered block with "shown, never executed".
- **Missing evidence/remediation** — honest fallback text, never an empty box.
- **Reduced motion** — all transitions and smooth scrolling disabled.

## Review workflow

The daily loop is "read a finding, decide, move on". Review ticks are deliberately
**browser-local scratch state**, not a second source of truth:

- Each card has a `data-key` = truncated SHA-256 of `rule | path | line | title`.
  Editing any of those makes it a new item instead of inheriting a stale tick.
- The key list is stored under `vigil-reviewed:<root>` in `localStorage`. It
  contains hashes only — no paths, titles, messages or evidence.
- `reviewed` is reflected in the card (`data-reviewed`), its button
  (`aria-pressed`), the hero KPI and the live progress line; the reviewed filter
  hides or isolates cards without a reload.
- `Clear marks` resets the root's store after confirmation; unmarking one card
  works too. If a mark hides the focused card under the reviewed filter, focus
  advances to the next visible card instead of disappearing. Nothing is sent to
  the server, and nothing here is an approval: `vigil.lock` / `vigil approve`
  remain the durable record.
- The summary copies only **visible** cards as a Markdown checklist, so the
  reviewer can narrow to `urgent + unreviewed + fixable` first and send exactly
  that context.
- All review controls are `needs-js`: without JavaScript the findings remain
  fully readable and no dead buttons appear.

## Accessibility

Target: WCAG 2.2 AA for the chrome and content.

- Semantic landmarks (`header`, `main`, `section` + `aria-labelledby`), one `h1`,
  ordered headings, skip link to findings.
- All controls are native `button`, `input`, `select`, `details`, `dialog`;
  no div-buttons, no keyboard traps.
- Visible `:focus-visible` ring (2px, 3:1 against both themes); `j/k` moves real
  focus, not a CSS-only selection.
- Search has a label; chips are in a labelled group with `aria-pressed`;
  the result count and review progress are polite live regions. Review buttons
  carry `aria-pressed` and an action-specific label.
- The mobile header wraps to a second row instead of overflowing; the severity
  chips scroll horizontally, and controls stay reachable with one hand.
- Contrast: body text uses `--ink` on `--panel` (≥ 12:1), secondary `--dim`
  (≥ 4.5:1), severity colors are used for large/bold labels or paired with text.
- `pre` blocks are focusable and scrollable; tables have headers; `<meter>`
  carries a text count beside it.
- Print stylesheet hides chrome and forces evidence open.

## Security constraints

- **CSP with hashes**, not `unsafe-inline`: `default-src 'none'`, no connect,
  no frames, no forms; the exact stylesheet and both scripts are allow-listed
  by SHA-256. `tests/test_ui.py` recomputes the style hash from the constant.
- **No `innerHTML` with finding data.** The page is server-rendered and escaped;
  JavaScript only toggles `hidden`, sorts existing nodes, writes `textContent`,
  and copies strings. A hostile title/path/decoded payload is covered by a test.
- **No external requests**: no fonts, images, analytics or CDN. The favicon is
  an inline SVG route. The Export menu downloads same-origin endpoints.
- **Review storage is local and minimal**: `localStorage` holds only a set of
  12-hex review keys under a root-scoped name. No finding content, no cookies,
  no network call; clearing site data removes it.
- **Read-only**: only GET/HEAD; 404 otherwise; `no-store` and `nosniff` on every
  response; `Referrer-Policy: no-referrer`; `X-Frame-Options: DENY`.
- The Kiroween theme keeps its own CSP (`style-src 'unsafe-inline'`,
  `script-src 'none'`) because its meter uses a CSS custom property and it ships
  no JavaScript at all.

## Performance budget

- One HTML request, zero subresources; ~98 KB for 18 findings (~5.4 KB/finding)
  including inline CSS/JS, the attack-path SVG and the review/export layer;
  ~45 KB for a clean surface.
- Scan happens once per request, server-side, stdlib only. No hydration, no
  virtual DOM, no client-side parsing of the full finding set.
- Target: interactive under 200 ms for the fixture repos on a laptop; the
  footer shows the measured scan time.
- If a repo produces hundreds of findings, the page grows linearly; a future
  cap/virtual list is only worth adding if real repos exceed a few hundred.

## How we would measure it

No telemetry. Use task tests with 5 maintainers:

1. "Which finding would you fix first?" → time to first click, correctness.
2. "Show only critical and high." → chips vs search, time.
3. "Copy the exact path to fix." → copy affordance success.
4. "What command pins this surface?" → actions panel recall.
5. "Mark three findings reviewed and copy the summary." → ticks persist after
   reload, progress updates, summary contains only visible cards.
6. "Is this repo safe to run an agent in?" → verdict comprehension.

Success: median < 30 s for (1) and (2), 5/5 correct on (5), no keyboard traps.

## What we borrowed, and what we rejected

- **GitHub security overview** — severity/rule/state filters, explicit sort,
  and preserved investigation context. We adopted the filter bar and URL state;
  we did not adopt org-wide role views (this is a single repo, read-only).
- **Wiz / security-console research** — three levels of progressive disclosure
  (posture → issue list → issue detail) and compound risk framing. We adopted
  the three levels and the capability/penalty framing; we rejected toxic-
  combination scoring, which needs cross-resource context this tool does not have.
- **Trivy HTML report requests and `semgrep-ui`** — users repeatedly ask for
  severity filtering/grouping inside a self-contained HTML report. We built
  filtering client-side into the existing page; we rejected the Next.js + Mongo
  triage app model because it turns a zero-dependency report into a service.
- **Semgrep triage statuses** (open/reviewing/fixed/ignored) — deliberately not
  built here. The browser tick is a disposable reading aid, not a status store;
  `vigil.lock` approvals already own durable state, and a second server-side
  status store would drift.
- **A review database / accounts** — would turn a read-only report into a
  service and make the same finding mean different things to different viewers.

## Deliberately not built

- A SPA/router: the report is one document; URL params cover saved views.
- A triage database (open/ignored/fixed): that belongs in the lockfile/approvals
  workflow, not a read-only demo server.
- Live LLM adjudication in the browser: `--llm` stays a CLI opt-in.
- Charts for their own sake: the only graph is the attack path, because it
  explains composition rather than decorating counts.
